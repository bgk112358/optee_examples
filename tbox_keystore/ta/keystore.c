/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Key lifecycle management:
 *   - Generate RSA/AES keys inside TEE
 *   - Serialize/deserialize to persistent storage
 *   - Export public key material
 *   - Delete keys
 */

#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/* ---- Serialized key header (precedes attribute data) ---- */

#define KEY_ATTR_RSA_COUNT  8
#define KEY_ATTR_AES_COUNT  1

struct serialized_key {
	uint32_t key_type;
	uint32_t permissions;
	uint32_t key_size_bits;
	uint32_t attr_count;
	uint32_t attr_sizes[KEY_ATTR_RSA_COUNT];
	/* followed by attr_sizes[0] + attr_sizes[1] + ... bytes of data */
};

/* ---- RSA attribute indices ---- */
enum rsa_attr_idx {
	RSA_ATTR_MODULUS = 0,
	RSA_ATTR_PUB_EXP = 1,
	RSA_ATTR_PRIV_EXP = 2,
	RSA_ATTR_PRIME1 = 3,
	RSA_ATTR_PRIME2 = 4,
	RSA_ATTR_EXP1 = 5,
	RSA_ATTR_EXP2 = 6,
	RSA_ATTR_COEFF = 7,
};

static const uint32_t g_rsa_attr_ids[] = {
	TEE_ATTR_RSA_MODULUS,
	TEE_ATTR_RSA_PUBLIC_EXPONENT,
	TEE_ATTR_RSA_PRIVATE_EXPONENT,
	TEE_ATTR_RSA_PRIME1,
	TEE_ATTR_RSA_PRIME2,
	TEE_ATTR_RSA_EXPONENT1,
	TEE_ATTR_RSA_EXPONENT2,
	TEE_ATTR_RSA_COEFFICIENT,
};

/* ---- Per-session read cache (avoids REE FS close→reopen bug) ---- */

#define CACHE_SLOTS 4

struct cache_entry {
	TEE_UUID uuid;
	uint8_t *data;
	size_t   data_len;
};

static struct cache_entry g_cache[CACHE_SLOTS];
static int g_cache_init;

static void cache_clear(void)
{
	int i;
	for (i = 0; i < CACHE_SLOTS; i++) {
		if (g_cache[i].data) {
			TEE_Free(g_cache[i].data);
			g_cache[i].data = NULL;
		}
	}
	g_cache_init = 1;
}

static struct cache_entry *cache_lookup(const TEE_UUID *uuid)
{
	int i;
	if (!g_cache_init)
		return NULL;
	for (i = 0; i < CACHE_SLOTS; i++) {
		if (g_cache[i].data &&
		    !TEE_MemCompare(&g_cache[i].uuid, uuid, sizeof(TEE_UUID)))
			return &g_cache[i];
	}
	return NULL;
}

static void cache_store(const TEE_UUID *uuid, uint8_t *data, size_t len)
{
	int i;
	if (!g_cache_init)
		cache_clear();
	if (g_cache[0].data)
		TEE_Free(g_cache[0].data);
	for (i = 0; i < CACHE_SLOTS - 1; i++)
		g_cache[i] = g_cache[i + 1];
	g_cache[CACHE_SLOTS - 1].uuid     = *uuid;
	g_cache[CACHE_SLOTS - 1].data     = data;
	g_cache[CACHE_SLOTS - 1].data_len = len;
}

static void cache_invalidate(const TEE_UUID *uuid)
{
	int i;
	for (i = 0; i < CACHE_SLOTS; i++) {
		if (g_cache[i].data &&
		    !TEE_MemCompare(&g_cache[i].uuid, uuid, sizeof(TEE_UUID))) {
			TEE_Free(g_cache[i].data);
			g_cache[i].data = NULL;
		}
	}
}

/* ---- UUID derivation from label (deterministic) ---- */

static void label_to_uuid(const uint8_t *label, size_t label_len,
			  TEE_UUID *uuid)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	uint8_t hash[32];
	size_t hash_len = sizeof(hash);
	size_t i;
	uint8_t *p;

	TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	TEE_DigestDoFinal(op, label, label_len, hash, &hash_len);
	TEE_FreeOperation(op);

	/* Build UUID from hash bytes */
	memset(uuid, 0, sizeof(*uuid));
	p = (uint8_t *)uuid;
	for (i = 0; i < 16; i++)
		p[i] = hash[i];
}

/* ---- Acquire attribute data from TEE object ---- */

static TEE_Result get_attr_data(TEE_ObjectHandle key, uint32_t attr_id,
				uint8_t **data, size_t *data_len)
{
	TEE_Result res;

	/* Query size first */
	res = TEE_GetObjectBufferAttribute(key, attr_id, NULL, data_len);
	if (res != TEE_ERROR_SHORT_BUFFER)
		return res;

	*data = TEE_Malloc(*data_len, TEE_MALLOC_FILL_ZERO);
	if (!*data)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_GetObjectBufferAttribute(key, attr_id, *data, data_len);
	if (res != TEE_SUCCESS) {
		TEE_Free(*data);
		*data = NULL;
	}
	return res;
}

/* ---- Serialize RSA key ---- */

static TEE_Result serialize_rsa(TEE_ObjectHandle key,
				uint32_t size_bits, uint32_t perms,
				uint8_t **out, size_t *out_len)
{
	struct serialized_key hdr;
	uint8_t *attrs[KEY_ATTR_RSA_COUNT] = { NULL };
	size_t sizes[KEY_ATTR_RSA_COUNT];
	uint8_t *buf = NULL;
	size_t total;
	size_t off;
	size_t i;
	TEE_Result res;

	memset(&hdr, 0, sizeof(hdr));
	hdr.key_type = KEY_TYPE_RSA_KEYPAIR;
	hdr.permissions = perms;
	hdr.key_size_bits = size_bits;
	hdr.attr_count = KEY_ATTR_RSA_COUNT;

	total = sizeof(hdr);

	for (i = 0; i < KEY_ATTR_RSA_COUNT; i++) {
		res = get_attr_data(key, g_rsa_attr_ids[i],
				   &attrs[i], &sizes[i]);
		if (res != TEE_SUCCESS)
			goto cleanup;
		hdr.attr_sizes[i] = (uint32_t)sizes[i];
		total += sizes[i];
	}

	buf = TEE_Malloc(total, TEE_MALLOC_FILL_ZERO);
	if (!buf) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(buf, &hdr, sizeof(hdr));
	off = sizeof(hdr);
	for (i = 0; i < KEY_ATTR_RSA_COUNT; i++) {
		memcpy(buf + off, attrs[i], sizes[i]);
		off += sizes[i];
	}

	*out = buf;
	*out_len = total;
	buf = NULL;   /* caller owns it */
	res = TEE_SUCCESS;

cleanup:
	for (i = 0; i < KEY_ATTR_RSA_COUNT; i++) {
		if (attrs[i])
			TEE_Free(attrs[i]);
	}
	return res;
}

/* ---- Serialize AES key ---- */

static TEE_Result serialize_aes(TEE_ObjectHandle key,
				uint32_t size_bits, uint32_t perms,
				uint8_t **out, size_t *out_len)
{
	struct serialized_key hdr;
	uint8_t *secret = NULL;
	size_t secret_len;
	size_t total;
	TEE_Result res;

	memset(&hdr, 0, sizeof(hdr));
	hdr.key_type = KEY_TYPE_AES;
	hdr.permissions = perms;
	hdr.key_size_bits = size_bits;
	hdr.attr_count = KEY_ATTR_AES_COUNT;

	res = get_attr_data(key, TEE_ATTR_SECRET_VALUE,
			    &secret, &secret_len);
	if (res != TEE_SUCCESS)
		return res;

	hdr.attr_sizes[0] = (uint32_t)secret_len;
	total = sizeof(hdr) + secret_len;

	*out = TEE_Malloc(total, TEE_MALLOC_FILL_ZERO);
	if (!*out) {
		TEE_Free(secret);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	memcpy(*out, &hdr, sizeof(hdr));
	memcpy(*out + sizeof(hdr), secret, secret_len);
	*out_len = total;

	TEE_Free(secret);
	return TEE_SUCCESS;
}

/* ---- Store serialized key to persistent storage ---- */

static TEE_Result keystore_write(const uint8_t *label, size_t label_len,
				 uint8_t *data, size_t data_len,
				 uint32_t perms)
{
	TEE_UUID uuid;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META;

	label_to_uuid(label, label_len, &uuid);

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					  &uuid, sizeof(uuid),
					  flags, TEE_HANDLE_NULL,
					  data, data_len, &obj);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent key '%.*s': 0x%x",
		     (int)label_len, label, (unsigned int)res);
		return res;
	}

	TEE_CloseObject(obj);
	DMSG("Key stored, label='%.*s'", (int)label_len, label);
	return TEE_SUCCESS;
}

/* ---- Read key from persistent storage ---- */

static TEE_Result keystore_read(const uint8_t *label, size_t label_len,
				uint8_t **data, size_t *data_len)
{
	TEE_UUID uuid;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	uint32_t read_bytes;
	struct cache_entry *ce;

	label_to_uuid(label, label_len, &uuid);

	/*
	 * Session cache: the ENGINE (or any REE caller) may load the
	 * same key several times in one session.  REE FS on OP-TEE 3.2
	 * can spuriously refuse TEE_OpenPersistentObject on the second
	 * open.  Serving from cache avoids the close→reopen cycle.
	 */
	ce = cache_lookup(&uuid);
	if (ce) {
		*data = TEE_Malloc(ce->data_len, TEE_MALLOC_FILL_ZERO);
		if (!*data)
			return TEE_ERROR_OUT_OF_MEMORY;
		TEE_MemMove(*data, ce->data, ce->data_len);
		*data_len = ce->data_len;
		return TEE_SUCCESS;
	}

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &uuid, sizeof(uuid),
				       TEE_DATA_FLAG_ACCESS_READ,
				       &obj);
	if (res == TEE_ERROR_ACCESS_CONFLICT) {
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					       &uuid, sizeof(uuid),
					       TEE_DATA_FLAG_ACCESS_READ |
					       TEE_DATA_FLAG_ACCESS_WRITE_META,
					       &obj);
	}
	if (res != TEE_SUCCESS) {
		EMSG("Key not found: '%.*s' (TEE_OpenPersistentObject: 0x%x)",
		     (int)label_len, label, (unsigned int)res);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	res = TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_END);
	if (res != TEE_SUCCESS) {
		TEE_CloseObject(obj);
		return res;
	}

	*data_len = 0;
	*data = TEE_Malloc(16384, TEE_MALLOC_FILL_ZERO);
	if (!*data) {
		TEE_CloseObject(obj);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_SeekObjectData(obj, 0, TEE_DATA_SEEK_SET);
	res = TEE_ReadObjectData(obj, *data, 16384, &read_bytes);
	*data_len = read_bytes;

	TEE_CloseObject(obj);

	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		/* Keep a copy in the session cache */
		uint8_t *copy = TEE_Malloc(read_bytes, TEE_MALLOC_FILL_ZERO);
		if (copy) {
			TEE_MemMove(copy, *data, read_bytes);
			cache_store(&uuid, copy, read_bytes);
		}
		return TEE_SUCCESS;
	}
	return res;
}

/* ---- Delete key from persistent storage ---- */

static TEE_Result keystore_delete(const uint8_t *label, size_t label_len)
{
	TEE_UUID uuid;
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	label_to_uuid(label, label_len, &uuid);

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &uuid, sizeof(uuid),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &obj);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_ITEM_NOT_FOUND;

	TEE_CloseAndDeletePersistentObject1(obj);
	DMSG("Key deleted: '%.*s'", (int)label_len, label);
	return TEE_SUCCESS;
}

/* ---- Restore RSA key from serialized data ---- */

static TEE_Result restore_rsa(uint8_t *data, size_t data_len,
			      TEE_ObjectHandle *key)
{
	struct serialized_key *hdr = (struct serialized_key *)data;
	TEE_Attribute attrs[KEY_ATTR_RSA_COUNT];
	uint8_t *p;
	size_t i;
	TEE_Result res;

	if (data_len < sizeof(*hdr))
		return TEE_ERROR_CORRUPT_OBJECT;
	if (hdr->attr_count != KEY_ATTR_RSA_COUNT)
		return TEE_ERROR_CORRUPT_OBJECT;

	p = data + sizeof(*hdr);
	for (i = 0; i < KEY_ATTR_RSA_COUNT; i++) {
		TEE_InitRefAttribute(&attrs[i], g_rsa_attr_ids[i],
				     p, hdr->attr_sizes[i]);
		p += hdr->attr_sizes[i];
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					  hdr->key_size_bits, key);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_PopulateTransientObject(*key, attrs, KEY_ATTR_RSA_COUNT);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(*key);
		*key = TEE_HANDLE_NULL;
	}
	return res;
}

/* ---- Restore AES key from serialized data ---- */

static TEE_Result restore_aes(uint8_t *data, size_t data_len,
			      TEE_ObjectHandle *key)
{
	struct serialized_key *hdr = (struct serialized_key *)data;
	TEE_Attribute attr;

	if (data_len < sizeof(*hdr))
		return TEE_ERROR_CORRUPT_OBJECT;
	if (hdr->attr_count < 1)
		return TEE_ERROR_CORRUPT_OBJECT;

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
			     data + sizeof(*hdr), hdr->attr_sizes[0]);

	TEE_AllocateTransientObject(TEE_TYPE_AES, hdr->key_size_bits, key);
	TEE_PopulateTransientObject(*key, &attr, 1);
	return TEE_SUCCESS;
}

/* ---- Public API ---- */

/*
 * Generate an RSA key pair and store persistently.
 * Returns TEE_ERROR_ACCESS_CONFLICT if a key with the same label exists.
 */
TEE_Result keystore_gen_rsa(const uint8_t *label, size_t label_len,
			    uint32_t size_bits, uint32_t perms)
{
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint8_t *data = NULL;
	size_t data_len = 0;
	TEE_Result res;

	/* Forbid overwrite: check if label is already in use */
	res = keystore_read(label, label_len, &data, &data_len);
	if (res == TEE_SUCCESS) {
		EMSG("Key already exists, overwrite forbidden: '%.*s'",
		     (int)label_len, label);
		TEE_Free(data);
		return TEE_ERROR_ACCESS_CONFLICT;
	}
	/* TEE_ERROR_ITEM_NOT_FOUND is expected — label is free to use */

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
					  size_bits, &key);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate RSA failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_GenerateKey(key, size_bits, NULL, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Generate RSA key failed: 0x%x", (unsigned int)res);
		goto out;
	}

	res = serialize_rsa(key, size_bits, perms, &data, &data_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = keystore_write(label, label_len, data, data_len, perms);

out:
	if (data) TEE_Free(data);
	if (key != TEE_HANDLE_NULL) TEE_FreeTransientObject(key);
	return res;
}

/*
 * Generate an AES key and store persistently.
 * Returns TEE_ERROR_ACCESS_CONFLICT if a key with the same label exists.
 */
TEE_Result keystore_gen_aes(const uint8_t *label, size_t label_len,
			    uint32_t size_bits, uint32_t perms)
{
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint8_t *data = NULL;
	size_t data_len = 0;
	TEE_Result res;

	/* Forbid overwrite: check if label is already in use */
	res = keystore_read(label, label_len, &data, &data_len);
	if (res == TEE_SUCCESS) {
		EMSG("Key already exists, overwrite forbidden: '%.*s'",
		     (int)label_len, label);
		TEE_Free(data);
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, size_bits, &key);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate AES failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_GenerateKey(key, size_bits, NULL, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Generate AES key failed: 0x%x", (unsigned int)res);
		goto out;
	}

	res = serialize_aes(key, size_bits, perms, &data, &data_len);
	if (res != TEE_SUCCESS)
		goto out;

	res = keystore_write(label, label_len, data, data_len, perms);

out:
	if (data) TEE_Free(data);
	if (key != TEE_HANDLE_NULL) TEE_FreeTransientObject(key);
	return res;
}

/*
 * Load a key, return type + permissions + restored handle.
 * Caller frees *key with TEE_FreeTransientObject.
 */
TEE_Result keystore_load(const uint8_t *label, size_t label_len,
			 uint32_t *type, uint32_t *perms,
			 TEE_ObjectHandle *key)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	struct serialized_key *hdr;
	TEE_Result res;

	res = keystore_read(label, label_len, &data, &data_len);
	if (res != TEE_SUCCESS)
		return res;

	if (data_len < sizeof(struct serialized_key)) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	hdr = (struct serialized_key *)data;
	*type = hdr->key_type;
	*perms = hdr->permissions;

	switch (hdr->key_type) {
	case KEY_TYPE_RSA_KEYPAIR:
		res = restore_rsa(data, data_len, key);
		break;
	case KEY_TYPE_AES:
		res = restore_aes(data, data_len, key);
		break;
	default:
		EMSG("Unknown key type: %" PRIu32, hdr->key_type);
		res = TEE_ERROR_CORRUPT_OBJECT;
		break;
	}

out:
	if (data) TEE_Free(data);
	return res;
}

/*
 * Export RSA public key as DER SubjectPublicKeyInfo.
 * Uses simple PKCS#1 -> SPKI wrapping (works for RSA keys).
 */
TEE_Result keystore_export_pub(const uint8_t *label, size_t label_len,
			       uint8_t *out, size_t *out_len)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	struct serialized_key *hdr;
	TEE_Result res;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type;
	uint32_t perms;

	res = keystore_load(label, label_len, &type, &perms, &key);
	if (res != TEE_SUCCESS)
		return res;

	if (type != KEY_TYPE_RSA_KEYPAIR) {
		EMSG("Export only supported for RSA keys");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	(void)data;
	(void)data_len;
	(void)hdr;

	/*
	 * Export public-key material via TEE_GetObjectBufferAttribute
	 * on modulus (n) and public exponent (e).
	 * Pack as simple DER — in production, use a proper ASN.1 encoder.
	 */
	{
		size_t n_len = 0;
		size_t e_len = 0;
		uint8_t *n_data = NULL;
		uint8_t *e_data = NULL;
		size_t total;

		res = get_attr_data(key, TEE_ATTR_RSA_MODULUS,
				    &n_data, &n_len);
		if (res != TEE_SUCCESS) goto out_export;

		res = get_attr_data(key, TEE_ATTR_RSA_PUBLIC_EXPONENT,
				    &e_data, &e_len);
		if (res != TEE_SUCCESS) {
			TEE_Free(n_data);
			goto out_export;
		}

	/* Format: [n_len:4][e_len:4][modulus][exponent].
		 * Caller (ENGINE / CA) can parse without knowing key size. */
		total = 8 + n_len + e_len;
		if (*out_len < total) {
			*out_len = total;
			res = TEE_ERROR_SHORT_BUFFER;
		} else {
			uint32_t header[2];
			header[0] = (uint32_t)n_len;
			header[1] = (uint32_t)e_len;
			memcpy(out, header, 8);
			memcpy(out + 8, n_data, n_len);
			memcpy(out + 8 + n_len, e_data, e_len);
			*out_len = total;
			res = TEE_SUCCESS;
		}

out_export:
		if (n_data) TEE_Free(n_data);
		if (e_data) TEE_Free(e_data);
	}

out:
	if (key != TEE_HANDLE_NULL) TEE_FreeTransientObject(key);
	return res;
}

/*
 * Get key info.
 */
TEE_Result keystore_get_info(const uint8_t *label, size_t label_len,
			     struct key_info *info)
{
	uint8_t *data = NULL;
	size_t data_len = 0;
	struct serialized_key *hdr;
	TEE_Result res;

	res = keystore_read(label, label_len, &data, &data_len);
	if (res != TEE_SUCCESS)
		return res;

	if (data_len < sizeof(*hdr)) {
		res = TEE_ERROR_CORRUPT_OBJECT;
		goto out;
	}

	hdr = (struct serialized_key *)data;
	memset(info, 0, sizeof(*info));
	info->type = hdr->key_type;
	info->size_bits = hdr->key_size_bits;
	info->permissions = hdr->permissions;

	if (label_len < sizeof(info->label))
		memcpy(info->label, label, label_len);
	else
		memcpy(info->label, label, sizeof(info->label) - 1);

out:
	if (data) TEE_Free(data);
	return res;
}

/*
 * Delete a key.
 */
TEE_Result keystore_delete_key(const uint8_t *label, size_t label_len)
{
	return keystore_delete(label, label_len);
}
