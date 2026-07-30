/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * SO-PIN management — Security Officer dual-factor unlock.
 *
 * State machine:
 *   UNSET → PROVISIONED → LOCKED ↔ UNLOCKED (temporary)
 *   Any state → BRICKED (1000 total SO-PIN failures, permanent)
 *
 * Persistent objects:
 *   SO_PIN_UUID    — SHA-256(SO-PIN), 32 bytes
 *   SO_DONGLE_UUID — dongle whitelist, 4 + N×36 bytes
 *   SO_FAIL_UUID   — failure counter, 12 bytes
 *   SO_LOCK_UUID   — SO unlock flag, 1 byte (0=LOCKED, 1=UNLOCKED)
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/*
 * Forward declaration — crypto_ecdsa_verify lives in crypto_ops.c.
 * Declared here so so_unlock_verify() can call it without including
 * crypto_ops.c internals.
 */
TEE_Result crypto_ecdsa_verify(const uint8_t *pubkey_der, size_t der_len,
			       const uint8_t *hash, size_t hash_len,
			       const uint8_t *sig_der, size_t sig_len);

/* ---- Persistent object UUIDs ---- */
static const TEE_UUID SO_PIN_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x10 }
};

static const TEE_UUID SO_DONGLE_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x11 }
};

static const TEE_UUID SO_FAIL_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x12 }
};

static const TEE_UUID SO_LOCK_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x13 }
};

/* ---- Limits ---- */
#define SO_FAIL_MAX_CONSECUTIVE  3
#define SO_FAIL_COOLDOWN_SECS    60
#define SO_FAIL_MAX_TOTAL        1000

/* ---- In-memory state ---- */
static int g_so_state = SO_STATE_UNSET;

/* ---- Internal: SHA-256 helper ---- */
static TEE_Result so_sha256(const uint8_t *data, size_t data_len,
			    uint8_t *hash_out, size_t hash_out_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t hlen = 32;

	if (hash_out_len < 32)
		return TEE_ERROR_SHORT_BUFFER;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, (void *)data, data_len, hash_out, &hlen);
	TEE_FreeOperation(op);
	return res;
}

/* ---- Internal: persistent object helpers ---- */

static TEE_Result so_obj_create(const TEE_UUID *uuid, const void *data, size_t len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META;
	TEE_Result res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					  (void *)uuid, sizeof(*uuid),
					  flags, TEE_HANDLE_NULL,
					  (void *)data, len, &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return res;
}

static TEE_Result so_obj_read(const TEE_UUID *uuid, void *buf, size_t *len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t rd;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_ReadObjectData(obj, buf, *len, &rd);
	TEE_CloseObject(obj);

	if (res == TEE_SUCCESS)
		*len = rd;
	return res;
}

static int so_obj_exists(const TEE_UUID *uuid)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return (res == TEE_SUCCESS) ? 1 : 0;
}

static TEE_Result so_obj_delete(const TEE_UUID *uuid)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
	if (res != TEE_SUCCESS)
		return res;

	TEE_CloseAndDeletePersistentObject(obj);
	return TEE_SUCCESS;
}

/* ---- Failure counter ---- */

struct so_fail_counter {
	uint32_t consecutive_fails;
	uint32_t total_fails;
	uint32_t cooldown_until;     /* TEE_GetSystemTime seconds */
};

static void so_fail_load(struct so_fail_counter *fc)
{
	size_t len = sizeof(*fc);
	memset(fc, 0, sizeof(*fc));
	so_obj_read(&SO_FAIL_UUID, fc, &len);
}

static TEE_Result so_fail_save(const struct so_fail_counter *fc)
{
	so_obj_delete(&SO_FAIL_UUID);
	return so_obj_create(&SO_FAIL_UUID, fc, sizeof(*fc));
}

static int so_check_fail_counter(uint32_t *cooldown_left)
{
	struct so_fail_counter fc;
	TEE_Time now;
	uint32_t now_sec;

	so_fail_load(&fc);

	/* Permanent brick check */
	if (fc.total_fails >= SO_FAIL_MAX_TOTAL) {
		g_so_state = SO_STATE_BRICKED;
		*cooldown_left = 0;
		return 0; /* bricked */
	}

	/* Cooldown check */
	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
		TEE_GetSystemTime(&now);
		now_sec = now.seconds; /* truncate to 32-bit for simplicity */

		if (now_sec < fc.cooldown_until) {
			*cooldown_left = fc.cooldown_until - now_sec;
			return 0; /* cooling */
		}

		/* Cooldown expired, reset consecutive */
		fc.consecutive_fails = 0;
		fc.cooldown_until = 0;
		so_fail_save(&fc);
	}

	*cooldown_left = 0;
	return 1; /* OK to try */
}

static void so_record_failure(void)
{
	struct so_fail_counter fc;
	TEE_Time now;

	so_fail_load(&fc);

	fc.consecutive_fails++;
	fc.total_fails++;

	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
		TEE_GetSystemTime(&now);
		fc.cooldown_until = now.seconds + SO_FAIL_COOLDOWN_SECS;
	}

	so_fail_save(&fc);
}

static void so_reset_consecutive(void)
{
	struct so_fail_counter fc;

	so_fail_load(&fc);
	fc.consecutive_fails = 0;
	fc.cooldown_until = 0;
	so_fail_save(&fc);
}

/* ---- Dongle whitelist ---- */

struct so_dongle_list {
	uint32_t count;
	struct so_dongle_entry entries[SO_DONGLE_MAX];
};

static void so_dongle_load(struct so_dongle_list *dl)
{
	size_t len = sizeof(*dl);
	memset(dl, 0, sizeof(*dl));
	so_obj_read(&SO_DONGLE_UUID, dl, &len);
}

static TEE_Result so_dongle_save(const struct so_dongle_list *dl)
{
	so_obj_delete(&SO_DONGLE_UUID);
	return so_obj_create(&SO_DONGLE_UUID, dl,
			     4 + dl->count * sizeof(struct so_dongle_entry));
}

/* ---- SO-PIN management ---- */

static TEE_Result so_pin_hash_and_check(const uint8_t *pin, size_t pin_len,
					 uint8_t *hash_out)
{
	uint8_t stored[32];
	uint8_t computed[32];
	size_t len = 32;
	TEE_Result res;

	/* Hash the incoming PIN */
	res = so_sha256(pin, pin_len, computed, sizeof(computed));
	if (res != TEE_SUCCESS)
		return res;

	/* Read stored hash */
	res = so_obj_read(&SO_PIN_UUID, stored, &len);
	if (res != TEE_SUCCESS || len != 32) {
		EMSG("SO-PIN not provisioned");
		return TEE_ERROR_NO_DATA;
	}

	/* Constant-time comparison */
	if (memcmp(computed, stored, 32) != 0)
		return TEE_ERROR_ACCESS_DENIED;

	if (hash_out)
		memcpy(hash_out, computed, 32);
	return TEE_SUCCESS;
}

/*
 * Initialize SO-PIN — provisioning phase only.
 * Fails if already provisioned.
 */
TEE_Result so_pin_init(const uint8_t *pin, size_t pin_len)
{
	uint8_t hash[32];
	TEE_Result res;

	if (so_obj_exists(&SO_PIN_UUID)) {
		EMSG("SO-PIN already initialized");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	if (pin_len == 0 || pin_len > 128) {
		EMSG("Invalid SO-PIN length: %zu", pin_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = so_sha256(pin, pin_len, hash, sizeof(hash));
	if (res != TEE_SUCCESS)
		return res;

	res = so_obj_create(&SO_PIN_UUID, hash, sizeof(hash));
	if (res == TEE_SUCCESS) {
		DMSG("SO-PIN initialized");
		/* Transition UNSET → PROVISIONED */
		if (g_so_state == SO_STATE_UNSET)
			g_so_state = SO_STATE_PROVISIONED;
	}
	return res;
}

/*
 * Register a dongle public key in the whitelist.
 * pubkey_der: ASN.1 DER SubjectPublicKeyInfo (P-256, ~88-91 bytes)
 */
TEE_Result so_provision_dongle(const uint8_t *pubkey_der, size_t der_len)
{
	struct so_dongle_list dl;
	uint8_t hash[32];
	uint32_t i;
	TEE_Result res;

	if (!pubkey_der || der_len < 88 || der_len > 256)
		return TEE_ERROR_BAD_PARAMETERS;

	so_dongle_load(&dl);

	if (dl.count >= SO_DONGLE_MAX) {
		EMSG("Dongle whitelist full");
		return TEE_ERROR_OVERFLOW;
	}

	/* Check for duplicate */
	res = so_sha256(pubkey_der, der_len, hash, sizeof(hash));
	if (res != TEE_SUCCESS)
		return res;

	for (i = 0; i < dl.count; i++) {
		if (memcmp(dl.entries[i].pubkey_hash, hash, 32) == 0) {
			EMSG("Dongle already registered");
			return TEE_ERROR_ACCESS_CONFLICT;
		}
	}

	/* Add new entry */
	memcpy(dl.entries[dl.count].pubkey_hash, hash, 32);
	memset(dl.entries[dl.count].serial, 0, 4);
	dl.count++;

	res = so_dongle_save(&dl);
	if (res == TEE_SUCCESS)
		DMSG("Dongle %u registered", dl.count);

	return res;
}

/* ---- Unlock protocol ---- */

/*
 * Phase 1: verify SO-PIN, return challenge + dongle list.
 * Caller provides buffer of at least SO_CHG_BUF_SIZE bytes.
 */
TEE_Result so_unlock_req(const uint8_t *pin, size_t pin_len,
			 uint8_t *chg_out, size_t chg_out_size,
			 uint32_t *dongle_count, uint32_t *cooldown_left)
{
	struct so_dongle_list dl;
	uint32_t count;
	uint32_t i;
	TEE_Result res;

	if (!pin || !chg_out || chg_out_size < SO_CHG_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check failure counter */
	if (!so_check_fail_counter(cooldown_left)) {
		if (g_so_state == SO_STATE_BRICKED)
			return TEE_ERROR_ACCESS_DENIED;
		return TEE_ERROR_BAD_STATE;
	}

	/* Verify SO-PIN */
	res = so_pin_hash_and_check(pin, pin_len, NULL);
	if (res != TEE_SUCCESS) {
		so_record_failure();
		return res;
	}

	/* Generate challenge */
	TEE_GenerateRandom(chg_out, 32);

	/* Append dongle list */
	so_dongle_load(&dl);
	count = dl.count;

	/* Write dongle count (use memcpy to avoid alignment warning) */
	memcpy(chg_out + 32, &count, sizeof(count));

	for (i = 0; i < count; i++) {
		memcpy(chg_out + 36 + i * 36, dl.entries[i].pubkey_hash, 32);
		memcpy(chg_out + 36 + i * 36 + 32, dl.entries[i].serial, 4);
	}

	*dongle_count = count;

	DMSG("SO unlock phase 1: challenge generated, %u dongles", count);
	return TEE_SUCCESS;
}
/*

 * Phase 2: verify dongle signature against challenge.
 * The dongle signs the raw 32-byte challenge; TA verifies the same bytes.
 * Challenge is TEE_GenerateRandom output - fresh each Phase 1, no replay risk.
 */
TEE_Result so_unlock_verify(const uint8_t *pubkey_der, size_t der_len,
			    const uint8_t *sig_der, size_t sig_len,
			    uint32_t dongle_index,
			    const uint8_t *challenge)
{
	struct so_dongle_list dl;
	uint8_t pk_hash[32];
	TEE_Result res;

	/* Debug: entry */
	DMSG("SO verify: idx=%lu der_len=%zu sig_len=%zu",
	     (unsigned long)dongle_index, der_len, sig_len);
	DMSG("SO verify: chg[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
	     challenge[0],challenge[1],challenge[2],challenge[3],
	     challenge[4],challenge[5],challenge[6],challenge[7]);

	/* Check SO state */
	if (g_so_state == SO_STATE_BRICKED)
		return TEE_ERROR_ACCESS_DENIED;

	/* Verify pubkey is in whitelist */
	res = so_sha256(pubkey_der, der_len, pk_hash, sizeof(pk_hash));
	if (res != TEE_SUCCESS)
		return res;

	so_dongle_load(&dl);

	if (dongle_index >= dl.count) {
		EMSG("Dongle index %u out of range (count=%u)",
		     (unsigned int)dongle_index, (unsigned int)dl.count);
		so_record_failure();
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (memcmp(pk_hash, dl.entries[dongle_index].pubkey_hash, 32) != 0) {
		DMSG("SO verify: pk_hash[0..3]=%02x%02x%02x%02x whitelist[%lu][0..3]=%02x%02x%02x%02x",
		     pk_hash[0], pk_hash[1], pk_hash[2], pk_hash[3],
		     (unsigned long)dongle_index,
		     dl.entries[dongle_index].pubkey_hash[0], dl.entries[dongle_index].pubkey_hash[1],
		     dl.entries[dongle_index].pubkey_hash[2], dl.entries[dongle_index].pubkey_hash[3]);
		EMSG("Public key not in whitelist at index %u",
		     (unsigned int)dongle_index);
		so_record_failure();
		return TEE_ERROR_ACCESS_DENIED;
	}
	DMSG("SO verify: whitelist MATCHED index=%lu", (unsigned long)dongle_index);

	/*
	 * Both sides sign/verify SHA-256(challenge):
	 *   CA:  msg = SHA256(challenge)  → dongle.sign(msg, 32)
	 *   TA:  msg = SHA256(challenge)  → ECDSA verify(msg, sig)
	 */
	{
		uint8_t msg_hash[32];
		res = so_sha256(challenge, 32, msg_hash, sizeof(msg_hash));
		if (res != TEE_SUCCESS)
			return res;
			DMSG("SO verify: msg_hash[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x",
			     msg_hash[0],msg_hash[1],msg_hash[2],msg_hash[3],
			     msg_hash[4],msg_hash[5],msg_hash[6],msg_hash[7]);
		res = crypto_ecdsa_verify(pubkey_der, der_len,
					  msg_hash, 32, sig_der, sig_len);
	}
	if (res != TEE_SUCCESS) {
		EMSG("ECDSA verify failed: 0x%x", (unsigned int)res);
		so_record_failure();
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	/* Success — transition to UNLOCKED */
	so_reset_consecutive();
	g_so_state = SO_STATE_UNLOCKED;

	/* Persist unlocked flag */
	{
		uint8_t flag = 1;
		so_obj_delete(&SO_LOCK_UUID);
		so_obj_create(&SO_LOCK_UUID, &flag, 1);
	}

	DMSG("SO unlock phase 2: verified, TA UNLOCKED");
	return TEE_SUCCESS;
}

/* ---- Lock / re-lock ---- */

void so_pin_lock(void)
{
	uint8_t flag = 0;

	so_obj_delete(&SO_LOCK_UUID);
	so_obj_create(&SO_LOCK_UUID, &flag, 1);

	g_so_state = SO_STATE_LOCKED;
	DMSG("SO locked");
}

void so_pin_auto_lock(void)
{
	if (g_so_state == SO_STATE_UNLOCKED) {
		DMSG("SO auto-locking (session close)");
		so_pin_lock();
	}
}

int so_pin_is_unlocked(void)
{
	return g_so_state == SO_STATE_UNLOCKED;
}

/* ---- Query ---- */

void so_pin_get_info(struct so_status *st)
{
	struct so_dongle_list dl;
	struct so_fail_counter fc;
	TEE_Time now;
	uint32_t now_sec;

	memset(st, 0, sizeof(*st));

	st->state = g_so_state;

	so_dongle_load(&dl);
	st->dongle_count = dl.count;

	so_fail_load(&fc);
	st->fail_total = fc.total_fails;
	st->fail_consecutive = fc.consecutive_fails;

	/* Compute remaining cooldown */
	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE &&
	    fc.cooldown_until > 0) {
		TEE_GetSystemTime(&now);
		now_sec = now.seconds;
		if (now_sec < fc.cooldown_until)
			st->cooldown_left = fc.cooldown_until - now_sec;
	}
}

/* ---- Session restore ---- */

/* pin_mgr_is_locked() lives in pin_mgr.c; declared here to avoid header coupling */
extern int pin_mgr_is_locked(void);

void so_pin_restore(void)
{
	/* Check SO_LOCK_UUID first — this records the unlocked state */
	if (so_obj_exists(&SO_LOCK_UUID)) {
		uint8_t flag = 0;
		size_t len = 1;
		so_obj_read(&SO_LOCK_UUID, &flag, &len);

		if (flag == 1) {
			g_so_state = SO_STATE_UNLOCKED;
			DMSG("SO state restored: UNLOCKED");
			return;
		}
	}

	/* Check if SO-PIN is provisioned */
	if (so_obj_exists(&SO_PIN_UUID)) {
		/* Check if bricked */
		struct so_fail_counter fc;
		so_fail_load(&fc);
		if (fc.total_fails >= SO_FAIL_MAX_TOTAL) {
			g_so_state = SO_STATE_BRICKED;
			DMSG("SO state restored: BRICKED");
			return;
		}

		/*
		 * Distinguish PROVISIONED vs LOCKED:
		 *   pin_mgr_is_locked() → the normal provision_lock has been applied → LOCKED
		 *   otherwise            → SO-PIN+dongle configured but TA not yet locked → PROVISIONED
		 */
		if (pin_mgr_is_locked())
			g_so_state = SO_STATE_LOCKED;
		else
			g_so_state = SO_STATE_PROVISIONED;

		DMSG("SO state restored: %s",
		     g_so_state == SO_STATE_LOCKED ? "LOCKED" : "PROVISIONED");
		return;
	}

	g_so_state = SO_STATE_UNSET;
	DMSG("SO state restored: UNSET");
}
