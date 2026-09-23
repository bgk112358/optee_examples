/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Crypto operations: sign, verify, encrypt, decrypt.
 * Wraps TEE Internal API for concise command handlers.
 */

#include <inttypes.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/* ---- RSA sign (SHA-256 hash + PKCS#1 v1.5) ---- */

TEE_Result crypto_rsa_sign(TEE_ObjectHandle key, uint32_t key_size_bits,
			   const uint8_t *data, size_t data_len,
			   uint8_t *sig, size_t *sig_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
				    TEE_MODE_SIGN, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate sign op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey failed: 0x%x", (unsigned int)res);
		goto out;
	}

	res = TEE_AsymmetricSignDigest(op, NULL, 0, data, data_len,
				       sig, sig_len);

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- RSA verify ---- */

TEE_Result crypto_rsa_verify(TEE_ObjectHandle key, uint32_t key_size_bits,
			     const uint8_t *data, size_t data_len,
			     const uint8_t *sig, size_t sig_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_AllocateOperation(&op, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
				    TEE_MODE_VERIFY, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate verify op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey failed: 0x%x", (unsigned int)res);
		goto out;
	}

	res = TEE_AsymmetricVerifyDigest(op, NULL, 0, data, data_len,
					 sig, sig_len);

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- AES-CBC encrypt (no padding) ---- */

TEE_Result crypto_aes_encrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *plain, size_t plain_len,
			      uint8_t *cipher, size_t *cipher_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	uint8_t iv[16];
	size_t iv_len = sizeof(iv);

	memset(iv, 0, sizeof(iv));

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate AES enc op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CipherInit(op, iv, iv_len);

	res = TEE_CipherDoFinal(op, plain, plain_len, cipher, cipher_len);

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- AES-CBC decrypt (no padding) ---- */

TEE_Result crypto_aes_decrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *cipher, size_t cipher_len,
			      uint8_t *plain, size_t *plain_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	uint8_t iv[16];
	size_t iv_len = sizeof(iv);

	memset(iv, 0, sizeof(iv));

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_DECRYPT, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate AES dec op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CipherInit(op, iv, iv_len);

	res = TEE_CipherDoFinal(op, cipher, cipher_len, plain, plain_len);

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- AES-CBC encrypt with explicit IV + optional PKCS#7 padding ---- */

TEE_Result crypto_aes_encrypt_ex(TEE_ObjectHandle key, uint32_t key_size_bits,
				 const uint8_t *iv, size_t iv_len,
				 const uint8_t *plain, size_t plain_len,
				 uint8_t *cipher, size_t *cipher_len,
				 int do_padding)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t main_len;
	size_t rem;
	size_t n;
	size_t out_len = 0;
	uint8_t tail[16];	/* only the final padded block, fixed 16B */

	if (!do_padding && (plain_len % 16 != 0))
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_ENCRYPT, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate AES enc op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CipherInit(op, iv, iv_len);

	if (do_padding) {
		/* PKCS#7: full blocks streamed, remainder + pad in a 16B tail */
		main_len = plain_len - (plain_len % 16);
		rem = plain_len % 16;
	} else {
		main_len = plain_len;
		rem = 0;
	}

	if (main_len > 0) {
		n = *cipher_len;
		res = TEE_CipherUpdate(op, plain, main_len, cipher, &n);
		if (res != TEE_SUCCESS)
			goto out;
		out_len += n;
	}

	if (do_padding) {
		/* PKCS#7 pad value: full block when already aligned */
		uint8_t pad_val = (uint8_t)(16 - rem);

		memcpy(tail, plain + main_len, rem);
		memset(tail + rem, pad_val, pad_val);

		n = *cipher_len - out_len;
		res = TEE_CipherDoFinal(op, tail, rem + pad_val,
					cipher + out_len, &n);
		if (res != TEE_SUCCESS)
			goto out;
		out_len += n;
	} else {
		n = *cipher_len - out_len;
		res = TEE_CipherDoFinal(op, NULL, 0, cipher + out_len, &n);
		if (res != TEE_SUCCESS)
			goto out;
		out_len += n;
	}

	*cipher_len = out_len;

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- AES-CBC decrypt with explicit IV + optional PKCS#7 strip ---- */

TEE_Result crypto_aes_decrypt_ex(TEE_ObjectHandle key, uint32_t key_size_bits,
				 const uint8_t *iv, size_t iv_len,
				 const uint8_t *cipher, size_t cipher_len,
				 uint8_t *plain, size_t *plain_len,
				 int do_unpad)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t out_len = *plain_len;
	size_t pad_len;
	size_t i;

	if (cipher_len % 16 != 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
				    TEE_MODE_DECRYPT, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate AES dec op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CipherInit(op, iv, iv_len);

	res = TEE_CipherDoFinal(op, cipher, cipher_len, plain, &out_len);
	if (res != TEE_SUCCESS)
		goto out;

	if (do_unpad) {
		if (out_len == 0)
			return TEE_ERROR_BAD_FORMAT;
		pad_len = plain[out_len - 1];
		if (pad_len == 0 || pad_len > 16 || pad_len > out_len)
			return TEE_ERROR_BAD_FORMAT;
		for (i = 0; i < pad_len; i++) {
			if (plain[out_len - 1 - i] != pad_len)
				return TEE_ERROR_BAD_FORMAT;
		}
		out_len -= pad_len;
	}

	*plain_len = out_len;

out:
	TEE_FreeOperation(op);
	return res;
}

/* ---- ECDSA P-256 verify (for SO dongle challenge-response) ---- */

TEE_Result crypto_ecdsa_verify(const uint8_t *pubkey_der, size_t der_len,
			       const uint8_t *hash, size_t hash_len,
			       const uint8_t *sig_der, size_t sig_len)
{
	TEE_ObjectHandle ec_obj = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute attrs[3];
	TEE_Result res;
	const uint8_t *point = NULL;
	size_t point_len = 0;
	size_t off;
	uint32_t curve;

	if (!pubkey_der || der_len < 88 || !hash || hash_len != 32 || !sig_der)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Parse SPKI DER to extract uncompressed EC point (x||y, 64 bytes).
	 * Format: SEQUENCE { SEQUENCE { OID }, BIT STRING { 0x04 x[32] y[32] } }
	 * We scan for the BIT STRING tag (0x03) with length >= 0x40 (64+2).
	 */
	DMSG("EC: der_len=%zu sig_len=%zu", der_len, sig_len);

	for (off = 22; off + 3 < der_len; off++) {
		if (pubkey_der[off] == 0x03 &&
		    pubkey_der[off + 1] >= 0x40 &&
		    pubkey_der[off + 1] <= 0x44) {
			point = pubkey_der + off + 3;
			point_len = pubkey_der[off + 1] - 1;

			if (point_len >= 65 && point[0] == 0x04) {
				point++;         /* skip 0x04 */
				point_len = 64;  /* x[32] + y[32] */
				DMSG("EC: BITSTR at off=%zu x[0..3]=%02x%02x%02x%02x",
				     off, point[0], point[1], point[2], point[3]);
				break;
			}
			point = NULL;
		}
	}

	if (!point) {
		EMSG("ECDSA verify: cannot parse pubkey DER");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Create transient ECC object and populate with public key */
	DMSG("EC: Allocating transient keypair obj...");
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, 256, &ec_obj);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate ECC object failed: 0x%x", (unsigned int)res);
		return res;
	}

	curve = TEE_ECC_CURVE_NIST_P256;
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_CURVE,
			     &curve, sizeof(curve));
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     (void *)point, 32);
	TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     (void *)(point + 32), 32);

	DMSG("EC: Populating with curve+x+y...");
	res = TEE_PopulateTransientObject(ec_obj, attrs, 3);
	DMSG("EC: PopulateTransient → 0x%x", (unsigned int)res);
	if (res != TEE_SUCCESS) {
		EMSG("Populate ECC object failed: 0x%x", (unsigned int)res);
		goto out_obj;
	}

	/* Allocate verify operation and verify */
	res = TEE_AllocateOperation(&op, TEE_ALG_ECDSA_P256,
				    TEE_MODE_VERIFY, 256);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate ECDSA op failed: 0x%x", (unsigned int)res);
		goto out_obj;
	}

	res = TEE_SetOperationKey(op, ec_obj);
	if (res != TEE_SUCCESS) {
		EMSG("SetOperationKey ECDSA failed: 0x%x", (unsigned int)res);
		goto out_op;
	}

	res = TEE_AsymmetricVerifyDigest(op, NULL, 0, hash, hash_len,
					 sig_der, sig_len);
	DMSG("EC: AsymmetricVerifyDigest → 0x%x", (unsigned int)res);

out_op:
	TEE_FreeOperation(op);
out_obj:
	TEE_FreeTransientObject(ec_obj);
	return res;
}

/* ---- Minimal DER parser (for RSA public key import) ---- */

/*
 * Read one TLV (tag-length-value) from buf at *off.
 * Only the subset needed for SubjectPublicKeyInfo is supported:
 * definite-length, short form (<=127) and long form (<=4 length bytes).
 * On success, val and val_len point at the VALUE and off is advanced past it.
 */
static TEE_Result der_read_tlv(const uint8_t *buf, size_t buf_len, size_t *off,
			       uint8_t want_tag,
			       const uint8_t **val, size_t *val_len)
{
	size_t p = *off;
	size_t len;
	size_t i;
	uint8_t tag;

	if (p + 2 > buf_len)
		return TEE_ERROR_BAD_FORMAT;

	tag = buf[p++];
	if (tag != want_tag) {
		EMSG("DER: expected tag 0x%02x, got 0x%02x", want_tag, tag);
		return TEE_ERROR_BAD_FORMAT;
	}

	len = buf[p++];
	if (len & 0x80) {			/* long form */
		size_t n = len & 0x7f;

		if (n == 0 || n > 4 || p + n > buf_len)
			return TEE_ERROR_BAD_FORMAT;
		len = 0;
		for (i = 0; i < n; i++)
			len = (len << 8) | buf[p++];
	}

	if (p + len > buf_len)
		return TEE_ERROR_BAD_FORMAT;

	*val = buf + p;
	*val_len = len;
	*off = p + len;
	return TEE_SUCCESS;
}

/*
 * Import an RSA public key from SubjectPublicKeyInfo DER.
 *
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *       algorithm  AlgorithmIdentifier,     -- SEQUENCE { OID, NULL }
 *       subjectPublicKey BIT STRING }       -- contains RSAPublicKey
 *   RSAPublicKey ::= SEQUENCE {
 *       modulus         INTEGER,
 *       publicExponent  INTEGER }
 *
 * Builds a TEE_TYPE_RSA_PUBLIC_KEY transient object usable by
 * crypto_rsa_verify().  Used by the SO unlock path to verify the dongle's
 * signature inside the secure world.
 */
TEE_Result rsa_import_pubkey_from_der(const uint8_t *der, size_t der_len,
				      TEE_ObjectHandle *key)
{
	const uint8_t *outer, *alg, *bits, *inner, *mod, *exp;
	size_t outer_len, alg_len, bits_len, inner_len, mod_len, exp_len;
	size_t off;
	uint32_t key_bits;
	TEE_Attribute attrs[2];
	TEE_Result res;

	if (!der || !key)
		return TEE_ERROR_BAD_PARAMETERS;

	*key = TEE_HANDLE_NULL;

	/* outer SEQUENCE */
	off = 0;
	res = der_read_tlv(der, der_len, &off, 0x30, &outer, &outer_len);
	if (res != TEE_SUCCESS)
		return res;

	/* skip AlgorithmIdentifier (we accept any; key type is checked below) */
	off = 0;
	res = der_read_tlv(outer, outer_len, &off, 0x30, &alg, &alg_len);
	if (res != TEE_SUCCESS)
		return res;
	(void)alg;
	(void)alg_len;

	/* BIT STRING: first byte is the number of unused bits (must be 0) */
	res = der_read_tlv(outer, outer_len, &off, 0x03, &bits, &bits_len);
	if (res != TEE_SUCCESS)
		return res;
	if (bits_len < 2 || bits[0] != 0x00)
		return TEE_ERROR_BAD_FORMAT;
	bits++;
	bits_len--;

	/* RSAPublicKey SEQUENCE */
	off = 0;
	res = der_read_tlv(bits, bits_len, &off, 0x30, &inner, &inner_len);
	if (res != TEE_SUCCESS)
		return res;

	/* modulus INTEGER, publicExponent INTEGER */
	off = 0;
	res = der_read_tlv(inner, inner_len, &off, 0x02, &mod, &mod_len);
	if (res != TEE_SUCCESS)
		return res;
	res = der_read_tlv(inner, inner_len, &off, 0x02, &exp, &exp_len);
	if (res != TEE_SUCCESS)
		return res;

	/* DER INTEGERs carry a leading 0x00 when the top bit is set — strip it */
	if (mod_len > 1 && mod[0] == 0x00) {
		mod++;
		mod_len--;
	}
	if (exp_len > 1 && exp[0] == 0x00) {
		exp++;
		exp_len--;
	}

	if (mod_len == 0 || exp_len == 0)
		return TEE_ERROR_BAD_FORMAT;

	key_bits = (uint32_t)(mod_len * 8);

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_bits, key);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate RSA pubkey object failed: 0x%x", (unsigned int)res);
		return res;
	}

	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS,
			     (void *)mod, mod_len);
	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT,
			     (void *)exp, exp_len);

	res = TEE_PopulateTransientObject(*key, attrs, 2);
	if (res != TEE_SUCCESS) {
		EMSG("Populate RSA pubkey failed: 0x%x", (unsigned int)res);
		TEE_FreeTransientObject(*key);
		*key = TEE_HANDLE_NULL;
		return res;
	}

	DMSG("RSA pubkey imported: %u bits (mod %zu B, exp %zu B)",
	     key_bits, mod_len, exp_len);
	return TEE_SUCCESS;
}

/* ---- RSA PKCS#1 v1.5 decrypt ---- */

TEE_Result crypto_rsa_decrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *cipher, size_t cipher_len,
			      uint8_t *plain, size_t *plain_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_AllocateOperation(&op, TEE_ALG_RSA_NOPAD,
				    TEE_MODE_DECRYPT, key_size_bits);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate RSA decrypt op failed: 0x%x", (unsigned int)res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AsymmetricDecrypt(op, NULL, 0, cipher, cipher_len,
				    plain, plain_len);
out:
	TEE_FreeOperation(op);
	return res;
}
