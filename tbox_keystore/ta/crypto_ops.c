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
