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

/*
 * Verify an ECDSA P-256 signature over a pre-computed SHA-256 hash.
 *
 * pubkey_der: SubjectPublicKeyInfo DER (88-91 bytes, standard SPKI).
 * hash:       32-byte SHA-256 digest of the signed message.
 * sig_der:    DER-encoded ECDSA signature (64-72 bytes).
 *
 * The DER is parsed to extract the uncompressed EC point (x, y),
 * a transient ECC object is created, and TEE_AsymmetricVerifyDigest
 * verifies the signature.
 */
TEE_Result crypto_ecdsa_verify(const uint8_t *pubkey_der, size_t der_len,
			       const uint8_t *hash, size_t hash_len,
			       const uint8_t *sig_der, size_t sig_len)
{
	TEE_ObjectHandle ec_obj = TEE_HANDLE_NULL;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Attribute attrs[3];
	TEE_Result res;
	const uint8_t *point;
	size_t point_len;

	/*
	 * Minimal SPKI DER parser for P-256:
	 *
	 *   Offset  Content
	 *   0       0x30 SEQUENCE
	 *   1       total len (0x59 = 89 for P-256, or 0x5A = 90)
	 *   2       0x30 SEQUENCE (algorithm)
	 *   3       algorithm len (0x13 = 19)
	 *   4-22    OID: ecPublicKey + prime256v1
	 *   23      0x03 BIT STRING
	 *   24      bit string len (0x42 = 66, or 0x43 = 67 with padding)
	 *   25      0x00 unused bits
	 *   26      0x04 uncompressed point flag
	 *   27-58   x coordinate (32 bytes)
	 *   59-90   y coordinate (32 bytes)
	 *
	 * We look for the 0x03 BIT STRING tag, then skip to the 0x04 point.
	 */
	if (!pubkey_der || der_len < 88 || !hash || hash_len != 32 || !sig_der)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Scan for BIT STRING marker 0x03 followed by 0x42 (66 bytes) */
	{
		size_t off;
		int found = 0;

		for (off = 22; off + 3 < der_len; off++) {
			if (pubkey_der[off] == 0x03 &&
			    pubkey_der[off + 1] >= 0x40 &&
			    pubkey_der[off + 1] <= 0x44) {
				point = pubkey_der + off + 3; /* skip tag + len + unused */
				point_len = pubkey_der[off + 1] - 1; /* minus unused bits byte */

				/* Must start with 0x04 (uncompressed point) */
				if (point_len >= 65 && point[0] == 0x04) {
					point++;     /* skip 0x04 flag */
					point_len = 64; /* x[32] + y[32] */
					found = 1;
					break;
				}
			}
		}

		if (!found) {
			EMSG("ECDSA verify: cannot parse pubkey DER");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	/* Create transient ECC public key object */
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, 256,
					  &ec_obj);
	if (res != TEE_SUCCESS) {
		EMSG("Allocate ECC object failed: 0x%x", (unsigned int)res);
		return res;
	}

	uint32_t curve = TEE_ECC_CURVE_NIST_P256;
	TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_CURVE,
			     &curve, sizeof(curve));

	TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     (void *)point, 32);

	TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     (void *)(point + 32), 32);

	res = TEE_PopulateTransientObject(ec_obj, attrs, 3);
	if (res != TEE_SUCCESS) {
		EMSG("Populate ECC object failed: 0x%x", (unsigned int)res);
		goto out_obj;
	}

	/* Allocate verify operation */
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
