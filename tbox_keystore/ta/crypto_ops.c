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
