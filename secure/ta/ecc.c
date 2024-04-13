#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ecc.h"

static TEE_Result ecc_arithmetic(TEE_ObjectHandle key, uint32_t mode, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len)
{
	TEE_Result res;

	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	uint32_t alg = 0;
	
	EMSG("%s enter", __func__);

	if (!key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1 error! res=0x%x", res);
		return res;
	}
	
	switch (mode)
	{
		case TEE_MODE_ENCRYPT:
		case TEE_MODE_DECRYPT:
			alg = TEE_ALG_SHA256;  //TODO
			break;
		case TEE_MODE_SIGN:
		case TEE_MODE_VERIFY:
			alg = TEE_ALG_ECDSA_P256;
		default:
			break;
	}

	res = TEE_AllocateOperation(&op, alg, mode, key_info.objectSize);
	if (res) {
		EMSG("TEE_AllocateTransientObject error! res=0x%x", res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res) {
		EMSG("TEE_SetOperationKey error! res=0x%x", res);
		TEE_FreeOperation(op);
		return TEE_ERROR_BAD_STATE;
	}

	switch (mode)
	{
		case TEE_MODE_ENCRYPT:
			res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricEncrypt error! res=0x%x", res);
			}
			break;
		case TEE_MODE_DECRYPT:
			res = TEE_AsymmetricDecrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricDecrypt error! res=0x%x", res);
			}
			break;
		case TEE_MODE_SIGN:
			res = TEE_AsymmetricSignDigest(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AllocateTransientObject error! res=0x%x", res);
			}
			break;
		case TEE_MODE_VERIFY:
			res = TEE_AsymmetricVerifyDigest(op, NULL, 0, inbuf, inbuf_len, outbuf, *outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricVerifyDigest error! res=0x%x", res);
			}
			break;
		default:
			break;
	}

	TEE_FreeOperation(op);
	
	EMSG("%s exit", __func__);
	return res;

}

#define ECC(name1,name2) \
TEE_Result ecc_##name1(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len) \
{ \
	return ecc_arithmetic(key, TEE_MODE_##name2, inbuf, inbuf_len, outbuf, outbuf_len); \
}

ECC(enc, ENCRYPT)
ECC(dec, DECRYPT)
ECC(sign, SIGN)
ECC(verify, VERIFY)