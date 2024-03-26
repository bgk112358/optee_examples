#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <rsa.h>

TEE_Result RsaEncode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    TEE_OperationHandle operation;

    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, keyInfo.keySize);
    if(res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        return res;
    }

    res = TEE_SetOperationKey(operation, keyPair);
    if(res != TEE_SUCCESS) {
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        TEE_FreeOperation(operation);
        return res;
    }

    res = TEE_AsymmetricEncrypt(operation, NULL, 0, in.data, in.len, out->data, &(out->len));
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
    }

    TEE_FreeOperation(operation);
    return res;
}

TEE_Result RsaDecode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    TEE_OperationHandle operation;

    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res) {
        EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
        return res;
    }

    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, keyInfo.keySize);
    if(res != TEE_SUCCESS) {
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        return res;
    }

    res = TEE_SetOperationKey(operation, keyPair);
    if(res != TEE_SUCCESS){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        TEE_FreeOperation(operation);
        return res;
    }

    res =  TEE_AsymmetricDecrypt(operation, NULL, 0, in.data, in.len, out->data, &out->len);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
    }

    TEE_FreeOperation(operation);
    return res;
}

static TEE_Result rsa_arithmetic(TEE_ObjectHandle key, uint32_t mode, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len)
{
    TEE_Result res;

    TEE_OperationHandle op;
    TEE_ObjectInfo key_info;
    uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;


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
            alg = TEE_ALG_RSAES_PKCS1_V1_5;
            break;
        case TEE_MODE_SIGN:
        case TEE_MODE_VERIFY:
            alg = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
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
            if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
                EMSG("TEE_AllocateTransientObject error! res=0x%x", res);
            }
            break;
        case TEE_MODE_VERIFY:
            res = TEE_AsymmetricVerifyDigest(op, NULL, 0, inbuf, inbuf_len, outbuf, *outbuf_len);
            if (res != TEE_SUCCESS && res != TEE_ERROR_SIGNATURE_INVALID) {
                EMSG("TEE_AsymmetricVerifyDigest error! res=0x%x", res);
            }
            break;
    }

    TEE_FreeOperation(op);

    return res;
}

#define RSA(name1,name2) \
TEE_Result rsa_##name1(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len) \
{ \
	return rsa_arithmetic(key, TEE_MODE_##name2, inbuf, inbuf_len, outbuf, outbuf_len); \
}

RSA(enc, ENCRYPT)
RSA(dec, DECRYPT)
RSA(sign, SIGN)
RSA(verify, VERIFY)