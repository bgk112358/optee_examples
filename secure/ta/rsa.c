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