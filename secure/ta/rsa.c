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

    IMSG("[bxq] Rsa_Encode 1");
    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

    IMSG("[bxq] secure_cmd_rsa_enc 13, keyInfo.keySize = %d", keyInfo.keySize);
    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, keyInfo.keySize);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] secure_cmd_rsa_enc 14");
    res = TEE_SetOperationKey(operation, keyPair);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] secure_cmd_rsa_enc 14.1 inbuf:");
    for (size_t i = 0; i < in.len; i++) {
        IMSG("0x%02x ", *(in.data + i));
    }
    IMSG("[bxq] secure_cmd_rsa_enc 14.2 end");
    

    IMSG("[bxq] secure_cmd_rsa_enc 15");
    res = TEE_AsymmetricEncrypt(operation, NULL, 0, in.data, in.len, out->data, &(out->len));
    if(res == TEE_SUCCESS) {
        IMSG("[bxq] secure_cmd_rsa_enc 15.1, out->len = %d, outbuf:", out->len);
        for (size_t i = 0; i < out->len; i++) {
            IMSG("0x%02x ", *(out->data + i));
        }
        IMSG("[bxq] secure_cmd_rsa_enc 15.2 end");
    }

    return res;
}

TEE_Result RsaDecode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    TEE_OperationHandle operation;

    IMSG("[bxq] RsaDecode 12");
    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res) {
        EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
        return res;
    }

    IMSG("[bxq] RsaDecode 13, keyInfo.keySize = %d", keyInfo.keySize);
    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, keyInfo.keySize);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] RsaDecode 14");
    res = TEE_SetOperationKey(operation, keyPair);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] RsaDecode 14.1 inbuf:");
    for (size_t i = 0; i < in.len; i++) {
        IMSG("0x%02x ", *(in.data + i));
    }
    IMSG("[bxq] RsaDecode 14.2 end");

    IMSG("[bxq] RsaDecode 15");
    res = TEE_AsymmetricDecrypt(operation, NULL, 0, in.data, in.len, out->data, &out->len);
    if(res == TEE_SUCCESS) {
        IMSG("[bxq] secure_cmd_rsa_dec 15.1, out->len = %d, outbuf:", out->len);
        for (size_t i = 0; i < out->len; i++) {
            IMSG("0x%02x ", *(out->data + i));
        }
        IMSG("[bxq] secure_cmd_rsa_enc 15.2 end");
    }

    return res;
}