#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "aes.h"

static TEE_Result AesArithmetic(TEE_ObjectHandle aes_key, uint32_t keysize, uint32_t alg, uint32_t mode, void *iv, uint32_t iv_len, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len)
{
    TEE_Result res;
    TEE_OperationHandle op;
    size_t destLen;
    int outsize;
    uint32_t block = 128;

    res = TEE_AllocateOperation(&op, mode, alg, keysize);
    if(res != TEE_SUCCESS) {
        EMSG("%s error 1, res = [%x]", __func__, res);
        return res;
    }

    res = TEE_SetOperationKey(op, aes_key);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 2, res = [%x]", __func__, res);
        return res;
    }

    TEE_CipherInit(op, iv, iv_len);

    outsize = 0;
    destLen = *outbuf_len;

    while (inbuf_len > (block/8)) {
        res = TEE_CipherUpdate(op, inbuf, (block/8), outbuf, &destLen);
        if(res != TEE_SUCCESS) {
            TEE_FreeOperation(op);
            EMSG("%s error 3, res = [%x]", __func__, res);
            return res;
        }
        inbuf_len -= (block/8);
        inbuf += (block/8);
        outbuf += destLen;
        outsize += destLen;
        destLen = *outbuf_len - outsize;
    }

    res = TEE_CipherDoFinal(op, inbuf, inbuf_len, outbuf, &destLen);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 4, res = [%x]", __func__, res);
        return res;
    }
    *outbuf_len = outsize + destLen;

    TEE_FreeOperation(op);
    return res;
}

static uint8_t iv[16] = {0};

#define AES(alg, mode, length) \
TEE_Result AES_##alg##_##mode##_##length(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len) \
{ \
	return AesArithmetic(aes_key, length, TEE_MODE_##alg, TEE_ALG_AES_##mode##_NOPAD, iv, sizeof(iv), inbuf, inbuf_len, outbuf, outbuf_len); \
}

AES(ENCRYPT, ECB, 128)
AES(ENCRYPT, ECB, 192)
AES(ENCRYPT, ECB, 256)
AES(DECRYPT, ECB, 128)
AES(DECRYPT, ECB, 192)
AES(DECRYPT, ECB, 256)
AES(ENCRYPT, CBC, 128)
AES(ENCRYPT, CBC, 192)
AES(ENCRYPT, CBC, 256)
AES(DECRYPT, CBC, 128)
AES(DECRYPT, CBC, 192)
AES(DECRYPT, CBC, 256)

TEE_Result AES_ENCRYPT_ECB_128(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_ENCRYPT_ECB_192(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_ENCRYPT_ECB_256(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_128(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_192(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_256(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_128(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_192(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_256(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_128(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_192(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_256(TEE_ObjectHandle aes_key, void *inbuf, uint32_t inbuf_len, void *outbuf, uint32_t *outbuf_len);

TEE_Result AesEncode(TEE_ObjectHandle key, uint32_t mode, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo info;

    res = TEE_GetObjectInfo1(key, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    if (info.objectType != TEE_TYPE_AES) {
        EMSG("Bad key type.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (info.objectSize)
    {
    case 128:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_128(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_128(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 192:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_192(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_192(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 256:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_256(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_256(key, in.data, in.len, out->data, &out->len);
        }
        break;
    default:
        break;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}


TEE_Result AesDecode(TEE_ObjectHandle key, uint32_t mode, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo info;

    res = TEE_GetObjectInfo1(key, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    if (info.objectType != TEE_TYPE_AES) {
        EMSG("Bad key type.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (info.objectSize)
    {
    case 128:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_128(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_128(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 192:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_192(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_192(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 256:
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_256(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_256(key, in.data, in.len, out->data, &out->len);
        }
        break;
    default:
        break;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}