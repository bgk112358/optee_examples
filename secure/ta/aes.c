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

    EMSG("%s enter", __func__);
    IMSG("[bxq] AesArithmetic 1");

    res = TEE_AllocateOperation(&op, mode, alg, keysize);
    if(res != TEE_SUCCESS) {
        EMSG("%s error 1, res = [%x]", __func__, res);
        return res;
    }

    IMSG("[bxq] AesArithmetic 2");
    res = TEE_SetOperationKey(op, aes_key);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 2, res = [%x]", __func__, res);
        return res;
    }

    IMSG("[bxq] AesArithmetic 3");

    TEE_CipherInit(op, iv, iv_len);

    outsize = 0;
    destLen = *outbuf_len;

    IMSG("[bxq] AesArithmetic 4, inbuf_len = %d", inbuf_len);

    while (inbuf_len > (block/8)) {
        IMSG("[bxq] AesArithmetic 4.1");
        res = TEE_CipherUpdate(op, inbuf, (block/8), outbuf, &destLen);
        IMSG("[bxq] AesArithmetic 4.2, res = 0x%08x", res);
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

    IMSG("[bxq] AesArithmetic 5");
    res = TEE_CipherDoFinal(op, inbuf, inbuf_len, outbuf, &destLen);
    IMSG("[bxq] AesArithmetic 6, res = 0x%08x, destLen = %d", res, destLen);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 4, res = [%x]", __func__, res);
        return res;
    }
    *outbuf_len = outsize + destLen;

    IMSG("[bxq] AesArithmetic 7, outbuf_len = %d", *outbuf_len);
    TEE_FreeOperation(op);
    IMSG("[bxq] AesArithmetic 8");

    EMSG("%s exit", __func__);
    return res;
}

static uint8_t iv[16] = {0x0b, 0xdf, 0xab, 0xb1, 0x8d, 0x0a, 0x79, 0x9f, 0xa6, 0x66, 0xeb, 0x84, 0x39, 0x05, 0xe6, 0x5f};

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

    IMSG("[bxq] AesEncode 1");
    res = TEE_GetObjectInfo1(key, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    if (info.objectType != TEE_TYPE_AES) {
        IMSG("[bxq] err AesEncode 2");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    IMSG("[bxq] AesEncode 3");

    switch (info.keySize)
    {
    case 128:
        IMSG("[bxq] AesEncode 4");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_128(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_128(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 192:
        IMSG("[bxq] AesEncode 5");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_192(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_192(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 256:
        IMSG("[bxq] AesEncode 6");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_ENCRYPT_ECB_256(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_ENCRYPT_CBC_256(key, in.data, in.len, out->data, &out->len);
        }
        break;
    default:
        IMSG("[bxq] AesEncode 7");
        break;
    }

    return TEE_ERROR_BAD_PARAMETERS;
}


TEE_Result AesDecode(TEE_ObjectHandle key, uint32_t mode, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_ObjectInfo info;

    IMSG("[bxq] AesDecode 1");
    res = TEE_GetObjectInfo1(key, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    if (info.objectType != TEE_TYPE_AES) {
        IMSG("[bxq] AesDecode 2");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    IMSG("[bxq] AesDecode 3");
    switch (info.keySize)
    {
    case 128:
        IMSG("[bxq] AesDecode 4");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_128(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_128(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 192:
        IMSG("[bxq] AesDecode 5");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_192(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_192(key, in.data, in.len, out->data, &out->len);
        }
        break;
    case 256:
        IMSG("[bxq] AesDecode 6");
        if (mode == TEE_ALG_AES_ECB_NOPAD) {
            return AES_DECRYPT_ECB_256(key, in.data, in.len, out->data, &out->len);
        } else if (mode == TEE_ALG_AES_CBC_NOPAD) {
            return AES_DECRYPT_CBC_256(key, in.data, in.len, out->data, &out->len);
        }
        break;
    default:
        IMSG("[bxq] AesDecode 7");
        break;
    }

    return TEE_ERROR_BAD_PARAMETERS;

    // res = AES_ENCRYPT_CBC_128(aeskey, in_buf, in_sz, tmp_buf, &tmp_sz);
    // EMSG("%s : res = %d, tmp_sz=%d", __func__, res, tmp_sz);
    // print_hex_data("Cipher Date : ", tmp_buf, tmp_sz);

    // res = AES_DECRYPT_CBC_128(aeskey, tmp_buf, tmp_sz, out_buf, &out_sz);
    // EMSG("%s : res = %d, out_sz=%d", __func__, res, out_sz);
    // print_hex_data("Plaintext Date : ", out_buf, out_sz);

    // if(in_sz == out_sz &&  TEE_MemCompare(in_buf, out_buf, out_sz) == 0)
    // {
    //     EMSG("Test %s pass", __func__);
    // } else {
    //     EMSG("Test %s failed", __func__);
    // }
}