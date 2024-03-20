#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <key.h>
#include <store.h>
#include <sm2.h>

typedef enum {
    ECC_PUBLIC_VALUE_X      = 0,
    ECC_PUBLIC_VALUE_Y      = 1,
    ECC_PRIVATE_VALUE       = 2,
    ECC_ATTR_END            = 3
} SM2_ATTR;

typedef enum {
    AES_SECRET_VALUE    =   0,
    AES_IV_VAULE        =   1,
    AES_ATTR_END        =   2
} AES_ATTR;

typedef enum {
    SM4_SECRET_VALUE    =   0,
    SM4_IV_VAULE        =   1,
    SM4_ATTR_END        =   2
} SM4_ATTR;

typedef enum {
    RSA_MODULUS             =   0,
    RSA_PUBLIC_EXPONENT     =   1,
    RSA_PRIVATE_EXPONENT    =   2,
    RSA_PRIME1              =   3,
    RSA_PRIME2              =   4,
    RSA_EXPONENT1           =   5,
    RSA_EXPONENT2           =   6,
    RSA_COEFFICIENT         =   7,
    RSA_ATTR_END            =   8
} RSA_ATTR;

typedef enum {
    KEY_SIZE        =   0,
    KEY_TYPE        =   1,
    REVERSE_2       =   2,
    REVERSE_3       =   3,
    CUS_PARAMS_END  =   4
} CUS_PARAMS;

const uint32_t op_rsa_attr[] = {TEE_ATTR_RSA_MODULUS,
                                TEE_ATTR_RSA_PUBLIC_EXPONENT,
                                TEE_ATTR_RSA_PRIVATE_EXPONENT,
                                TEE_ATTR_RSA_PRIME1,
                                TEE_ATTR_RSA_PRIME2,
                                TEE_ATTR_RSA_EXPONENT1,
                                TEE_ATTR_RSA_EXPONENT2,
                                TEE_ATTR_RSA_COEFFICIENT
};

const uint32_t op_sm2_attr[] = {TEE_ATTR_ECC_PUBLIC_VALUE_X,
                                TEE_ATTR_ECC_PUBLIC_VALUE_Y,
                                TEE_ATTR_ECC_PRIVATE_VALUE
};

typedef struct {
    uint32_t params[CUS_PARAMS_END];
    uint32_t len[RSA_ATTR_END];             // MAX(AES_ATTR_END, RSA_ATTR_END)
    uint8_t* data[RSA_ATTR_END];
} KEY_ATTR;

TEE_Result KeyGen(const uint32_t keyType, KEY_PARAM keyParam, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    TEE_ObjectHandle key;

    IMSG("[bxq] KeyGen 1, keyType = 0x%x, keySize = %d", keyType, keyParam.keySize);
    res = TEE_AllocateTransientObject(keyType, keyParam.keySize, &key);
    if (res) {
        EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, keyType, keyParam.keySize, res);
        return res;
    }

    IMSG("[bxq] KeyGen 2");
    res = TEE_GenerateKey(key, keyParam.keySize, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, keyParam.keySize, res);
        return res;
    }
    *keyPair = key;

    TEE_ObjectInfo key_info;
	res = TEE_GetObjectInfo1(key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1 error! res=0x%x", res);
		return res;
	}
    IMSG("[bxq] KeyGen 3, keySize = %d", key_info.keySize);

    res = KeyStore(keyParam, key);
    if (res != TEE_SUCCESS) {
        EMSG("Key_Store err, id = %s, res = 0x%x ", keyParam.id, res);
        return res;
    }
    IMSG("[bxq] KeyGen 4");

    return TEE_SUCCESS;
}

TEE_Result KeyStoreRsa(const uint8_t *keyID, uint32_t keyIDLen, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    uint32_t bufLen = 0;
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);

    IMSG("[bxq] secure_cmd_gen_key 4");
    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    IMSG("[bxq] secure_cmd_gen_key 4");
    
    key_attr.params[KEY_SIZE] = keyInfo.keySize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    IMSG("[bxq] secure_cmd_gen_key 5, keySize = %d", key_attr.params[KEY_SIZE]);
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        IMSG("[bxq] secure_cmd_gen_key 5.1.%d", i);
        res = TEE_GetObjectBufferAttribute(keyPair, op_rsa_attr[i], NULL, &(key_attr.len[i]));
        if(res != TEE_ERROR_SHORT_BUFFER) {
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_key 5.2.%d,  key_attr.len[%d] = %d", i, i, key_attr.len[i]);
        key_attr.data[i] = TEE_Malloc(key_attr.len[i], 0);
        if (!key_attr.data[i]) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_key 5.3.%d, key_attr.data[%d] = 0x%02x", i, i, key_attr.data[i]);
        res = TEE_GetObjectBufferAttribute(keyPair, op_rsa_attr[i], key_attr.data[i], &(key_attr.len[i]));
        if(TEE_SUCCESS != res){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }
        bufLen += key_attr.len[i];
        IMSG("[bxq] secure_cmd_gen_key 5.4.%d, key_attr.len[%d] = %d", i, i, key_attr.len[i]);

        IMSG_RAW("[bxq] key_attr.data[%d]: ", i);
        for (size_t j = 0; j < key_attr.len[i]; j++) {
            IMSG_RAW("0x%02x ", *(key_attr.data[i] + j));
        }
        IMSG("end");
    }

    IMSG("[bxq] secure_cmd_gen_key 6, bufHeadLen = %d", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    IMSG("[bxq] secure_cmd_gen_key 7, bufLen = %d", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    IMSG("[bxq] secure_cmd_gen_key 8, key_attr.data[0] = 0x%02x", key_attr.data[0]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[0], key_attr.len[0]);
    IMSG("[bxq] secure_cmd_gen_key 9");
    TEE_Free(key_attr.data[0]);
    IMSG("[bxq] secure_cmd_gen_key 10");
    uint8_t *p = buff + bufHeadLen;
    for (size_t i = 1; i < RSA_ATTR_END; i++) {
        IMSG("[bxq] secure_cmd_gen_key 10.1.%d", i);
        p += key_attr.len[i - 1];
        IMSG("[bxq] secure_cmd_gen_key 10.2.%d, p = 0x%02x, len[%d] = %d, len[%d] = %d", i, p, i - 1, key_attr.len[i - 1], i, key_attr.len[i]);
        TEE_MemMove(p, key_attr.data[i], key_attr.len[i]);
        TEE_Free(key_attr.data[i]);
    }

    IMSG_RAW("[bxq] bufLen = %d, key_attr: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     IMSG_RAW("0x%02x ", *(buff + j));
    // }
    IMSG("end");

    int32_t code;
    return Store_WriteKey(keyID, keyIDLen, buff, bufLen, &code);
}

TEE_Result KeyStoreAes(KEY_PARAM keyParam, TEE_ObjectHandle key)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    uint32_t bufLen = 0;
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);

    IMSG("[bxq] KeyStoreAes 1");
    res = TEE_GetObjectInfo1(key, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    IMSG("[bxq] KeyStoreAes 2");
    
    TEE_MemFill(&key_attr, 0, sizeof(key_attr));
    key_attr.params[KEY_SIZE] = keyInfo.keySize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    IMSG("[bxq] KeyStoreAes 3, keySize = %d", key_attr.params[KEY_SIZE]);


    IMSG("[bxq] KeyStoreAes 3.1.%d", AES_SECRET_VALUE);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, NULL, &(key_attr.len[AES_SECRET_VALUE]));
    if(res != TEE_ERROR_SHORT_BUFFER){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyStoreAes 3.2.%d,  key_attr.len[%d] = %d", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.len[AES_SECRET_VALUE]);
    key_attr.data[AES_SECRET_VALUE] = TEE_Malloc(key_attr.len[AES_SECRET_VALUE], 0);
    if (!key_attr.data[AES_SECRET_VALUE]) {
        EMSG("TEE_Malloc() fail.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
        return res;
    }

    IMSG("[bxq] KeyStoreAes 3.3.%d, key_attr.data[%d] = 0x%02x", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE]);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE], &(key_attr.len[AES_SECRET_VALUE]));
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }
    bufLen += key_attr.len[AES_SECRET_VALUE];
    IMSG("[bxq] KeyStoreAes 3.4.%d, key_attr.len[%d] = %d", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.len[AES_SECRET_VALUE]);

    IMSG_RAW("[bxq] key_attr.data[%d]: ", AES_SECRET_VALUE);
    for (size_t j = 0; j < key_attr.len[AES_SECRET_VALUE]; j++) {
        IMSG_RAW("0x%02x ", *(key_attr.data[AES_SECRET_VALUE] + j));
    }
    IMSG("end");

    bufLen += sizeof(keyParam.iv);

    IMSG("[bxq] KeyStoreAes 4, bufHeadLen = %d", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    IMSG("[bxq] KeyStoreAes 5, bufLen = %d", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    IMSG("[bxq] KeyStoreAes 6, key_attr.data[AES_SECRET_VALUE] = 0x%02x", key_attr.data[AES_SECRET_VALUE]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[AES_SECRET_VALUE], key_attr.len[AES_SECRET_VALUE]);
    IMSG("[bxq] KeyStoreAes 7");
    TEE_Free(key_attr.data[AES_SECRET_VALUE]);
    IMSG("[bxq] KeyStoreAes 8");
    TEE_MemMove(buff + bufHeadLen + key_attr.len[AES_SECRET_VALUE], keyParam.iv, sizeof(keyParam.iv));

    IMSG_RAW("[bxq] bufLen = %d, aes_key_attr_value: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     IMSG_RAW("0x%02x ", *(buff + j));
    // }
    IMSG("KeyStoreAes 9, aes buff line end");

    int32_t code;
    return Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen, &code);
}

TEE_Result KeyStoreSm2Pke(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    uint32_t bufLen = 0;
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);

    // // test start
    // uint8_t in[] = "1234567890123456";
    // uint8_t out[1024];
    // uint32_t outLen = 1024;
    // res = sm2_enc(keyPair, in, sizeof(in), out, &outLen);
    // if (res != TEE_SUCCESS) {
    //     EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
    //     return res;
    // }
    // IMSG("[bxq] KeyStoreSm2Pke 2, Sm2Enc start");
    // for (size_t i = 0; i < outLen; i++) {
    //     IMSG(" 0x%02x", out[i]);
    // }
    // IMSG("[bxq] KeyStoreSm2Pke 3, Sm2Enc end");
    // // test end

    IMSG("[bxq] KeyStoreSm2Pke 4");
    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    IMSG("[bxq] KeyStoreSm2Pke 4");
    
    key_attr.params[KEY_SIZE] = keyInfo.keySize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    IMSG("[bxq] KeyStoreSm2Pke 5, keySize = %d", key_attr.params[KEY_SIZE]);
    for (size_t i = 0; i < ECC_ATTR_END; i++) {
        IMSG("[bxq] KeyStoreSm2Pke 5.1.%d", i);
        res = TEE_GetObjectBufferAttribute(keyPair, op_sm2_attr[i], NULL, &(key_attr.len[i]));
        if(res != TEE_ERROR_SHORT_BUFFER){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] KeyStoreSm2Pke 5.2.%d,  key_attr.len[%d] = %d", i, i, key_attr.len[i]);
        key_attr.data[i] = TEE_Malloc(key_attr.len[i], 0);
        if (!key_attr.data[i]) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
            return res;
        }

        IMSG("[bxq] KeyStoreSm2Pke 5.3.%d, key_attr.data[%d] = 0x%02x", i, i, key_attr.data[i]);
        res = TEE_GetObjectBufferAttribute(keyPair, op_sm2_attr[i], key_attr.data[i], &(key_attr.len[i]));
        if(TEE_SUCCESS != res){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }
        bufLen += key_attr.len[i];
        IMSG("[bxq] KeyStoreSm2Pke 5.4.%d, key_attr.len[%d] = %d", i, i, key_attr.len[i]);

        IMSG_RAW("[bxq] key_attr.data[%d]: ", i);
        for (size_t j = 0; j < key_attr.len[i]; j++) {
            IMSG_RAW("0x%02x ", *(key_attr.data[i] + j));
        }
        IMSG("end");
    }

    IMSG("[bxq] KeyStoreSm2Pke 6, bufHeadLen = %d", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    IMSG("[bxq] KeyStoreSm2Pke 7, bufLen = %d", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    IMSG("[bxq] KeyStoreSm2Pke 8, key_attr.data[0] = 0x%02x", key_attr.data[0]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[0], key_attr.len[0]);
    IMSG("[bxq] KeyStoreSm2Pke 9");
    TEE_Free(key_attr.data[0]);
    IMSG("[bxq] KeyStoreSm2Pke 10");
    uint8_t *p = buff + bufHeadLen;
    for (size_t i = 1; i < ECC_ATTR_END; i++) {
        IMSG("[bxq] KeyStoreSm2Pke 10.1.%d", i);
        p += key_attr.len[i - 1];
        IMSG("[bxq] KeyStoreSm2Pke 10.2.%d, p = 0x%02x, len[%d] = %d, len[%d] = %d", i, p, i - 1, key_attr.len[i - 1], i, key_attr.len[i]);
        TEE_MemMove(p, key_attr.data[i], key_attr.len[i]);
        TEE_Free(key_attr.data[i]);
    }

    IMSG_RAW("[bxq] bufLen = %d, key_attr: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     IMSG_RAW("0x%02x ", *(buff + j));
    // }
    IMSG("end");

    int32_t code;
    return Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen, &code);
}

TEE_Result KeyStoreSm2Dsa(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    return KeyStoreSm2Pke(keyParam, keyPair);
}

TEE_Result KeyStoreSm4(KEY_PARAM keyParam, TEE_ObjectHandle key)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    uint32_t bufLen = 0;
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);

    IMSG("[bxq] KeyStoreSm4 1");
    res = TEE_GetObjectInfo1(key, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    IMSG("[bxq] KeyStoreSm4 2");
    
    TEE_MemFill(&key_attr, 0, sizeof(key_attr));
    key_attr.params[KEY_SIZE] = keyInfo.keySize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    IMSG("[bxq] KeyStoreSm4 3, keySize = %d", key_attr.params[KEY_SIZE]);


    IMSG("[bxq] KeyStoreSm4 3.1.%d", SM4_SECRET_VALUE);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, NULL, &(key_attr.len[SM4_SECRET_VALUE]));
    if(res != TEE_ERROR_SHORT_BUFFER){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyStoreSm4 3.2.%d,  key_attr.len[%d] = %d", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.len[SM4_SECRET_VALUE]);
    key_attr.data[SM4_SECRET_VALUE] = TEE_Malloc(key_attr.len[SM4_SECRET_VALUE], 0);
    if (!key_attr.data[SM4_SECRET_VALUE]) {
        EMSG("TEE_Malloc() fail.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
        return res;
    }

    IMSG("[bxq] KeyStoreSm4 3.3.%d, key_attr.data[%d] = 0x%02x", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE]);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE], &(key_attr.len[SM4_SECRET_VALUE]));
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }
    bufLen += key_attr.len[SM4_SECRET_VALUE];
    IMSG("[bxq] KeyStoreSm4 3.4.%d, key_attr.len[%d] = %d", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.len[SM4_SECRET_VALUE]);

    IMSG_RAW("[bxq] key_attr.data[%d]: ", SM4_SECRET_VALUE);
    for (size_t j = 0; j < key_attr.len[SM4_SECRET_VALUE]; j++) {
        IMSG_RAW("0x%02x ", *(key_attr.data[SM4_SECRET_VALUE] + j));
    }
    IMSG("end");

    bufLen += sizeof(keyParam.iv);

    IMSG("[bxq] KeyStoreSm4 4, bufHeadLen = %d", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    IMSG("[bxq] KeyStoreSm4 5, bufLen = %d", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    IMSG("[bxq] KeyStoreSm4 6, key_attr.data[SM4_SECRET_VALUE] = 0x%02x", key_attr.data[SM4_SECRET_VALUE]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[SM4_SECRET_VALUE], key_attr.len[SM4_SECRET_VALUE]);
    IMSG("[bxq] KeyStoreSm4 7");
    TEE_Free(key_attr.data[SM4_SECRET_VALUE]);
    IMSG("[bxq] KeyStoreSm4 8");
    TEE_MemMove(buff + bufHeadLen + key_attr.len[SM4_SECRET_VALUE], keyParam.iv, sizeof(keyParam.iv));

    IMSG_RAW("[bxq] bufLen = %d, aes_key_attr_value: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     IMSG_RAW("0x%02x ", *(buff + j));
    // }
    IMSG("KeyStoreSm4 9, aes buff line end");

    int32_t code;
    return Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen, &code);
}


TEE_Result KeyStore(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo info;

    IMSG("[bxq] KeyStore 1");
    res = TEE_GetObjectInfo1(keyPair, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    IMSG("[bxq] KeyStore 2");

    if (info.objectType == TEE_TYPE_RSA_KEYPAIR) {
        res = KeyStoreRsa(keyParam.id, keyParam.idLen, keyPair);
    } else if (info.objectType == TEE_TYPE_AES) {
        res = KeyStoreAes(keyParam, keyPair);
    } else if (info.objectType == TEE_TYPE_SM2_PKE_KEYPAIR) {
        res = KeyStoreSm2Pke(keyParam, keyPair);
    } else if (info.objectType == TEE_TYPE_SM2_DSA_KEYPAIR) {
        res = KeyStoreSm2Dsa(keyParam, keyPair);
    } else if (info.objectType == TEE_TYPE_SM4) {
        res = KeyStoreSm4(keyParam, keyPair);
    }    

    return res;
}

TEE_Result KeyRestoreRsa(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    uint32_t keyDataLen;
    uint32_t code;
    TEE_Attribute attrs[8];
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        IMSG("[bxq] secure_cmd_rsa_enc 7.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] secure_cmd_rsa_enc 7.2.%d, p = 0x%02x", i, p);
    }

    IMSG("[bxq] secure_cmd_rsa_enc 8");

    IMSG("[bxq] secure_cmd_rsa_enc 9");
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, key_attr.data[RSA_MODULUS], key_attr.len[RSA_MODULUS]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_attr.data[RSA_PUBLIC_EXPONENT], key_attr.len[RSA_PUBLIC_EXPONENT]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_attr.data[RSA_PRIVATE_EXPONENT], key_attr.len[RSA_PRIVATE_EXPONENT]);

    TEE_InitRefAttribute(&attrs[3], TEE_ATTR_RSA_PRIME1, key_attr.data[RSA_PRIME1], key_attr.len[RSA_PRIME1]);
    TEE_InitRefAttribute(&attrs[4], TEE_ATTR_RSA_PRIME2, key_attr.data[RSA_PRIME2], key_attr.len[RSA_PRIME2]);
    TEE_InitRefAttribute(&attrs[5], TEE_ATTR_RSA_EXPONENT1, key_attr.data[RSA_EXPONENT1], key_attr.len[RSA_EXPONENT1]);
    TEE_InitRefAttribute(&attrs[6], TEE_ATTR_RSA_EXPONENT2, key_attr.data[RSA_EXPONENT2], key_attr.len[RSA_EXPONENT2]);
    TEE_InitRefAttribute(&attrs[7], TEE_ATTR_RSA_COEFFICIENT, key_attr.data[RSA_COEFFICIENT], key_attr.len[RSA_COEFFICIENT]);

    IMSG("[bxq] secure_cmd_rsa_enc 10, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] secure_cmd_rsa_enc 11");
    res = TEE_PopulateTransientObject(key, attrs, 8);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    *keyPair = key;

    // test start
    uint32_t p_len;
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        IMSG("[bxq] secure_cmd_rsa_enc 11.1.%d", i);
        res = TEE_GetObjectBufferAttribute(key, op_rsa_attr[i], NULL, &p_len);
        if(res != TEE_ERROR_SHORT_BUFFER){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.2.%d,  p_len[%d] = %d", i, i, p_len);
        p = TEE_Malloc(p_len, 0);
        if (!p) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.3.%d, p[%d] = 0x%02x", i, i, *p);
        res = TEE_GetObjectBufferAttribute(key, op_rsa_attr[i], p, &p_len);
        if(TEE_SUCCESS != res){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.4.%d, p_len[%d] = %d", i, i, p_len);

        IMSG_RAW("[bxq] p[%d]: ", i);
        for (size_t j = 0; j < p_len; j++) {
            IMSG_RAW("0x%02x ", *(p + j));
        }
        IMSG("end");

        TEE_Free(p);
    }
    // test end

    return TEE_SUCCESS;
}

TEE_Result KeyRestoreAes(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    IMSG("[bxq] KeyRestoreAes 1");

    TEE_Result res;
    uint32_t keyDataLen;
    uint32_t code;
    TEE_Attribute attrs;
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    // uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);
    key_attr.data[0] = keyData + bufHeadLen;

    IMSG("[bxq] KeyRestoreAes 2");

    IMSG("[bxq] KeyRestoreAes 3");
    TEE_InitRefAttribute(&attrs, TEE_ATTR_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE], key_attr.len[AES_SECRET_VALUE]);

    IMSG("[bxq] KeyRestoreAes 4, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreAes 5");
    res = TEE_PopulateTransientObject(key, &attrs, 1);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreAes 6");
    *keyPair = key;
    return TEE_SUCCESS;
}

TEE_Result KeyRestoreSm2Pke(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    uint32_t keyDataLen;
    uint32_t code;
    TEE_Attribute attrs[3];
    // TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < ECC_ATTR_END - 1; i++) {
        IMSG("[bxq] KeyRestoreSm2Pke 7.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] KeyRestoreSm2Pke 7.2.%d, p = 0x%02x", i, p);
    }

    for (size_t i = 0; i < ECC_ATTR_END; i++)
    {
        IMSG_RAW("[bxq] key_attr.data[%d]: ", i);
        for (size_t j = 0; j < key_attr.len[i]; j++) {
            IMSG_RAW("0x%02x ", *(key_attr.data[i] + j));
        }
        IMSG("end");
    }

    IMSG("[bxq] KeyRestoreSm2Pke 8");

    IMSG("[bxq] KeyRestoreSm2Pke 9");
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_attr.data[ECC_PUBLIC_VALUE_X], key_attr.len[ECC_PUBLIC_VALUE_X]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_attr.data[ECC_PUBLIC_VALUE_Y], key_attr.len[ECC_PUBLIC_VALUE_Y]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_attr.data[ECC_PRIVATE_VALUE], key_attr.len[ECC_PRIVATE_VALUE]);

    IMSG("[bxq] KeyRestoreSm2Pke 10, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, key_attr.params[KEY_SIZE], keyPair);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreSm2Pke 11");
    res = TEE_PopulateTransientObject(*keyPair, attrs, 3);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    // test start 
    // uint8_t in[] = "1234567890123456";
    // uint8_t out[1024];
    // uint32_t outLen = 1024;
    // res = sm2_enc(*keyPair, in, sizeof(in), out, &outLen);
    // if (res != TEE_SUCCESS) {
    //     EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
    //     return res;
    // }
    // IMSG("[bxq] KeyRestoreSm2Pke 11.1, Sm2Enc start");
    // for (size_t i = 0; i < outLen; i++) {
    //     IMSG(" 0x%02x", out[i]);
    // }
    // IMSG("[bxq] KeyRestoreSm2Pke 11.2, Sm2Enc end");
    // test end


    // *keyPair = key;

    TEE_ObjectInfo key_info;
	res = TEE_GetObjectInfo1(*keyPair, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1 error! res=0x%x", res);
		return res;
	}
    IMSG("[bxq] KeyRestoreSm2Pke 12, keySize = %d, objectSize = %d, maxKeySize = %d, maxObjectSize = %d, dataSize = %d",
        key_info.keySize, key_info.objectSize, key_info.maxKeySize, key_info.maxObjectSize, key_info.dataSize);

    return TEE_SUCCESS;
}

TEE_Result KeyRestoreSm2Dsa(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    uint32_t keyDataLen;
    uint32_t code;
    TEE_Attribute attrs[8];
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        IMSG("[bxq] KeyRestoreSm2Dsa 7.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] KeyRestoreSm2Dsa 7.2.%d, p = 0x%02x", i, p);
    }

    IMSG("[bxq] KeyRestoreSm2Dsa 8");

    IMSG("[bxq] KeyRestoreSm2Dsa 9");
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_attr.data[ECC_PUBLIC_VALUE_X], key_attr.len[ECC_PUBLIC_VALUE_X]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_attr.data[ECC_PUBLIC_VALUE_Y], key_attr.len[ECC_PUBLIC_VALUE_Y]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_attr.data[ECC_PRIVATE_VALUE], key_attr.len[ECC_PRIVATE_VALUE]);

    IMSG("[bxq] KeyRestoreSm2Dsa 10, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_KEYPAIR, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreSm2Dsa 11");
    res = TEE_PopulateTransientObject(key, attrs, 8);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    *keyPair = key;

    return TEE_SUCCESS;
}

TEE_Result KeyRestoreSm4(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    IMSG("[bxq] KeyRestoreSm4 1");

    TEE_Result res;
    uint32_t keyDataLen;
    uint32_t code;
    TEE_Attribute attrs;
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    // uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);
    key_attr.data[0] = keyData + bufHeadLen;

    IMSG("[bxq] KeyRestoreSm4 2");

    IMSG("[bxq] KeyRestoreSm4 3");
    TEE_InitRefAttribute(&attrs, TEE_ATTR_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE], key_attr.len[SM4_SECRET_VALUE]);

    IMSG("[bxq] KeyRestoreSm4 4, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_SM4, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreSm4 5");
    res = TEE_PopulateTransientObject(key, &attrs, 1);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    IMSG("[bxq] KeyRestoreSm4 6");
    *keyPair = key;
    return TEE_SUCCESS;
}

TEE_Result KeyRestore(const uint8_t *keyID, uint32_t keyIDLen, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    uint8_t *keyData;
    uint32_t keyDataLen;
    uint32_t code;
    KEY_ATTR key_attr;

    IMSG("[bxq] KeyRestore 1");
    res = Store_ReadKey(keyID, keyIDLen, &keyData, &keyDataLen, &code);

    IMSG("[bxq] KeyRestore 2, keyData = 0x%p, keyDataLen = %d", keyData, keyDataLen);
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    // uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);
    IMSG("[bxq] secure_cmd_rsa_enc 7.0, bufHeadLen = %d", bufHeadLen);

    if (key_attr.params[KEY_TYPE] == TEE_TYPE_RSA_KEYPAIR) {
        return KeyRestoreRsa(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_AES) {
        return KeyRestoreAes(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM2_PKE_KEYPAIR) {
        return KeyRestoreSm2Pke(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM2_DSA_KEYPAIR) {
        return KeyRestoreSm2Dsa(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM4) {
        return KeyRestoreSm4(keyData, keyPair);
    }

    return res;
}

TEE_Result KeyRestoreValue(const uint8_t *keyID, uint32_t keyIDLen, void *buffer, uint32_t *bufferLen)
{
    TEE_Result res;
    uint8_t *keyData;
    uint32_t keyDataLen;
    uint32_t code;
    KEY_ATTR key_attr;

    IMSG("[bxq] KeyRestoreValue 1");
    res = Store_ReadKey(keyID, keyIDLen, &keyData, &keyDataLen, &code);

    IMSG("[bxq] KeyRestoreValue 2, keyData = 0x%p, keyDataLen = %d", keyData, keyDataLen);
    uint32_t bufHeadLen = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    IMSG("[bxq] KeyRestoreValue 3, p = %p, bufHeadLen = %d", p, bufHeadLen);
    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        IMSG("[bxq] KeyRestoreValue 3.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] KeyRestoreValue 3.2.%d, p = 0x%02x", i, p);
    }

    // 内存返回不合理，后续修改再完成
    return TEE_SUCCESS;
}