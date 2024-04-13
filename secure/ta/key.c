#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <key.h>
#include <store.h>
#include <sm4.h>

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
    size_t len[RSA_ATTR_END];             // MAX(AES_ATTR_END, RSA_ATTR_END)
    uint8_t* data[RSA_ATTR_END];
} KEY_ATTR;

TEE_Result KeyGen(const uint32_t keyType, KEY_PARAM keyParam, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    TEE_ObjectHandle key;

    res = TEE_AllocateTransientObject(keyType, keyParam.keySize, &key);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId64 "): %#" PRIx32, keyType, keyParam.keySize, res);
        return res;
    }

    res = TEE_GenerateKey(key, keyParam.keySize, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GenerateKey(%" PRId64 "): %#" PRIx32, keyParam.keySize, res);
        return res;
    }
    *keyPair = key;

    res = KeyStore(keyParam, key);
    if (res != TEE_SUCCESS) {
        EMSG("Key_Store err, id = %s, res = 0x%x ", keyParam.id, res);
        return res;
    }

    TEE_FreeTransientObject(key);
    return TEE_SUCCESS;
}

static TEE_Result KeyStoreRsa(const uint8_t *keyID, size_t keyIDLen, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    size_t bufLen = 0;
    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;

    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    
    key_attr.params[KEY_SIZE] = keyInfo.objectSize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        res = TEE_GetObjectBufferAttribute(keyPair, op_rsa_attr[i], NULL, &(key_attr.len[i]));
        if(res != TEE_ERROR_SHORT_BUFFER) {
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        key_attr.data[i] = TEE_Malloc(key_attr.len[i], 0);
        if (!key_attr.data[i]) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        res = TEE_GetObjectBufferAttribute(keyPair, op_rsa_attr[i], key_attr.data[i], &(key_attr.len[i]));
        if(res != TEE_SUCCESS){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }
        bufLen += key_attr.len[i];
    }

    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(buff, &key_attr, bufHeadLen);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[0], key_attr.len[0]);
    TEE_Free(key_attr.data[0]);
    uint8_t *p = buff + bufHeadLen;
    for (size_t i = 1; i < RSA_ATTR_END; i++) {
        p += key_attr.len[i - 1];
        TEE_MemMove(p, key_attr.data[i], key_attr.len[i]);
        TEE_Free(key_attr.data[i]);
    }

    res = Store_WriteKey(keyID, keyIDLen, buff, bufLen);
    if(res != TEE_SUCCESS){
        EMSG("Store_WriteKey() fail. res = %x.\n", res);
    }

    TEE_Free(buff);
    return res;
}

static TEE_Result KeyStoreAes(KEY_PARAM keyParam, TEE_ObjectHandle key)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    size_t bufLen = 0;
    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;

    // IMSG("[bxq] KeyStoreAes 1");
    res = TEE_GetObjectInfo1(key, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    // IMSG("[bxq] KeyStoreAes 2");
    
    TEE_MemFill(&key_attr, 0, sizeof(key_attr));
    key_attr.params[KEY_SIZE] = keyInfo.objectSize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    // IMSG("[bxq] KeyStoreAes 3, objectSize = %d", key_attr.params[KEY_SIZE]);


    // IMSG("[bxq] KeyStoreAes 3.1.%d", AES_SECRET_VALUE);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, NULL, &(key_attr.len[AES_SECRET_VALUE]));
    if(res != TEE_ERROR_SHORT_BUFFER){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }

    // IMSG("[bxq] KeyStoreAes 3.2.%d,  key_attr.len[%d] = %d", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.len[AES_SECRET_VALUE]);
    key_attr.data[AES_SECRET_VALUE] = TEE_Malloc(key_attr.len[AES_SECRET_VALUE], 0);
    if (!key_attr.data[AES_SECRET_VALUE]) {
        EMSG("TEE_Malloc() fail.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
        return res;
    }

    // IMSG("[bxq] KeyStoreAes 3.3.%d, key_attr.data[%d] = 0x%02x", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE]);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE], &(key_attr.len[AES_SECRET_VALUE]));
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }
    bufLen += key_attr.len[AES_SECRET_VALUE];
    // IMSG("[bxq] KeyStoreAes 3.4.%d, key_attr.len[%d] = %d", AES_SECRET_VALUE, AES_SECRET_VALUE, key_attr.len[AES_SECRET_VALUE]);

    // IMSG_RAW("[bxq] key_attr.data[%d]: ", AES_SECRET_VALUE);
    for (size_t j = 0; j < key_attr.len[AES_SECRET_VALUE]; j++) {
        // IMSG_RAW("0x%02x ", *(key_attr.data[AES_SECRET_VALUE] + j));
    }
    // IMSG("end");

    bufLen += sizeof(keyParam.iv);

    // IMSG("[bxq] KeyStoreAes 4, bufHeadLen = %d", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // IMSG("[bxq] KeyStoreAes 5, bufLen = %d", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    // IMSG("[bxq] KeyStoreAes 6, key_attr.data[AES_SECRET_VALUE] = 0x%02x", key_attr.data[AES_SECRET_VALUE]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[AES_SECRET_VALUE], key_attr.len[AES_SECRET_VALUE]);
    // IMSG("[bxq] KeyStoreAes 7");
    TEE_Free(key_attr.data[AES_SECRET_VALUE]);
    // IMSG("[bxq] KeyStoreAes 8");
    TEE_MemMove(buff + bufHeadLen + key_attr.len[AES_SECRET_VALUE], keyParam.iv, sizeof(keyParam.iv));

    // IMSG_RAW("[bxq] bufLen = %d, aes_key_attr_value: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     // IMSG_RAW("0x%02x ", *(buff + j));
    // }
    // IMSG("KeyStoreAes 9, aes buff line end");

    return Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen);
}

static TEE_Result KeyStoreSm2Pke(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    size_t bufLen = 0;
    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;

    res = TEE_GetObjectInfo1(keyPair, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    
    key_attr.params[KEY_SIZE] = keyInfo.objectSize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    for (size_t i = 0; i < ECC_ATTR_END; i++) {
        res = TEE_GetObjectBufferAttribute(keyPair, op_sm2_attr[i], NULL, &(key_attr.len[i]));
        if(res != TEE_ERROR_SHORT_BUFFER){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        key_attr.data[i] = TEE_Malloc(key_attr.len[i], 0);
        if (!key_attr.data[i]) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        res = TEE_GetObjectBufferAttribute(keyPair, op_sm2_attr[i], key_attr.data[i], &(key_attr.len[i]));
        if(res != TEE_SUCCESS){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }
        bufLen += key_attr.len[i];
    }

    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    TEE_MemMove(buff, &key_attr, bufHeadLen);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[0], key_attr.len[0]);
    TEE_Free(key_attr.data[0]);
    uint8_t *p = buff + bufHeadLen;
    for (size_t i = 1; i < ECC_ATTR_END; i++) {
        p += key_attr.len[i - 1];
        TEE_MemMove(p, key_attr.data[i], key_attr.len[i]);
        TEE_Free(key_attr.data[i]);
    }

    res = Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen);
    if(res != TEE_SUCCESS){
        EMSG("Store_WriteKey() fail. res = %x.\n", res);
    }

    TEE_Free(buff);
    return res;
}

static TEE_Result KeyStoreSm2Dsa(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    return KeyStoreSm2Pke(keyParam, keyPair);
}

static TEE_Result KeyStoreSm4(KEY_PARAM keyParam, TEE_ObjectHandle key)
{
    TEE_Result res;
    TEE_ObjectInfo keyInfo;
    KEY_ATTR key_attr;
    size_t bufLen = 0;
    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;

    EMSG("[bxq] KeyStoreSm4 1");
    res = TEE_GetObjectInfo1(key, &keyInfo);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }
    EMSG("[bxq] KeyStoreSm4 2");
    
    TEE_MemFill(&key_attr, 0, sizeof(key_attr));
    key_attr.params[KEY_SIZE] = keyInfo.objectSize;
    key_attr.params[KEY_TYPE] = keyInfo.objectType;

    EMSG("[bxq] KeyStoreSm4 3, objectSize = %d", key_attr.params[KEY_SIZE]);


    EMSG("[bxq] KeyStoreSm4 3.1.%d", SM4_SECRET_VALUE);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, NULL, &(key_attr.len[SM4_SECRET_VALUE]));
    if(res != TEE_ERROR_SHORT_BUFFER){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }

    EMSG("[bxq] KeyStoreSm4 3.2.%d,  key_attr.len[%d] = %ld", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.len[SM4_SECRET_VALUE]);
    key_attr.data[SM4_SECRET_VALUE] = TEE_Malloc(key_attr.len[SM4_SECRET_VALUE], 0);
    if (!key_attr.data[SM4_SECRET_VALUE]) {
        EMSG("TEE_Malloc() fail.\n");
        return TEE_ERROR_OUT_OF_MEMORY;
        return res;
    }

    EMSG("[bxq] KeyStoreSm4 3.3.%d, key_attr.data[%d] = %p", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE]);
    res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE], &(key_attr.len[SM4_SECRET_VALUE]));
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        return res;
    }
    bufLen += key_attr.len[SM4_SECRET_VALUE];
    EMSG("[bxq] KeyStoreSm4 3.4.%d, key_attr.len[%d] = %ld", SM4_SECRET_VALUE, SM4_SECRET_VALUE, key_attr.len[SM4_SECRET_VALUE]);

    // IMSG_RAW("[bxq] key_attr.data[%d]: ", SM4_SECRET_VALUE);
    // for (size_t j = 0; j < key_attr.len[SM4_SECRET_VALUE]; j++) {
        // IMSG_RAW("0x%02x ", *(key_attr.data[SM4_SECRET_VALUE] + j));
    // 
    // IMSG("end");

    bufLen += sizeof(keyParam.iv);

    EMSG("[bxq] KeyStoreSm4 4, bufHeadLen = %ld", bufHeadLen);
    bufLen += bufHeadLen;
    uint8_t *buff = TEE_Malloc(bufLen, 0);
    if (!buff) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    EMSG("[bxq] KeyStoreSm4 5, bufLen = %ld", bufLen);
    TEE_MemMove(buff, &key_attr, bufHeadLen);
    EMSG("[bxq] KeyStoreSm4 6, key_attr.data[SM4_SECRET_VALUE] = %p", key_attr.data[SM4_SECRET_VALUE]);
    TEE_MemMove(buff + bufHeadLen, key_attr.data[SM4_SECRET_VALUE], key_attr.len[SM4_SECRET_VALUE]);
    EMSG("[bxq] KeyStoreSm4 7");
    TEE_Free(key_attr.data[SM4_SECRET_VALUE]);
    EMSG("[bxq] KeyStoreSm4 8");
    TEE_MemMove(buff + bufHeadLen + key_attr.len[SM4_SECRET_VALUE], keyParam.iv, sizeof(keyParam.iv));

    // IMSG_RAW("[bxq] bufLen = %d, aes_key_attr_value: ", bufLen);
    // for (size_t j = 0; j < bufLen; j++) {
    //     // IMSG_RAW("0x%02x ", *(buff + j));
    // }
    // IMSG("KeyStoreSm4 9, aes buff line end");

    return Store_WriteKey(keyParam.id, keyParam.idLen, buff, bufLen);
}


TEE_Result KeyStore(KEY_PARAM keyParam, TEE_ObjectHandle keyPair)
{
    TEE_Result res;
    TEE_ObjectInfo info;

    EMSG("KeyStore() 1");
    res = TEE_GetObjectInfo1(keyPair, &info);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_GetObjectInfo1() fail. res = %x.\n", res);
        return res;
    }

    EMSG("KeyStore() 2");
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

static TEE_Result KeyRestoreRsa(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    TEE_Attribute attrs[8];
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, key_attr.data[RSA_MODULUS], key_attr.len[RSA_MODULUS]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_attr.data[RSA_PUBLIC_EXPONENT], key_attr.len[RSA_PUBLIC_EXPONENT]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_attr.data[RSA_PRIVATE_EXPONENT], key_attr.len[RSA_PRIVATE_EXPONENT]);

    TEE_InitRefAttribute(&attrs[3], TEE_ATTR_RSA_PRIME1, key_attr.data[RSA_PRIME1], key_attr.len[RSA_PRIME1]);
    TEE_InitRefAttribute(&attrs[4], TEE_ATTR_RSA_PRIME2, key_attr.data[RSA_PRIME2], key_attr.len[RSA_PRIME2]);
    TEE_InitRefAttribute(&attrs[5], TEE_ATTR_RSA_EXPONENT1, key_attr.data[RSA_EXPONENT1], key_attr.len[RSA_EXPONENT1]);
    TEE_InitRefAttribute(&attrs[6], TEE_ATTR_RSA_EXPONENT2, key_attr.data[RSA_EXPONENT2], key_attr.len[RSA_EXPONENT2]);
    TEE_InitRefAttribute(&attrs[7], TEE_ATTR_RSA_COEFFICIENT, key_attr.data[RSA_COEFFICIENT], key_attr.len[RSA_COEFFICIENT]);

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    res = TEE_PopulateTransientObject(key, attrs, 8);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        return res;
    }

    *keyPair = key;

    return TEE_SUCCESS;
}

static TEE_Result KeyRestoreAes(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    // IMSG("[bxq] KeyRestoreAes 1");

    TEE_Result res;
    TEE_Attribute attrs;
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    // uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);
    key_attr.data[0] = keyData + bufHeadLen;

    // IMSG("[bxq] KeyRestoreAes 2");

    // IMSG("[bxq] KeyRestoreAes 3");
    TEE_InitRefAttribute(&attrs, TEE_ATTR_SECRET_VALUE, key_attr.data[AES_SECRET_VALUE], key_attr.len[AES_SECRET_VALUE]);

    // IMSG("[bxq] KeyRestoreAes 4, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    // IMSG("[bxq] KeyRestoreAes 5");
    res = TEE_PopulateTransientObject(key, &attrs, 1);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    // IMSG("[bxq] KeyRestoreAes 6");
    *keyPair = key;
    return TEE_SUCCESS;
}

static TEE_Result KeyRestoreSm2Pke(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    TEE_Attribute attrs[3];
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < ECC_ATTR_END - 1; i++) {
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_attr.data[ECC_PUBLIC_VALUE_X], key_attr.len[ECC_PUBLIC_VALUE_X]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_attr.data[ECC_PUBLIC_VALUE_Y], key_attr.len[ECC_PUBLIC_VALUE_Y]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_attr.data[ECC_PRIVATE_VALUE], key_attr.len[ECC_PRIVATE_VALUE]);

    res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    res = TEE_PopulateTransientObject(key, attrs, 3);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        return res;
    }

    *keyPair = key;
    return TEE_SUCCESS;
}

static TEE_Result KeyRestoreSm2Dsa(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    TEE_Attribute attrs[8];
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    key_attr.data[0] = p;
    for (size_t i = 0; i < ECC_ATTR_END - 1; i++) {
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
    }

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_attr.data[ECC_PUBLIC_VALUE_X], key_attr.len[ECC_PUBLIC_VALUE_X]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_attr.data[ECC_PUBLIC_VALUE_Y], key_attr.len[ECC_PUBLIC_VALUE_Y]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_attr.data[ECC_PRIVATE_VALUE], key_attr.len[ECC_PRIVATE_VALUE]);

    res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_KEYPAIR, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    res = TEE_PopulateTransientObject(key, attrs, ECC_ATTR_END);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        return res;
    }

    *keyPair = key;
    return res;
}

static TEE_Result KeyRestoreSm4(uint8_t *keyData, TEE_ObjectHandle *keyPair)
{
    EMSG("[bxq] KeyRestoreSm4 1");

    TEE_Result res;
    TEE_Attribute attrs;
    TEE_ObjectHandle key;
    KEY_ATTR key_attr;

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    // uint8_t *p = keyData + bufHeadLen;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);
    key_attr.data[0] = keyData + bufHeadLen;

    EMSG("[bxq] KeyRestoreSm4 2");

    EMSG("[bxq] KeyRestoreSm4 3");
    TEE_InitRefAttribute(&attrs, TEE_ATTR_SECRET_VALUE, key_attr.data[SM4_SECRET_VALUE], key_attr.len[SM4_SECRET_VALUE]);

    EMSG("[bxq] KeyRestoreSm4 4, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_SM4, key_attr.params[KEY_SIZE], &key);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    EMSG("[bxq] KeyRestoreSm4 5");
    res = TEE_PopulateTransientObject(key, &attrs, 1);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        return res;
    }

    EMSG("[bxq] KeyRestoreSm4 6");
    *keyPair = key;
    return TEE_SUCCESS;
}

TEE_Result KeyRestore(const uint8_t *keyID, size_t keyIDLen, TEE_ObjectHandle *keyPair)
{
    TEE_Result res;
    uint8_t *keyData;
    size_t keyDataLen;
    KEY_ATTR key_attr;

    EMSG("KeyRestore. 1");

    res = Store_ReadKey(keyID, keyIDLen, &keyData, &keyDataLen);
    if (res != TEE_SUCCESS) {
        EMSG("Store_ReadKey fail. res = %x.", res);
        return res;
    }

    EMSG("KeyRestore. 2");

    size_t bufHeadLen = sizeof(uint32_t) * CUS_PARAMS_END + sizeof(size_t) * RSA_ATTR_END;
    TEE_MemMove(&key_attr, keyData, bufHeadLen);

    EMSG("KeyRestore. 3");
    if (key_attr.params[KEY_TYPE] == TEE_TYPE_RSA_KEYPAIR) {
        res = KeyRestoreRsa(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_AES) {
        res = KeyRestoreAes(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM2_PKE_KEYPAIR) {
        res = KeyRestoreSm2Pke(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM2_DSA_KEYPAIR) {
        res = KeyRestoreSm2Dsa(keyData, keyPair);
    } else if (key_attr.params[KEY_TYPE] == TEE_TYPE_SM4) {
        res = KeyRestoreSm4(keyData, keyPair);
    } else {
        res = TEE_ERROR_BAD_PARAMETERS;
    }

    EMSG("KeyRestore. 4");
    TEE_Free(keyData);
    return res;
}