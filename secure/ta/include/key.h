#ifndef __KEY_H__
#define __KEY_H__

#include <tee_internal_api.h>

typedef struct _key_param {
    uint8_t *id;
    uint32_t idLen;
    uint32_t keySize;
    uint8_t iv[16];
} KEY_PARAM;

TEE_Result KeyGen(const uint32_t keyType, KEY_PARAM keyParam, TEE_ObjectHandle *keyPair);
TEE_Result KeyStore(KEY_PARAM keyParam, TEE_ObjectHandle keyPair);
TEE_Result KeyRestore(const uint8_t *keyID, uint32_t keyIDLen, TEE_ObjectHandle *keyPair);
TEE_Result KeyRestoreValue(const uint8_t *keyID, uint32_t keyIDLen, void *buffer, uint32_t *bufferLen);
TEE_Result KeyRestoreValueFree(void *buffer);

#endif /* __KEY_H__ */
