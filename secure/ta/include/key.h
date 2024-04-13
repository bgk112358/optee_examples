#ifndef __KEY_H__
#define __KEY_H__

#include <tee_internal_api.h>

typedef struct _key_param {
    uint8_t *id;
    size_t idLen;
    size_t keySize;
    uint8_t iv[16];
} KEY_PARAM;

TEE_Result KeyGen(const uint32_t keyType, KEY_PARAM keyParam, TEE_ObjectHandle *keyPair);
TEE_Result KeyStore(KEY_PARAM keyParam, TEE_ObjectHandle keyPair);
TEE_Result KeyRestore(const uint8_t *keyID, size_t keyIDLen, TEE_ObjectHandle *keyPair);

#endif /* __KEY_H__ */
