#ifndef __KEY_H__
#define __KEY_H__

#include <tee_internal_api.h>

TEE_Result Key_Gen(const uint32_t keyType, uint32_t keySize, TEE_ObjectHandle *keyPair);
TEE_Result Key_Store(const uint8_t *keyID, uint32_t keyIDLen, TEE_ObjectHandle keyPair);
TEE_Result Key_Restore(const uint8_t *keyID, uint32_t keyIDLen, TEE_ObjectHandle *keyPair);

#endif /* __KEY_H__ */
