#ifndef __STORE_H__
#define __STORE_H__

#include <tee_internal_api.h>

TEE_Result Store_WriteKey(const uint8_t *keyID, size_t keyIDLen, const uint8_t *keyAttr, size_t keyAttrLen);
TEE_Result Store_ReadKey(const uint8_t *keyID, size_t keyIDLen, uint8_t **keyData, size_t *keyDataLen);


#endif /* __STORE_H__ */
