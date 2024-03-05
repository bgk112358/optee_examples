#ifndef __STORE_H__
#define __STORE_H__

#include <tee_internal_api.h>

TEE_Result Store_WriteKey(const uint8_t *keyID, uint32_t keyIDLen, const uint8_t *keyAttr, uint32_t keyAttrLen, int32_t *code);
TEE_Result Store_ReadKey(const uint8_t *keyID, uint32_t keyIDLen, uint8_t **keyData, uint32_t *keyDataLen, int32_t *code);


#endif /* __STORE_H__ */
