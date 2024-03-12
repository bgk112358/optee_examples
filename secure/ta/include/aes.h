#ifndef __AES_H__
#define __AES_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result AesEncode(TEE_ObjectHandle keyPair, uint32_t mode, BUFFER in, BUFFER *out);
TEE_Result AesDecode(TEE_ObjectHandle keyPair, uint32_t mode, BUFFER in, BUFFER *out);

#endif /* __AES_H__ */
