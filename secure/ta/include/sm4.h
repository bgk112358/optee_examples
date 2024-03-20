#ifndef __SM4_H__
#define __SM4_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result Sm4Encode(TEE_ObjectHandle key, uint32_t algorithm, BUFFER in, BUFFER *out);
TEE_Result Sm4Decode(TEE_ObjectHandle key, uint32_t algorithm, BUFFER in, BUFFER *out);

#endif /* __SM4_H__ */

