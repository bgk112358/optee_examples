#ifndef __RSA_H__
#define __RSA_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result RsaEncode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);
TEE_Result RsaDecode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);

#endif /* __RSA_H__ */
