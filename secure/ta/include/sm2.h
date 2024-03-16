#ifndef __SM2_H__
#define __SM2_H__

#include <tee_internal_api.h>
#include "common.h"


TEE_Result sm2_enc(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sm2_dec(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sm2_sign(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *signature, size_t *signatureLen);
TEE_Result sm2_verify(TEE_ObjectHandle key, const void *digest, uint32_t digestLen, void *signature, size_t *signatureLen);


#endif /* __SM2_H__ */

