#ifndef __RSA_H__
#define __RSA_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result RsaEncode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);
TEE_Result RsaDecode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);

TEE_Result rsa_enc(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result rsa_dec(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result rsa_sign(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *signature, size_t *signatureLen);
TEE_Result rsa_verify(TEE_ObjectHandle key, const void *digest, uint32_t digestLen, void *signature, size_t *signatureLen);

#endif /* __RSA_H__ */
