#ifndef __HASH_H__
#define __HASH_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result sha1(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sha224(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sha256(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sha384(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sha512(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result sm3(void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len);

#endif /* __HASH_H__ */