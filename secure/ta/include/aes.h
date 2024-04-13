#ifndef __AES_H__
#define __AES_H__

#include <tee_internal_api.h>
#include "common.h"

TEE_Result AesEncode(TEE_ObjectHandle keyPair, uint32_t mode, BUFFER in, BUFFER *out);
TEE_Result AesDecode(TEE_ObjectHandle keyPair, uint32_t mode, BUFFER in, BUFFER *out);

TEE_Result AES_ENCRYPT_ECB_128(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_ENCRYPT_ECB_192(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_ENCRYPT_ECB_256(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_128(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_192(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_ECB_256(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_128(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_192(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_ENCRYPT_CBC_256(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_128(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_192(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);
TEE_Result AES_DECRYPT_CBC_256(TEE_ObjectHandle aes_key, void *inbuf, size_t inbuf_len, void *outbuf, size_t *outbuf_len);

#endif /* __AES_H__ */
