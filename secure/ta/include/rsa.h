#ifndef __RSA_H__
#define __RSA_H__

#include <tee_internal_api.h>

typedef struct buffer {
    uint8_t *data;
    uint32_t len;
} BUFFER;

TEE_Result RsaEncode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);
TEE_Result RsaDecode(TEE_ObjectHandle keyPair, BUFFER in, BUFFER *out);

#endif /* __RSA_H__ */
