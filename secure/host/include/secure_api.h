#ifndef __SECURE_API_H__
#define __SECURE_API_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define RSA2048_KEY1 1u
#define RSA2048_KEY2 2u
#define RSA2048_KEY3 3u
#define RSA2048_KEY4 4u


typedef struct _buffer {
    uint8_t *data;
    uint32_t len;
} BUFFER;

typedef enum {
    RSA_MODULUS             =   0,
    RSA_PUBLIC_EXPONENT     =   1,
    RSA_PRIVATE_EXPONENT    =   2,
    RSA_PRIME1              =   3,
    RSA_PRIME2              =   4,
    RSA_EXPONENT1           =   5,
    RSA_EXPONENT2           =   6,
    RSA_COEFFICIENT         =   7,
    RSA_ATTR_END            =   8
} RSA_KEY_ATTR_ENUM;

typedef struct _rsa_key_attr_value {
    uint8_t* attr[RSA_ATTR_END];
    uint32_t len[RSA_ATTR_END];
} RSA_KEY_ATTR_VALUE;

int32_t TeecInit();

int32_t KeyAesGen(uint8_t *id, uint32_t idLen, uint32_t keyLen, BUFFER iv);
int32_t KeyRsaGen(uint8_t *id, uint32_t idLen, uint32_t keyLen);
int32_t KeySm2PkeGen(uint8_t *id, uint32_t idLen, uint32_t keyLen);
int32_t KeySm2DsaGen(uint8_t *id, uint32_t idLen, uint32_t keyLen);
int32_t KeyBufferGetByID(const uint8_t *id, uint32_t idLen, void *buffer, uint32_t *size);

int32_t StoreWrite(uint8_t *name, uint32_t nameLen, void *buffer, uint32_t len);
int32_t StoreRead(uint8_t *name, uint32_t nameLen, void **buffer, uint32_t *size);

int32_t CryptoAesEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);
int32_t CryptoAesDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);

int32_t CryptoRsaEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);
int32_t CryptoRsaDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);
int32_t CryptoRsaSign(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER *signOut);
int32_t CryptoRsaVerify(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER signIn);

int32_t CryptoSm2PkeEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);
int32_t CryptoSm2PkeDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf);
int32_t CryptoSm2DsaSign(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER *signOut);
int32_t CryptoSm2DsaVerify(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER signIn);

int32_t CerCsrCreate(uint8_t *id, uint32_t idLen, void *DN, uint32_t *size);

#endif __SECURE_API_H__