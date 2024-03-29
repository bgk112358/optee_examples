/*
 * Copyright (c) 2024-2024
 * All rights reserved.
 *
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <secure_api.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_ta.h>


typedef struct _tee_hdl {
    TEEC_Context ctx;
    TEEC_Session sess;
} TEE_HDL;

static TEE_HDL teeHdl;

static void usage(int argc, char *argv[])
{
	const char *pname = "acipher";

	if (argc)
		pname = argv[0];

	fprintf(stderr, "usage: %s <key_size> <string to encrypt>\n", pname);
	exit(1);
}

static void get_args(int argc, char *argv[], size_t *key_size, void **inbuf,
		     size_t *inbuf_len)
{
	char *ep;
	long ks;

	if (argc != 3) {
		warnx("Unexpected number of arguments %d (expected 2)",
		      argc - 1);
		usage(argc, argv);
	}

	ks = strtol(argv[1], &ep, 0);
	if (*ep) {
		warnx("cannot parse key_size \"%s\"", argv[1]);
		usage(argc, argv);
	}
	if (ks < 0 || ks == LONG_MAX) {
		warnx("bad key_size \"%s\" (%ld)", argv[1], ks);
		usage(argc, argv);
	}
	*key_size = ks;

	*inbuf = argv[2];
	*inbuf_len = strlen(argv[2]);
}

static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
{
	errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
}

void write_file(uint8_t *buf, int32_t len)
{
	int32_t fd;
	fd = open("/tmp/key.der", O_RDWR | O_CREAT, 0644);
	if (fd <= 0) {
		printf("open /tmp/key.der err\n");
	}
	int32_t res = write(fd, buf, len);
	if (res == len) {
		printf("write /tmp/key.der success\n");
	}

	close(fd);
}

int32_t read_file(uint8_t *buf, int32_t *len)
{
	int32_t fd;
	fd = open("/tmp/key.der", O_RDONLY);
	if (fd <= 0) {
		printf("open /tmp/key.der err\n");
	}

	int32_t nread = read(fd, buf, *len);
	if (nread > 0) {
		printf("read /tmp/key.der success\n");
	} else {
		printf("read /tmp/key.der err\n");
	}
	close(fd);
	return nread;
}

int32_t KeySm4Gen(uint8_t *id, uint32_t idLen, uint32_t keyLen)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].value.a = keyLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_SM4_GEN, &op, &eo);
    return res;
}

int32_t KeySm2PkeGen(uint8_t *id, uint32_t idLen, uint32_t keyLen)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].value.a = keyLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_SM2_PKE_GEN, &op, &eo);
    return res;
}

int32_t KeySm2DsaGen(uint8_t *id, uint32_t idLen, uint32_t keyLen)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].value.a = keyLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_SM2_DSA_GEN, &op, &eo);
    return res;
}

int32_t KeyAesGen(uint8_t *id, uint32_t idLen, uint32_t keyLen, BUFFER iv)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].value.a = keyLen;
    op.params[2].tmpref.buffer = iv.data;
    op.params[2].tmpref.size = iv.len;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_AES_GEN, &op, &eo);
    return res;
}

int32_t KeyRsaGen(uint8_t *id, uint32_t idLen, uint32_t keyLen)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].value.a = keyLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_RSA_GEN, &op, &eo);
    return res;
}

int32_t KeyBufferGetByID(const uint8_t *id, uint32_t idLen, void *buffer, uint32_t *size)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_KEY_BUFFER_GET, &op, &eo);
    return res;
}

int32_t CryptoRsaEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.buffer = NULL;
    op.params[2].tmpref.size = 0;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_ENC, &op, &eo);
    if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_ENC)");
    }

    // 外部free
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
    if (!op.params[2].tmpref.buffer) {
        teec_err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
    }

    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_ENC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoRsaDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.buffer = NULL;
    op.params[2].tmpref.size = 0;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_DEC, &op, &eo);
    if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_DEC)");
    }

    // 外部free
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
    if (!op.params[2].tmpref.buffer) {
        teec_err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
    }

    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_DEC, &op, &eo);
    if (res) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_DEC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoRsaSign(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER *signOut)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = digestIn.data;
    op.params[1].tmpref.size = digestIn.len;
    op.params[2].tmpref.buffer = NULL;
    op.params[2].tmpref.size = 0;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_SIGN, &op, &eo);
    if (res != TEEC_SUCCESS && res != TEEC_ERROR_SHORT_BUFFER) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_SIGN) 1 ");
    }

    // 外部free
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
    if (!op.params[2].tmpref.buffer) {
        teec_err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
    }

    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_SIGN, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_SIGN) 2 ");
    }

    signOut->data = op.params[2].tmpref.buffer;
    signOut->len = op.params[2].tmpref.size;
    return res;
}

int32_t CryptoRsaVerify(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER signIn)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = digestIn.data;
    op.params[1].tmpref.size = digestIn.len;
    op.params[2].tmpref.buffer = signIn.data;
    op.params[2].tmpref.size = signIn.len;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_VERIFY, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_VERIFY)");
    }
    return op.params[3].value.a;
}

int32_t CryptoAesEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    const uint32_t aesBlockSize = 16;   // Bytes -> 128bits
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.size = ((uint32_t)ceil(inbuf.len / aesBlockSize)) * aesBlockSize + aesBlockSize;
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_AES_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_AES_ENC)");
    }
    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoAesDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.size = inbuf.len;
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_AES_DEC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_AES_ENC)");
    }
    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoSm2PkeEnc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;

    // 外部free
    op.params[2].tmpref.buffer = malloc(inbuf.len + 128u);
    op.params[2].tmpref.size = inbuf.len + 128u;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_PKE_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_PKE_ENC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    // free(op.params[2].tmpref.buffer);
    return res;
}

int32_t CryptoSm2PkeDec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;

    // 外部free
    op.params[2].tmpref.buffer = malloc(inbuf.len + 128u);
    op.params[2].tmpref.size = inbuf.len + 128u;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_PKE_DEC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_PKE_DEC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoSm2DsaSign(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER *signOut)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = digestIn.data;
    op.params[1].tmpref.size = digestIn.len;

    // 外部free
    const uint32_t sm2SignatureLen = 64u;
    op.params[2].tmpref.buffer = malloc(sm2SignatureLen);
    op.params[2].tmpref.size = sm2SignatureLen;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_DSA_SIGN, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_DSA_SIGN)");
    }

    signOut->data = op.params[2].tmpref.buffer;
    signOut->len = op.params[2].tmpref.size;

    // free(op.params[2].tmpref.buffer);
    return res;
}

int32_t CryptoSm2DsaVerify(uint8_t *id, uint32_t idLen, const BUFFER digestIn, BUFFER signIn)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_VALUE_OUTPUT);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = digestIn.data;
    op.params[1].tmpref.size = digestIn.len;
    op.params[2].tmpref.buffer = signIn.data;
    op.params[2].tmpref.size = signIn.len;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_DSA_VERIFY, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_DSA_VERIFY)");
    }
    return op.params[3].value.a;
}

int32_t CryptoSm4Enc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    const uint32_t sm4BlockSize = 16;   // Bytes -> 128bits
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.size = ((uint32_t)ceil(inbuf.len / sm4BlockSize)) * sm4BlockSize + sm4BlockSize;
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM4_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM4_ENC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}

int32_t CryptoSm4Dec(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = id;
    op.params[0].tmpref.size = idLen;
    op.params[1].tmpref.buffer = inbuf.data;
    op.params[1].tmpref.size = inbuf.len;
    op.params[2].tmpref.size = inbuf.len;
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM4_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM4_ENC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    return res;
}


int32_t CryptoSm3Hash(void *inbuf, uint32_t inbuf_len, void **outbuf, size_t *outbuf_len)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = inbuf;
    op.params[0].tmpref.size = inbuf_len;
    op.params[1].tmpref.size = 32;
    op.params[1].tmpref.buffer = malloc(32);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM3, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM3)");
    }

    *outbuf = op.params[1].tmpref.buffer;
    *outbuf_len = op.params[1].tmpref.size;

    return res;
}

int32_t CryptoShaHash(void *inbuf, uint32_t inbuf_len, void **outbuf, size_t *outbuf_len)
{
    TEEC_Result res;
    TEEC_Operation op;
    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_VALUE_INPUT,
                                     TEEC_NONE);
    op.params[0].tmpref.buffer = inbuf;
    op.params[0].tmpref.size = inbuf_len;
    op.params[1].tmpref.size = 32;
    op.params[1].tmpref.buffer = malloc(32);
    op.params[2].value.a = 256;

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SHA, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SHA)");
    }

    *outbuf = op.params[1].tmpref.buffer;
    *outbuf_len = op.params[1].tmpref.size;

    return res;
}

int32_t TeecInit()
{
    TEEC_Result res;
    const TEEC_UUID uuid = TA_SECURE_UUID;

    res = TEEC_InitializeContext(NULL, &teeHdl.ctx);
    if (res) {
        errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);
    }

    uint32_t eo;
    res = TEEC_OpenSession(&teeHdl.ctx, &teeHdl.sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
    if (res) {
        teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");
    }

    return res;
}

#define LOOP_COUNT 10

main(int argc, char *argv[])
{
    void *inbuf;
    size_t inbuf_len;
    size_t key_size;

    // get_args(argc, argv, &key_size, &inbuf, &inbuf_len);

    int32_t res = TeecInit();

#if 1   // rsa2048 enc/dec
    BUFFER rsa2048EncIn;
    BUFFER rsa2048EncOut;
    BUFFER rsa2048EncOri;
    uint8_t rsa2048EncData[32 + 1] = "abcdefgh12345678hgfedcba87654321"; // < 245Bytes
    rsa2048EncIn.data = rsa2048EncData;
    rsa2048EncIn.len = 32;
    uint32_t rsa2048KeySize = 2048;
    const uint8_t rsa2048key[] = "rsa2048key";
    struct timeval rsa2048EncTv1, rsa2048EncTv2, rsa2048EncTv3;
    gettimeofday(&rsa2048EncTv1, NULL);
    res = KeyRsaGen(rsa2048key, sizeof(rsa2048key), rsa2048KeySize);
    gettimeofday(&rsa2048EncTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoRsaEnc(rsa2048key, sizeof(rsa2048key), rsa2048EncIn, &rsa2048EncOut);
        *(uint8_t *)(rsa2048EncIn.data) += 1u;
        res = CryptoRsaDec(rsa2048key, sizeof(rsa2048key), rsa2048EncOut, &rsa2048EncOri);
        printf("rsa ori, i = %d: %s \n", i, rsa2048EncOri.data);

        free(rsa2048EncOut.data);
        rsa2048EncOut.len = 0;
        free(rsa2048EncOri.data);
        rsa2048EncOri.len = 0;
    }
    gettimeofday(&rsa2048EncTv3, NULL);
    printf("rsa2048 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            rsa2048EncTv1.tv_sec, rsa2048EncTv1.tv_usec, rsa2048EncTv2.tv_sec, rsa2048EncTv2.tv_usec, rsa2048EncTv3.tv_sec, rsa2048EncTv3.tv_usec,
            rsa2048EncTv2.tv_sec - rsa2048EncTv1.tv_sec, rsa2048EncTv2.tv_usec - rsa2048EncTv1.tv_usec,
            rsa2048EncTv3.tv_sec - rsa2048EncTv2.tv_sec, rsa2048EncTv3.tv_usec - rsa2048EncTv2.tv_usec);
#endif

#if 1   // rsa2048 sign/verify
    BUFFER rsa2048DigestIn;
    BUFFER rsa2048SignOut;
    uint8_t rsa2048SignData[32 + 1] = "asdfghjkl12345678kjhgfdsa87654321"; // sha256
    rsa2048DigestIn.data = rsa2048SignData;
    rsa2048DigestIn.len = 32;
    rsa2048SignOut.data = (uint8_t *)malloc(32);
    rsa2048SignOut.len = 32;
    uint32_t rsa2048SignKeySize = 2048;
    const uint8_t rsa_sign_key[] = "rsaSignKey";
    struct timeval rsa2048SignTv1, rsa2048SignTv2, rsa2048SignTv3;
    gettimeofday(&rsa2048SignTv1, NULL);
    res = KeyRsaGen(rsa_sign_key, sizeof(rsa_sign_key), rsa2048SignKeySize);
    gettimeofday(&rsa2048SignTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoRsaSign(rsa_sign_key, sizeof(rsa_sign_key), rsa2048DigestIn, &rsa2048SignOut);
        if (i % 5 == 0) {
            ((uint8_t *)(rsa2048SignOut.data))[5] += 1u;
        }
        res = CryptoRsaVerify(rsa_sign_key, sizeof(rsa_sign_key), rsa2048DigestIn, rsa2048SignOut);
        if(res == 0) {
            printf("rsa verify pass, i = %d\n", i);
        } else {
            printf("rsa verify failed, i = %d\n", i);
        }
        *(uint8_t *)(rsa2048DigestIn.data) += 1u;
    }
    gettimeofday(&rsa2048SignTv3, NULL);
    printf("rsa2048 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            rsa2048SignTv1.tv_sec, rsa2048SignTv1.tv_usec, rsa2048SignTv2.tv_sec, rsa2048SignTv2.tv_usec, rsa2048SignTv3.tv_sec, rsa2048SignTv3.tv_usec,
            rsa2048SignTv2.tv_sec - rsa2048SignTv1.tv_sec, rsa2048SignTv2.tv_usec - rsa2048SignTv1.tv_usec,
            rsa2048SignTv3.tv_sec - rsa2048SignTv2.tv_sec, rsa2048SignTv3.tv_usec - rsa2048SignTv2.tv_usec);

    free(rsa2048SignOut.data);
    rsa2048SignOut.len = 0;
#endif

#if 1   // rsa3072 enc/dec
    BUFFER rsa3072EncIn;
    BUFFER rsa3072EncOut;
    BUFFER rsa3072EncOri;
    uint8_t rsa3072EncData[32 + 1] = "abcdefgh12345678hgfedcba87654321";
    rsa3072EncIn.data = rsa3072EncData;
    rsa3072EncIn.len = 32;
    uint32_t rsa3072keySize = 3072;
    const uint8_t rsa3072key[] = "rsa3072key";
    struct timeval rsa3072EncTv1, rsa3072EncTv2, rsa3072EncTv3;
    gettimeofday(&rsa3072EncTv1, NULL);
    res = KeyRsaGen(rsa3072key, sizeof(rsa3072key), rsa3072keySize);
    gettimeofday(&rsa3072EncTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoRsaEnc(rsa3072key, sizeof(rsa3072key), rsa3072EncIn, &rsa3072EncOut);
        *(uint8_t *)(rsa3072EncIn.data) += 1u;
        res = CryptoRsaDec(rsa3072key, sizeof(rsa3072key), rsa3072EncOut, &rsa3072EncOri);
        printf("rsa ori, i = %d: %s \n", i, rsa3072EncOri.data);

        free(rsa3072EncOut.data);
        rsa3072EncOut.len = 0;
        free(rsa3072EncOri.data);
        rsa3072EncOri.len = 0;
    }
    gettimeofday(&rsa3072EncTv3, NULL);
    printf("rsa3072 enc:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            rsa3072EncTv1.tv_sec, rsa3072EncTv1.tv_usec, rsa3072EncTv2.tv_sec, rsa3072EncTv2.tv_usec, rsa3072EncTv3.tv_sec, rsa3072EncTv3.tv_usec,
            rsa3072EncTv2.tv_sec - rsa3072EncTv1.tv_sec, rsa3072EncTv2.tv_usec - rsa3072EncTv1.tv_usec,
            rsa3072EncTv3.tv_sec - rsa3072EncTv2.tv_sec, rsa3072EncTv3.tv_usec - rsa3072EncTv2.tv_usec);
#endif

#if 1   // rsa3072 sign/verify
    BUFFER rsaDigestIn;
    BUFFER rsaSignOut;
    uint8_t rsa3072SignData[32 + 1] = "asdfghjkl12345678kjhgfdsa87654321"; // sha256
    rsaDigestIn.data = rsa3072SignData;
    rsaDigestIn.len = 32;
    rsaSignOut.data = (uint8_t *)malloc(32);
    rsaSignOut.len = 32;
    uint32_t rsaSignKeySize = 3072;
    const uint8_t rsa3072_sign_key[] = "rsaSignKey";
    struct timeval rsaSignTv1, rsaSignTv2, rsaSignTv3;
    gettimeofday(&rsaSignTv1, NULL);
    res = KeyRsaGen(rsa3072_sign_key, sizeof(rsa3072_sign_key), rsaSignKeySize);
    gettimeofday(&rsaSignTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoRsaSign(rsa3072_sign_key, sizeof(rsa3072_sign_key), rsaDigestIn, &rsaSignOut);
        if (i % 5 == 0) {
            ((uint8_t *)(rsaSignOut.data))[5] += 1u;
        }
        res = CryptoRsaVerify(rsa3072_sign_key, sizeof(rsa3072_sign_key), rsaDigestIn, rsaSignOut);
        if(res == 0) {
            printf("rsa verify pass, i = %d\n", i);
        } else {
            printf("rsa verify failed, i = %d\n", i);
        }
        *(uint8_t *)(rsaDigestIn.data) += 1u;
    }
    gettimeofday(&rsaSignTv3, NULL);
    printf("rsa3072 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            rsaSignTv1.tv_sec, rsaSignTv1.tv_usec, rsaSignTv2.tv_sec, rsaSignTv2.tv_usec, rsaSignTv3.tv_sec, rsaSignTv3.tv_usec,
            rsaSignTv2.tv_sec - rsaSignTv1.tv_sec, rsaSignTv2.tv_usec - rsaSignTv1.tv_usec,
            rsaSignTv3.tv_sec - rsaSignTv2.tv_sec, rsaSignTv3.tv_usec - rsaSignTv2.tv_usec);

    free(rsaSignOut.data);
    rsaSignOut.len = 0;
#endif

#if 1   // sm2 enc/dec
    BUFFER sm2In;
    BUFFER sm2Out;
    BUFFER sm2Ori;
    uint8_t sm2Data[32 + 1] = "abcdefgh12345678hgfedcba87654321";
    sm2In.data = sm2Data;
    sm2In.len = 32;
    uint32_t sm2pkekeySize = 256;
    const uint8_t sm2_pke_key[] = "sm2pkekey";
    struct timeval sm2Tv1, sm2Tv2, sm2Tv3;
    gettimeofday(&sm2Tv1, NULL);
    res = KeySm2PkeGen(sm2_pke_key, sizeof(sm2_pke_key), sm2pkekeySize);
    gettimeofday(&sm2Tv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoSm2PkeEnc(sm2_pke_key, sizeof(sm2_pke_key), sm2In, &sm2Out);
        *(uint8_t *)(sm2In.data) += 1u;
        res = CryptoSm2PkeDec(sm2_pke_key, sizeof(sm2_pke_key), sm2Out, &sm2Ori);
        printf("sm2 ori, i = %d: %s \n", i, sm2Ori.data);
        free(sm2Out.data);
        sm2Out.len = 0;
        free(sm2Ori.data);
        sm2Ori.len = 0;
    }
    gettimeofday(&sm2Tv3, NULL);
    printf("sm2 enc/dec:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n",
            sm2Tv1.tv_sec, sm2Tv1.tv_usec, sm2Tv2.tv_sec, sm2Tv2.tv_usec, sm2Tv3.tv_sec, sm2Tv3.tv_usec);
    printf("sm2 enc:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            sm2Tv1.tv_sec, sm2Tv1.tv_usec, sm2Tv2.tv_sec, sm2Tv2.tv_usec, sm2Tv3.tv_sec, sm2Tv3.tv_usec,
            sm2Tv2.tv_sec - sm2Tv1.tv_sec, sm2Tv2.tv_usec - sm2Tv1.tv_usec,
            sm2Tv3.tv_sec - sm2Tv2.tv_sec, sm2Tv3.tv_usec - sm2Tv2.tv_usec);
#endif

#if 1   // sm2 sign/verify
    BUFFER sm2DigestIn;
    BUFFER sm2SignOut;
    uint8_t sm2SignData[32 + 1] = "asdfghjkl12345678kjhgfdsa87654321";  // sm3
    sm2DigestIn.data = sm2SignData;
    sm2DigestIn.len = 32;
    sm2SignOut.data = (uint8_t *)malloc(32);
    sm2SignOut.len = 32;
    uint32_t sm2dsakeySize = 256;
    const uint8_t sm2_dsa_key[] = "sm2dsakey";
    struct timeval sm2SignTv1, sm2SignTv2, sm2SignTv3;
    gettimeofday(&sm2SignTv1, NULL);
    res = KeySm2DsaGen(sm2_dsa_key, sizeof(sm2_dsa_key), sm2dsakeySize);
    gettimeofday(&sm2SignTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoSm2DsaSign(sm2_dsa_key, sizeof(sm2_dsa_key), sm2DigestIn, &sm2SignOut);
        if (i % 5 == 0) {
            ((uint8_t *)(sm2SignOut.data))[5] += 1u;
        }
        res = CryptoSm2DsaVerify(sm2_dsa_key, sizeof(sm2_dsa_key), sm2DigestIn, sm2SignOut);
        if(res == 0) {
            printf("sm2 dsa verify pass, i = %d\n", i);
        } else {
            printf("sm2 dsa verify failed, i = %d\n", i);
        }
        *(uint8_t *)(sm2DigestIn.data) += 1u;
    }
    gettimeofday(&sm2SignTv3, NULL);
    printf("sm2 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            sm2SignTv1.tv_sec, sm2SignTv1.tv_usec, sm2SignTv2.tv_sec, sm2SignTv2.tv_usec, sm2SignTv3.tv_sec, sm2SignTv3.tv_usec,
            sm2SignTv2.tv_sec - sm2SignTv1.tv_sec, sm2SignTv2.tv_usec - sm2SignTv1.tv_usec,
            sm2SignTv3.tv_sec - sm2SignTv2.tv_sec, sm2SignTv3.tv_usec - sm2SignTv2.tv_usec);

    free(sm2SignOut.data);
    sm2SignOut.len = 0;
#endif

#if 1   // aes
    BUFFER aesIn;
    BUFFER aesOut;
    BUFFER aesOri;
    uint8_t aesData[16 + 1] = "abcdefgh12345678";
    aesIn.data = aesData;
    aesIn.len = 16;
    uint32_t aesKeySize = 128;
    const uint8_t aes_key[] = "aeskey01";
    BUFFER iv;
    iv.data = (uint8_t *)malloc(16);
    if (iv.data == NULL) {
        printf("iv malloc err \n");
    }
    memset(iv.data, 0, 16);
    iv.len = 16;

    struct timeval aesTv1, aesTv2, aesTv3;
    gettimeofday(&aesTv1, NULL);
    res = KeyAesGen(aes_key, sizeof(aes_key), aesKeySize, iv);
    gettimeofday(&aesTv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoAesEnc(aes_key, sizeof(aes_key), aesIn, &aesOut);
        res = CryptoAesDec(aes_key, sizeof(aes_key), aesOut, &aesOri);
        *(uint8_t *)(aesIn.data) += 1u;
        printf("aes i = %d: %s \n", i, aesOri.data);
        free(aesOut.data);
        aesOut.len = 0;
        free(aesOri.data);
        aesOri.len = 0;
    }
    gettimeofday(&aesTv3, NULL);
    printf("sm2 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
            aesTv1.tv_sec, aesTv1.tv_usec, aesTv2.tv_sec, aesTv2.tv_usec, aesTv3.tv_sec, aesTv3.tv_usec,
            aesTv2.tv_sec - aesTv1.tv_sec, aesTv2.tv_usec - aesTv1.tv_usec,
            aesTv3.tv_sec - aesTv2.tv_sec, aesTv3.tv_usec - aesTv2.tv_usec);

    free(iv.data);
#endif

#if 1   // sm4
    BUFFER sm4In;
    BUFFER sm4Out;
    BUFFER sm4Ori;
    uint8_t sm4Data[16 + 1] = "abcdefgh12345678";
    sm4In.data = sm4Data;
    sm4In.len = 16;
    uint32_t sm4KeySize = 128;
    const uint8_t sm4_key[] = "sm4key01";
    struct timeval sm4Tv1, sm4Tv2, sm4Tv3;
    gettimeofday(&sm4Tv1, NULL);
    res = KeySm4Gen(sm4_key, sizeof(sm4_key), sm4KeySize);
    gettimeofday(&sm4Tv2, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoSm4Enc(sm4_key, sizeof(sm4_key), sm4In, &sm4Out);
        res = CryptoSm4Dec(sm4_key, sizeof(sm4_key), sm4Out, &sm4Ori);
        *(uint8_t *)(sm4In.data) += 1u;
        printf("sm4 i = %d: %s \n", i, sm4Ori.data);
        free(sm4Out.data);
        sm4Out.len = 0;
        free(sm4Ori.data);
        sm4Ori.len = 0;
    }
    gettimeofday(&sm4Tv3, NULL);
    printf("sm2 signature:\n    start: %lds-%ldus \n    kygen: %lds-%ldus\n    en/de: %lds-%ldus\n    kygen:%ld.%lds\n    calti:%ld.%lds\n",
        sm4Tv1.tv_sec, sm4Tv1.tv_usec, sm4Tv2.tv_sec, sm4Tv2.tv_usec, sm4Tv3.tv_sec, sm4Tv3.tv_usec,
        sm4Tv2.tv_sec - sm4Tv1.tv_sec, sm4Tv2.tv_usec - sm4Tv1.tv_usec,
        sm4Tv3.tv_sec - sm4Tv2.tv_sec, sm4Tv3.tv_usec - sm4Tv2.tv_usec);
#endif

#if 1   // SM3 hash
    BUFFER sm3In;
    BUFFER sm3Out;

    uint8_t sm3Data[16 + 1] = "abcdefgh12345678";
    sm3In.data = sm3Data;
    sm3In.len = 16;

    struct timeval sm3Tv1, sm3Tv2;
    gettimeofday(&sm3Tv1, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoSm3Hash(sm3In.data, sm3In.len, &sm3Out.data, &sm3Out.len);
        free(sm3Out.data);
    }
    gettimeofday(&sm3Tv2, NULL);

    printf("sm2 hash hex got online: a650ee014b518dea4459360af17b38ab7cea5548d521c87397c11d2f87e9dac1");
    printf("sm2 hash:");
    for (size_t i = 0; i < sm3Out.len; i++) {
        printf(" 0x%02x", sm3Out.data[i]);
    }
    printf("\n");

    printf("sm3 hash:\n    start: %lds-%ldus \n    sm3--: %lds-%ldus\n    calti:%ld.%lds\n",
        sm3Tv1.tv_sec, sm3Tv1.tv_usec, sm3Tv2.tv_sec, sm3Tv2.tv_usec,
        sm3Tv2.tv_sec - sm3Tv1.tv_sec, sm3Tv2.tv_usec - sm3Tv1.tv_usec);
#endif

#if 1   // SHA hash
    BUFFER shaIn;
    BUFFER shaOut;

    uint8_t shaData[16 + 1] = "abcdefgh12345678";
    shaIn.data = shaData;
    shaIn.len = 16;

    struct timeval shaTv1, shaTv2;
    gettimeofday(&shaTv1, NULL);
    for (size_t i = 0; i < LOOP_COUNT; i++) {
        res = CryptoShaHash(shaIn.data, shaIn.len, &shaOut.data, &shaOut.len);
        free(shaOut.data);
    }
    gettimeofday(&shaTv2, NULL);

    printf("sha256 hash hex get online: 25f94a2a5c7fbaf499c665bc73d67c1c87e496da8985131633ee0a95819db2e8");
    printf("sha256 hash:");
    for (size_t i = 0; i < shaOut.len; i++) {
        printf(" 0x%02x", shaOut.data[i]);
    }
    printf("\n");

    printf("sha hash:\n    start: %lds-%ldus \n    sha256 %lds-%ldus\n    calti:%ld.%lds\n",
        shaTv1.tv_sec, shaTv1.tv_usec, shaTv2.tv_sec, shaTv2.tv_usec,
        shaTv2.tv_sec - shaTv1.tv_sec, shaTv2.tv_usec - shaTv1.tv_usec);
#endif

}