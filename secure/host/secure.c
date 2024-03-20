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
#include <sys/types.h>
#include <sys/stat.h>
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
    return 0;
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
    return 0;
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
    return 0;
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
    return 0;
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
    return 0;
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
    return 0;
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

    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
    if (!op.params[2].tmpref.buffer) {
        err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
    }

    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_ENC, &op, &eo);
    if (res) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_ENC)");
    }

    printf("[bxq] %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");
    write_file((uint8_t *)op.params[2].tmpref.buffer, op.params[2].tmpref.size);

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoRsaEnc end\n");
    return 0;
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

    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
    if (!op.params[2].tmpref.buffer) {
        err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
    }

    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_RSA_DEC, &op, &eo);
    if (res) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_RSA_DEC)");
    }

    printf("[bxq] dec_data %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");
    printf("[bxq] dec_data %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++)
        printf("%c", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    printf("\n");

    // free(op.params[2].tmpref.buffer);
    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    return 0;
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
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_AES_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_AES_ENC)");
    }

    printf("[bxq] 2 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);

    printf("[bxq] AES ENC %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoAesEnc end\n");
    return 0;
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
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_AES_DEC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_AES_ENC)");
    }
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);

    printf("[bxq] AES DEC %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoAesDec end\n");
    return 0;
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
    op.params[2].tmpref.buffer = malloc(inbuf.len + 128u);
    op.params[2].tmpref.size = inbuf.len + 128u;
    printf("[bxq] CryptoSm2PkeEnc 1, size = %d: ", op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_PKE_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_PKE_ENC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoSm2PkeEnc end\n");

    return 0;
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
    op.params[2].tmpref.buffer = malloc(inbuf.len + 128u);
    op.params[2].tmpref.size = inbuf.len + 128u;

    printf("[bxq] CryptoSm2PkeDec 1, inbufLen = %d, outsize = %d: ", inbuf.len, op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM2_PKE_DEC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM2_PKE_DEC)");
    }

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;

    printf("[bxq] %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");

    printf("CryptoSm2PkeDec end\n");

    return 0;
}

int32_t CryptoSm4Enc(uint8_t *id, uint32_t idLen, const BUFFER inbuf, BUFFER *outbuf)
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
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM4_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM4_ENC)");
    }

    printf("[bxq] 2 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);

    printf("[bxq] SM4 ENC %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoSm4Enc end\n");
    return 0;
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
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
    op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);

    uint32_t eo;
    res = TEEC_InvokeCommand(&teeHdl.sess, TA_CMD_CRYPTO_SM4_ENC, &op, &eo);
    if (res != TEEC_SUCCESS) {
        teec_err(res, eo, "TEEC_InvokeCommand(TA_CMD_CRYPTO_SM4_ENC)");
    }
    printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);

    printf("[bxq] SM4 DEC %s: ", id);
    for (uint32_t n = 0; n < op.params[2].tmpref.size; n++) {
        printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
    }
    printf("\n");

    outbuf->data = op.params[2].tmpref.buffer;
    outbuf->len = op.params[2].tmpref.size;
    
    printf("CryptoSm4Dec end\n");
    return 0;
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

    return 0;
}

main(int argc, char *argv[])
{
	void *inbuf;
	size_t inbuf_len;
    size_t key_size;
	get_args(argc, argv, &key_size, &inbuf, &inbuf_len);

    int32_t res = TeecInit();

    BUFFER in;
    BUFFER out;
    BUFFER ori;
    in.data = inbuf;
    in.len = inbuf_len;

    // const uint8_t rsa_key[] = "rsakey01";
    // res = KeyRsaGen(rsa_key, sizeof(rsa_key), key_size);
    // res = CryptoRsaEnc(rsa_key, sizeof(rsa_key), in, &out);
    // res = CryptoRsaDec(rsa_key, sizeof(rsa_key), out, &ori);
    // printf("[bxq] rsa ori: %s \n", ori.data);
    // free(out.data);
    // out.len = 0;
    // free(ori.data);
    // ori.len = 0;

    // const uint8_t aes_key[] = "aeskey01";
    // BUFFER iv;
    // iv.data = (uint8_t *)malloc(16);
    // if (iv.data == NULL) {
    //     printf("iv malloc err \n");
    // }
    // memset(iv.data, 0, 16);
    // iv.len = 16;

    // res = KeyAesGen(aes_key, sizeof(aes_key), key_size, iv);
    // res = CryptoAesEnc(aes_key, sizeof(aes_key), in, &out);
    // res = CryptoAesDec(aes_key, sizeof(aes_key), out, &ori);

    // printf("[bxq] aes ori: %s \n", ori.data);
    // free(out.data);
    // out.len = 0;
    // free(ori.data);
    // ori.len = 0;

    // const uint8_t sm2_pke_key[] = "sm2pkekey01";
    // const uint8_t sm2_dsa_key[] = "sm2dsakey01";
    // res = KeySm2PkeGen(sm2_pke_key, sizeof(sm2_pke_key), key_size);
    // // res = KeySm2DsaGen(sm2_dsa_key, sizeof(sm2_dsa_key), key_size);
    // res = CryptoSm2PkeEnc(sm2_pke_key, sizeof(sm2_pke_key), in, &out);
    // printf("[bxq] CryptoSm2PkeEnc outbuf, size = %d: ", out.len);
    // for (uint32_t n = 0; n < out.len; n++) {
    //     printf("%02x ", out.data[n]);
    // }
    // printf("\n");
    // res = CryptoSm2PkeDec(sm2_pke_key, sizeof(sm2_pke_key), out, &ori);
    // printf("[bxq] sm2 ori: %s \n", ori.data);


    const uint8_t sm4_key[] = "sm4key01";
    res = KeySm4Gen(sm4_key, sizeof(sm4_key), key_size);
    res = CryptoSm4Enc(sm4_key, sizeof(sm4_key), in, &out);
    printf("[bxq] CryptoSm4Enc outbuf, size = %d: ", out.len);
    for (uint32_t n = 0; n < out.len; n++) {
        printf("%02x ", out.data[n]);
    }
    printf("\n");
    res = CryptoSm4Dec(sm4_key, sizeof(sm4_key), out, &ori);
    printf("[bxq] sm2 ori: %s \n", ori.data);

}
