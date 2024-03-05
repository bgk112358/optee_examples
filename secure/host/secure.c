/*
 * Copyright (c) 2024-2024
 * All rights reserved.
 *
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* TA API: UUID and command IDs */
#include <secure_ta.h>


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





int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t eo;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	size_t key_size;
	uint8_t key_slot[] = "KEY#RSA2048#01";
	void *inbuf;
	size_t inbuf_len;
	size_t n;
	const TEEC_UUID uuid = TA_SECURE_UUID;

	get_args(argc, argv, &key_size, &inbuf, &inbuf_len);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_VALUE_INPUT,
									 TEEC_NONE,
									 TEEC_NONE);
	op.params[0].tmpref.buffer = key_slot;
	op.params[0].tmpref.size = sizeof(key_slot);
	op.params[1].value.a = key_size;
	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_GEN_KEY, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_GEN_KEY)");

// 	memset(&op, 0, sizeof(op));
// 	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
// 									 TEEC_MEMREF_TEMP_INPUT,
// 									 TEEC_MEMREF_TEMP_OUTPUT,
// 									 TEEC_NONE);
// 	op.params[0].tmpref.buffer = key_slot;
// 	op.params[0].tmpref.size = sizeof(key_slot);
// 	op.params[1].tmpref.buffer = inbuf;
// 	op.params[1].tmpref.size = inbuf_len;

// #if 1	// RSA

// 	printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
// 	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_ENC, &op, &eo);
// 	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
// 		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");

// 	printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
// 	op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
// 	if (!op.params[2].tmpref.buffer) {
// 		err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
// 	}

// 	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_ENC, &op, &eo);
// 	if (res) {
// 		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");
// 	}

// 	printf("[bxq] %s: ", key_slot);
// 	for (n = 0; n < op.params[2].tmpref.size; n++)
// 		printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
// 	printf("\n");
// 	write_file((uint8_t *)op.params[2].tmpref.buffer, op.params[2].tmpref.size);
// 	free(op.params[2].tmpref.buffer);
// 	op.params[2].tmpref.size = 0;

// 	// dec
// 	uint8_t enc_data[3072];
// 	int32_t enc_len = 3072;
// 	enc_len = read_file(enc_data, &enc_len);

// 	op.params[0].tmpref.buffer = key_slot;
// 	op.params[0].tmpref.size = sizeof(key_slot);
// 	op.params[1].tmpref.buffer = enc_data;
// 	op.params[1].tmpref.size = enc_len;

// 	printf("[bxq] read enc_data, enc_len = %d: ", enc_len);
// 	for (n = 0; n < op.params[1].tmpref.size; n++)
// 		printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
// 	printf("\n");

// 	printf("[bxq] 2 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
// 	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_DEC, &op, &eo);
// 	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
// 		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");

// 	printf("[bxq] 2 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
// 	op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
// 	if (!op.params[2].tmpref.buffer) {
// 		err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
// 	}

// 	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_DEC, &op, &eo);
// 	if (res) {
// 		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");
// 	}

// 	printf("[bxq] dec_data %s: ", key_slot);
// 	for (n = 0; n < op.params[2].tmpref.size; n++)
// 		printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
// 	printf("\n");
// 	printf("[bxq] dec_data %s: ", key_slot);
// 	for (n = 0; n < op.params[2].tmpref.size; n++)
// 		printf("%c", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
// 	printf("\n");

// 	free(op.params[2].tmpref.buffer);
// 	return 0;
// #else	// AES


// #endif
}
