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

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SECURE_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	7000

int libmain(void)
{
	struct test_ctx ctx;
	char obj1_id[] = "object#1";		/* string identification for the object */
	char obj2_id[] = "object#2";		/* string identification for the object */
	char obj1_data[TEST_OBJECT_SIZE];
	char read_data[TEST_OBJECT_SIZE];
	TEEC_Result res;

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	/*
	 * Create object, read it, delete it.
	 */
	printf("\nTest on object \"%s\"\n", obj1_id);

	printf("- Create and load object in the TA secure storage\n");

	memset(obj1_data, 0xA1, sizeof(obj1_data));

	res = write_secure_object(&ctx, obj1_id,
				  obj1_data, sizeof(obj1_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to create an object in the secure storage");

	printf("- Read back the object\n");

	res = read_secure_object(&ctx, obj1_id,
				 read_data, sizeof(read_data));
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to read an object from the secure storage");
	if (memcmp(obj1_data, read_data, sizeof(obj1_data)))
		errx(1, "Unexpected content found in secure storage");

	printf("- Delete the object\n");

	res = delete_secure_object(&ctx, obj1_id);
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to delete the object: 0x%x", res);

	/*
	 * Non volatile storage: create object2 if not found, delete it if found
	 */
	printf("\nTest on object \"%s\"\n", obj2_id);

	res = read_secure_object(&ctx, obj2_id,
				  read_data, sizeof(read_data));
	if (res != TEEC_SUCCESS && res != TEEC_ERROR_ITEM_NOT_FOUND)
		errx(1, "Unexpected status when reading an object : 0x%x", res);

	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		char data[] = "This is data stored in the secure storage.\n";

		printf("- Object not found in TA secure storage, create it.\n");

		res = write_secure_object(&ctx, obj2_id,
					  data, sizeof(data));
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to create/load an object");

	} else if (res == TEEC_SUCCESS) {
		printf("- Object found in TA secure storage, delete it.\n");

		res = delete_secure_object(&ctx, obj2_id);
		if (res != TEEC_SUCCESS)
			errx(1, "Failed to delete an object");
	}

	printf("\nWe're done, close and release TEE resources\n");
	terminate_tee_session(&ctx);
	return 0;
}

int32_t rsa_keygen(uint32_t key_slot, int32_t key_size)
{

	return  0;
}

































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

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_INPUT,
									 TEEC_MEMREF_TEMP_OUTPUT,
									 TEEC_NONE);
	op.params[0].tmpref.buffer = key_slot;
	op.params[0].tmpref.size = sizeof(key_slot);
	op.params[1].tmpref.buffer = inbuf;
	op.params[1].tmpref.size = inbuf_len;
	printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_ENC, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");

	printf("[bxq] 1 op.params[2].tmpref.size = %d \n" , op.params[2].tmpref.size);
	op.params[2].tmpref.buffer = malloc(op.params[2].tmpref.size);
	if (!op.params[2].tmpref.buffer) {
		err(1, "Cannot allocate out buffer of size %zu", op.params[2].tmpref.size);
	}

	res = TEEC_InvokeCommand(&sess, TA_SECURE_CMD_RSA_ENC, &op, &eo);
	if (res) {
		teec_err(res, eo, "TEEC_InvokeCommand(TA_SECURE_CMD_RSA_ENC)");
	}

	printf("[bxq] %s: ", key_slot);
	for (n = 0; n < op.params[2].tmpref.size; n++)
		printf("%02x ", ((uint8_t *)op.params[2].tmpref.buffer)[n]);
	printf("\n");
	write_file((uint8_t *)op.params[2].tmpref.buffer, op.params[2].tmpref.size);

	free(op.params[2].tmpref.buffer);
	return 0;
}
