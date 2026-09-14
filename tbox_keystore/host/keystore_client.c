/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * CA client — command-line tool for TBox Keystore TA.
 *
 * Usage:
 *   tbox_keystore --init-pin <hex-pin>
 *   tbox_keystore --gen-rsa <label> [--size 2048] [--sign] [--decrypt]
 *   tbox_keystore --gen-aes <label> [--size 256] [--encrypt] [--decrypt]
 *   tbox_keystore --export-pub <label> [--out <file>]
 *   tbox_keystore --sign <label> --data <hex> [--out <file>]
 *   tbox_keystore --verify <label> --data <hex> --sig <hex>
 *   tbox_keystore --encrypt <label> --data <hex> [--out <file>]
 *   tbox_keystore --decrypt <label> --data <hex> [--out <file>]
 *   tbox_keystore --info <label>
 *   tbox_keystore --delete <label>
 *   tbox_keystore --lock
 *   tbox_keystore --list
 *
 * Compile:
 *   $(CROSS_COMPILE)gcc -o tbox_keystore keystore_client.c \
 *       -I../ta/include -I$(TEEC_EXPORT)/include \
 *       -L$(TEEC_EXPORT)/lib -lteec
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include "tbox_keystore_ta.h"

/* GP TEE / OP-TEE error code for "object already exists" */
#define TEEC_ERROR_ACCESS_CONFLICT  0xffff0003

/* ---- Hex utility ---- */

static int hex_decode(const char *hex, uint8_t **out, size_t *out_len)
{
	size_t len;
	size_t i;
	uint8_t *buf;

	if (!hex || !out || !out_len)
		return -1;

	len = strlen(hex);
	if (len % 2 != 0)
		return -1;

	*out_len = len / 2;
	buf = malloc(*out_len);
	if (!buf)
		return -1;

	for (i = 0; i < *out_len; i++) {
		unsigned int byte;
		if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
			free(buf);
			return -1;
		}
		buf[i] = (uint8_t)byte;
	}

	*out = buf;
	return 0;
}

static void hex_print(FILE *fp, const uint8_t *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		fprintf(fp, "%02x", data[i]);
	fprintf(fp, "\n");
}

static int read_file(const char *path, uint8_t **out, size_t *out_len)
{
	FILE *fp;
	long size;

	fp = fopen(path, "rb");
	if (!fp)
		return -1;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size <= 0) {
		fclose(fp);
		return -1;
	}

	*out = malloc((size_t)size);
	if (!*out) {
		fclose(fp);
		return -1;
	}

	*out_len = (size_t)fread(*out, 1, (size_t)size, fp);
	fclose(fp);
	return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *fp;

	fp = fopen(path, "wb");
	if (!fp)
		return -1;

	fwrite(data, 1, len, fp);
	fclose(fp);
	return 0;
}

/* ---- TA communication ---- */

static TEEC_Context g_ctx;
static TEEC_Session g_sess;
static int g_initialized = 0;

static void init_tee(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_TBOX_KEYSTORE_UUID;

	if (g_initialized)
		return;

	res = TEEC_InitializeContext(NULL, &g_ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed: 0x%x", res);

	res = TEEC_OpenSession(&g_ctx, &g_sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed: 0x%x", res);

	g_initialized = 1;
}

static void fini_tee(void)
{
	if (!g_initialized)
		return;
	TEEC_CloseSession(&g_sess);
	TEEC_FinalizeContext(&g_ctx);
	g_initialized = 0;
}

static TEEC_Result invoke_cmd(uint32_t cmd, TEEC_Operation *op)
{
	return TEEC_InvokeCommand(&g_sess, cmd, op, NULL);
}

/* ---- Command wrappers ---- */

static void do_init_pin(const char *pin_hex)
{
	TEEC_Operation op = { 0 };
	uint8_t *pin = NULL;
	size_t pin_len;
	TEEC_Result res;

	if (!pin_hex)
		errx(1, "--init-pin requires argument");

	if (hex_decode(pin_hex, &pin, &pin_len) != 0)
		errx(1, "Invalid hex PIN");

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pin;
	op.params[0].tmpref.size = pin_len;

	res = invoke_cmd(CMD_PIN_INIT, &op);
	free(pin);

	if (res != TEEC_SUCCESS)
		errx(1, "PIN_INIT failed: 0x%x", res);
	printf("PIN initialized.\n");
}

static void do_gen_rsa(const char *label, uint32_t size_bits,
		       int can_sign, int can_decrypt)
{
	TEEC_Operation op = { 0 };
	uint32_t perms = PERM_EXPORT_PUB | PERM_VERIFY;
	TEEC_Result res;

	if (can_sign)   perms |= PERM_SIGN;
	if (can_decrypt) perms |= PERM_DECRYPT;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].value.a = size_bits;
	op.params[1].value.b = perms;

	res = invoke_cmd(CMD_KEY_GEN_RSA, &op);
	if (res == TEEC_ERROR_ACCESS_CONFLICT)
		errx(1, "Key already exists: '%s'", label);
	if (res != TEEC_SUCCESS)
		errx(1, "KEY_GEN_RSA failed: 0x%x", res);
	printf("RSA-%u key generated: '%s' (perms=0x%x)\n",
	       size_bits, label, perms);
}

static void do_gen_aes(const char *label, uint32_t size_bits,
		       int can_encrypt, int can_decrypt)
{
	TEEC_Operation op = { 0 };
	uint32_t perms = 0;
	TEEC_Result res;

	if (can_encrypt) perms |= PERM_ENCRYPT;
	if (can_decrypt) perms |= PERM_DECRYPT;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_INPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].value.a = size_bits;
	op.params[1].value.b = perms;

	res = invoke_cmd(CMD_KEY_GEN_AES, &op);
	if (res == TEEC_ERROR_ACCESS_CONFLICT)
		errx(1, "Key already exists: '%s'", label);
	if (res != TEEC_SUCCESS)
		errx(1, "KEY_GEN_AES failed: 0x%x", res);
	printf("AES-%u key generated: '%s' (perms=0x%x)\n",
	       size_bits, label, perms);
}

static void do_export_pub(const char *label, const char *out_file)
{
	TEEC_Operation op = { 0 };
	uint8_t buf[4096];
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = sizeof(buf);

	res = invoke_cmd(CMD_KEY_EXPORT_PUB, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "KEY_EXPORT_PUB failed: 0x%x", res);

	if (out_file) {
		write_file(out_file, buf, op.params[1].tmpref.size);
		printf("Public key written to %s\n", out_file);
	} else {
		hex_print(stdout, buf, op.params[1].tmpref.size);
	}
}

static void do_sign(const char *label, const uint8_t *data, size_t data_len,
		    const char *out_file)
{
	TEEC_Operation op = { 0 };
	uint8_t sig[512];
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = data_len;
	op.params[2].tmpref.buffer = sig;
	op.params[2].tmpref.size = sizeof(sig);

	res = invoke_cmd(CMD_SIGN, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "SIGN failed: 0x%x", res);

	if (out_file) {
		write_file(out_file, sig, op.params[2].tmpref.size);
		printf("Signature written to %s\n", out_file);
	} else {
		hex_print(stdout, sig, op.params[2].tmpref.size);
	}
}

static void do_verify(const char *label,
		      const uint8_t *data, size_t data_len,
		      const uint8_t *sig, size_t sig_len)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_OUTPUT);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = data_len;
	op.params[2].tmpref.buffer = (void *)sig;
	op.params[2].tmpref.size = sig_len;

	res = invoke_cmd(CMD_VERIFY, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "VERIFY failed: 0x%x", res);

	if (op.params[3].value.a)
		printf("Signature VALID.\n");
	else
		printf("Signature INVALID.\n");
}

static void do_encrypt(const char *label,
		       const uint8_t *data, size_t data_len,
		       const char *out_file)
{
	TEEC_Operation op = { 0 };
	uint8_t *buf;
	TEEC_Result res;

	buf = malloc(data_len + 32);
	if (!buf)
		errx(1, "Out of memory");

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = data_len;
	op.params[2].tmpref.buffer = buf;
	op.params[2].tmpref.size = data_len + 32;

	res = invoke_cmd(CMD_ENCRYPT_AES, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "ENCRYPT_AES failed: 0x%x", res);

	if (out_file) {
		write_file(out_file, buf, op.params[2].tmpref.size);
		printf("Ciphertext written to %s\n", out_file);
	} else {
		hex_print(stdout, buf, op.params[2].tmpref.size);
	}

	free(buf);
}

static void do_decrypt(const char *label,
		       const uint8_t *data, size_t data_len,
		       const char *out_file)
{
	TEEC_Operation op = { 0 };
	uint8_t *buf;
	TEEC_Result res;

	buf = malloc(data_len);
	if (!buf)
		errx(1, "Out of memory");

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)data;
	op.params[1].tmpref.size = data_len;
	op.params[2].tmpref.buffer = buf;
	op.params[2].tmpref.size = data_len;

	res = invoke_cmd(CMD_DECRYPT_AES, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "DECRYPT_AES failed: 0x%x", res);

	if (out_file) {
		write_file(out_file, buf, op.params[2].tmpref.size);
		printf("Plaintext written to %s\n", out_file);
	} else {
		hex_print(stdout, buf, op.params[2].tmpref.size);
	}

	free(buf);
}

static void do_get_info(const char *label)
{
	TEEC_Operation op = { 0 };
	struct key_info info;
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = &info;
	op.params[1].tmpref.size = sizeof(info);

	res = invoke_cmd(CMD_GET_INFO, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "GET_INFO failed: 0x%x", res);

	printf("Key:       %s\n", info.label);
	printf("Type:      %s\n",
	       info.type == KEY_TYPE_RSA_KEYPAIR ? "RSA" :
	       info.type == KEY_TYPE_AES ? "AES" : "Unknown");
	printf("Size:      %u bits\n", info.size_bits);
	printf("Perms:     SIGN=%s VERIFY=%s ENCRYPT=%s DECRYPT=%s\n",
	       (info.permissions & PERM_SIGN) ? "Y" : "N",
	       (info.permissions & PERM_VERIFY) ? "Y" : "N",
	       (info.permissions & PERM_ENCRYPT) ? "Y" : "N",
	       (info.permissions & PERM_DECRYPT) ? "Y" : "N");
}

static void do_delete_key(const char *label)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);

	res = invoke_cmd(CMD_KEY_DELETE, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "KEY_DELETE failed: 0x%x", res);
	printf("Key '%s' deleted.\n", label);
}

static void do_lock(void)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = invoke_cmd(CMD_PROVISION_LOCK, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "PROVISION_LOCK failed: 0x%x", res);
	printf("TA locked. Write operations disabled.\n");
}

/* ---- Usage ---- */

static void usage(const char *prog)
{
	fprintf(stderr,
"Usage: %s <command> [options]\n"
"\n"
"Provisioning commands:\n"
"  --init-pin <hex>           Initialize PIN (once only)\n"
"  --lock                     Lock TA (disable write operations)\n"
"\n"
"Key generation:\n"
"  --gen-rsa <label>          Generate RSA key pair\n"
"       [--size 2048|4096]    Key size (default 2048)\n"
"       [--sign]              Enable signing permission\n"
"       [--decrypt]           Enable decryption permission\n"
"  --gen-aes <label>          Generate AES key\n"
"       [--size 128|256]      Key size (default 256)\n"
"       [--encrypt]           Enable encrypt permission\n"
"       [--decrypt]           Enable decrypt permission\n"
"\n"
"Crypto operations:\n"
"  --export-pub <label>       Export RSA public key\n"
"       [--out <file>]        Output file (default: stdout hex)\n"
"  --sign <label>             RSA sign\n"
"       --data <hex|@file>    Data to sign (hex string or @path)\n"
"       [--out <file>]        Output file (default: stdout hex)\n"
"  --verify <label>           RSA verify\n"
"       --data <hex|@file>    Original data\n"
"       --sig <hex|@file>     Signature to verify\n"
"  --encrypt <label>          AES encrypt\n"
"       --data <hex|@file>    Plaintext\n"
"       [--out <file>]        Output file\n"
"  --decrypt <label>          AES decrypt\n"
"       --data <hex|@file>    Ciphertext\n"
"       [--out <file>]        Output file\n"
"\n"
"Management:\n"
"  --info <label>             Show key info\n"
"  --delete <label>           Delete key\n"
"\n", prog);
	exit(1);
}

static void parse_data(const char *arg, uint8_t **data, size_t *data_len)
{
	if (arg[0] == '@') {
		if (read_file(arg + 1, data, data_len) != 0)
			errx(1, "Cannot read file: %s", arg + 1);
	} else {
		if (hex_decode(arg, data, data_len) != 0)
			errx(1, "Invalid hex data: %s", arg);
	}
}

/* ---- Main ---- */

int main(int argc, char **argv)
{
	const char *cmd = NULL;
	const char *label = NULL;
	const char *pin_hex = NULL;
	const char *data_arg = NULL;
	const char *sig_arg = NULL;
	const char *out_file = NULL;
	uint32_t size_bits = 0;
	int can_sign = 0;
	// int can_verify = 0;
	int can_encrypt = 0;
	int can_decrypt = 0;
	int i;

	if (argc < 2)
		usage(argv[0]);

	/* Parse command */
	cmd = argv[1];

	if (strcmp(cmd, "--init-pin") == 0 && argc > 2) {
		pin_hex = argv[2];
	} else if (strcmp(cmd, "--lock") == 0) {
		/* no extra args */
	} else if (strcmp(cmd, "--gen-rsa") == 0 ||
		   strcmp(cmd, "--gen-aes") == 0 ||
		   strcmp(cmd, "--export-pub") == 0 ||
		   strcmp(cmd, "--sign") == 0 ||
		   strcmp(cmd, "--verify") == 0 ||
		   strcmp(cmd, "--encrypt") == 0 ||
		   strcmp(cmd, "--decrypt") == 0 ||
		   strcmp(cmd, "--info") == 0 ||
		   strcmp(cmd, "--delete") == 0) {
		if (argc < 3)
			usage(argv[0]);
		label = argv[2];
	} else {
		usage(argv[0]);
	}

	/* Parse options */
	for (i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
			size_bits = (uint32_t)atoi(argv[++i]);
		} else if (strcmp(argv[i], "--sign") == 0) {
			can_sign = 1;
		} else if (strcmp(argv[i], "--verify") == 0) {
			// can_verify = 1;
		} else if (strcmp(argv[i], "--encrypt") == 0) {
			can_encrypt = 1;
		} else if (strcmp(argv[i], "--decrypt") == 0) {
			can_decrypt = 1;
		} else if (strcmp(argv[i], "--data") == 0 && i + 1 < argc) {
			data_arg = argv[++i];
		} else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
			sig_arg = argv[++i];
		} else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
			out_file = argv[++i];
		} else {
			errx(1, "Unknown option: %s", argv[i]);
		}
	}

	/* Defaults */
	if (size_bits == 0) {
		if (strcmp(cmd, "--gen-rsa") == 0)
			size_bits = 2048;
		else if (strcmp(cmd, "--gen-aes") == 0)
			size_bits = 256;
	}

	init_tee();

	/* Dispatch */
	if (strcmp(cmd, "--init-pin") == 0) {
		do_init_pin(pin_hex);
	} else if (strcmp(cmd, "--lock") == 0) {
		do_lock();
	} else if (strcmp(cmd, "--gen-rsa") == 0) {
		do_gen_rsa(label, size_bits, can_sign, can_decrypt);
	} else if (strcmp(cmd, "--gen-aes") == 0) {
		do_gen_aes(label, size_bits, can_encrypt, can_decrypt);
	} else if (strcmp(cmd, "--export-pub") == 0) {
		do_export_pub(label, out_file);
	} else if (strcmp(cmd, "--sign") == 0) {
		uint8_t *data = NULL;
		size_t data_len = 0;
		if (!data_arg) errx(1, "--sign requires --data");
		parse_data(data_arg, &data, &data_len);
		do_sign(label, data, data_len, out_file);
		free(data);
	} else if (strcmp(cmd, "--verify") == 0) {
		uint8_t *data = NULL, *sig = NULL;
		size_t data_len = 0, sig_len = 0;
		if (!data_arg) errx(1, "--verify requires --data");
		if (!sig_arg) errx(1, "--verify requires --sig");
		parse_data(data_arg, &data, &data_len);
		parse_data(sig_arg, &sig, &sig_len);
		do_verify(label, data, data_len, sig, sig_len);
		free(data); free(sig);
	} else if (strcmp(cmd, "--encrypt") == 0) {
		uint8_t *data = NULL;
		size_t data_len = 0;
		if (!data_arg) errx(1, "--encrypt requires --data");
		parse_data(data_arg, &data, &data_len);
		do_encrypt(label, data, data_len, out_file);
		free(data);
	} else if (strcmp(cmd, "--decrypt") == 0) {
		uint8_t *data = NULL;
		size_t data_len = 0;
		if (!data_arg) errx(1, "--decrypt requires --data");
		parse_data(data_arg, &data, &data_len);
		do_decrypt(label, data, data_len, out_file);
		free(data);
	} else if (strcmp(cmd, "--info") == 0) {
		do_get_info(label);
	} else if (strcmp(cmd, "--delete") == 0) {
		do_delete_key(label);
	} else {
		usage(argv[0]);
	}

	fini_tee();
	return 0;
}
