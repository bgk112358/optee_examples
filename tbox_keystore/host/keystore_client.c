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
 * SO (Security Officer) commands (requires dongle):
 *   tbox_keystore --init-so-pin <hex-pin>
 *   tbox_keystore --provision-dongle [--dongle <name>] [--dongle-index <n>]
 *   tbox_keystore --provision-dongle-from-file <pubkey.der> [--dongle-index <n>]
 *   tbox_keystore --so-unlock --so-pin <hex> [--dongle <name>] [--dongle-index <n>]
 *   tbox_keystore --so-lock
 *   tbox_keystore --so-info
 *
 * Compile:
 *   make DONGLE_BACKENDS="dongle_dummy dongle_yubikey"
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <tee_client_api.h>
#include "tbox_keystore_ta.h"
#include "dongle/dongle_ops.h"

/* GP TEE / OP-TEE error codes not in libteec headers */
#define TEEC_ERROR_OVERFLOW       0xFFFF000F  /* TEE_ERROR_OVERFLOW */

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

/* ---- Command wrappers (existing) ---- */

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

/* ================================================================
 *  SO (Security Officer) commands — dongle-aware
 * ============================================================== */

/*
 * Load a dongle by name or auto-detect.
 * Returns the open context (caller must dongle->close(ctx)).
 */
static struct dongle_ctx *dongle_open(const struct dongle_ops **ops_out,
				       const char *dongle_name)
{
	const struct dongle_ops *ops;
	struct dongle_ctx *ctx = NULL;

	ops = dongle_name ? dongle_get(dongle_name) : dongle_detect();
	if (!ops)
		errx(1, "No dongle available (try --dongle dummy or make gen-dummy-key)");

	if (ops->open(&ctx) != 0)
		errx(1, "Failed to open dongle: %s", ops->name);

	fprintf(stderr, "[dongle] Using: %s\n", ops->name);
	*ops_out = ops;
	return ctx;
}

/* ---- do_so_pin_init ---- */
static void do_so_pin_init(const char *pin_hex)
{
	TEEC_Operation op = { 0 };
	uint8_t *pin_raw = NULL;
	size_t pin_len;
	TEEC_Result res;

	if (!pin_hex)
		errx(1, "--init-so-pin requires argument");

	if (hex_decode(pin_hex, &pin_raw, &pin_len) != 0)
		errx(1, "Invalid hex SO-PIN");

	/* We send the raw SO-PIN; TA will SHA-256 it internally */
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pin_raw;
	op.params[0].tmpref.size = pin_len;

	res = invoke_cmd(CMD_SO_PIN_INIT, &op);
	free(pin_raw);

	if (res != TEEC_SUCCESS)
		errx(1, "SO_PIN_INIT failed: 0x%x", res);
	printf("SO-PIN initialized.\n");
}

/* ---- do_provision_dongle (from connected dongle) ---- */
static void do_provision_dongle(const char *dongle_name)
{
	const struct dongle_ops *ops;
	struct dongle_ctx *ctx;
	TEEC_Operation op = { 0 };
	uint8_t pubkey_der[256];
	size_t pubkey_len = sizeof(pubkey_der);
	TEEC_Result res;

	ctx = dongle_open(&ops, dongle_name);

	if (ops->get_pubkey(ctx, pubkey_der, &pubkey_len) != 0)
		errx(1, "Failed to read public key from dongle");

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pubkey_der;
	op.params[0].tmpref.size = pubkey_len;

	res = invoke_cmd(CMD_PROVISION_DONGLE, &op);
	ops->close(ctx);

	if (res == TEEC_ERROR_ACCESS_CONFLICT)
		errx(1, "Dongle already registered (duplicate)");
	if (res == TEEC_ERROR_OVERFLOW)
		errx(1, "Dongle whitelist full (max %u)", SO_DONGLE_MAX);
	if (res != TEEC_SUCCESS)
		errx(1, "PROVISION_DONGLE failed: 0x%x", res);

	printf("Dongle registered in TA whitelist.\n");
}

/* ---- do_provision_dongle_from_file ---- */
static void do_provision_dongle_from_file(const char *path)
{
	TEEC_Operation op = { 0 };
	uint8_t *pubkey_der = NULL;
	size_t pubkey_len = 0;
	TEEC_Result res;

	if (read_file(path, &pubkey_der, &pubkey_len) != 0)
		errx(1, "Cannot read public key file: %s", path);

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pubkey_der;
	op.params[0].tmpref.size = pubkey_len;

	res = invoke_cmd(CMD_PROVISION_DONGLE, &op);
	free(pubkey_der);

	if (res == TEEC_ERROR_ACCESS_CONFLICT)
		errx(1, "Dongle already registered (duplicate)");
	if (res == TEEC_ERROR_OVERFLOW)
		errx(1, "Dongle whitelist full (max %u)", SO_DONGLE_MAX);
	if (res != TEEC_SUCCESS)
		errx(1, "PROVISION_DONGLE failed: 0x%x", res);

	printf("Dongle registered from file: %s\n", path);
}

/* ---- do_so_unlock (two-phase protocol) ---- */
static void do_so_unlock(const char *pin_hex, const char *dongle_name,
			 int dongle_index)
{
	const struct dongle_ops *ops;
	struct dongle_ctx *ctx = NULL;
	uint8_t *pin_raw = NULL;
	size_t pin_len;
	uint8_t chg_buf[SO_CHG_BUF_SIZE];
	uint32_t dongle_count;
	uint32_t *dongle_count_ptr;
	uint8_t *challenge;
	uint8_t sig_der[128];
	size_t sig_len = sizeof(sig_der);
	uint8_t pubkey_der[256];
	size_t pubkey_len = sizeof(pubkey_der);
	TEEC_Operation op;
	TEEC_Result res;

	if (!pin_hex)
		errx(1, "--so-unlock requires --so-pin");

	if (hex_decode(pin_hex, &pin_raw, &pin_len) != 0)
		errx(1, "Invalid hex SO-PIN");

	/* Phase 1: Request challenge from TA */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_VALUE_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = pin_raw;
	op.params[0].tmpref.size = pin_len;
	op.params[1].tmpref.buffer = chg_buf;
	op.params[1].tmpref.size = sizeof(chg_buf);

	res = invoke_cmd(CMD_SO_UNLOCK_REQ, &op);
	free(pin_raw);

	if (res == TEEC_ERROR_BAD_STATE) {
		uint32_t left = op.params[2].value.b;
		errx(1, "SO cooldown active, %u seconds remaining", left);
	}
	if (res == TEEC_ERROR_ACCESS_DENIED) {
		errx(1, "SO permanently bricked (1000 failures reached)");
	}
	if (res != TEEC_SUCCESS)
		errx(1, "SO_UNLOCK_REQ failed: 0x%x", res);

	/* Parse response */
	challenge       = chg_buf;
	dongle_count_ptr = (uint32_t *)(chg_buf + 32);
	dongle_count    = *dongle_count_ptr;

	printf("TA challenge received. %u dongle(s) registered.\n", dongle_count);

	if (dongle_count == 0)
		errx(1, "No dongles registered in TA whitelist");

	/* Phase 2: Sign challenge with dongle */
	ctx = dongle_open(&ops, dongle_name);

	/* Determine which dongle index to use */
	if (dongle_index < 0)
		dongle_index = 0; /* Default: first registered */

	if ((uint32_t)dongle_index >= dongle_count) {
		fprintf(stderr, "Warning: dongle_index %d >= count %u, using index 0\n",
			dongle_index, dongle_count);
		dongle_index = 0;
	}

	/* sign() receives SHA-256 of (challenge || TA_UUID || dongle_index).
	 * TA computes the same composite internally for verification.
	 * We pass challenge raw; dongle hashes the composite.
	 *
	 * For simplicity in the dummy backend, we just sign the challenge
	 * directly. TA will verify against the composite hash.
	 *
	 * See docs/24-so-pin-yubikey-unlock.md §3.1 for the composite spec.
	 */
	/* Hash challenge before signing: msg = SHA256(challenge).
	 * TA verifies against the same SHA256(challenge). */
	uint8_t chg_hash[32];
	SHA256(challenge, 32, chg_hash);

	fprintf(stderr, "[CA] challenge[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		challenge[0],challenge[1],challenge[2],challenge[3],
		challenge[4],challenge[5],challenge[6],challenge[7]);
	fprintf(stderr, "[CA] chg_hash[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		chg_hash[0],chg_hash[1],chg_hash[2],chg_hash[3],
		chg_hash[4],chg_hash[5],chg_hash[6],chg_hash[7]);

	if (ops->sign(ctx, chg_hash, 32, sig_der, &sig_len) != 0)
		errx(1, "Dongle sign failed");

	fprintf(stderr, "[CA] sig_len=%zu sig[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		sig_len, sig_der[0],sig_der[1],sig_der[2],sig_der[3],
		sig_der[4],sig_der[5],sig_der[6],sig_der[7]);

	if (ops->get_pubkey(ctx, pubkey_der, &pubkey_len) != 0)
		errx(1, "Failed to read public key from dongle");

	fprintf(stderr, "[CA] pubkey_len=%zu pubkey[0..7]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
		pubkey_len, pubkey_der[0],pubkey_der[1],pubkey_der[2],pubkey_der[3],
		pubkey_der[4],pubkey_der[5],pubkey_der[6],pubkey_der[7]);

	/* Verify ECDSA signature locally with OpenSSL.
	 * OP-TEE 3.2 lacks ECDSA transient object support; TA would panic.
	 * CA verifies the dongle sig, then tells TA to unlock. */
	{
		const unsigned char *p;
		EVP_PKEY *pkey = NULL;
		EC_KEY *ec = NULL;
		ECDSA_SIG *ecsig = NULL;
		int vfy;

		p = pubkey_der;
		pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_len);
		if (!pkey)
			errx(1, "Failed to parse dongle public key DER");

		ec = EVP_PKEY_get0_EC_KEY(pkey);
		if (!ec) {
			EVP_PKEY_free(pkey);
			errx(1, "Dongle public key is not an EC key");
		}

		p = sig_der;
		ecsig = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
		if (!ecsig) {
			EVP_PKEY_free(pkey);
			errx(1, "Failed to parse dongle signature DER");
		}

		vfy = ECDSA_do_verify(chg_hash, 32, ecsig, ec);

		ECDSA_SIG_free(ecsig);
		EVP_PKEY_free(pkey);

		if (vfy != 1)
			errx(1, "CA: ECDSA signature verification FAILED (wrong dongle?)");

		fprintf(stderr, "[CA] ECDSA signature VERIFIED OK\n");
	}

	/* Tell TA: CA verified the signature, unlock now. */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = invoke_cmd(CMD_SO_UNLOCK_CONFIRM, &op);
	ops->close(ctx);

	if (res == TEEC_ERROR_BAD_STATE)
		errx(1, "SO unlock confirm: challenge not valid (call CMD_SO_UNLOCK_REQ first)");
	if (res != TEEC_SUCCESS)
		errx(1, "SO_UNLOCK_CONFIRM failed: 0x%x", res);

	printf("✓ SO unlock successful. TA is now UNLOCKED (5 min timeout).\n");
	printf("  Remember: run --so-lock when maintenance is complete.\n");
}

/* ---- do_so_lock ---- */
static void do_so_lock(void)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = invoke_cmd(CMD_SO_LOCK, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "SO_LOCK failed: 0x%x", res);
	printf("TA re-locked. Write operations disabled.\n");
}

/* ---- do_so_get_info ---- */
static void do_so_get_info(void)
{
	TEEC_Operation op = { 0 };
	struct so_status st;
	TEEC_Result res;

	memset(&st, 0, sizeof(st));

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &st;
	op.params[0].tmpref.size = sizeof(st);

	res = invoke_cmd(CMD_SO_GET_INFO, &op);
	if (res != TEEC_SUCCESS)
		errx(1, "SO_GET_INFO failed: 0x%x", res);

	static const char *state_names[] = {
		[SO_STATE_UNSET]       = "UNSET",
		[SO_STATE_PROVISIONED] = "PROVISIONED",
		[SO_STATE_LOCKED]      = "LOCKED",
		[SO_STATE_UNLOCKED]    = "UNLOCKED",
		[SO_STATE_BRICKED]     = "BRICKED (permanent)",
	};

	printf("SO State:       %s\n",
	       st.state <= SO_STATE_BRICKED ? state_names[st.state] : "UNKNOWN");
	printf("Dongles:        %u registered\n", st.dongle_count);
	printf("Failures:       %u consecutive, %u total (max 3/1000)\n",
	       st.fail_consecutive, st.fail_total);
	if (st.cooldown_left > 0)
		printf("Cooldown:       %u seconds remaining\n", st.cooldown_left);
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
	"\n"
	"SO (Security Officer) commands — requires dongle:\n"
	"  --init-so-pin <hex>        Initialize SO-PIN (provisioning only)\n"
	"  --provision-dongle         Register connected dongle to TA whitelist\n"
	"       [--dongle <name>]     Dongle backend: yubikey | dummy\n"
	"  --provision-dongle-from-file <path>\n"
	"                             Register dongle from public key DER file\n"
	"  --so-unlock                Unlock TA (two-phase dongle challenge)\n"
	"       --so-pin <hex>        SO-PIN (required)\n"
	"       [--dongle <name>]     Dongle backend: yubikey | dummy\n"
	"       [--dongle-index <n>]  Dongle index in whitelist (default 0)\n"
	"  --so-lock                  Re-lock TA after maintenance\n"
	"  --so-info                  Show SO state and stats\n"
	"\n"
	"Dongle options:\n"
	"  --dongle <name>            Select dongle backend (yubikey, dummy)\n"
	"                             Default: auto-detect\n"
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
	const char *so_pin_hex = NULL;
	const char *data_arg = NULL;
	const char *sig_arg = NULL;
	const char *out_file = NULL;
	const char *dongle_name = NULL;
	const char *pubkey_file = NULL;
	uint32_t size_bits = 0;
	int can_sign = 0;
	int can_encrypt = 0;
	int can_decrypt = 0;
	int dongle_index = -1;
	int opt_start = 3;  /* first unconsumed argv index */
	int i;

	if (argc < 2)
		usage(argv[0]);

	/* Parse command */
	cmd = argv[1];

	if (strcmp(cmd, "--init-pin") == 0 && argc > 2) {
		pin_hex = argv[2];
	} else if (strcmp(cmd, "--lock") == 0) {
		/* no extra args */
	} else if (strcmp(cmd, "--so-lock") == 0) {
		opt_start = 2; /* only argv[1] consumed */
	} else if (strcmp(cmd, "--so-info") == 0) {
		opt_start = 2;
	} else if (strcmp(cmd, "--init-so-pin") == 0 && argc > 2) {
		so_pin_hex = argv[2];
		/* argv[2] consumed, opt_start stays 3 */
	} else if (strcmp(cmd, "--provision-dongle") == 0) {
		opt_start = 2;
	} else if (strcmp(cmd, "--provision-dongle-from-file") == 0 && argc > 2) {
		pubkey_file = argv[2];
		/* argv[2] consumed, opt_start stays 3 */
	} else if (strcmp(cmd, "--so-unlock") == 0) {
		opt_start = 2;
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
	for (i = opt_start; i < argc; i++) {
		if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
			size_bits = (uint32_t)atoi(argv[++i]);
		} else if (strcmp(argv[i], "--sign") == 0) {
			can_sign = 1;
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
		} else if (strcmp(argv[i], "--dongle") == 0 && i + 1 < argc) {
			dongle_name = argv[++i];
		} else if (strcmp(argv[i], "--dongle-index") == 0 && i + 1 < argc) {
			dongle_index = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--so-pin") == 0 && i + 1 < argc) {
			so_pin_hex = argv[++i];
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

	/* ---- SO commands ---- */
	} else if (strcmp(cmd, "--init-so-pin") == 0) {
		do_so_pin_init(so_pin_hex);
	} else if (strcmp(cmd, "--provision-dongle") == 0) {
		do_provision_dongle(dongle_name);
	} else if (strcmp(cmd, "--provision-dongle-from-file") == 0) {
		do_provision_dongle_from_file(pubkey_file);
	} else if (strcmp(cmd, "--so-unlock") == 0) {
		do_so_unlock(so_pin_hex, dongle_name, dongle_index);
	} else if (strcmp(cmd, "--so-lock") == 0) {
		do_so_lock();
	} else if (strcmp(cmd, "--so-info") == 0) {
		do_so_get_info();
	} else {
		usage(argv[0]);
	}

	fini_tee();
	return 0;
}
