/*
 * Copyright (c) 2026, TBox Keystore Example
 *
 * rsa_crypt - file RSA-2048 sign/verify demo using TBox Keystore TA.
 *
 * Pipeline: read file -> SHA-256 (CA, OpenSSL) -> TA CMD_SIGN/CMD_VERIFY.
 * The TA signs the 32-byte digest with RSASSA-PKCS1-v1_5-SHA256.
 *
 * Usage:
 *   rsa_crypt sign   --key <label> --in <file> --out <sig> [--bench-sec N] [--verbose]
 *   rsa_crypt verify --key <label> --in <file> --sig <sig>  [--bench-sec N] [--verbose]
 *
 * Hash params (reported on every run):
 *   hash=SHA-256  digest=32B  padding=RSASSA-PKCS1-v1_5  key=RSA-2048  sig=256B
 *
 * Benchmark: with --bench-sec N, loop the TA call for ~N seconds and report
 * ops/s and average ms/op (pure TA-call time, excludes file read + hashing).
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/sha.h>

#include <tee_client_api.h>
#include "tbox_keystore_ta.h"

#define SIG_MAX		512	/* RSA-2048 sig is 256 B; allow headroom */
#define HASH_LEN	32	/* SHA-256 */

static TEEC_Context g_ctx;
static TEEC_Session g_sess;
static int g_verbose = 0;

static void die(const char *msg)
{
	fprintf(stderr, "rsa_crypt: %s\n", msg);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"  rsa_crypt sign   --key <label> --in <file> --out <sig> [--bench-sec N] [--verbose]\n"
		"  rsa_crypt verify --key <label> --in <file> --sig <sig>  [--bench-sec N] [--verbose]\n");
	exit(1);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull +
	       (uint64_t)ts.tv_nsec;
}

static void print_hash_params(const char *label)
{
	printf("rsa_crypt: hash=SHA-256  digest=%uB  padding=RSASSA-PKCS1-v1_5"
	       "  key=RSA-2048  sig=%dB  key-label=%s\n",
	       HASH_LEN, SIG_MAX, label);
}

static void init_tee(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_TBOX_KEYSTORE_UUID;

	res = TEEC_InitializeContext(NULL, &g_ctx);
	if (res != TEEC_SUCCESS)
		die("TEEC_InitializeContext failed");

	res = TEEC_OpenSession(&g_ctx, &g_sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, NULL);
	if (res != TEEC_SUCCESS)
		die("TEEC_OpenSession failed");
}

static void fini_tee(void)
{
	TEEC_CloseSession(&g_sess);
	TEEC_FinalizeContext(&g_ctx);
}

/* Query key via CMD_GET_INFO; returns 0 if not an RSA keypair */
static uint32_t get_rsa_key_size(const char *label)
{
	TEEC_Operation op = { 0 };
	struct key_info info;
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = &info;
	op.params[1].tmpref.size = sizeof(info);

	res = TEEC_InvokeCommand(&g_sess, CMD_GET_INFO, &op, NULL);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "rsa_crypt: GET_INFO failed: 0x%x\n", res);
		return 0;
	}
	if (info.type != KEY_TYPE_RSA_KEYPAIR) {
		fprintf(stderr, "rsa_crypt: key '%s' is not an RSA key\n", label);
		return 0;
	}
	return info.size_bits;
}

/* Read whole file into a malloc'd buffer */
static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *fp;
	long size;
	uint8_t *buf;

	fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "rsa_crypt: cannot open %s: %s\n",
			path, strerror(errno));
		return NULL;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size <= 0) {
		fprintf(stderr, "rsa_crypt: %s is empty or unreadable\n", path);
		fclose(fp);
		return NULL;
	}

	buf = malloc((size_t)size);
	if (!buf) {
		fprintf(stderr, "rsa_crypt: out of memory\n");
		fclose(fp);
		return NULL;
	}

	if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
		fprintf(stderr, "rsa_crypt: short read from %s\n", path);
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	*out_len = (size_t)size;
	return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
	FILE *fp;

	fp = fopen(path, "wb");
	if (!fp) {
		fprintf(stderr, "rsa_crypt: cannot open %s: %s\n",
			path, strerror(errno));
		return -1;
	}
	if (fwrite(data, 1, len, fp) != len) {
		fprintf(stderr, "rsa_crypt: short write to %s\n", path);
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/* ---- Sign once: hash -> TA CMD_SIGN -> sig ---- */

static size_t do_sign(const char *label, const uint8_t *hash, size_t hash_len,
		      uint8_t *sig)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,		/* label */
		TEEC_MEMREF_TEMP_INPUT,		/* hash  */
		TEEC_MEMREF_TEMP_OUTPUT,	/* sig   */
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)hash;
	op.params[1].tmpref.size = hash_len;
	op.params[2].tmpref.buffer = sig;
	op.params[2].tmpref.size = SIG_MAX;

	res = TEEC_InvokeCommand(&g_sess, CMD_SIGN, &op, NULL);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "rsa_crypt: SIGN failed: 0x%x\n", res);
		exit(1);
	}
	return op.params[2].tmpref.size;
}

/* ---- Verify once: hash + sig -> TA CMD_VERIFY -> 1/0 ---- */

static int do_verify(const char *label, const uint8_t *hash, size_t hash_len,
		     const uint8_t *sig, size_t sig_len)
{
	TEEC_Operation op = { 0 };
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,		/* label */
		TEEC_MEMREF_TEMP_INPUT,		/* hash  */
		TEEC_MEMREF_TEMP_INPUT,		/* sig   */
		TEEC_VALUE_OUTPUT);		/* result */
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size = strlen(label);
	op.params[1].tmpref.buffer = (void *)hash;
	op.params[1].tmpref.size = hash_len;
	op.params[2].tmpref.buffer = (void *)sig;
	op.params[2].tmpref.size = sig_len;

	res = TEEC_InvokeCommand(&g_sess, CMD_VERIFY, &op, NULL);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "rsa_crypt: VERIFY failed: 0x%x\n", res);
		exit(1);
	}
	return (int)op.params[3].value.a;
}

/* ---- Benchmark: loop TA sign for ~bench_sec seconds ---- */

static void bench_sign(const char *label, const uint8_t *hash, size_t hash_len,
		       double secs)
{
	uint8_t sig[SIG_MAX];
	uint64_t t0, t1;
	double elapsed;
	int count = 0;

	t0 = now_ns();
	do {
		do_sign(label, hash, hash_len, sig);
		count++;
		t1 = now_ns();
		elapsed = (double)(t1 - t0) / 1e9;
	} while (elapsed < secs);

	printf("rsa_crypt: sign bench: time=%.3f s  ops=%d  avg=%.3f ms/op"
	       "  rate=%.1f ops/s\n",
	       elapsed, count,
	       (double)(t1 - t0) / 1e6 / count,
	       (double)count / elapsed);
}

static void bench_verify(const char *label, const uint8_t *hash, size_t hash_len,
			 const uint8_t *sig, size_t sig_len, double secs)
{
	uint64_t t0, t1;
	double elapsed;
	int count = 0;

	t0 = now_ns();
	do {
		do_verify(label, hash, hash_len, sig, sig_len);
		count++;
		t1 = now_ns();
		elapsed = (double)(t1 - t0) / 1e9;
	} while (elapsed < secs);

	printf("rsa_crypt: verify bench: time=%.3f s  ops=%d  avg=%.3f ms/op"
	       "  rate=%.1f ops/s\n",
	       elapsed, count,
	       (double)(t1 - t0) / 1e6 / count,
	       (double)count / elapsed);
}

int main(int argc, char **argv)
{
	const char *mode = NULL;
	const char *label = NULL;
	const char *in_path = NULL;
	const char *out_path = NULL;
	const char *sig_path = NULL;
	double bench_secs = 0.0;
	uint8_t *file = NULL;
	uint8_t hash[HASH_LEN];
	uint8_t sig[SIG_MAX];
	size_t file_len = 0;
	size_t sig_len = 0;
	uint32_t key_bits;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "sign") == 0)
			mode = "sign";
		else if (strcmp(argv[i], "verify") == 0)
			mode = "verify";
		else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
			label = argv[++i];
		else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc)
			in_path = argv[++i];
		else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc)
			sig_path = argv[++i];
		else if (strcmp(argv[i], "--bench-sec") == 0 && i + 1 < argc)
			bench_secs = atof(argv[++i]);
		else if (strcmp(argv[i], "--verbose") == 0)
			g_verbose = 1;
		else
			usage();
	}

	if (!mode || !label || !in_path)
		usage();
	if (strcmp(mode, "sign") == 0 && !out_path)
		usage();
	if (strcmp(mode, "verify") == 0 && !sig_path)
		usage();

	init_tee();

	key_bits = get_rsa_key_size(label);
	if (key_bits == 0)
		exit(1);
	if (key_bits != 2048) {
		fprintf(stderr, "rsa_crypt: key is %u-bit, expected 2048\n",
			key_bits);
		exit(1);
	}

	print_hash_params(label);

	file = read_file(in_path, &file_len);
	if (!file)
		exit(1);

	SHA256(file, file_len, hash);
	if (g_verbose)
		printf("rsa_crypt: SHA-256(%s) = %02x%02x%02x%02x...%02x%02x\n",
		       in_path, hash[0], hash[1], hash[2], hash[3],
		       hash[30], hash[31]);
	free(file);

	if (strcmp(mode, "sign") == 0) {
		sig_len = do_sign(label, hash, HASH_LEN, sig);
		printf("rsa_crypt: sign: %s -> %s (%zu B sig)\n",
		       in_path, out_path, sig_len);
		if (write_file(out_path, sig, sig_len) != 0)
			exit(1);

		/* self-check: verify right after signing */
		if (do_verify(label, hash, HASH_LEN, sig, sig_len))
			printf("rsa_crypt: verify: VALID (self-check)\n");
		else
			printf("rsa_crypt: verify: INVALID (self-check)\n");

		if (bench_secs > 0.0)
			bench_sign(label, hash, HASH_LEN, bench_secs);
	} else {
		uint8_t *sig_in = NULL;
		size_t sig_in_len = 0;

		sig_in = read_file(sig_path, &sig_in_len);
		if (!sig_in)
			exit(1);

		if (do_verify(label, hash, HASH_LEN, sig_in, sig_in_len))
			printf("rsa_crypt: verify: VALID\n");
		else
			printf("rsa_crypt: verify: INVALID\n");

		if (bench_secs > 0.0)
			bench_verify(label, hash, HASH_LEN, sig_in, sig_in_len,
				     bench_secs);
		free(sig_in);
	}

	fini_tee();
	return 0;
}
