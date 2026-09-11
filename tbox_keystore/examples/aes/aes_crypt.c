/*
 * Copyright (c) 2026, TBox Keystore Example
 *
 * aes_crypt - file AES encrypt/decrypt demo using TBox Keystore TA.
 *
 * Encrypts/decrypts a binary file through the TA (CMD_FILE_ENCRYPT /
 * CMD_FILE_DECRYPT), supporting:
 *   - PKCS#7 padding  (done inside TA on the last chunk)
 *   - IV selection    (--iv zero | random)
 *   - arbitrary file size (chunked CBC, IV chained across chunks)
 *
 * Usage:
 *   aes_crypt encrypt --key <label> --in <input> --out <output> [--iv zero|random]
 *   aes_crypt decrypt --key <label> --in <input> --out <output> [--iv zero|random]
 *
 * Output file format:
 *   --iv zero   : ciphertext only
 *   --iv random : 16-byte IV header || ciphertext
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>
#include "tbox_keystore_ta.h"

/* 16-byte-multiple, must stay a multiple of the AES block size */
#define CHUNK_SIZE	(64 * 1024)
/* Files up to this size use a single TA call; larger ones are chunked */
#define MAX_SINGLE	(1 * 1024 * 1024)

static TEEC_Context g_ctx;
static TEEC_Session g_sess;
static int g_verbose = 0;

/* ---- Timing (millisecond precision via CLOCK_MONOTONIC) ---- */

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull +
	       (uint64_t)ts.tv_nsec;
}

static void print_ms(const char *tag, uint64_t ns)
{
	printf("%s: %llu.%03llu ms\n", tag,
	       (unsigned long long)(ns / 1000000),
	       (unsigned long long)((ns % 1000000) / 1000));
}

static void print_timing(const char *what, uint64_t total_ns,
			 uint64_t ta_ns, int calls, size_t bytes)
{
	double rate = 0.0;

	if (total_ns > 0)
		rate = (double)bytes * 1000.0 / (double)total_ns; /* MB/s */

	printf("%s: total=%llu.%03llu ms  TA-calls=%d  TA-time=%llu.%03llu ms"
	       "  file=%zu B  rate=%.2f MB/s\n",
	       what,
	       (unsigned long long)(total_ns / 1000000),
	       (unsigned long long)((total_ns % 1000000) / 1000),
	       calls,
	       (unsigned long long)(ta_ns / 1000000),
	       (unsigned long long)((ta_ns % 1000000) / 1000),
	       bytes, rate);
}

static void die(const char *msg)
{
	fprintf(stderr, "aes_crypt: %s\n", msg);
	exit(1);
}

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"  aes_crypt encrypt --key <label> --in <input> --out <output> [--iv zero|random] [--verbose]\n"
		"  aes_crypt decrypt --key <label> --in <input> --out <output> [--iv zero|random] [--verbose]\n");
	exit(1);
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

/* Query key size via CMD_GET_INFO; returns size in bits, 0 on error */
static uint32_t get_key_size(const char *label)
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
		fprintf(stderr, "aes_crypt: GET_INFO failed: 0x%x\n", res);
		return 0;
	}
	if (info.type != KEY_TYPE_AES) {
		fprintf(stderr, "aes_crypt: key '%s' is not an AES key\n", label);
		return 0;
	}
	return info.size_bits;
}

/* Read exactly n bytes or die */
static void read_file_bytes(FILE *f, uint8_t *buf, size_t n, const char *what)
{
	if (fread(buf, 1, n, f) != n)
		die(what);
}

static void do_encrypt(const char *label, uint32_t key_size,
		       FILE *fin, FILE *fout, int iv_mode)
{
	struct aes_file_meta meta;
	uint8_t *inbuf = NULL;
	uint8_t *outbuf = NULL;
	uint8_t prev_iv[16];
	size_t file_size;
	size_t pos = 0;
	size_t buf_max;
	int is_first = 1;
	int calls = 0;
	uint64_t t0, t_chunk, t_total, t_ta = 0;
	TEEC_Result res;

	fseek(fin, 0, SEEK_END);
	file_size = (size_t)ftell(fin);
	fseek(fin, 0, SEEK_SET);

	t_total = now_ns();

	buf_max = file_size <= MAX_SINGLE ? file_size : CHUNK_SIZE;
	if (buf_max < 16)
		buf_max = 16;			/* PKCS#7 always pads to >= 1 block */

	inbuf = malloc(buf_max ? buf_max : 1);
	outbuf = malloc(buf_max + 16);
	if (!inbuf || !outbuf)
		die("out of memory");

	memset(prev_iv, 0, sizeof(prev_iv));

	while (pos < file_size || is_first) {
		size_t chunk_len;
		size_t out_len;
		int is_last;
		TEEC_Operation op = { 0 };

		if (file_size <= MAX_SINGLE) {
			chunk_len = file_size;
			is_last = 1;
		} else {
			chunk_len = file_size - pos;
			if (chunk_len > CHUNK_SIZE)
				chunk_len = CHUNK_SIZE;
			is_last = (pos + chunk_len == file_size);
		}

		read_file_bytes(fin, inbuf, chunk_len, "short read from input");
		t0 = now_ns();

		memset(&meta, 0, sizeof(meta));
		meta.key_size = key_size;
		meta.iv_mode = iv_mode;
		meta.is_first = is_first;
		meta.is_last = is_last;
		memcpy(meta.iv, prev_iv, sizeof(prev_iv));

		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_MEMREF_TEMP_INPUT,		/* label   */
			TEEC_MEMREF_TEMP_INOUT,		/* meta    */
			TEEC_MEMREF_TEMP_INPUT,		/* plain   */
			TEEC_MEMREF_TEMP_OUTPUT);	/* cipher  */
		op.params[0].tmpref.buffer = (void *)label;
		op.params[0].tmpref.size = strlen(label);
		op.params[1].tmpref.buffer = &meta;
		op.params[1].tmpref.size = sizeof(meta);
		op.params[2].tmpref.buffer = inbuf;
		op.params[2].tmpref.size = chunk_len;
		op.params[3].tmpref.buffer = outbuf;
		op.params[3].tmpref.size = chunk_len + 16;

		res = TEEC_InvokeCommand(&g_sess, CMD_FILE_ENCRYPT, &op, NULL);
		if (res != TEEC_SUCCESS) {
			fprintf(stderr, "aes_crypt: FILE_ENCRYPT failed: 0x%x\n", res);
			exit(1);
		}
		t_ta += now_ns() - t0;
		calls++;
		out_len = op.params[3].tmpref.size;

		if (is_first && iv_mode == 1)
			fwrite(meta.iv, 1, 16, fout);	/* random IV header */
		fwrite(outbuf, 1, out_len, fout);

		/* CBC chaining: next chunk IV = last ciphertext block */
		memcpy(prev_iv, outbuf + out_len - 16, 16);

		if (g_verbose) {
			t_chunk = now_ns() - t0;
			printf("aes_crypt:   chunk %zu: ", pos / CHUNK_SIZE);
			print_ms("", t_chunk);
		}

		is_first = 0;
		pos += chunk_len;
	}

	free(inbuf);
	free(outbuf);

	t_total = now_ns() - t_total;
	print_timing("aes_crypt: encrypt timing", t_total, t_ta, calls, file_size);
}

static void do_decrypt(const char *label, uint32_t key_size,
		       FILE *fin, FILE *fout, int iv_mode)
{
	struct aes_file_meta meta;
	uint8_t *inbuf = NULL;
	uint8_t *outbuf = NULL;
	uint8_t prev_iv[16];
	size_t file_size;
	size_t cipher_len;
	size_t pos = 0;
	size_t buf_max;
	int is_first = 1;
	int calls = 0;
	uint64_t t0, t_chunk, t_total, t_ta = 0;
	TEEC_Result res;

	fseek(fin, 0, SEEK_END);
	file_size = (size_t)ftell(fin);
	fseek(fin, 0, SEEK_SET);

	t_total = now_ns();

	if (iv_mode == 1) {
		if (file_size < 16)
			die("random-IV file too short (no IV header)");
		read_file_bytes(fin, prev_iv, 16, "short read from IV header");
		file_size -= 16;
	} else {
		memset(prev_iv, 0, sizeof(prev_iv));
	}
	cipher_len = file_size;

	if (cipher_len % 16 != 0)
		die("ciphertext length is not a multiple of 16");

	buf_max = cipher_len <= MAX_SINGLE ? cipher_len : CHUNK_SIZE;
	if (buf_max < 16)
		buf_max = 16;

	inbuf = malloc(buf_max ? buf_max : 1);
	outbuf = malloc(buf_max + 16);
	if (!inbuf || !outbuf)
		die("out of memory");

	while (pos < cipher_len || is_first) {
		size_t chunk_len;
		size_t out_len;
		int is_last;
		TEEC_Operation op = { 0 };

		if (cipher_len <= MAX_SINGLE) {
			chunk_len = cipher_len;
			is_last = 1;
		} else {
			chunk_len = cipher_len - pos;
			if (chunk_len > CHUNK_SIZE)
				chunk_len = CHUNK_SIZE;
			is_last = (pos + chunk_len == cipher_len);
		}

		read_file_bytes(fin, inbuf, chunk_len, "short read from input");
		t0 = now_ns();

		memset(&meta, 0, sizeof(meta));
		meta.key_size = key_size;
		meta.iv_mode = iv_mode;
		meta.is_first = is_first;
		meta.is_last = is_last;
		memcpy(meta.iv, prev_iv, sizeof(prev_iv));

		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_MEMREF_TEMP_INPUT,		/* label   */
			TEEC_MEMREF_TEMP_INOUT,		/* meta    */
			TEEC_MEMREF_TEMP_INPUT,		/* cipher  */
			TEEC_MEMREF_TEMP_OUTPUT);	/* plain   */
		op.params[0].tmpref.buffer = (void *)label;
		op.params[0].tmpref.size = strlen(label);
		op.params[1].tmpref.buffer = &meta;
		op.params[1].tmpref.size = sizeof(meta);
		op.params[2].tmpref.buffer = inbuf;
		op.params[2].tmpref.size = chunk_len;
		op.params[3].tmpref.buffer = outbuf;
		op.params[3].tmpref.size = chunk_len;

		res = TEEC_InvokeCommand(&g_sess, CMD_FILE_DECRYPT, &op, NULL);
		if (res != TEEC_SUCCESS) {
			fprintf(stderr, "aes_crypt: FILE_DECRYPT failed: 0x%x\n", res);
			exit(1);
		}
		t_ta += now_ns() - t0;
		calls++;
		out_len = op.params[3].tmpref.size;

		fwrite(outbuf, 1, out_len, fout);

		/* CBC chaining: next chunk IV = last ciphertext block */
		memcpy(prev_iv, inbuf + chunk_len - 16, 16);

		if (g_verbose) {
			t_chunk = now_ns() - t0;
			printf("aes_crypt:   chunk %zu: ", pos / CHUNK_SIZE);
			print_ms("", t_chunk);
		}

		is_first = 0;
		pos += chunk_len;
	}

	free(inbuf);
	free(outbuf);

	t_total = now_ns() - t_total;
	print_timing("aes_crypt: decrypt timing", t_total, t_ta, calls, cipher_len);
}

int main(int argc, char **argv)
{
	const char *mode = NULL;
	const char *label = NULL;
	const char *in_path = NULL;
	const char *out_path = NULL;
	int iv_mode = 0;
	FILE *fin = NULL;
	FILE *fout = NULL;
	uint32_t key_size;
	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "encrypt") == 0)
			mode = "encrypt";
		else if (strcmp(argv[i], "decrypt") == 0)
			mode = "decrypt";
		else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
			label = argv[++i];
		else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc)
			in_path = argv[++i];
		else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else if (strcmp(argv[i], "--iv") == 0 && i + 1 < argc) {
			if (strcmp(argv[i + 1], "random") == 0)
				iv_mode = 1;
			else if (strcmp(argv[i + 1], "zero") == 0)
				iv_mode = 0;
			else
				usage();
			i++;
		} else if (strcmp(argv[i], "--verbose") == 0) {
			g_verbose = 1;
		} else {
			usage();
		}
	}

	if (!mode || !label || !in_path || !out_path)
		usage();

	init_tee();
	key_size = get_key_size(label);
	if (key_size == 0)
		exit(1);

	fin = fopen(in_path, "rb");
	if (!fin) {
		fprintf(stderr, "aes_crypt: cannot open %s: %s\n",
			in_path, strerror(errno));
		exit(1);
	}
	fout = fopen(out_path, "wb");
	if (!fout) {
		fprintf(stderr, "aes_crypt: cannot open %s: %s\n",
			out_path, strerror(errno));
		exit(1);
	}

	if (strcmp(mode, "encrypt") == 0)
		do_encrypt(label, key_size, fin, fout, iv_mode);
	else
		do_decrypt(label, key_size, fin, fout, iv_mode);

	fclose(fin);
	fclose(fout);
	fini_tee();

	printf("aes_crypt: %s: %s -> %s (%s IV)\n", mode, in_path, out_path,
	       iv_mode ? "random" : "zero");
	return 0;
}
