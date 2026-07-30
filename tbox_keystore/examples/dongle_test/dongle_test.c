/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle abstraction layer unit test.
 *
 * Tests the dongle_ops interface directly (no TEE/TA dependency).
 * Uses the dummy backend with a temporary P-256 key.
 *
 * Build: see CMakeLists.txt
 * Run:   ./dongle_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>

#include "dongle_ops.h"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name)  static void test_##name(void)
#define CHECK(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
		g_failed++; return; \
	} \
} while(0)

#define PASS() do { \
	printf("  PASS\n"); g_passed++; \
} while(0)

#define RUN(name) do { \
	printf("\n=== %s ===\n", #name); \
	test_##name(); \
} while(0)

/* ---- Helper: generate temporary P-256 key ---- */
static const char *TMP_KEY = "/tmp/tbox_dongle_test_key.pem";

static void gen_key(void)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	assert(pctx);
	assert(EVP_PKEY_keygen_init(pctx) > 0);
	assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) > 0);
	assert(EVP_PKEY_keygen(pctx, &pkey) > 0);
	EVP_PKEY_CTX_free(pctx);

	fp = fopen(TMP_KEY, "w");
	assert(fp);
	assert(PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL));
	fclose(fp);
	EVP_PKEY_free(pkey);

	setenv("TBOX_DUMMY_KEY", TMP_KEY, 1);
	printf("  Key generated: %s\n", TMP_KEY);
}

static void del_key(void)
{
	remove(TMP_KEY);
}

/* ---- Helper: verify ECDSA signature with OpenSSL (1.1.x and 3.x compat) ---- */
static int verify_sig(const uint8_t *pubkey_der, size_t pk_len,
		      const uint8_t *digest, size_t dgst_len,
		      const uint8_t *sig_der, size_t sig_len)
{
	const unsigned char *p;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL;
	ECDSA_SIG *ecsig = NULL;
	int ret = -1;

	p = pubkey_der;
	pkey = d2i_PUBKEY(NULL, &p, (long)pk_len);
	if (!pkey) { fprintf(stderr, "  d2i_PUBKEY failed\n"); return -1; }

	ec = EVP_PKEY_get0_EC_KEY(pkey);
	if (!ec) { fprintf(stderr, "  not an EC key\n"); goto out; }

	p = sig_der;
	ecsig = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
	if (!ecsig) { fprintf(stderr, "  d2i_ECDSA_SIG failed\n"); goto out; }

	/* ECDSA_do_verify: raw hash verify, no double-hash (works on 1.1.x + 3.x) */
	ret = ECDSA_do_verify(digest, (int)dgst_len, ecsig, ec);
	ret = (ret == 1) ? 0 : -1;

out:
	if (ecsig) ECDSA_SIG_free(ecsig);
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

/* ---- Test 1: Factory functions ---- */
TEST(factory)
{
	const struct dongle_ops *ops;

	/* dongle_get("dummy") should work */
	ops = dongle_get("dummy");
	CHECK(ops != NULL, "dongle_get(\"dummy\") returned NULL");
	CHECK(strcmp(ops->name, "dummy") == 0, "backend name mismatch");

	/* dongle_get("nonexistent") should return NULL */
	ops = dongle_get("nonexistent");
	CHECK(ops == NULL, "dongle_get(\"nonexistent\") should be NULL");

	PASS();
}

/* ---- Test 2: probe (without key) ---- */
TEST(probe_no_key)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	const char *saved;

	/* Remove key env so probe fails */
	saved = getenv("TBOX_DUMMY_KEY");
	unsetenv("TBOX_DUMMY_KEY");
	del_key();

	CHECK(ops->probe() == 0, "probe() should return 0 without key file");

	/* Restore */
	if (saved) setenv("TBOX_DUMMY_KEY", saved, 1);

	PASS();
}

/* ---- Test 3: probe/open/close ---- */
TEST(open_close)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx = NULL;

	gen_key();

	CHECK(ops->probe() == 1, "probe() should return 1 with key file");
	CHECK(ops->open(&ctx) == 0, "open() failed");
	CHECK(ctx != NULL, "ctx should not be NULL after open");

	ops->close(ctx);

	del_key();
	PASS();
}

/* ---- Test 4: sign ---- */
TEST(sign)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx = NULL;
	uint8_t digest[32];
	uint8_t sig_der[128];
	size_t sig_len = sizeof(sig_der);
	int i;

	gen_key();

	CHECK(ops->open(&ctx) == 0, "open() failed");

	/* Create a test digest */
	for (i = 0; i < 32; i++)
		digest[i] = (uint8_t)(i * 7 + 13);

	CHECK(ops->sign(ctx, digest, 32, sig_der, &sig_len) == 0, "sign() failed");
	CHECK(sig_len >= 64 && sig_len <= 72, "signature length out of range");

	/* sign with wrong digest length should fail */
	{
		size_t sl = sizeof(sig_der);
		int rc = ops->sign(ctx, digest, 16, sig_der, &sl);
		CHECK(rc != 0, "sign() with 16-byte digest should fail");
	}

	ops->close(ctx);
	del_key();
	PASS();
}

/* ---- Test 5: sign + verify round-trip ---- */
TEST(sign_verify)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx = NULL;
	uint8_t digest[32];
	uint8_t sig_der[128];
	size_t sig_len = sizeof(sig_der);
	uint8_t pubkey_der[256];
	size_t pubkey_len = sizeof(pubkey_der);
	int i;

	gen_key();

	CHECK(ops->open(&ctx) == 0, "open() failed");
	CHECK(ops->get_pubkey(ctx, pubkey_der, &pubkey_len) == 0, "get_pubkey() failed");
	CHECK(pubkey_len >= 88 && pubkey_len <= 256, "pubkey DER length out of range");

	for (i = 0; i < 32; i++)
		digest[i] = (uint8_t)(i * 7 + 13);

	CHECK(ops->sign(ctx, digest, 32, sig_der, &sig_len) == 0, "sign() failed");

	/* Verify the signature with OpenSSL */
	CHECK(verify_sig(pubkey_der, pubkey_len, digest, 32, sig_der, sig_len) == 0,
	      "signature verification failed");

	/* Corrupt the digest: should NOT verify */
	digest[10] ^= 0xFF;
	CHECK(verify_sig(pubkey_der, pubkey_len, digest, 32, sig_der, sig_len) != 0,
	      "corrupted digest should not verify");

	ops->close(ctx);
	del_key();
	PASS();
}

/* ---- Test 6: get_pubkey ---- */
TEST(get_pubkey)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx = NULL;
	uint8_t pubkey_der[256];
	size_t pubkey_len = sizeof(pubkey_der);
	const unsigned char *p;
	EVP_PKEY *pkey = NULL;

	gen_key();
	CHECK(ops->open(&ctx) == 0, "open() failed");

	CHECK(ops->get_pubkey(ctx, pubkey_der, &pubkey_len) == 0, "get_pubkey() failed");

	/* Parse with OpenSSL to verify it's valid DER */
	p = pubkey_der;
	pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_len);
	CHECK(pkey != NULL, "pubkey DER could not be parsed by OpenSSL");
	CHECK(EVP_PKEY_id(pkey) == EVP_PKEY_EC, "pubkey is not an EC key");

	EVP_PKEY_free(pkey);
	ops->close(ctx);
	del_key();
	PASS();
}

/* ---- Test 7: get_serial / get_attr ---- */
TEST(serial_attr)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx = NULL;
	uint32_t serial;
	char buf[128];

	gen_key();
	CHECK(ops->open(&ctx) == 0, "open() failed");

	CHECK(ops->get_serial(ctx, &serial) == 0, "get_serial() failed");
	CHECK(serial == 0xDEAD0001, "serial mismatch");

	CHECK(ops->get_attr(ctx, "name", buf, sizeof(buf)) == 0, "get_attr(\"name\") failed");
	CHECK(strcmp(buf, "dummy") == 0, "name attr mismatch");

	CHECK(ops->get_attr(ctx, "model", buf, sizeof(buf)) == 0, "get_attr(\"model\") failed");
	CHECK(strlen(buf) > 0, "model attr is empty");

	CHECK(ops->get_attr(ctx, "nonexistent", buf, sizeof(buf)) != 0,
	      "get_attr(\"nonexistent\") should return -1");

	ops->close(ctx);
	del_key();
	PASS();
}

/* ---- Test 8: double-open / double-close safety ---- */
TEST(double_open)
{
	const struct dongle_ops *ops = dongle_get("dummy");
	struct dongle_ctx *ctx1 = NULL, *ctx2 = NULL;

	gen_key();

	CHECK(ops->open(&ctx1) == 0, "first open() failed");
	CHECK(ops->open(&ctx2) == 0, "second open() should succeed (separate instance)");
	CHECK(ctx1 != ctx2, "two opens should return different ctx");

	ops->close(ctx1);
	ops->close(ctx2);

	/* close(NULL) should be safe */
	ops->close(NULL);

	del_key();
	PASS();
}

/* ---- Test 9: dongle_detect ---- */
TEST(detect)
{
	const struct dongle_ops *ops;

	gen_key();

	/* Should auto-detect dummy when it's the only available backend */
	ops = dongle_detect();
	CHECK(ops != NULL, "dongle_detect() should find a dongle (dummy)");
	CHECK(ops->probe() == 1, "detected backend probe() should pass");
	printf("  Detected: %s\n", ops->name);

	del_key();
	PASS();
}

/* ---- Main ---- */
int main(int argc, char **argv)
{
	(void)argc; (void)argv;

	printf("=== TBox Dongle Abstraction Layer Unit Tests ===\n");

	RUN(factory);
	RUN(probe_no_key);
	RUN(open_close);
	RUN(sign);
	RUN(sign_verify);
	RUN(get_pubkey);
	RUN(serial_attr);
	RUN(double_open);
	RUN(detect);

	printf("\n=== Results: %d passed, %d failed ===\n", g_passed, g_failed);

	/* Clean up temp key */
	del_key();

	return g_failed > 0 ? 1 : 0;
}
