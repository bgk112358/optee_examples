/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle abstraction layer unit test.
 *
 * Tests the dongle_ops interface through the PLUGIN LOADER (no TEE/TA
 * dependency).  The dummy backend is dlopen'd from `dummy.so` sitting next
 * to this binary, driven by a temporary RSA-2048 key.
 *
 * NOTE: signatures are RSA-2048 (PKCS#1 v1.5 / SHA-256) — exactly what the
 * TA verifies with TEE_ALG_RSASSA_PKCS1_V1_5_SHA256.  ECDSA is no longer
 * supported (OP-TEE 3.2 cannot verify it in the secure world — docs/30,
 * docs/32 §4).
 *
 * Build: see CMakeLists.txt
 * Run:   ./dongle_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>	/* d2i_PUBKEY lives here, not in evp.h */

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

/* ---- Helper: generate temporary RSA-2048 key ---- */
static const char *TMP_KEY = "/tmp/tbox_dongle_test_key.pem";

static void gen_key(void)
{
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	FILE *fp;

	rsa = RSA_new();
	e = BN_new();
	assert(rsa && e);
	assert(BN_set_word(e, RSA_F4) == 1);
	assert(RSA_generate_key_ex(rsa, 2048, e, NULL) == 1);

	fp = fopen(TMP_KEY, "w");
	assert(fp);
	assert(PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL) == 1);
	fclose(fp);
	RSA_free(rsa);
	BN_free(e);

	/*
	 * Points the dummy backend at our temp key.  Note this is the LEGACY
	 * variable: it loses to a `<plugin dir>/dummy.key` if one exists, so
	 * the plugin directory used here must not contain one.
	 */
	setenv("TBOX_DUMMY_KEY", TMP_KEY, 1);
	printf("  Key generated: %s (RSA-2048)\n", TMP_KEY);
}

static void del_key(void)
{
	remove(TMP_KEY);
	remove("/tmp/dummy-dongle-key.pem");
}

/*
 * Verify a signature the same way the TA does:
 * RSA-2048 PKCS#1 v1.5 over a SHA-256 digest
 * (TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 + TEE_AsymmetricVerifyDigest).
 */
static int verify_sig(const uint8_t *pubkey_der, size_t pk_len,
		      const uint8_t *digest, size_t dgst_len,
		      const uint8_t *sig_der, size_t sig_len)
{
	const unsigned char *p;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	int ret = -1;

	p = pubkey_der;
	pkey = d2i_PUBKEY(NULL, &p, (long)pk_len);
	if (!pkey) { fprintf(stderr, "  d2i_PUBKEY failed\n"); return -1; }

	pctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!pctx) goto out;
	if (EVP_PKEY_verify_init(pctx) <= 0) goto out;
	EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);
	EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());

	/* Prehashed: `digest` is the SHA-256 output, not the raw message */
	ret = (EVP_PKEY_verify(pctx, sig_der, sig_len, digest, dgst_len) == 1) ? 0 : -1;

out:
	if (pctx) EVP_PKEY_CTX_free(pctx);
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

/* ---- Test 1: Factory functions + caps ---- */
TEST(factory)
{
	const struct dongle_ops *ops;

	/* dongle_get("dummy") should work */
	ops = dongle_get("dummy");
	CHECK(ops != NULL, "dongle_get(\"dummy\") returned NULL");
	CHECK(strcmp(ops->name, "dummy") == 0, "backend name mismatch");

	/* Capability flags must include expected features */
	CHECK((ops->caps & DONGLE_CAP_SIGN) != 0,
	      "DONGLE_CAP_SIGN not set");
	CHECK((ops->caps & DONGLE_CAP_GET_PUBKEY) != 0,
	      "DONGLE_CAP_GET_PUBKEY not set");
	CHECK((ops->caps & DONGLE_CAP_GET_SERIAL) != 0,
	      "DONGLE_CAP_GET_SERIAL not set");
	CHECK((ops->caps & DONGLE_CAP_GET_ATTR) != 0,
	      "DONGLE_CAP_GET_ATTR not set");

	/* All mandatory function pointers must be non-NULL */
	CHECK(ops->probe != NULL,      "ops->probe is NULL");
	CHECK(ops->open != NULL,       "ops->open is NULL");
	CHECK(ops->close != NULL,      "ops->close is NULL");
	CHECK(ops->sign != NULL,       "ops->sign is NULL");
	CHECK(ops->get_pubkey != NULL, "ops->get_pubkey is NULL");
	CHECK(ops->get_serial != NULL, "ops->get_serial is NULL");
	CHECK(ops->get_attr != NULL,   "ops->get_attr is NULL");

	/* dongle_get("nonexistent") should return NULL */
	ops = dongle_get("nonexistent");
	CHECK(ops == NULL, "dongle_get(\"nonexistent\") should be NULL");

	/*
	 * ---- By-name loading: <name> must be a PLAIN FILE NAME ----
	 *
	 * The name is concatenated into "<dir>/<name>.so", so anything with a
	 * '/' is rejected.  That keeps the plugin directory from being escaped
	 * ("../evil"), and it also stops one file from acquiring a second path
	 * spelling -- which would defeat the loader's path dedup and load the
	 * same plugin twice.
	 */
	CHECK(dongle_get("../dummy") == NULL,  "relative path must be rejected");
	CHECK(dongle_get("/tmp/dummy") == NULL, "absolute path must be rejected");
	CHECK(dongle_get("sub/dummy") == NULL, "name containing '/' must be rejected");
	CHECK(dongle_get(".hidden") == NULL,   "leading dot must be rejected");
	CHECK(dongle_get("") == NULL,          "empty backend name must be rejected");
	CHECK(dongle_get(NULL) == NULL,        "NULL backend name must be rejected");

	/* The loader appends ".so" itself -- passing it in must NOT resolve */
	CHECK(dongle_get("dummy.so") == NULL,
	      "\"dummy.so\" must not resolve (suffix is added by the loader)");

	{
		char longname[80];

		memset(longname, 'a', sizeof(longname) - 1);
		longname[sizeof(longname) - 1] = '\0';
		CHECK(dongle_get(longname) == NULL,
		      "over-long backend name must be rejected");
	}

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
	uint8_t sig_der[512];
	size_t sig_len = sizeof(sig_der);
	int i;

	gen_key();

	CHECK(ops->open(&ctx) == 0, "open() failed");

	/* Create a test digest */
	for (i = 0; i < 32; i++)
		digest[i] = (uint8_t)(i * 7 + 13);

	CHECK(ops->sign(ctx, digest, 32, sig_der, &sig_len) == 0, "sign() failed");
	CHECK(sig_len == 256, "RSA-2048 signature must be 256 bytes");

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
	uint8_t sig_der[512];
	size_t sig_len = sizeof(sig_der);
	uint8_t pubkey_der[512];
	size_t pubkey_len = sizeof(pubkey_der);
	int i;

	gen_key();

	CHECK(ops->open(&ctx) == 0, "open() failed");
	CHECK(ops->get_pubkey(ctx, pubkey_der, &pubkey_len) == 0, "get_pubkey() failed");
	/* RSA-2048 SubjectPublicKeyInfo DER is ~294 bytes */
	CHECK(pubkey_len >= 256 && pubkey_len <= 512, "pubkey DER length out of range");

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
	uint8_t pubkey_der[512];
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
	CHECK(EVP_PKEY_id(pkey) == EVP_PKEY_RSA, "pubkey is not an RSA key");

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
/*
 * The loader reads plugins from $TBOX_DONGLE_DIR (default /oemdata/opt/optee/dongle).
 * Point it at the directory holding our freshly built dummy.so, which CMake
 * places next to this test binary.  Fail loudly if it is not there — a
 * silent fallback would make every test fail with a confusing message.
 */
static void setup_plugin_dir(void)
{
	char exe[512];
	char so[600];
	ssize_t n;
	char *slash;

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	assert(n > 0);
	exe[n] = '\0';

	slash = strrchr(exe, '/');
	assert(slash);
	*slash = '\0';

	snprintf(so, sizeof(so), "%s/dummy.so", exe);
	if (access(so, R_OK) != 0) {
		fprintf(stderr, "FATAL: %s not found.\n"
			"  Build the plugin first: make dummy_plugin_for_test\n", so);
		exit(1);
	}

	setenv("TBOX_DONGLE_DIR", exe, 1);
	printf("Plugin dir: %s\n", exe);
}

int main(int argc, char **argv)
{
	(void)argc; (void)argv;

	printf("=== TBox Dongle Abstraction Layer Unit Tests ===\n");

	setup_plugin_dir();

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
