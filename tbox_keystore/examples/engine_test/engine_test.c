/*
 * Minimal ENGINE smoke-test: load TA key → sign → verify.
 *
 * Build (add to CMakeLists.txt):
 *   add_executable(engine_test test/engine_test.c)
 *   target_link_libraries(engine_test ${OPENSSL_LIBRARIES} e_tbox_keystore)
 *
 * Run:
 *   ./engine_test <label>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

extern int ENGINE_load_tbox_keystore(void);

int main(int argc, char *argv[])
{
	const char *label = (argc > 1) ? argv[1] : "server-key";
	ENGINE *e = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	const unsigned char test_data[] = "TEE ENGINE smoke test payload";
	unsigned char sig[512];
	size_t sig_len = sizeof(sig);

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	printf("=== ENGINE smoke test  (label: %s) ===\n\n", label);

	/* ---- Step 1: register ENGINE ---- */
	printf("[1] Registering tbox_keystore ENGINE ...\n");
	if (!ENGINE_load_tbox_keystore()) {
		fprintf(stderr, "FAIL: ENGINE_load_tbox_keystore() returned 0\n");
		return 1;
	}
	printf("    OK\n");

	/* ---- Step 2: get engine handle ---- */
	printf("[2] ENGINE_by_id('tbox_keystore') ...\n");
	e = ENGINE_by_id("tbox_keystore");
	if (!e) {
		fprintf(stderr, "FAIL: ENGINE_by_id returned NULL\n");
		return 1;
	}
	printf("    OK  (name: %s)\n", ENGINE_get_name(e));

	/* ---- Step 3: init (connects TA) ---- */
	printf("[3] ENGINE_init  (TEEC -> TA) ...\n");
	if (!ENGINE_init(e)) {
		fprintf(stderr, "FAIL: ENGINE_init returned 0\n"
		        "       Is tee-supplicant running?\n"
		        "       Is TA f8e9209a-... deployed?\n");
		ENGINE_free(e);
		return 1;
	}
	printf("    OK  (TA session opened)\n");

	/* ---- Step 4: load key ---- */
	printf("[4] ENGINE_load_private_key('%s') ...\n", label);
	pkey = ENGINE_load_private_key(e, label, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "FAIL: ENGINE_load_private_key returned NULL\n"
		        "       Does the key exist?  tbox_keystore --info %s\n",
		        label);
		ENGINE_finish(e);
		ENGINE_free(e);
		return 1;
	}
	printf("    OK  (EVP_PKEY type: %d)\n", EVP_PKEY_id(pkey));

	/* ---- Step 5: RSA sign via EVP ---- */
	printf("[5] EVP_DigestSign (SHA-256, goes through TA) ...\n");
	{
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		EVP_PKEY_CTX *pctx = NULL;

		if (!mdctx) { fprintf(stderr, "FAIL: EVP_MD_CTX_new\n"); goto out; }

		if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestSignInit\n");
			ERR_print_errors_fp(stderr);
			EVP_MD_CTX_free(mdctx);
			goto out;
		}

		if (EVP_DigestSignUpdate(mdctx, test_data, sizeof(test_data)) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestSignUpdate\n");
			ERR_print_errors_fp(stderr);
			EVP_MD_CTX_free(mdctx);
			goto out;
		}

		if (EVP_DigestSignFinal(mdctx, sig, &sig_len) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestSignFinal\n");
			ERR_print_errors_fp(stderr);
			EVP_MD_CTX_free(mdctx);
			goto out;
		}
		EVP_MD_CTX_free(mdctx);
	}
	printf("    OK  (signature: %zu bytes)\n", sig_len);

	/* ---- Step 6: verify (proves round-trip) ---- */
	printf("[6] EVP_DigestVerify via ENGINE key ...\n");
	{
		EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
		EVP_PKEY_CTX *pctx = NULL;

		if (!mdctx) { fprintf(stderr, "FAIL\n"); goto out; }

		if (EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestVerifyInit\n");
			ERR_print_errors_fp(stderr);
			EVP_MD_CTX_free(mdctx);
			goto out;
		}

		if (EVP_DigestVerifyUpdate(mdctx, test_data, sizeof(test_data)) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestVerifyUpdate\n");
			EVP_MD_CTX_free(mdctx);
			goto out;
		}

		if (EVP_DigestVerifyFinal(mdctx, sig, sig_len) != 1) {
			fprintf(stderr, "FAIL: EVP_DigestVerifyFinal\n");
			ERR_print_errors_fp(stderr);
			EVP_MD_CTX_free(mdctx);
			goto out;
		}
		EVP_MD_CTX_free(mdctx);
	}
	printf("    OK  (signature verified)\n");

	printf("\n=== ALL TESTS PASSED ===\n");
	ret = 0;

out:
	if (pkey) EVP_PKEY_free(pkey);
	ENGINE_finish(e);
	ENGINE_free(e);
	return ret;
}
