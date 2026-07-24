/*
 * gen_csr — Generate a PKCS#10 CSR signed by a TA key via ENGINE.
 *
 * Usage: ./gen_csr <key-label> <CN> [out.csr]
 *
 * Example:
 *   ./gen_csr pub-key  tbox-pub  /tmp/pub.csr
 *   ./gen_csr sub-key  tbox-sub  /tmp/sub.csr
 *
 * The CSR is written to the file, or stdout if no file given.
 * The Root CA then signs it:
 *   openssl x509 -req -in /tmp/pub.csr \
 *     -CA root-ca.crt -CAkey root-ca.key -CAcreateserial \
 *     -out /tmp/pub.crt -days 3650
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

extern int ENGINE_load_tbox_keystore(void);

int main(int argc, char *argv[])
{
	const char *label;
	const char *cn;
	const char *out_path;
	ENGINE *e;
	EVP_PKEY *pkey;
	X509_REQ *req;
	FILE *fp;
	int ret = 1;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <key-label> <CN> [out.csr]\n", argv[0]);
		return 1;
	}
	label    = argv[1];
	cn       = argv[2];
	out_path = (argc > 3) ? argv[3] : NULL;

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	/* ---- 1. Load TA key via ENGINE ---- */
	if (!ENGINE_load_tbox_keystore()) {
		fprintf(stderr, "gen_csr: ENGINE_load_tbox_keystore failed\n");
		return 1;
	}
	e = ENGINE_by_id("tbox_keystore");
	if (!e || !ENGINE_init(e)) {
		fprintf(stderr, "gen_csr: ENGINE init failed\n");
		return 1;
	}
	pkey = ENGINE_load_private_key(e, label, NULL, NULL);
	if (!pkey) {
		fprintf(stderr, "gen_csr: key '%s' not found in TA\n", label);
		return 1;
	}

	/* ---- 2. Build X509_REQ ---- */
	req = X509_REQ_new();
	if (!req) { fprintf(stderr, "gen_csr: X509_REQ_new failed\n"); goto out; }

	X509_REQ_set_version(req, 0);

	{
		X509_NAME *name = X509_NAME_new();
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
					   (unsigned char *)cn, -1, -1, 0);
		X509_REQ_set_subject_name(req, name);
		X509_NAME_free(name);
	}

	X509_REQ_set_pubkey(req, pkey);

	/* 3. Sign the CSR (goes through ENGINE → TA) */
	if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
		fprintf(stderr, "gen_csr: X509_REQ_sign failed\n");
		ERR_print_errors_fp(stderr);
		goto out;
	}

	/* ---- 4. Write PEM ---- */
	fp = out_path ? fopen(out_path, "wb") : stdout;
	if (!fp) { perror(out_path); goto out; }

	if (!PEM_write_X509_REQ(fp, req)) {
		fprintf(stderr, "gen_csr: PEM_write_X509_REQ failed\n");
		if (out_path) fclose(fp);
		goto out;
	}
	if (out_path) {
		fclose(fp);
		fprintf(stdout, "gen_csr: wrote %s\n", out_path);
	}

	ret = 0;
out:
	X509_REQ_free(req);
	EVP_PKEY_free(pkey);
	return ret;
}
