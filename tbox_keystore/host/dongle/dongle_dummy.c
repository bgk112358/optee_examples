/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dummy dongle backend — local P-256 key file for development and CI.
 *
 * Uses a PEM-encoded P-256 private key stored on disk:
 *   Default:  ~/.tbox/dummy-dongle-key.pem
 *   Override: $TBOX_DUMMY_KEY=<path>
 *
 * Build:  gcc -c dongle_dummy.c -lssl -lcrypto
 *         (links against OpenSSL for EVP signing)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "dongle_ops.h"

/* ---- Per-instance state ---- */
struct dongle_ctx {
	EVP_PKEY *pkey;     /* P-256 private key */
	uint32_t  serial;   /* Virtual serial number */
};

/* ---- Resolve key file path ---- */
static const char *key_path(void)
{
	const char *env = getenv("TBOX_DUMMY_KEY");
	if (env)
		return env;

	const char *home = getenv("HOME");
	if (!home)
		return NULL;

	static char path[512];
	snprintf(path, sizeof(path), "%s/.tbox/dummy-dongle-key.pem", home);
	return path;
}

/* ---- Probe: check if key file exists ---- */
static int dummy_probe(void)
{
	const char *path = key_path();
	FILE *fp;

	if (!path)
		return 0;

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	fclose(fp);
	return 1;
}

/* ---- Open: load key from file ---- */
static int dummy_open(struct dongle_ctx **ctx_out)
{
	struct dongle_ctx *ctx;
	const char *path;
	FILE *fp;
	EVP_PKEY *pkey = NULL;
	const EC_KEY *ec;
	const EC_GROUP *grp;

	path = key_path();
	if (!path) {
		fprintf(stderr, "[dummy] No key path (set HOME or TBOX_DUMMY_KEY)\n");
		return -1;
	}

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "[dummy] Cannot open key file: %s\n", path);
		return -1;
	}

	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!pkey) {
		fprintf(stderr, "[dummy] Failed to read P-256 key from %s\n", path);
		return -1;
	}

	/* Verify it's P-256 */
	ec = EVP_PKEY_get0_EC_KEY(pkey);
	if (!ec) {
		fprintf(stderr, "[dummy] Key is not an EC key\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	grp = EC_KEY_get0_group(ec);
	if (!grp || EC_GROUP_get_curve_name(grp) != NID_X9_62_prime256v1) {
		fprintf(stderr, "[dummy] Key is not P-256\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	ctx->pkey = pkey;
	ctx->serial = 0xDEAD0001; /* dummy serial */

	fprintf(stderr, "[dummy] Loaded key from %s (serial=%08x)\n",
		path, ctx->serial);

	*ctx_out = ctx;
	return 0;
}

static void dummy_close(struct dongle_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->pkey)
		EVP_PKEY_free(ctx->pkey);
	free(ctx);
}

/* ---- Sign: ECDSA P-256 over SHA-256 digest (OpenSSL 1.1.x compat) ---- */
static int dummy_sign(struct dongle_ctx *ctx,
		      const uint8_t *digest, size_t digest_len,
		      uint8_t *sig_der, size_t *sig_len)
{
	EC_KEY *ec = NULL;
	ECDSA_SIG *ecsig = NULL;
	unsigned char *p = sig_der;
	int der_len;

	if (!ctx || !ctx->pkey || digest_len != 32 || !sig_len)
		return -1;

	ec = EVP_PKEY_get0_EC_KEY(ctx->pkey);
	if (!ec) {
		fprintf(stderr, "[dummy] Failed to get EC_KEY\n");
		return -1;
	}

	ecsig = ECDSA_do_sign(digest, (int)digest_len, ec);
	if (!ecsig) {
		fprintf(stderr, "[dummy] ECDSA_do_sign failed\n");
		return -1;
	}

	der_len = i2d_ECDSA_SIG(ecsig, &p);
	if (der_len <= 0 || der_len > 128) {
		fprintf(stderr, "[dummy] i2d_ECDSA_SIG failed (len=%d)\n", der_len);
		ECDSA_SIG_free(ecsig);
		return -1;
	}

	*sig_len = (size_t)der_len;
	ECDSA_SIG_free(ecsig);
	return 0;
}

/* ---- Get public key DER ---- */
static int dummy_get_pubkey(struct dongle_ctx *ctx,
			    uint8_t *pubkey_der, size_t *pubkey_len)
{
	BIO *bio = NULL;
	unsigned char *p = NULL;
	int n;

	if (!ctx || !ctx->pkey)
		return -1;

	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return -1;

	if (i2d_PUBKEY_bio(bio, ctx->pkey) != 1) {
		BIO_free(bio);
		return -1;
	}

	n = BIO_get_mem_data(bio, &p);
	if (n <= 0 || (size_t)n > *pubkey_len) {
		BIO_free(bio);
		return -1;
	}

	memcpy(pubkey_der, p, n);
	*pubkey_len = n;

	BIO_free(bio);
	return 0;
}

/* ---- Get serial ---- */
static int dummy_get_serial(struct dongle_ctx *ctx, uint32_t *serial)
{
	if (!ctx)
		return -1;
	*serial = ctx->serial;
	return 0;
}

/* ---- Get attribute ---- */
static int dummy_get_attr(struct dongle_ctx *ctx,
			  const char *key, char *val, size_t val_len)
{
	if (!ctx || !key || !val)
		return -1;

	if (strcmp(key, "name") == 0) {
		snprintf(val, val_len, "dummy");
		return 0;
	}
	if (strcmp(key, "model") == 0) {
		snprintf(val, val_len, "Dummy Dongle v1.0 (OpenSSL P-256)");
		return 0;
	}
	if (strcmp(key, "version") == 0) {
		snprintf(val, val_len, "1.0.0");
		return 0;
	}

	return -1; /* unknown key */
}

/* ---- Ops table ---- */
static struct dongle_ops dummy_ops = {
	.name       = "dummy",
	.caps       = DONGLE_CAP_SIGN | DONGLE_CAP_GET_PUBKEY |
	              DONGLE_CAP_GET_SERIAL | DONGLE_CAP_GET_ATTR,
	.probe      = dummy_probe,
	.open       = dummy_open,
	.close      = dummy_close,
	.sign       = dummy_sign,
	.get_pubkey = dummy_get_pubkey,
	.get_serial = dummy_get_serial,
	.get_attr   = dummy_get_attr,
};

/*
 * Generate a new dummy key pair (utility for setup scripts).
 * Usage:  dongle_dummy --gen-key [output-path]
 *
 * Called as a standalone tool:  cc -DGENKEY_MAIN dongle_dummy.c -o dongle_dummy_genkey -lssl -lcrypto
 */
#ifdef GENKEY_MAIN
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

int main(int argc, char **argv)
{
	const char *path;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	FILE *fp;

	path = (argc > 1) ? argv[1] : key_path();
	if (!path) {
		fprintf(stderr, "Usage: %s <output-key.pem>\n", argv[0]);
		return 1;
	}

	/* Generate P-256 key */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx) { perror("EVP_PKEY_CTX_new_id"); return 1; }

	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		fprintf(stderr, "Key generation failed\n");
		EVP_PKEY_CTX_free(pctx);
		return 1;
	}
	EVP_PKEY_CTX_free(pctx);

	fp = fopen(path, "w");
	if (!fp) { perror(path); EVP_PKEY_free(pkey); return 1; }

	if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
		fprintf(stderr, "Failed to write key\n");
		fclose(fp);
		EVP_PKEY_free(pkey);
		return 1;
	}

	fclose(fp);
	EVP_PKEY_free(pkey);

	printf("Dummy dongle key generated: %s\n", path);
	printf("Set TBOX_DUMMY_KEY=%s to use it.\n", path);
	return 0;
}
#endif /* GENKEY_MAIN */

/* ---- Registration (called by dongle_factory.c) ---- */
const struct dongle_ops *dongle_dummy_get_ops(void)
{
	return &dummy_ops;
}
