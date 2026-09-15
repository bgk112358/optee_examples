/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dummy dongle backend — local RSA-2048 key file, loaded as a PLUGIN.
 *
 * Built as `dummy.so` and dropped into the dongle plugin directory
 * (default /usr/lib/tbox/dongle/, override $TBOX_DONGLE_DIR).  Together
 * with a companion key file that is what "plugging in a dongle" means:
 *
 *     <plugin dir>/dummy.so     ← the driver
 *     <plugin dir>/dummy.key    ← the "key inside the dongle"
 *
 * Key file resolution (first match wins — see key_path()):
 *   1. $TBOX_DONGLE_KEY_DUMMY
 *   2. <plugin dir>/dummy.key      (only if the file exists)
 *   3. $TBOX_DUMMY_KEY             (legacy)
 *   4. /tmp/dummy-dongle-key.pem   (legacy default)
 *
 * NOTE on the key type: this used to be ECDSA P-256.  It is now RSA-2048
 * because the TA verifies the dongle's challenge signature *inside the
 * secure world*, and OP-TEE 3.2 cannot do ECDSA there (no ECDSA transient
 * object support — see docs/30).  RSA-2048 is natively supported by the TA
 * (TEE_ALG_RSASSA_PKCS1_V1_5_SHA256), so a RSA-2048 dongle can be verified
 * atomically together with the whitelist check (docs/32 §8).
 *
 * Build:  as a shared object (CMake target `dummy_plugin` → dummy.so)
 *         cc -shared -fPIC dongle_dummy.c -o dummy.so -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "dongle_ops.h"

/* ---- Per-instance state ---- */
struct dongle_ctx {
	EVP_PKEY *pkey;     /* RSA-2048 private key */
	uint32_t  serial;   /* Virtual serial number */
};

/*
 * Plugin search directory, handed to us by the loader via
 * dongle_plugin_set_dir().  Used to locate the companion key file
 * <dir>/dummy.key — "drop a .so + a .key into the directory" is what
 * "plugging in the dongle" means (docs/32 §6).
 */
static char g_plugin_dir[512];

void dongle_plugin_set_dir(const char *dir)
{
	snprintf(g_plugin_dir, sizeof(g_plugin_dir), "%s", dir ? dir : "");
}

static int file_readable(const char *path)
{
	FILE *fp = fopen(path, "r");

	if (!fp)
		return 0;
	fclose(fp);
	return 1;
}

/*
 * Key path resolution (first match wins):
 *   1. $TBOX_DONGLE_KEY_DUMMY        — explicit per-plugin override
 *   2. <plugin dir>/dummy.key        — the "dongle key", only if present
 *   3. $TBOX_DUMMY_KEY               — legacy override (dev machines, CI)
 *   4. /tmp/dummy-dongle-key.pem     — legacy default
 *
 * Step 2 is conditional on the file existing so that existing setups which
 * put the key at the legacy locations keep working.
 */
static const char *key_path(void)
{
	static char buf[600];
	const char *env;

	env = getenv("TBOX_DONGLE_KEY_DUMMY");
	if (env && *env)
		return env;

	if (g_plugin_dir[0]) {
		snprintf(buf, sizeof(buf), "%s/dummy.key", g_plugin_dir);
		if (file_readable(buf))
			return buf;
	}

	env = getenv("TBOX_DUMMY_KEY");
	if (env && *env)
		return env;

	return "/tmp/dummy-dongle-key.pem";
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
	RSA *rsa = NULL;

	path = key_path();
	if (!path) {
		fprintf(stderr, "[dummy] No key path (set TBOX_DUMMY_KEY)\n");
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
		fprintf(stderr, "[dummy] Failed to read private key from %s\n", path);
		return -1;
	}

	/* Must be RSA-2048 — the TA verifies RSA/PKCS#1 v1.5/SHA-256 */
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (!rsa) {
		fprintf(stderr, "[dummy] Key is not an RSA key (ECDSA no longer supported)\n");
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (RSA_size(rsa) != 256) {
		fprintf(stderr, "[dummy] Key is RSA-%d, expected RSA-2048\n",
			RSA_size(rsa) * 8);
		RSA_free(rsa);
		EVP_PKEY_free(pkey);
		return -1;
	}
	RSA_free(rsa);	/* released here; dummy_sign() obtains its own ref */

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

/* ---- Sign: RSA-2048 PKCS#1 v1.5 over the SHA-256 digest ---- */
static int dummy_sign(struct dongle_ctx *ctx,
		      const uint8_t *digest, size_t digest_len,
		      uint8_t *sig_der, size_t *sig_len)
{
	RSA *rsa;
	unsigned int slen = 0;
	int ok;

	if (!ctx || !ctx->pkey || digest_len != 32 || !sig_len)
		return -1;

	/* RSA-2048 signature is exactly 256 bytes */
	if (*sig_len < 256) {
		fprintf(stderr, "[dummy] signature buffer too small (%zu < 256)\n",
			*sig_len);
		return -1;
	}

	/*
	 * Obtain the RSA key per use rather than caching a borrowed pointer:
	 * on OpenSSL 3.0 a provider-backed EVP_PKEY builds its legacy RSA
	 * copy lazily, and holding on to a get0_RSA() pointer across calls is
	 * fragile.  get1/free is valid on both 1.1.x and 3.x.
	 */
	rsa = EVP_PKEY_get1_RSA(ctx->pkey);
	if (!rsa) {
		fprintf(stderr, "[dummy] no RSA key in EVP_PKEY\n");
		return -1;
	}

	/*
	 * RSA_sign() with NID_sha256 produces
	 *   RSA-PKCS1v1.5(DigestInfo(SHA-256), digest)
	 * which is exactly what the TA verifies with
	 * TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 + TEE_AsymmetricVerifyDigest().
	 */
	ok = RSA_sign(NID_sha256, digest, (unsigned int)digest_len,
		      sig_der, &slen, rsa);
	RSA_free(rsa);

	if (ok != 1) {
		fprintf(stderr, "[dummy] RSA_sign failed\n");
		return -1;
	}

	*sig_len = (size_t)slen;
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
	.key_type   = "RSA-2048",
	.caps       = DONGLE_CAP_SIGN | DONGLE_CAP_GET_PUBKEY |
	              DONGLE_CAP_GET_SERIAL | DONGLE_CAP_GET_ATTR,
	.priority   = 10,
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
 * Built as a separate binary by CMake (target: `dummy_genkey`) and intended
 * to run ON THE TARGET, where the `openssl` command is usually absent — it
 * links libcrypto directly instead of shelling out to the CLI.
 *
 *   target$  ./dummy_genkey [/path/to/dummy-dongle-key.pem]
 *   host  $  cc -DGENKEY_MAIN dongle_dummy.c -o dummy_genkey -lssl -lcrypto
 */
#ifdef GENKEY_MAIN
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>	/* i2d_PUBKEY / d2i_PUBKEY live here */

/*
 * Mode 2 — export the public key DER (SubjectPublicKeyInfo) of an existing
 * key file.  Used by the lifecycle test to provision a SECOND dongle via
 * --provision-dongle-from-file, without needing the openssl CLI on target.
 *
 *   dummy_genkey --pubout <key.pem> [<out.der>]     (no file → hex on stdout)
 */
static int pubout_main(int argc, char **argv)
{
	const char *key_path_arg;
	const char *out_path = NULL;
	FILE *fp;
	EVP_PKEY *pkey;
	BIO *bio;
	unsigned char *der = NULL;
	int n;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s --pubout <key.pem> [<out.der>]\n", argv[0]);
		return 1;
	}
	key_path_arg = argv[2];
	if (argc > 3)
		out_path = argv[3];

	fp = fopen(key_path_arg, "r");
	if (!fp) {
		perror(key_path_arg);
		return 1;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!pkey) {
		fprintf(stderr, "Failed to read private key from %s\n", key_path_arg);
		return 1;
	}

	bio = BIO_new(BIO_s_mem());
	if (!bio || i2d_PUBKEY_bio(bio, pkey) != 1) {
		fprintf(stderr, "Failed to encode public key\n");
		if (bio)
			BIO_free(bio);
		EVP_PKEY_free(pkey);
		return 1;
	}
	n = BIO_get_mem_data(bio, &der);

	if (out_path) {
		FILE *of = fopen(out_path, "wb");
		if (!of || fwrite(der, 1, (size_t)n, of) != (size_t)n) {
			perror(out_path);
			if (of)
				fclose(of);
			BIO_free(bio);
			EVP_PKEY_free(pkey);
			return 1;
		}
		fclose(of);
		fprintf(stderr, "Public key DER written: %s (%d bytes)\n", out_path, n);
	} else {
		int i;
		for (i = 0; i < n; i++)
			printf("%02x", der[i]);
		printf("\n");
	}

	BIO_free(bio);
	EVP_PKEY_free(pkey);
	return 0;
}

int main(int argc, char **argv)
{
	const char *path;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
	FILE *fp;

	if (argc > 2 && strcmp(argv[1], "--pubout") == 0)
		return pubout_main(argc, argv);

	path = (argc > 1) ? argv[1] : key_path();
	if (!path) {
		fprintf(stderr, "Usage: %s <output-key.pem>\n", argv[0]);
		return 1;
	}

	/* Generate RSA-2048 with the usual public exponent 65537 */
	rsa = RSA_new();
	e = BN_new();
	if (!rsa || !e || BN_set_word(e, RSA_F4) != 1) {
		fprintf(stderr, "RSA allocation failed\n");
		goto fail;
	}

	if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
		fprintf(stderr, "Key generation failed\n");
		goto fail;
	}

	fp = fopen(path, "w");
	if (!fp) {
		perror(path);
		goto fail;
	}

	if (!PEM_write_RSAPrivateKey(fp, rsa, NULL, NULL, 0, NULL, NULL)) {
		fprintf(stderr, "Failed to write key\n");
		fclose(fp);
		goto fail;
	}
	fclose(fp);

	RSA_free(rsa);
	BN_free(e);

	printf("Dummy dongle key generated: %s (RSA-2048)\n", path);
	printf("Set TBOX_DUMMY_KEY=%s to use it.\n", path);
	return 0;

fail:
	if (e)
		BN_free(e);
	if (rsa)
		RSA_free(rsa);
	return 1;
}
#endif /* GENKEY_MAIN */

/* ---- Plugin entry points (required by dongle_ops.h) ---- */

const struct dongle_ops *dongle_plugin_get_ops(void)
{
	return &dummy_ops;
}

uint32_t dongle_plugin_abi_version(void)
{
	return DONGLE_PLUGIN_ABI_VERSION;
}
