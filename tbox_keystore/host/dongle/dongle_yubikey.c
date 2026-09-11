/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * YubiKey dongle backend — PIV (FIPS 201) via libykpiv.
 *
 * Two build modes:
 *   WITH_LIBYKPIV=1   → Link against libykpiv for direct USB access.
 *   WITH_LIBYKPIV=0   → Use ykman CLI subprocess as fallback.
 *
 * Default: fallback mode (ykman CLI).  Requires ykman >= 4.0 in PATH.
 *
 * YubiKey PIV slot usage:
 *   Slot 9a  → Authentication (ECDSA P-256, factory-provisioned)
 *   Slot 9c  → Digital Signature (optional)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "dongle_ops.h"

/* ---- Per-instance state ---- */
struct dongle_ctx {
	int   use_ykman;       /* 1 = CLI fallback, 0 = libykpiv     */
	char  model[64];       /* Cached model string                 */
	uint8_t pubkey_der[91]; /* Cached public key DER               */
	size_t pubkey_len;     /* Cached public key length             */
	uint32_t serial;       /* Cached serial number                 */
};

/* ================================================================
 *  libykpiv direct mode (WITH_LIBYKPIV=1)
 *  Stub — full implementation requires libykpiv headers + linking.
 * ============================================================== */
#ifdef WITH_LIBYKPIV
/* libykpiv stubs — replace with real calls when library is available */
static int yk_dummy_probe(void)  { return 0; }
static int yk_dummy_open(struct dongle_ctx **ctx) { (void)ctx; return -1; }
static void yk_dummy_close(struct dongle_ctx *ctx) { (void)ctx; }
static int yk_dummy_sign(struct dongle_ctx *c, const uint8_t *d, size_t dl,
			 uint8_t *s, size_t *sl)
{ (void)c;(void)d;(void)dl;(void)s;(void)sl; return -1; }
static int yk_dummy_get_pubkey(struct dongle_ctx *c, uint8_t *p, size_t *pl)
{ (void)c;(void)p;(void)pl; return -1; }
static int yk_dummy_get_serial(struct dongle_ctx *c, uint32_t *s)
{ (void)c;(void)s; return -1; }

#define yk_probe     yk_dummy_probe
#define yk_open      yk_dummy_open
#define yk_close     yk_dummy_close
#define yk_sign      yk_dummy_sign
#define yk_get_pk    yk_dummy_get_pubkey
#define yk_get_ser   yk_dummy_get_serial

#else /* WITH_LIBYKPIV */

/* ================================================================
 *  ykman CLI fallback mode (WITH_LIBYKPIV=0, default)
 * ============================================================== */

/* ---- Probe: check if ykman and a YubiKey are available ---- */
static int yk_probe(void)
{
	int rc = system("ykman piv info >/dev/null 2>&1");
	return (rc == 0) ? 1 : 0;
}

/* ---- Read a ykman output line into a buffer ---- */
static int ykman_run(const char *cmd, char *out, size_t out_len)
{
	FILE *fp;
	size_t n;

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	n = fread(out, 1, out_len - 1, fp);
	pclose(fp);

	if (n == 0)
		return -1;

	out[n] = '\0';

	/* Trim trailing newline */
	while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r'))
		out[--n] = '\0';

	return 0;
}

/* ---- Open: cache YubiKey info ---- */
static int yk_open(struct dongle_ctx **ctx_out)
{
	struct dongle_ctx *ctx;
	char buf[256];

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->use_ykman = 1;

	/* Get model */
	if (ykman_run("ykman info 2>/dev/null | grep 'Device type' | cut -d: -f2",
		      buf, sizeof(buf)) == 0) {
		/* Trim leading space */
		char *p = buf;
		while (*p == ' ') p++;
		snprintf(ctx->model, sizeof(ctx->model), "%s", p);
	} else {
		snprintf(ctx->model, sizeof(ctx->model), "YubiKey (unknown)");
	}

	/* Get serial */
	if (ykman_run("ykman info 2>/dev/null | grep 'Serial number' | awk '{print $NF}'",
		      buf, sizeof(buf)) == 0) {
		ctx->serial = (uint32_t)strtoul(buf, NULL, 10);
	} else {
		ctx->serial = 0;
	}

	/* Get public key via export-certificate */
	(void) ykman_run("ykman piv export-certificate 9a - 2>/dev/null | "
		       "openssl x509 -pubkey -noout 2>/dev/null | "
		       "openssl pkey -pubin -outform DER 2>/dev/null | "
		       "xxd -p | tr -d '\n'",
		       buf, sizeof(buf));

	/* For simplicity, store a placeholder; real impl would hex-decode */
	/* In practice, callers use ykman piv sign directly for signing */

	fprintf(stderr, "[yubikey] Detected: %s (serial=%u)\n",
		ctx->model, ctx->serial);

	*ctx_out = ctx;
	return 0;
}

static void yk_close(struct dongle_ctx *ctx)
{
	if (!ctx)
		return;
	free(ctx);
}

/* ---- Sign via ykman CLI ---- */
static int yk_sign(struct dongle_ctx *ctx,
		   const uint8_t *digest, size_t digest_len,
		   uint8_t *sig_der, size_t *sig_len)
{
	FILE *fp;
	char cmd[1024];
	char tmp_in[128], tmp_out[128];
	int i;
	size_t n;

	if (!ctx || digest_len != 32)
		return -1;

	/* Write digest to temp file (ykman reads from file) */
	snprintf(tmp_in, sizeof(tmp_in), "/tmp/tbox_dongle_digest_%d.bin", getpid());
	fp = fopen(tmp_in, "wb");
	if (!fp) return -1;
	fwrite(digest, 1, digest_len, fp);
	fclose(fp);

	snprintf(tmp_out, sizeof(tmp_out), "/tmp/tbox_dongle_sig_%d.der", getpid());

	/* ykman piv sign 9a -s SHA256 <in> <out> */
	snprintf(cmd, sizeof(cmd),
		 "ykman piv sign 9a -s SHA256 %s %s 2>/dev/null",
		 tmp_in, tmp_out);
	i = system(cmd);
	unlink(tmp_in);

	if (i != 0) {
		fprintf(stderr, "[yubikey] ykman sign failed (exit %d)\n", i);
		unlink(tmp_out);
		return -1;
	}

	/* Read signature */
	fp = fopen(tmp_out, "rb");
	if (!fp) { unlink(tmp_out); return -1; }
	n = fread(sig_der, 1, *sig_len, fp);
	fclose(fp);
	unlink(tmp_out);

	if (n == 0)
		return -1;

	*sig_len = n;
	return 0;
}

/* ---- Get public key via ykman ---- */
static int yk_get_pubkey(struct dongle_ctx *ctx,
			 uint8_t *pubkey_der, size_t *pubkey_len)
{
	FILE *fp;
	char cmd[512];
	size_t n;

	if (!ctx)
		return -1;

	/* Export cert → extract pubkey → DER */
	snprintf(cmd, sizeof(cmd),
		 "ykman piv export-certificate 9a - 2>/dev/null | "
		 "openssl x509 -pubkey -noout 2>/dev/null | "
		 "openssl pkey -pubin -outform DER 2>/dev/null");

	fp = popen(cmd, "r");
	if (!fp)
		return -1;

	n = fread(pubkey_der, 1, *pubkey_len, fp);
	pclose(fp);

	if (n == 0)
		return -1;

	*pubkey_len = n;
	return 0;
}

static int yk_get_serial(struct dongle_ctx *ctx, uint32_t *serial)
{
	if (!ctx)
		return -1;
	*serial = ctx->serial;
	return 0;
}

static int yk_get_attr(struct dongle_ctx *ctx,
		       const char *key, char *val, size_t val_len)
{
	if (!ctx || !key || !val)
		return -1;

	if (strcmp(key, "name") == 0) {
		snprintf(val, val_len, "yubikey");
		return 0;
	}
	if (strcmp(key, "model") == 0) {
		snprintf(val, val_len, "%s", ctx->model);
		return 0;
	}
	if (strcmp(key, "backend") == 0) {
		snprintf(val, val_len, "%s", ctx->use_ykman ? "ykman-cli" : "libykpiv");
		return 0;
	}

	return -1;
}

#endif /* WITH_LIBYKPIV */

/* ---- Ops table ---- */
static struct dongle_ops yubikey_ops = {
	.name       = "yubikey",
	.caps       = DONGLE_CAP_SIGN | DONGLE_CAP_GET_PUBKEY |
	              DONGLE_CAP_GET_SERIAL | DONGLE_CAP_GET_ATTR,
	.probe      = yk_probe,
	.open       = yk_open,
	.close      = yk_close,
	.sign       = yk_sign,
	.get_pubkey = yk_get_pubkey,
	.get_serial = yk_get_serial,
	.get_attr   = yk_get_attr,
};

/* ---- Registration (called by dongle_factory.c) ---- */
const struct dongle_ops *dongle_yubikey_get_ops(void)
{
	return &yubikey_ops;
}
