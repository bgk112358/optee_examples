/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle abstraction layer — unified interface for security tokens.
 *
 * Backends are loaded at run time as PLUGINS (shared objects) from a
 * directory, so "installing a dongle driver = dropping a .so in the
 * directory".  See docs/32-dongle-plugin-architecture.md.
 *
 *   default dir : /usr/lib/tbox/dongle/
 *   override    : $TBOX_DONGLE_DIR
 *
 * The CA (keystore_client.c) only depends on this header — it never
 * includes or references any backend directly.
 */

#ifndef __DONGLE_OPS_H__
#define __DONGLE_OPS_H__

#include <stddef.h>
#include <stdint.h>

/*
 * ---- Plugin ABI version ----
 *
 * Bump this on ANY breaking change to struct dongle_ops (field order,
 * semantics, callback signatures).  The loader refuses to load a plugin
 * whose reported version differs: the plugin and the host are compiled
 * separately, and reading an old plugin through a new struct layout would
 * dereference the wrong function pointers.
 */
#define DONGLE_PLUGIN_ABI_VERSION   1

/*
 * ---- Symbols a plugin MUST export ----
 *
 *   const struct dongle_ops *dongle_plugin_get_ops(void);
 *   uint32_t                 dongle_plugin_abi_version(void);
 *
 * and MAY export (optional — the loader probes for it with dlsym):
 *
 *   void dongle_plugin_set_dir(const char *dir);
 *       Lets the plugin learn the search directory, so it can resolve a
 *       companion key file next to itself (e.g. <dir>/dummy.key).
 */
#define DONGLE_PLUGIN_SYM_GET_OPS    "dongle_plugin_get_ops"
#define DONGLE_PLUGIN_SYM_ABI_VER    "dongle_plugin_abi_version"
#define DONGLE_PLUGIN_SYM_SET_DIR    "dongle_plugin_set_dir"

/* ---- Dongle capability flags ---- */
#define DONGLE_CAP_SIGN         (1u << 0)  /* RSA sign */
#define DONGLE_CAP_GET_PUBKEY   (1u << 1)  /* Export public key */
#define DONGLE_CAP_GET_SERIAL   (1u << 2)  /* Read serial number */
#define DONGLE_CAP_GET_ATTR     (1u << 3)  /* Generic attribute query */

/* ---- Opaque handle (backend private state) ---- */
struct dongle_ctx;

/* ---- Unified operation table ---- */
struct dongle_ops {
	const char *name;       /* unique id, e.g. "dummy" | "remote"      */
	const char *key_type;   /* diagnostic, e.g. "RSA-2048"             */
	uint32_t    caps;       /* OR of DONGLE_CAP_* flags                */
	uint32_t    priority;   /* probe order: higher tried first, 0 = default */

	/* Lifecycle */
	int  (*probe)(void);    /* 1 if the dongle is present               */
	int  (*open)(struct dongle_ctx **ctx);
	void (*close)(struct dongle_ctx *ctx);

	/*
	 * sign — RSA-2048 PKCS#1 v1.5 over a SHA-256 digest.
	 *
	 * digest  : 32-byte SHA-256 hash (NOT the raw message).
	 * sig_der : output buffer, must hold at least 256 bytes;
	 *           exactly 256 bytes are written.
	 * Returns 0 on success, negative on error.
	 *
	 * This mirrors the TA side, which verifies with
	 * TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 + TEE_AsymmetricVerifyDigest().
	 * (ECDSA is no longer supported: OP-TEE 3.2 cannot verify it in the
	 * secure world — see docs/30.)
	 */
	int  (*sign)(struct dongle_ctx *ctx,
		     const uint8_t *digest, size_t digest_len,
		     uint8_t *sig_der, size_t *sig_len);

	/*
	 * get_pubkey — export the public key in DER (SubjectPublicKeyInfo).
	 * RSA-2048 keys are ~294 bytes.  Returns 0 on success, negative on error.
	 */
	int  (*get_pubkey)(struct dongle_ctx *ctx,
			   uint8_t *pubkey_der, size_t *pubkey_len);

	/*
	 * get_serial — read dongle serial number (4 bytes).
	 * Optional — backends that don't support it return a negative value
	 * and the caller should skip serial verification.
	 */
	int  (*get_serial)(struct dongle_ctx *ctx, uint32_t *serial);

	/*
	 * get_attr — generic string attribute query (model, version, etc.).
	 * Returns 0 on success, negative on error (or if key unknown).
	 */
	int  (*get_attr)(struct dongle_ctx *ctx,
			 const char *key, char *val, size_t val_len);
};

/*
 * Factory: auto-detect the first available dongle.
 *
 * Triggers the (one-time) plugin directory scan on first use, then calls
 * each loaded plugin's probe() in priority order (highest first; ties
 * broken by plugin name ascending, so the result is deterministic).
 * Returns NULL if no plugin is loaded or none reports a dongle present.
 */
const struct dongle_ops *dongle_detect(void);

/*
 * Factory: get a specific backend by name (ops->name).
 * Returns NULL if no loaded plugin matches.
 */
const struct dongle_ops *dongle_get(const char *name);

#endif /* __DONGLE_OPS_H__ */
