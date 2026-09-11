/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Dongle abstraction layer — unified interface for hardware security tokens.
 *
 * Supported backends:
 *   - dongle_yubikey.c   YubiKey 5 via libykpiv (production)
 *   - dongle_dummy.c     Local P-256 key file (development / CI)
 *
 * The CA (keystore_client.c) only depends on this header — it never
 * includes or references any backend directly.
 */

#ifndef __DONGLE_OPS_H__
#define __DONGLE_OPS_H__

#include <stddef.h>
#include <stdint.h>

/* ---- Dongle capability flags ---- */
#define DONGLE_CAP_SIGN         (1u << 0)  /* ECDSA P-256 sign */
#define DONGLE_CAP_GET_PUBKEY   (1u << 1)  /* Export public key */
#define DONGLE_CAP_GET_SERIAL   (1u << 2)  /* Read serial number */
#define DONGLE_CAP_GET_ATTR     (1u << 3)  /* Generic attribute query */

/* ---- Opaque handle (backend private state) ---- */
struct dongle_ctx;

/* ---- Unified operation table ---- */
struct dongle_ops {
	const char *name;       /* "yubikey" | "dummy"                     */
	uint32_t    caps;       /* OR of DONGLE_CAP_* flags                */

	/* Lifecycle */
	int  (*probe)(void);    /* Returns 1 if hardware is present        */
	int  (*open)(struct dongle_ctx **ctx);
	void (*close)(struct dongle_ctx *ctx);

	/*
	 * sign — ECDSA P-256 over SHA-256 digest.
	 * digest  : 32-byte SHA-256 hash (NOT the raw message).
	 * sig_der : output DER-encoded signature (64-72 bytes).
	 * Returns 0 on success, negative on error.
	 */
	int  (*sign)(struct dongle_ctx *ctx,
		     const uint8_t *digest, size_t digest_len,
		     uint8_t *sig_der, size_t *sig_len);

	/*
	 * get_pubkey — export P-256 public key in DER (SubjectPublicKeyInfo).
	 * Returns 0 on success, negative on error.
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
 * Tries backends in priority order (YubiKey → Dummy).
 * Returns NULL if no backend is available.
 */
const struct dongle_ops *dongle_detect(void);

/*
 * Factory: get a specific backend by name.
 * Returns NULL if the named backend is not compiled in.
 */
const struct dongle_ops *dongle_get(const char *name);

#endif /* __DONGLE_OPS_H__ */
