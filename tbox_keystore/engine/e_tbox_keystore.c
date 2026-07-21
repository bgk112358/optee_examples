/*
 * Copyright (c) 2024, TBox Keystore OpenSSL ENGINE
 *
 * OpenSSL 1.1.1 ENGINE that bridges RSA operations to the tbox_keystore TA
 * running inside OP-TEE.
 *
 * Private keys stay in TEE; the ENGINE holds only a label string reference
 * and the RSA public key (n, e).
 *
 * Build:
 *   See CMakeLists.txt
 *
 * Usage (code):
 *   ENGINE_load_tbox_keystore();
 *   ENGINE *e = ENGINE_by_id("tbox_keystore");
 *   EVP_PKEY *pkey = ENGINE_load_private_key(e, "ota-key", NULL, NULL);
 *   SSL_CTX_use_PrivateKey(ctx, pkey);
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <tee_client_api.h>
#include "tbox_keystore_ta.h"

/* ===================================================================
 *  Global state — single TEEC session (Phase 1: single-thread only)
 * =================================================================== */

static TEEC_Context  g_ctx;
static TEEC_Session  g_sess;
static int           g_ready   = 0;
static int           g_ex_idx  = -1;   /* RSA ex_data slot for label */

/* ===================================================================
 *  TEE session helpers
 * =================================================================== */

static int tee_start(void)
{
	TEEC_UUID uuid = TA_TBOX_KEYSTORE_UUID;

	if (g_ready)
		return 1;

	if (TEEC_InitializeContext(NULL, &g_ctx) != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore ENGINE: TEEC_InitializeContext failed\n");
		return 0;
	}

	if (TEEC_OpenSession(&g_ctx, &g_sess, &uuid,
			     TEEC_LOGIN_PUBLIC, NULL, NULL, NULL) != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore ENGINE: TEEC_OpenSession failed\n");
		TEEC_FinalizeContext(&g_ctx);
		return 0;
	}

	g_ready = 1;
	return 1;
}

static void tee_stop(void)
{
	if (!g_ready) return;
	TEEC_CloseSession(&g_sess);
	TEEC_FinalizeContext(&g_ctx);
	g_ready = 0;
}

/*
 * Invoke a TA command.  Returns 0 on failure, 1 on success.
 */
static int tee_cmd(uint32_t cmd, TEEC_Operation *op)
{
	TEEC_Result r = TEEC_InvokeCommand(&g_sess, cmd, op, NULL);
	if (r != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore ENGINE: cmd 0x%x failed 0x%x\n",
			(unsigned int)cmd, (unsigned int)r);
		return 0;
	}
	return 1;
}

/* ===================================================================
 *  RSA_METHOD callbacks
 * =================================================================== */

/*
 * Sign a raw digest.
 *
 * OpenSSL computes the TLS transcript hash then calls rsa_sign(dtype, dig, …).
 * The TA currently hardcodes TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 in
 * crypto_rsa_sign(), so we only accept NID_sha256 for now.
 *
 * Phase 2: pass dtype as a value param so the TA can select the right
 * TEE algorithm at runtime.
 */
static int tbox_rsa_sign(int dtype, const unsigned char *m,
			  unsigned int m_len,
			  unsigned char *sigret, unsigned int *siglen,
			  const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);
	if (!label || !g_ready)
		return 0;

	if (dtype != NID_sha256) {
		fprintf(stderr, "tbox_keystore ENGINE: "
			"unsupported digest NID %d (only SHA-256 in Phase 1)\n",
			dtype);
		return 0;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,    /* param[0] — key label */
		TEEC_MEMREF_TEMP_INPUT,    /* param[1] — raw digest  */
		TEEC_MEMREF_TEMP_OUTPUT,   /* param[2] — signature   */
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)m;
	op.params[1].tmpref.size   = m_len;
	op.params[2].tmpref.buffer = sigret;
	op.params[2].tmpref.size   = *siglen;

	if (!tee_cmd(CMD_SIGN, &op))
		return 0;

	*siglen = (unsigned int)op.params[2].tmpref.size;
	return 1;
}

/*
 * Verify a signature.
 */
static int tbox_rsa_verify(int dtype, const unsigned char *m,
			    unsigned int m_len,
			    const unsigned char *sigbuf, unsigned int siglen,
			    const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);
	if (!label || !g_ready)
		return 0;

	(void)dtype;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,    /* param[0] — key label  */
		TEEC_MEMREF_TEMP_INPUT,    /* param[1] — digest     */
		TEEC_MEMREF_TEMP_INPUT,    /* param[2] — signature  */
		TEEC_VALUE_OUTPUT);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)m;
	op.params[1].tmpref.size   = m_len;
	op.params[2].tmpref.buffer = (void *)sigbuf;
	op.params[2].tmpref.size   = siglen;

	if (!tee_cmd(CMD_VERIFY, &op))
		return 0;

	return (op.params[3].value.a == 1) ? 1 : 0;
}

/*
 * Raw RSA private-key operation (Phase 2 placeholder).
 */
static int tbox_rsa_priv_enc(int flen, const unsigned char *from,
			      unsigned char *to, RSA *rsa, int padding)
{
	(void)flen; (void)from; (void)to; (void)rsa; (void)padding;
	return 0;
}

/*
 * Keygen is unsupported — keys are pre-generated inside the TA.
 */
static int tbox_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	(void)rsa; (void)bits; (void)e; (void)cb;
	return 0;
}

/* ===================================================================
 *  Key loading — label string → EVP_PKEY
 * =================================================================== */

/*
 * Fetch RSA public key from the TA and build an RSA* with public components.
 *
 * Export format: [n_len:4][e_len:4][modulus][exponent]
 */
static RSA *load_rsa_pubkey(const char *label, ENGINE *e)
{
	TEEC_Operation op;
	uint8_t buf[4096];
	RSA *rsa;
	BIGNUM *n, *bn_e;
	uint32_t n_len, e_len;
	const unsigned char *p;

	/* 1. Export the public blob from TA */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size   = sizeof(buf);

	if (!tee_cmd(CMD_KEY_EXPORT_PUB, &op))
		return NULL;

	/* 2. Parse the header */
	if (op.params[1].tmpref.size < 8) {
		fprintf(stderr, "tbox_keystore ENGINE: pubkey blob too small\n");
		return NULL;
	}

	p = buf;
	n_len = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
	e_len = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
		((uint32_t)p[6] <<  8) | ((uint32_t)p[7]);

	if (op.params[1].tmpref.size < 8 + n_len + e_len) {
		fprintf(stderr, "tbox_keystore ENGINE: pubkey blob truncated\n");
		return NULL;
	}

	/* 3. Build an RSA object — bind to our ENGINE so operations are routed */
	rsa = RSA_new_method(e);
	if (!rsa)
		return NULL;

	n   = BN_bin2bn(p + 8,          (int)n_len, NULL);
	bn_e = BN_bin2bn(p + 8 + n_len, (int)e_len, NULL);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	RSA_set0_key(rsa, n, bn_e, NULL);
#else
	rsa->n = n;
	rsa->e = bn_e;
#endif

	/*
	 * Mark as "external key" — OpenSSL won't try to read d/p/q fields
	 * and will always go through our RSA_METHOD callbacks.
	 */
	RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);

	return rsa;
}

/*
 * ENGINE_load_private_key  callback.
 *
 * key_id  =  TA label string  (e.g. "ota-key", "server-key").
 */
static EVP_PKEY *tbox_load_privkey(ENGINE *e, const char *key_id,
				    UI_METHOD *ui, void *cb_data)
{
	RSA *rsa;
	EVP_PKEY *pkey;
	char *label_copy;

	(void)ui;
	(void)cb_data;

	if (!key_id || !g_ready) {
		fprintf(stderr, "tbox_keystore ENGINE: not ready or no key_id\n");
		return NULL;
	}

	rsa = load_rsa_pubkey(key_id, e);
	if (!rsa)
		return NULL;

	/* Store the label so callbacks can identify the key */
	label_copy = OPENSSL_strdup(key_id);
	if (!label_copy) {
		RSA_free(rsa);
		return NULL;
	}
	RSA_set_ex_data(rsa, g_ex_idx, label_copy);

	pkey = EVP_PKEY_new();
	if (!pkey) {
		OPENSSL_free(label_copy);
		RSA_free(rsa);
		return NULL;
	}

	EVP_PKEY_assign_RSA(pkey, rsa);   /* pkey owns rsa now */
	return pkey;
}

/*
 * ENGINE_load_pubkey  callback.
 */
static EVP_PKEY *tbox_load_pubkey(ENGINE *e, const char *key_id,
				   UI_METHOD *ui, void *cb_data)
{
	return tbox_load_privkey(e, key_id, ui, cb_data);
}

/* ===================================================================
 *  ENGINE lifecycle
 * =================================================================== */

static int tbox_engine_init(ENGINE *e)
{
	(void)e;
	return tee_start();
}

static int tbox_engine_finish(ENGINE *e)
{
	(void)e;
	tee_stop();
	return 1;
}

static int tbox_engine_destroy(ENGINE *e)
{
	(void)e;
	return 1;
}

/* ===================================================================
 *  ENGINE registration
 * =================================================================== */

static RSA_METHOD *tbox_rsa_meth = NULL;

static int create_rsa_method(void)
{
	int flags;

	tbox_rsa_meth = RSA_meth_new("TBox Keystore RSA", 0);
	if (!tbox_rsa_meth)
		return 0;

	RSA_meth_set_sign(tbox_rsa_meth, tbox_rsa_sign);
	RSA_meth_set_verify(tbox_rsa_meth, tbox_rsa_verify);
	RSA_meth_set_priv_enc(tbox_rsa_meth, tbox_rsa_priv_enc);
	RSA_meth_set_keygen(tbox_rsa_meth, tbox_rsa_keygen);

	flags  = RSA_meth_get_flags(tbox_rsa_meth);
	flags |= RSA_FLAG_EXT_PKEY;
	RSA_meth_set_flags(tbox_rsa_meth, flags);

	return 1;
}

int ENGINE_load_tbox_keystore(void)
{
	ENGINE *e;

	/* Allocate ex_data index for storing label on RSA objects */
	if (g_ex_idx < 0) {
		g_ex_idx = RSA_get_ex_new_index(0, (char *)"tbox_key_label",
						NULL, NULL, NULL);
		if (g_ex_idx < 0)
			return 0;
	}

	if (!create_rsa_method())
		return 0;

	e = ENGINE_new();
	if (!e)
		goto err_meth;

	if (!ENGINE_set_id(e, "tbox_keystore"))
		goto err_eng;
	if (!ENGINE_set_name(e, "TBox Keystore (OP-TEE backed)"))
		goto err_eng;
	if (!ENGINE_set_RSA(e, tbox_rsa_meth))
		goto err_eng;
	if (!ENGINE_set_init_function(e, tbox_engine_init))
		goto err_eng;
	if (!ENGINE_set_finish_function(e, tbox_engine_finish))
		goto err_eng;
	if (!ENGINE_set_destroy_function(e, tbox_engine_destroy))
		goto err_eng;
	if (!ENGINE_set_load_privkey_function(e, tbox_load_privkey))
		goto err_eng;
	if (!ENGINE_set_load_pubkey_function(e, tbox_load_pubkey))
		goto err_eng;

	ENGINE_add(e);
	ENGINE_free(e);   /* ENGINE_add() added its own ref */
	return 1;

err_eng:
	ENGINE_free(e);
err_meth:
	RSA_meth_free(tbox_rsa_meth);
	tbox_rsa_meth = NULL;
	return 0;
}

/*
 * For dynamic loading via openssl.cnf:
 *   dynamic_path = /path/to/e_tbox_keystore.so
 *
 * OpenSSL calls the "bind_engine" symbol.  The macro generates:
 *   int bind_engine(ENGINE *e, const char *id, ...) { return bind_fn(e, id); }
 * so the actual registration logic lives in bind_fn() below.
 */
static int bind_fn(ENGINE *e, const char *id)
{
	(void)id;
	if (!ENGINE_load_tbox_keystore())
		return 0;
	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
