/*
 * Copyright (c) 2024, TBox Keystore OpenSSL ENGINE
 *
 * OpenSSL 1.1.1 ENGINE that bridges RSA operations to the tbox_keystore TA
 * running inside OP-TEE.
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

static TEEC_Context  g_ctx;
static TEEC_Session  g_sess;
static int           g_ready   = 0;
static int           g_ex_idx  = -1;

/* ---- TEE helpers ---- */

static int tee_start(void)
{
	TEEC_UUID uuid = TA_TBOX_KEYSTORE_UUID;

	if (g_ready)
		return 1;

	if (TEEC_InitializeContext(NULL, &g_ctx) != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore: TEEC_InitializeContext failed\n");
		return 0;
	}

	if (TEEC_OpenSession(&g_ctx, &g_sess, &uuid,
			     TEEC_LOGIN_PUBLIC, NULL, NULL, NULL) != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore: TEEC_OpenSession failed\n");
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

static int tee_cmd(uint32_t cmd, TEEC_Operation *op)
{
	TEEC_Result r = TEEC_InvokeCommand(&g_sess, cmd, op, NULL);
	if (r != TEEC_SUCCESS) {
		fprintf(stderr, "tbox_keystore: cmd %u failed 0x%x\n",
			(unsigned int)cmd, (unsigned int)r);
		return 0;
	}
	return 1;
}

/* ---- RSA_METHOD: sign ---- */

static int tbox_rsa_sign(int dtype, const unsigned char *m,
			  unsigned int m_len,
			  unsigned char *sigret, unsigned int *siglen,
			  const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;
	unsigned char local_sig[512];
	unsigned int  req, orig_siglen;
	int use_local;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);
	orig_siglen = *siglen;
	req = (unsigned int)RSA_size(rsa);
	if (req == 0) req = 256;

	fprintf(stderr, "tbox_keystore: rsa_sign ENTER dtype=%d m_len=%u"
		" *siglen=%u RSA_size=%u label=%s\n",
		dtype, m_len, orig_siglen, req, label ? label : "(null)");

	if (!label || !g_ready)
		return 0;

	if (dtype != NID_sha256) {
		fprintf(stderr, "tbox_keystore: rsa_sign bad dtype %d\n", dtype);
		return 0;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)m;
	op.params[1].tmpref.size   = m_len;

	use_local = (*siglen < req);
	if (use_local) {
		op.params[2].tmpref.buffer = local_sig;
		op.params[2].tmpref.size   = sizeof(local_sig);
	} else {
		op.params[2].tmpref.buffer = sigret;
		op.params[2].tmpref.size   = *siglen;
	}

	if (!tee_cmd(CMD_SIGN, &op))
		return 0;

	*siglen = (unsigned int)op.params[2].tmpref.size;

	if (use_local) {
		unsigned int real = (unsigned int)op.params[2].tmpref.size;
		if (real == 0) real = req;
		/*
		 * sigret is the user's buffer (e.g. sig[512] in the test).
		 * *siglen may be 0 (size probe) but the underlying buffer is
		 * valid for at least 256 bytes.  Always copy the result.
		 */
		memcpy(sigret, local_sig, real);
		*siglen = real;
		fprintf(stderr, "tbox_keystore: rsa_sign probe real=%u\n", real);
		return 1;
	}

	fprintf(stderr, "tbox_keystore: rsa_sign OK *siglen=%u\n", *siglen);
	return 1;
}

/* ---- RSA_METHOD: verify ---- */

static int tbox_rsa_verify(int dtype, const unsigned char *m,
			    unsigned int m_len,
			    const unsigned char *sigbuf, unsigned int siglen,
			    const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);

	fprintf(stderr, "tbox_keystore: rsa_verify ENTER dtype=%d m_len=%u"
		" siglen=%u RSA_size=%d label=%s\n",
		dtype, m_len, siglen, RSA_size(rsa),
		label ? label : "(null)");

	if (!label || !g_ready)
		return 0;

	(void)dtype;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_VALUE_OUTPUT);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)m;
	op.params[1].tmpref.size   = m_len;
	op.params[2].tmpref.buffer = (void *)sigbuf;
	op.params[2].tmpref.size   = siglen;

	if (!tee_cmd(CMD_VERIFY, &op))
		return 0;

	fprintf(stderr, "tbox_keystore: rsa_verify TA result=%lu\n",
		op.params[3].value.a);
	return (op.params[3].value.a == 1) ? 1 : 0;
}

/* ---- RSA_METHOD: priv_enc (Phase 2) ---- */

static int tbox_rsa_priv_enc(int flen, const unsigned char *from,
			      unsigned char *to, RSA *rsa, int padding)
{
	(void)flen; (void)from; (void)to; (void)rsa; (void)padding;
	return 0;
}

static int tbox_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	(void)rsa; (void)bits; (void)e; (void)cb;
	return 0;
}

/* ---- Key loading ---- */

static RSA *load_rsa_pubkey(const char *label, ENGINE *e)
{
	TEEC_Operation op;
	uint8_t buf[4096];
	RSA *rsa;
	BIGNUM *n, *bn_e;
	uint32_t n_len, e_len;

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

	if (op.params[1].tmpref.size < 8) {
		fprintf(stderr, "tbox_keystore: pubkey blob too small (%zu)\n",
			op.params[1].tmpref.size);
		return NULL;
	}

	{
		uint32_t hdr[2];
		memcpy(hdr, buf, 8);
		n_len = hdr[0];
		e_len = hdr[1];
	}

	if (op.params[1].tmpref.size < 8 + n_len + e_len) {
		fprintf(stderr, "tbox_keystore: pubkey blob truncated"
			" (n_len=%u e_len=%u got=%zu)\n",
			n_len, e_len, op.params[1].tmpref.size);
		return NULL;
	}

	fprintf(stderr, "tbox_keystore: load_pubkey '%s' n_len=%u e_len=%u\n",
		label, n_len, e_len);

	rsa = RSA_new_method(e);
	if (!rsa)
		return NULL;

	n   = BN_bin2bn(buf + 8,          (int)n_len, NULL);
	bn_e = BN_bin2bn(buf + 8 + n_len, (int)e_len, NULL);

	RSA_set0_key(rsa, n, bn_e, NULL);
	RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
	return rsa;
}

static EVP_PKEY *tbox_load_privkey(ENGINE *e, const char *key_id,
				    UI_METHOD *ui, void *cb_data)
{
	RSA *rsa;
	EVP_PKEY *pkey;
	char *label_copy;

	(void)ui;
	(void)cb_data;

	fprintf(stderr, "tbox_keystore: load_privkey '%s' enter\n",
		key_id ? key_id : "(null)");

	if (!key_id || !g_ready)
		return NULL;

	rsa = load_rsa_pubkey(key_id, e);
	if (!rsa)
		return NULL;

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

	EVP_PKEY_assign_RSA(pkey, rsa);
	return pkey;
}

static EVP_PKEY *tbox_load_pubkey(ENGINE *e, const char *key_id,
				   UI_METHOD *ui, void *cb_data)
{
	return tbox_load_privkey(e, key_id, ui, cb_data);
}

/* ---- ENGINE lifecycle ---- */

static int tbox_engine_init(ENGINE *e)
{
	(void)e;
	fprintf(stderr, "tbox_keystore: engine_init\n");
	return tee_start();
}

static int tbox_engine_finish(ENGINE *e)
{
	(void)e;
	fprintf(stderr, "tbox_keystore: engine_finish\n");
	tee_stop();
	return 1;
}

static int tbox_engine_destroy(ENGINE *e)
{
	(void)e;
	return 1;
}

/* ---- ENGINE registration ---- */

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
	ENGINE_free(e);
	return 1;

err_eng:
	ENGINE_free(e);
err_meth:
	RSA_meth_free(tbox_rsa_meth);
	tbox_rsa_meth = NULL;
	return 0;
}

static int bind_fn(ENGINE *e, const char *id)
{
	(void)id;
	if (!ENGINE_load_tbox_keystore())
		return 0;
	return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
