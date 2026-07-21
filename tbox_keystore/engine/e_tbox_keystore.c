/*
 * tbox_keystore OpenSSL ENGINE (OP-TEE 3.2 / OpenSSL 1.1.1w)
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
static int           g_call_nr = 0;

#define LOG(fmt, ...) \
	fprintf(stderr, "tbox-eng[%d]: " fmt, g_call_nr++, ##__VA_ARGS__)

/* ---- TEE helpers ---- */

static int tee_start(void)
{
	TEEC_UUID uuid = TA_TBOX_KEYSTORE_UUID;
	if (g_ready) return 1;
	if (TEEC_InitializeContext(NULL, &g_ctx) != TEEC_SUCCESS) {
		LOG("TEEC_InitializeContext failed\n"); return 0;
	}
	if (TEEC_OpenSession(&g_ctx, &g_sess, &uuid,
			     TEEC_LOGIN_PUBLIC, NULL, NULL, NULL) != TEEC_SUCCESS) {
		LOG("TEEC_OpenSession failed\n");
		TEEC_FinalizeContext(&g_ctx); return 0;
	}
	g_ready = 1;
	LOG("TA session opened\n");
	return 1;
}

static void tee_stop(void)
{
	if (!g_ready) return;
	LOG("TA session closing\n");
	TEEC_CloseSession(&g_sess);
	TEEC_FinalizeContext(&g_ctx);
	g_ready = 0;
}

static int tee_cmd(uint32_t cmd, TEEC_Operation *op)
{
	TEEC_Result r = TEEC_InvokeCommand(&g_sess, cmd, op, NULL);
	if (r != TEEC_SUCCESS) {
		LOG("cmd %u -> 0x%x\n", (unsigned int)cmd, (unsigned int)r);
		return 0;
	}
	return 1;
}

/* ---- sign ---- */

static int tbox_rsa_sign(int dtype, const unsigned char *m,
			  unsigned int m_len,
			  unsigned char *sigret, unsigned int *siglen,
			  const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;
	unsigned char local_sig[512];
	unsigned int  req, orig;
	int use_local, ok;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);
	orig = *siglen;
	req  = (unsigned int)RSA_size(rsa);
	if (req == 0) req = 256;

	LOG("SIGN dtype=%d m_len=%u *siglen=%u req=%u label=%s\n",
	    dtype, m_len, orig, req, label ? label : "(null)");

	if (!label || !g_ready) { LOG("SIGN -> 0 (no label/session)\n"); return 0; }

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
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

	ok = tee_cmd(CMD_SIGN, &op);

	if (!ok) { LOG("SIGN -> 0 (cmd fail)\n"); return 0; }

	*siglen = (unsigned int)op.params[2].tmpref.size;
	if (*siglen == 0) *siglen = req;

	if (use_local)
		memcpy(sigret, local_sig, *siglen);

	LOG("SIGN -> 1  *siglen=%u\n", *siglen);
	return 1;
}

/* ---- verify ---- */

static int tbox_rsa_verify(int dtype, const unsigned char *m,
			    unsigned int m_len,
			    const unsigned char *sigbuf, unsigned int siglen,
			    const RSA *rsa)
{
	const char *label;
	TEEC_Operation op;
	unsigned long ta_result;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);

	LOG("VERIFY dtype=%d m_len=%u siglen=%u RSA_size=%d label=%s\n",
	    dtype, m_len, siglen, RSA_size(rsa), label ? label : "(null)");

	if (!label || !g_ready) { LOG("VERIFY -> 0 (no label/session)\n"); return 0; }

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)m;
	op.params[1].tmpref.size   = m_len;
	op.params[2].tmpref.buffer = (void *)sigbuf;
	op.params[2].tmpref.size   = siglen;

	if (!tee_cmd(CMD_VERIFY, &op)) { LOG("VERIFY -> 0 (cmd fail)\n"); return 0; }

	ta_result = op.params[3].value.a;
	LOG("VERIFY TA=%lu -> %d\n", ta_result, (ta_result == 1) ? 1 : 0);
	return (ta_result == 1) ? 1 : 0;
}

/* ---- priv_dec (RSA PKCS#1 v1.5 decrypt via TA) ---- */

static int tbox_rsa_priv_dec(int flen, const unsigned char *from,
			      unsigned char *to, RSA *rsa, int padding)
{
	const char *label;
	TEEC_Operation op;

	LOG("PRIV_DEC flen=%d padding=%d\n", flen, padding);

	/* Accept any padding — OpenSSL handles pad/unpad, TA does m^d mod n */
	(void)padding;

	label = (const char *)RSA_get_ex_data(rsa, g_ex_idx);
	if (!label || !g_ready) {
		LOG("PRIV_DEC -> 0 (no label/session)\n");
		return -1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = (void *)from;
	op.params[1].tmpref.size   = (size_t)flen;
	op.params[2].tmpref.buffer = to;
	op.params[2].tmpref.size   = (size_t)flen;

	if (!tee_cmd(CMD_RSA_DECRYPT, &op)) {
		LOG("PRIV_DEC -> -1 (cmd fail)\n");
		return -1;
	}

	LOG("PRIV_DEC -> %zu\n", op.params[2].tmpref.size);
	return (int)op.params[2].tmpref.size;
}

/* ---- priv_enc / priv_dec — raw RSA m^d mod n via TA ---- */

static int tbox_rsa_priv_enc(int flen, const unsigned char *from,
			      unsigned char *to, RSA *rsa, int padding)
{
	LOG("PRIV_ENC flen=%d padding=%d\n", flen, padding);
	return tbox_rsa_priv_dec(flen, from, to, rsa, padding);
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
		TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
		TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)label;
	op.params[0].tmpref.size   = strlen(label);
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size   = sizeof(buf);

	if (!tee_cmd(CMD_KEY_EXPORT_PUB, &op)) return NULL;

	{ uint32_t h[2]; memcpy(h, buf, 8); n_len = h[0]; e_len = h[1]; }

	LOG("load_pubkey '%s' n=%u e=%u\n", label, n_len, e_len);

	rsa = RSA_new_method(e);
	if (!rsa) return NULL;
	n   = BN_bin2bn(buf + 8,          (int)n_len, NULL);
	bn_e = BN_bin2bn(buf + 8 + n_len, (int)e_len, NULL);
	RSA_set0_key(rsa, n, bn_e, NULL);
	RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);
	return rsa;
}

static EVP_PKEY *tbox_load_privkey(ENGINE *e, const char *key_id,
				    UI_METHOD *ui, void *cb_data)
{
	RSA *rsa; EVP_PKEY *pkey; char *cp;
	(void)ui; (void)cb_data;
	LOG("load_privkey '%s'\n", key_id ? key_id : "(null)");
	if (!key_id || !g_ready) return NULL;
	rsa = load_rsa_pubkey(key_id, e);
	if (!rsa) return NULL;
	cp = OPENSSL_strdup(key_id);
	if (!cp) { RSA_free(rsa); return NULL; }
	RSA_set_ex_data(rsa, g_ex_idx, cp);
	pkey = EVP_PKEY_new();
	if (!pkey) { OPENSSL_free(cp); RSA_free(rsa); return NULL; }
	EVP_PKEY_assign_RSA(pkey, rsa);
	return pkey;
}

static EVP_PKEY *tbox_load_pubkey(ENGINE *e, const char *key_id,
				   UI_METHOD *ui, void *cb_data)
{ return tbox_load_privkey(e, key_id, ui, cb_data); }

/* ---- Lifecycle ---- */

static int tbox_engine_init(ENGINE *e)
{ (void)e; LOG("engine_init\n"); return tee_start(); }

static int tbox_engine_finish(ENGINE *e)
{ (void)e; LOG("engine_finish\n"); tee_stop(); return 1; }

static int tbox_engine_destroy(ENGINE *e)
{ (void)e; return 1; }

/* ---- Registration ---- */

static RSA_METHOD *tbox_rsa_meth;

static int create_rsa_method(void)
{
	int fl;
	tbox_rsa_meth = RSA_meth_new("TBox Keystore RSA", 0);
	if (!tbox_rsa_meth) return 0;
	RSA_meth_set_sign(tbox_rsa_meth, tbox_rsa_sign);
	RSA_meth_set_verify(tbox_rsa_meth, tbox_rsa_verify);
	RSA_meth_set_priv_enc(tbox_rsa_meth, tbox_rsa_priv_enc);
	RSA_meth_set_priv_dec(tbox_rsa_meth, tbox_rsa_priv_dec);
	RSA_meth_set_keygen(tbox_rsa_meth, tbox_rsa_keygen);
	fl  = RSA_meth_get_flags(tbox_rsa_meth);
	fl |= RSA_FLAG_EXT_PKEY;
	RSA_meth_set_flags(tbox_rsa_meth, fl);
	return 1;
}

int ENGINE_load_tbox_keystore(void)
{
	ENGINE *e;
	if (g_ex_idx < 0) {
		g_ex_idx = RSA_get_ex_new_index(0, (char *)"tbox_key_label",
						NULL, NULL, NULL);
		if (g_ex_idx < 0) return 0;
	}
	if (!create_rsa_method()) return 0;
	e = ENGINE_new();
	if (!e) goto err_meth;
	if (!ENGINE_set_id(e, "tbox_keystore"))        goto err_eng;
	if (!ENGINE_set_name(e, "TBox Keystore (OP-TEE backed)")) goto err_eng;
	if (!ENGINE_set_RSA(e, tbox_rsa_meth))          goto err_eng;
	if (!ENGINE_set_init_function(e, tbox_engine_init))    goto err_eng;
	if (!ENGINE_set_finish_function(e, tbox_engine_finish)) goto err_eng;
	if (!ENGINE_set_destroy_function(e, tbox_engine_destroy)) goto err_eng;
	if (!ENGINE_set_load_privkey_function(e, tbox_load_privkey)) goto err_eng;
	if (!ENGINE_set_load_pubkey_function(e, tbox_load_pubkey))  goto err_eng;
	ENGINE_add(e); ENGINE_free(e); return 1;
err_eng: ENGINE_free(e);
err_meth: RSA_meth_free(tbox_rsa_meth); tbox_rsa_meth = NULL; return 0;
}

static int bind_fn(ENGINE *e, const char *id)
{ (void)id; return ENGINE_load_tbox_keystore() ? 1 : 0; }

IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
