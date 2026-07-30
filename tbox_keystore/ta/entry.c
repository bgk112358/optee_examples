/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * TA entry point and command dispatch.
 */

#include <inttypes.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/* Internal module APIs */
TEE_Result pin_mgr_init(const uint8_t *pin, size_t pin_len);
TEE_Result pin_mgr_verify(void);
void       pin_mgr_lock(void);
int        pin_mgr_is_locked(void);
int        pin_mgr_is_set(void);
void       pin_mgr_restore(void);

TEE_Result keystore_gen_rsa(const uint8_t *label, size_t label_len,
			    uint32_t size_bits, uint32_t perms);
TEE_Result keystore_gen_aes(const uint8_t *label, size_t label_len,
			    uint32_t size_bits, uint32_t perms);
TEE_Result keystore_load(const uint8_t *label, size_t label_len,
			 uint32_t *type, uint32_t *perms,
			 TEE_ObjectHandle *key);
TEE_Result keystore_export_pub(const uint8_t *label, size_t label_len,
			       uint8_t *out, size_t *out_len);
TEE_Result keystore_get_info(const uint8_t *label, size_t label_len,
			     struct key_info *info);
TEE_Result keystore_delete_key(const uint8_t *label, size_t label_len);

TEE_Result acl_check(uint32_t permissions, uint32_t required_perm);

TEE_Result crypto_rsa_sign(TEE_ObjectHandle key, uint32_t key_size_bits,
			   const uint8_t *data, size_t data_len,
			   uint8_t *sig, size_t *sig_len);
TEE_Result crypto_rsa_verify(TEE_ObjectHandle key, uint32_t key_size_bits,
			     const uint8_t *data, size_t data_len,
			     const uint8_t *sig, size_t sig_len);
TEE_Result crypto_aes_encrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *plain, size_t plain_len,
			      uint8_t *cipher, size_t *cipher_len);
TEE_Result crypto_aes_decrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *cipher, size_t cipher_len,
			      uint8_t *plain, size_t *plain_len);
TEE_Result crypto_rsa_decrypt(TEE_ObjectHandle key, uint32_t key_size_bits,
			      const uint8_t *cipher, size_t cipher_len,
			      uint8_t *plain, size_t *plain_len);

/* SO-PIN module APIs (so_pin_mgr.c) */
TEE_Result so_pin_init(const uint8_t *pin, size_t pin_len);
TEE_Result so_provision_dongle(const uint8_t *pubkey_der, size_t der_len);
TEE_Result so_unlock_req(const uint8_t *pin, size_t pin_len,
			 uint8_t *chg_out, size_t chg_out_size,
			 uint32_t *dongle_count, uint32_t *cooldown_left);
void       so_pin_lock(void);
void       so_pin_auto_lock(void);
int        so_pin_is_unlocked(void);
void       so_pin_get_info(struct so_status *st);
void       so_pin_restore(void);
void       so_unlock_confirm(void);

/* Session-level challenge state for two-phase unlock */
static uint8_t g_so_challenge[32];
static int g_so_challenge_valid = 0;

/* ---- Command handlers ---- */

static TEE_Result cmd_pin_init(uint32_t pt,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	return pin_mgr_init(params[0].memref.buffer,
			    params[0].memref.size);
}

static TEE_Result cmd_key_gen_rsa(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return keystore_gen_rsa(params[0].memref.buffer,
				params[0].memref.size,
				params[1].value.a,
				params[1].value.b);
}

static TEE_Result cmd_key_gen_aes(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return keystore_gen_aes(params[0].memref.buffer,
				params[0].memref.size,
				params[1].value.a,
				params[1].value.b);
}

static TEE_Result cmd_key_export_pub(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return keystore_export_pub(params[0].memref.buffer,
				   params[0].memref.size,
				   params[1].memref.buffer,
				   &params[1].memref.size);
}

static TEE_Result cmd_key_delete(uint32_t pt,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return keystore_delete_key(params[0].memref.buffer,
				   params[0].memref.size);
}

static TEE_Result cmd_sign(uint32_t pt,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type;
	uint32_t perms;
	uint32_t key_bits;
	TEE_Result res;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = keystore_load(params[0].memref.buffer,
			    params[0].memref.size,
			    &type, &perms, &key);
	if (res != TEE_SUCCESS)
		return res;

	res = acl_check(perms, PERM_SIGN);
	if (res != TEE_SUCCESS)
		goto out;

	key_bits = (type == KEY_TYPE_RSA_KEYPAIR) ? 2048 : 256;
	res = crypto_rsa_sign(key, key_bits,
			      params[1].memref.buffer,
			      params[1].memref.size,
			      params[2].memref.buffer,
			      &params[2].memref.size);

out:
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	return res;
}

static TEE_Result cmd_verify(uint32_t pt,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT);

	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type;
	uint32_t perms;
	uint32_t key_bits;
	TEE_Result res;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = keystore_load(params[0].memref.buffer,
			    params[0].memref.size,
			    &type, &perms, &key);
	if (res != TEE_SUCCESS) {
		params[3].value.a = 0;
		return res;
	}

	res = acl_check(perms, PERM_VERIFY);
	if (res != TEE_SUCCESS) {
		params[3].value.a = 0;
		goto out;
	}

	key_bits = (type == KEY_TYPE_RSA_KEYPAIR) ? 2048 : 256;
	res = crypto_rsa_verify(key, key_bits,
				params[1].memref.buffer,
				params[1].memref.size,
				params[2].memref.buffer,
				params[2].memref.size);

	params[3].value.a = (res == TEE_SUCCESS) ? 1 : 0;

out:
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	return TEE_SUCCESS;
}

static TEE_Result cmd_encrypt_aes(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type;
	uint32_t perms;
	TEE_Result res;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = keystore_load(params[0].memref.buffer,
			    params[0].memref.size,
			    &type, &perms, &key);
	if (res != TEE_SUCCESS)
		return res;

	res = acl_check(perms, PERM_ENCRYPT);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_aes_encrypt(key, 256,
				 params[1].memref.buffer,
				 params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size);
out:
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	return res;
}

static TEE_Result cmd_decrypt_aes(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type;
	uint32_t perms;
	TEE_Result res;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = keystore_load(params[0].memref.buffer,
			    params[0].memref.size,
			    &type, &perms, &key);
	if (res != TEE_SUCCESS)
		return res;

	res = acl_check(perms, PERM_DECRYPT);
	if (res != TEE_SUCCESS)
		goto out;

	res = crypto_aes_decrypt(key, 256,
				 params[1].memref.buffer,
				 params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size);
out:
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	return res;
}

static TEE_Result cmd_get_info(uint32_t pt,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	struct key_info info;

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < sizeof(info))
		return TEE_ERROR_SHORT_BUFFER;

	memset(&info, 0, sizeof(info));
	TEE_Result res = keystore_get_info(params[0].memref.buffer,
					   params[0].memref.size, &info);
	if (res == TEE_SUCCESS) {
		memcpy(params[1].memref.buffer, &info, sizeof(info));
		params[1].memref.size = sizeof(info);
	}
	return res;
}

static TEE_Result cmd_rsa_decrypt(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t type, perms;
	TEE_Result res;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = keystore_load(params[0].memref.buffer,
			    params[0].memref.size, &type, &perms, &key);
	if (res != TEE_SUCCESS)
		return res;

	if (type != KEY_TYPE_RSA_KEYPAIR) {
		EMSG("Decrypt only supported for RSA keypairs");
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	res = crypto_rsa_decrypt(key, 2048,
				 params[1].memref.buffer,
				 params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size);
out:
	if (key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key);
	return res;
}

static TEE_Result cmd_provision_lock(uint32_t pt,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	(void)params;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	pin_mgr_lock();
	return TEE_SUCCESS;
}

/* ---- SO (Security Officer) command handlers ---- */

static TEE_Result cmd_so_pin_init(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return so_pin_init(params[0].memref.buffer,
			   params[0].memref.size);
}

static TEE_Result cmd_provision_dongle(uint32_t pt,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	return so_provision_dongle(params[0].memref.buffer,
				   params[0].memref.size);
}

static TEE_Result cmd_so_unlock_req(uint32_t pt,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE);

	uint32_t dongle_count = 0;
	uint32_t cooldown_left = 0;
	TEE_Result res;

	if (pt != exp_pt || !params[0].memref.buffer || !params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	g_so_challenge_valid = 0;

	res = so_unlock_req(params[0].memref.buffer,
			    params[0].memref.size,
			    params[1].memref.buffer,
			    params[1].memref.size,
			    &dongle_count, &cooldown_left);

	params[2].value.a = dongle_count;
	params[2].value.b = cooldown_left;

	if (res == TEE_SUCCESS) {
		memcpy(g_so_challenge, params[1].memref.buffer, 32);
		g_so_challenge_valid = 1;
		params[1].memref.size = 36 + dongle_count * 36;
	}

	return res;
}

static TEE_Result cmd_so_lock(uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	(void)params;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	so_pin_lock();
	return TEE_SUCCESS;
}

static TEE_Result cmd_so_unlock_confirm(uint32_t pt,
					TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	(void)params;

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!g_so_challenge_valid) {
		EMSG("SO unlock confirm: no prior CMD_SO_UNLOCK_REQ");
		return TEE_ERROR_BAD_STATE;
	}

	g_so_challenge_valid = 0;
	so_unlock_confirm();
	return TEE_SUCCESS;
}

static TEE_Result cmd_so_get_info(uint32_t pt,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE);

	struct so_status st;

	if (pt != exp_pt || !params[0].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].memref.size < sizeof(st))
		return TEE_ERROR_SHORT_BUFFER;

	so_pin_get_info(&st);
	memcpy(params[0].memref.buffer, &st, sizeof(st));
	params[0].memref.size = sizeof(st);

	return TEE_SUCCESS;
}

/* ---- Gate: check if command requires PIN verification ---- */

static int cmd_is_so(uint32_t cmd_id)
{
	switch (cmd_id) {
	case CMD_SO_PIN_INIT:
	case CMD_PROVISION_DONGLE:
	case CMD_SO_UNLOCK_REQ:
	case CMD_SO_LOCK:
	case CMD_SO_GET_INFO:
	case CMD_SO_UNLOCK_CONFIRM:
		return 1;
	default:
		return 0;
	}
}

static int cmd_needs_pin(uint32_t cmd_id)
{
	if (cmd_is_so(cmd_id))
		return 0;

	switch (cmd_id) {
	case CMD_PIN_INIT:
	case CMD_PROVISION_LOCK:
		return 0;
	default:
		return 1;
	}
}

static int cmd_needs_write(uint32_t cmd_id)
{
	switch (cmd_id) {
	case CMD_KEY_GEN_RSA:
	case CMD_KEY_GEN_AES:
	case CMD_KEY_DELETE:
	case CMD_PIN_INIT:
	case CMD_SO_PIN_INIT:
	case CMD_PROVISION_DONGLE:
		return 1;
	default:
		return 0;
	}
}

/* ---- TA entry points ---- */

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("TBox Keystore TA created");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("TBox Keystore TA destroyed");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS],
				    void **sess_ctx)
{
	(void)param_types;
	(void)params;
	(void)sess_ctx;

	pin_mgr_restore();
	so_pin_restore();

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)sess_ctx;
	/*
	 * SO auto-lock is intentionally NOT called here.
	 * UNLOCKED state persists across sessions until:
	 *   - explicit CMD_SO_LOCK (--so-lock)
	 *   - 5-minute idle timeout (not yet implemented)
	 *   - TA restart
	 *   - 1000 total SO-PIN failures (SO_BRICKED)
	 */
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;

	(void)sess_ctx;

	/* Gate 1: PIN check */
	if (cmd_needs_pin(cmd_id)) {
		res = pin_mgr_verify();
		if (res != TEE_SUCCESS)
			return res;
	}

	/* Gate 2: Write protection */
	if (cmd_needs_write(cmd_id) && pin_mgr_is_locked() &&
	    !so_pin_is_unlocked()) {
		EMSG("TA is locked, write operation denied");
		return TEE_ERROR_ACCESS_DENIED;
	}

	switch (cmd_id) {
	case CMD_PIN_INIT:
		return cmd_pin_init(param_types, params);
	case CMD_KEY_GEN_RSA:
		return cmd_key_gen_rsa(param_types, params);
	case CMD_KEY_GEN_AES:
		return cmd_key_gen_aes(param_types, params);
	case CMD_KEY_EXPORT_PUB:
		return cmd_key_export_pub(param_types, params);
	case CMD_KEY_DELETE:
		return cmd_key_delete(param_types, params);
	case CMD_SIGN:
		return cmd_sign(param_types, params);
	case CMD_VERIFY:
		return cmd_verify(param_types, params);
	case CMD_ENCRYPT_AES:
		return cmd_encrypt_aes(param_types, params);
	case CMD_DECRYPT_AES:
		return cmd_decrypt_aes(param_types, params);
	case CMD_RSA_DECRYPT:
		return cmd_rsa_decrypt(param_types, params);
	case CMD_GET_INFO:
		return cmd_get_info(param_types, params);
	case CMD_PROVISION_LOCK:
		return cmd_provision_lock(param_types, params);

	/* SO commands */
	case CMD_SO_PIN_INIT:
		return cmd_so_pin_init(param_types, params);
	case CMD_PROVISION_DONGLE:
		return cmd_provision_dongle(param_types, params);
	case CMD_SO_UNLOCK_REQ:
		return cmd_so_unlock_req(param_types, params);
	case CMD_SO_LOCK:
		return cmd_so_lock(param_types, params);
	case CMD_SO_GET_INFO:
		return cmd_so_get_info(param_types, params);
	case CMD_SO_UNLOCK_CONFIRM:
		return cmd_so_unlock_confirm(param_types, params);

	default:
		EMSG("Unsupported command ID: 0x%x", (unsigned int)cmd_id);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
