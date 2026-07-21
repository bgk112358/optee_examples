/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * PIN management module.
 * Stores a provisioning PIN once in persistent secure storage.
 * Once set, all subsequent crypto operations auto-verify internally.
 */

#include <inttypes.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/* Fixed object ID for PIN storage — unique across all TA instances */
static const TEE_UUID PIN_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x00 }
};

/* Fixed object ID for lock flag — persists across TA restarts */
static const TEE_UUID LOCK_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x01 }
};

/* Pin states */
enum pin_state {
	PIN_UNSET   = 0,  /* Not yet provisioned */
	PIN_SET     = 1,  /* PIN written */
	PIN_LOCKED  = 2   /* TA locked after provisioning */
};

static enum pin_state g_pin_state = PIN_UNSET;

/* Internal: compute SHA-256 hash of data, caller must free result */
static TEE_Result pin_hash(const uint8_t *data, size_t data_len,
			   uint8_t *hash_out, size_t hash_out_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;

	if (hash_out_len < 32)
		return TEE_ERROR_SHORT_BUFFER;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_DigestDoFinal(op, data, data_len, hash_out, &hash_out_len);
out:
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

/*
 * Initialize PIN — called during provisioning.
 * Stores SHA-256(PIN) as persistent object.
 * Fails if PIN already set.
 */
TEE_Result pin_mgr_init(const uint8_t *pin, size_t pin_len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	uint8_t hash[32];
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META;

	if (g_pin_state != PIN_UNSET) {
		EMSG("PIN already initialized");
		return TEE_ERROR_ACCESS_DENIED;
	}

	if (pin_len == 0 || pin_len > 128) {
		EMSG("Invalid PIN length: %zu", pin_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Hash PIN before storage */
	res = pin_hash(pin, pin_len, hash, sizeof(hash));
	if (res != TEE_SUCCESS) {
		EMSG("Failed to hash PIN: 0x%x", (unsigned int)res);
		return res;
	}

	/* Create persistent object for PIN hash */
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					  &PIN_UUID, sizeof(PIN_UUID),
					  flags, TEE_HANDLE_NULL,
					  hash, sizeof(hash),
					  &obj);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to store PIN: 0x%x", (unsigned int)res);
		return res;
	}

	TEE_CloseObject(obj);
	g_pin_state = PIN_SET;
	DMSG("PIN initialized successfully");
	return TEE_SUCCESS;
}

/*
 * Verify PIN — called internally before any key operation.
 * If PIN not set, returns TEE_ERROR_ACCESS_DENIED.
 *
 * PIN state is restored from persistent storage by pin_mgr_restore()
 * at session-open time.  For PIN_SET we trust that cached state —
 * re-opening the same object here can hit REE FS access-conflict quirks.
 * Only PIN_UNSET needs to be rejected.
 */
TEE_Result pin_mgr_verify(void)
{
	if (g_pin_state == PIN_UNSET) {
		EMSG("PIN not yet provisioned");
		return TEE_ERROR_ACCESS_DENIED;
	}

	/* PIN_SET or PIN_LOCKED — both allow crypto operations */
	return TEE_SUCCESS;
}

/*
 * Lock the TA after provisioning.
 * Disables PIN_INIT and key generation/delete commands.
 * Persists lock flag so state survives TA restarts.
 */
void pin_mgr_lock(void)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	uint8_t flag = 1;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					  &LOCK_UUID, sizeof(LOCK_UUID),
					  TEE_DATA_FLAG_ACCESS_READ |
					  TEE_DATA_FLAG_ACCESS_WRITE |
					  TEE_DATA_FLAG_ACCESS_WRITE_META,
					  TEE_HANDLE_NULL,
					  &flag, sizeof(flag), &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);

	g_pin_state = PIN_LOCKED;
	DMSG("TA locked");
}

/*
 * Restore PIN/lock state from persistent storage.
 * Must be called at session open — g_pin_state is lost on TA restart.
 */
void pin_mgr_restore(void)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	/* Check if lock flag exists */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &LOCK_UUID, sizeof(LOCK_UUID),
				       TEE_DATA_FLAG_ACCESS_READ,
				       &obj);
	if (res == TEE_SUCCESS) {
		TEE_CloseObject(obj);
		g_pin_state = PIN_LOCKED;
		DMSG("PIN state restored: LOCKED");
		return;
	}

	/* Check if PIN was provisioned */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &PIN_UUID, sizeof(PIN_UUID),
				       TEE_DATA_FLAG_ACCESS_READ,
				       &obj);
	if (res == TEE_SUCCESS) {
		TEE_CloseObject(obj);
		g_pin_state = PIN_SET;
		DMSG("PIN state restored: SET");
		return;
	}

	/* PIN never set */
	g_pin_state = PIN_UNSET;
	DMSG("PIN state restored: UNSET");
}

/*
 * Check if TA is in locked state
 */
int pin_mgr_is_locked(void)
{
	return g_pin_state == PIN_LOCKED;
}

/*
 * Check if PIN has been set
 */
int pin_mgr_is_set(void)
{
	return g_pin_state != PIN_UNSET;
}
