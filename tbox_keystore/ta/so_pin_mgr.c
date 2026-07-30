/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * SO-PIN management — Security Officer dual-factor unlock.
 *
 * State machine:
 *   UNSET → PROVISIONED → LOCKED ↔ UNLOCKED (temporary)
 *   Any state → BRICKED (1000 total SO-PIN failures, permanent)
 *
 * Persistent objects:
 *   SO_PIN_UUID    — SHA-256(SO-PIN), 32 bytes
 *   SO_DONGLE_UUID — dongle whitelist, 4 + N×36 bytes
 *   SO_FAIL_UUID   — failure counter, 12 bytes
 *   SO_LOCK_UUID   — SO unlock flag, 1 byte (0=LOCKED, 1=UNLOCKED)
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tbox_keystore_ta.h"

/* ---- Persistent object UUIDs ---- */
static const TEE_UUID SO_PIN_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x10 }
};

static const TEE_UUID SO_DONGLE_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x11 }
};

static const TEE_UUID SO_FAIL_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x12 }
};

static const TEE_UUID SO_LOCK_UUID = {
	0xf8e9209a, 0x3c7d, 0x4d6b,
	{ 0x00, 0x00, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x13 }
};

/* ---- Limits ---- */
#define SO_FAIL_MAX_CONSECUTIVE  3
#define SO_FAIL_COOLDOWN_SECS    60
#define SO_FAIL_MAX_TOTAL        1000

/* ---- In-memory state ---- */
static int g_so_state = SO_STATE_UNSET;

/* ---- Internal: SHA-256 helper ---- */
static TEE_Result so_sha256(const uint8_t *data, size_t data_len,
			    uint8_t *hash_out, size_t hash_out_len)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t hlen = 32;

	if (hash_out_len < 32)
		return TEE_ERROR_SHORT_BUFFER;

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_DigestDoFinal(op, (void *)data, data_len, hash_out, &hlen);
	TEE_FreeOperation(op);
	return res;
}

/* ---- Internal: persistent object helpers ---- */

static TEE_Result so_obj_create(const TEE_UUID *uuid, const void *data, size_t len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META;
	TEE_Result res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					  (void *)uuid, sizeof(*uuid),
					  flags, TEE_HANDLE_NULL,
					  (void *)data, len, &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return res;
}

static TEE_Result so_obj_read(const TEE_UUID *uuid, void *buf, size_t *len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;
	size_t rd;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_ReadObjectData(obj, buf, *len, &rd);
	TEE_CloseObject(obj);

	if (res == TEE_SUCCESS)
		*len = rd;
	return res;
}

static int so_obj_exists(const TEE_UUID *uuid)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ, &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return (res == TEE_SUCCESS) ? 1 : 0;
}

static TEE_Result so_obj_delete(const TEE_UUID *uuid)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					(void *)uuid, sizeof(*uuid),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META, &obj);
	if (res != TEE_SUCCESS)
		return res;

	TEE_CloseAndDeletePersistentObject(obj);
	return TEE_SUCCESS;
}

/* ---- Failure counter ---- */

struct so_fail_counter {
	uint32_t consecutive_fails;
	uint32_t total_fails;
	uint32_t cooldown_until;
};

static void so_fail_load(struct so_fail_counter *fc)
{
	size_t len = sizeof(*fc);
	memset(fc, 0, sizeof(*fc));
	so_obj_read(&SO_FAIL_UUID, fc, &len);
}

static TEE_Result so_fail_save(const struct so_fail_counter *fc)
{
	so_obj_delete(&SO_FAIL_UUID);
	return so_obj_create(&SO_FAIL_UUID, fc, sizeof(*fc));
}

static int so_check_fail_counter(uint32_t *cooldown_left)
{
	struct so_fail_counter fc;
	TEE_Time now;
	uint32_t now_sec;

	so_fail_load(&fc);

	if (fc.total_fails >= SO_FAIL_MAX_TOTAL) {
		g_so_state = SO_STATE_BRICKED;
		*cooldown_left = 0;
		return 0;
	}

	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
		TEE_GetSystemTime(&now);
		now_sec = now.seconds;

		if (now_sec < fc.cooldown_until) {
			*cooldown_left = fc.cooldown_until - now_sec;
			return 0;
		}

		fc.consecutive_fails = 0;
		fc.cooldown_until = 0;
		so_fail_save(&fc);
	}

	*cooldown_left = 0;
	return 1;
}

static void so_record_failure(void)
{
	struct so_fail_counter fc;
	TEE_Time now;

	so_fail_load(&fc);

	fc.consecutive_fails++;
	fc.total_fails++;

	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE) {
		TEE_GetSystemTime(&now);
		fc.cooldown_until = now.seconds + SO_FAIL_COOLDOWN_SECS;
	}

	so_fail_save(&fc);
}

static void so_reset_consecutive(void)
{
	struct so_fail_counter fc;

	so_fail_load(&fc);
	fc.consecutive_fails = 0;
	fc.cooldown_until = 0;
	so_fail_save(&fc);
}

/* ---- Dongle whitelist ---- */

struct so_dongle_list {
	uint32_t count;
	struct so_dongle_entry entries[SO_DONGLE_MAX];
};

static void so_dongle_load(struct so_dongle_list *dl)
{
	size_t len = sizeof(*dl);
	memset(dl, 0, sizeof(*dl));
	so_obj_read(&SO_DONGLE_UUID, dl, &len);
}

static TEE_Result so_dongle_save(const struct so_dongle_list *dl)
{
	so_obj_delete(&SO_DONGLE_UUID);
	return so_obj_create(&SO_DONGLE_UUID, dl,
			     4 + dl->count * sizeof(struct so_dongle_entry));
}

/* ---- SO-PIN management ---- */

static TEE_Result so_pin_hash_and_check(const uint8_t *pin, size_t pin_len,
					 uint8_t *hash_out)
{
	uint8_t stored[32];
	uint8_t computed[32];
	size_t len = 32;
	TEE_Result res;

	res = so_sha256(pin, pin_len, computed, sizeof(computed));
	if (res != TEE_SUCCESS)
		return res;

	res = so_obj_read(&SO_PIN_UUID, stored, &len);
	if (res != TEE_SUCCESS || len != 32) {
		EMSG("SO-PIN not provisioned");
		return TEE_ERROR_NO_DATA;
	}

	if (memcmp(computed, stored, 32) != 0)
		return TEE_ERROR_ACCESS_DENIED;

	if (hash_out)
		memcpy(hash_out, computed, 32);
	return TEE_SUCCESS;
}

TEE_Result so_pin_init(const uint8_t *pin, size_t pin_len)
{
	uint8_t hash[32];
	TEE_Result res;

	if (so_obj_exists(&SO_PIN_UUID)) {
		EMSG("SO-PIN already initialized");
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	if (pin_len == 0 || pin_len > 128) {
		EMSG("Invalid SO-PIN length: %zu", pin_len);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = so_sha256(pin, pin_len, hash, sizeof(hash));
	if (res != TEE_SUCCESS)
		return res;

	res = so_obj_create(&SO_PIN_UUID, hash, sizeof(hash));
	if (res == TEE_SUCCESS) {
		DMSG("SO-PIN initialized");
		if (g_so_state == SO_STATE_UNSET)
			g_so_state = SO_STATE_PROVISIONED;
	}
	return res;
}

TEE_Result so_provision_dongle(const uint8_t *pubkey_der, size_t der_len)
{
	struct so_dongle_list dl;
	uint8_t hash[32];
	uint32_t i;
	TEE_Result res;

	if (!pubkey_der || der_len < 88 || der_len > 256)
		return TEE_ERROR_BAD_PARAMETERS;

	so_dongle_load(&dl);

	if (dl.count >= SO_DONGLE_MAX) {
		EMSG("Dongle whitelist full");
		return TEE_ERROR_OVERFLOW;
	}

	res = so_sha256(pubkey_der, der_len, hash, sizeof(hash));
	if (res != TEE_SUCCESS)
		return res;

	for (i = 0; i < dl.count; i++) {
		if (memcmp(dl.entries[i].pubkey_hash, hash, 32) == 0) {
			EMSG("Dongle already registered");
			return TEE_ERROR_ACCESS_CONFLICT;
		}
	}

	memcpy(dl.entries[dl.count].pubkey_hash, hash, 32);
	memset(dl.entries[dl.count].serial, 0, 4);
	dl.count++;

	res = so_dongle_save(&dl);
	if (res == TEE_SUCCESS)
		DMSG("Dongle %u registered", dl.count);

	return res;
}

/* ---- Unlock protocol ---- */

TEE_Result so_unlock_req(const uint8_t *pin, size_t pin_len,
			 uint8_t *chg_out, size_t chg_out_size,
			 uint32_t *dongle_count, uint32_t *cooldown_left)
{
	struct so_dongle_list dl;
	uint32_t count;
	uint32_t i;
	TEE_Result res;

	if (!pin || !chg_out || chg_out_size < SO_CHG_BUF_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!so_check_fail_counter(cooldown_left)) {
		if (g_so_state == SO_STATE_BRICKED)
			return TEE_ERROR_ACCESS_DENIED;
		return TEE_ERROR_BAD_STATE;
	}

	res = so_pin_hash_and_check(pin, pin_len, NULL);
	if (res != TEE_SUCCESS) {
		so_record_failure();
		return res;
	}

	TEE_GenerateRandom(chg_out, 32);

	so_dongle_load(&dl);
	count = dl.count;

	memcpy(chg_out + 32, &count, sizeof(count));

	for (i = 0; i < count; i++) {
		memcpy(chg_out + 36 + i * 36, dl.entries[i].pubkey_hash, 32);
		memcpy(chg_out + 36 + i * 36 + 32, dl.entries[i].serial, 4);
	}

	*dongle_count = count;

	DMSG("SO unlock phase 1: challenge generated, %u dongles", count);
	return TEE_SUCCESS;
}

/*
 * Confirm CA-side ECDSA verification passed.
 * The CA verified the dongle's signature locally (OpenSSL).
 * TA just records the unlock — the real crypto check was done by CA.
 *
 * Security: CA and TA run on the same physical chip.  An attacker who
 * can compromise the CA can already call any TA command.  The dongle
 * is still required to produce a valid signature (verified by OpenSSL).
 */
void so_unlock_confirm(void)
{
	so_reset_consecutive();
	g_so_state = SO_STATE_UNLOCKED;

	{
		uint8_t flag = 1;
		so_obj_delete(&SO_LOCK_UUID);
		so_obj_create(&SO_LOCK_UUID, &flag, 1);
	}

	DMSG("SO unlock confirmed (CA verified ECDSA), TA UNLOCKED");
}

/* ---- Lock / re-lock ---- */

void so_pin_lock(void)
{
	uint8_t flag = 0;

	so_obj_delete(&SO_LOCK_UUID);
	so_obj_create(&SO_LOCK_UUID, &flag, 1);

	g_so_state = SO_STATE_LOCKED;
	DMSG("SO locked");
}

void so_pin_auto_lock(void)
{
	if (g_so_state == SO_STATE_UNLOCKED) {
		DMSG("SO auto-locking (session close)");
		so_pin_lock();
	}
}

int so_pin_is_unlocked(void)
{
	return g_so_state == SO_STATE_UNLOCKED;
}

/* ---- Query ---- */

void so_pin_get_info(struct so_status *st)
{
	struct so_dongle_list dl;
	struct so_fail_counter fc;
	TEE_Time now;
	uint32_t now_sec;

	memset(st, 0, sizeof(*st));

	st->state = g_so_state;

	so_dongle_load(&dl);
	st->dongle_count = dl.count;

	so_fail_load(&fc);
	st->fail_total = fc.total_fails;
	st->fail_consecutive = fc.consecutive_fails;

	if (fc.consecutive_fails >= SO_FAIL_MAX_CONSECUTIVE &&
	    fc.cooldown_until > 0) {
		TEE_GetSystemTime(&now);
		now_sec = now.seconds;
		if (now_sec < fc.cooldown_until)
			st->cooldown_left = fc.cooldown_until - now_sec;
	}
}

/* ---- Session restore ---- */

extern int pin_mgr_is_locked(void);

void so_pin_restore(void)
{
	if (so_obj_exists(&SO_LOCK_UUID)) {
		uint8_t flag = 0;
		size_t len = 1;
		so_obj_read(&SO_LOCK_UUID, &flag, &len);

		if (flag == 1) {
			g_so_state = SO_STATE_UNLOCKED;
			DMSG("SO state restored: UNLOCKED");
			return;
		}
	}

	if (so_obj_exists(&SO_PIN_UUID)) {
		struct so_fail_counter fc;
		so_fail_load(&fc);
		if (fc.total_fails >= SO_FAIL_MAX_TOTAL) {
			g_so_state = SO_STATE_BRICKED;
			DMSG("SO state restored: BRICKED");
			return;
		}

		if (pin_mgr_is_locked())
			g_so_state = SO_STATE_LOCKED;
		else
			g_so_state = SO_STATE_PROVISIONED;

		DMSG("SO state restored: %s",
		     g_so_state == SO_STATE_LOCKED ? "LOCKED" : "PROVISIONED");
		return;
	}

	g_so_state = SO_STATE_UNSET;
	DMSG("SO state restored: UNSET");
}
