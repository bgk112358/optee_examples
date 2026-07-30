/*
 * Copyright (c) 2024, TBox Keystore Example
 *
 * Shared definitions between TA and CA.
 */

#ifndef __TBOX_KEYSTORE_TA_H__
#define __TBOX_KEYSTORE_TA_H__

/* UUID of the Trusted Application */
#define TA_TBOX_KEYSTORE_UUID \
	{ 0xf8e9209a, 0x3c7d, 0x4d6b, \
		{ 0xa1, 0x5e, 0x7f, 0x32, 0x8b, 0x11, 0xc0, 0x49 } }

/* ---- Command IDs ---- */

/*
 * CMD_PIN_INIT - Store provisioning PIN (once-only)
 * param[0] (memref) PIN data
 */
#define CMD_PIN_INIT		0

/*
 * CMD_KEY_GEN_RSA - Generate RSA key pair in TEE
 * param[0] (memref) key label string (max 64 bytes)
 * param[1] (value)  a: key size in bits (2048/4096), b: permissions bitmask
 */
#define CMD_KEY_GEN_RSA		1

/*
 * CMD_KEY_GEN_AES - Generate AES key in TEE
 * param[0] (memref) key label string (max 64 bytes)
 * param[1] (value)  a: key size in bits (128/256), b: permissions bitmask
 */
#define CMD_KEY_GEN_AES		2

/*
 * CMD_KEY_EXPORT_PUB - Export RSA public key
 * param[0] (memref) key label string
 * param[1] (memref) output buffer: DER-encoded public key (SubjectPublicKeyInfo)
 */
#define CMD_KEY_EXPORT_PUB	3

/*
 * CMD_KEY_DELETE - Delete a persistent key
 * param[0] (memref) key label string
 */
#define CMD_KEY_DELETE		4

/*
 * CMD_SIGN - RSA sign (SHA-256 + PKCS#1 v1.5)
 * param[0] (memref) key label string
 * param[1] (memref) data to sign
 * param[2] (memref) output: signature
 */
#define CMD_SIGN		5

/*
 * CMD_VERIFY - RSA verify
 * param[0] (memref) key label string
 * param[1] (memref) original data
 * param[2] (memref) signature to verify
 * param[3] (value)  a: result (0=fail, 1=pass)
 */
#define CMD_VERIFY		6

/*
 * CMD_ENCRYPT_AES - AES-CBC encrypt (no padding, caller manages alignment)
 * param[0] (memref) key label string
 * param[1] (memref) plaintext (must be 16-byte aligned)
 * param[2] (memref) output: ciphertext
 */
#define CMD_ENCRYPT_AES		7

/*
 * CMD_DECRYPT_AES - AES-CBC decrypt (no padding)
 * param[0] (memref) key label string
 * param[1] (memref) ciphertext (must be 16-byte aligned)
 * param[2] (memref) output: plaintext
 */
#define CMD_DECRYPT_AES		8

/*
 * CMD_GET_INFO - Get key info by label
 * param[0] (memref) key label string
 * param[1] (memref) output: key info struct (see below)
 */
#define CMD_GET_INFO		9

/*
 * CMD_PROVISION_LOCK - Lock the TA (disable PIN_INIT and KEY_GEN/DELETE)
 * param[0] unused
 */
#define CMD_PROVISION_LOCK	10

/*
 * CMD_RSA_DECRYPT - RSA PKCS#1 v1.5 decrypt (private-key operation)
 * param[0] (memref) key label string
 * param[1] (memref) ciphertext
 * param[2] (memref) output: plaintext
 */
#define CMD_RSA_DECRYPT		11

/* ---- SO (Security Officer) commands ---- */

/*
 * CMD_SO_PIN_INIT - Store SO-PIN (provisioning phase only)
 * param[0] (memref) SHA-256(PIN) (32 bytes)
 */
#define CMD_SO_PIN_INIT		12

/*
 * CMD_PROVISION_DONGLE - Register authorised dongle public key
 * param[0] (memref) P-256 public key DER
 */
#define CMD_PROVISION_DONGLE	13

/*
 * CMD_SO_UNLOCK_REQ - Request SO unlock challenge (Phase 1)
 * param[0] (memref) SHA-256(SO-PIN) (32 bytes)
 * param[1] (memref) output: challenge[32] + dongle_list[]
 * param[2] (value)  a: dongle_count, b: cooldown_seconds_left
 */
#define CMD_SO_UNLOCK_REQ	14

/*
 * CMD_SO_UNLOCK_VERIFY - Submit signed challenge (Phase 2)
 * param[0] (memref) P-256 public key DER
 * param[1] (memref) ECDSA signature DER (64-72 bytes)
 * param[2] (value)  a: dongle_index (0..7)
 */
#define CMD_SO_UNLOCK_VERIFY	15

/*
 * CMD_SO_LOCK - Explicitly re-lock TA (UNLOCKED → LOCKED)
 */
#define CMD_SO_LOCK		16

/*
 * CMD_SO_GET_INFO - Query SO state
 * param[0] (memref) output: struct so_status
 */
#define CMD_SO_GET_INFO		17

/* ---- Key type identifiers ---- */
#define KEY_TYPE_RSA_KEYPAIR	1
#define KEY_TYPE_AES		2

/* ---- Permission bitmask ---- */
#define PERM_SIGN		0x01
#define PERM_VERIFY		0x02
#define PERM_ENCRYPT		0x04
#define PERM_DECRYPT		0x08
#define PERM_EXPORT_PUB		0x10

/* Maximum key label length */
#define KEY_LABEL_MAX		64

/* Key info structure returned by CMD_GET_INFO */
struct key_info {
	uint32_t type;
	uint32_t size_bits;
	uint32_t permissions;
	uint8_t  label[KEY_LABEL_MAX];
};

/* ---- SO (Security Officer) shared structures ---- */

/* Maximum number of authorised dongles per device */
#define SO_DONGLE_MAX		8

/* SO state enum (returned in so_status.state) */
#define SO_STATE_UNSET		0
#define SO_STATE_PROVISIONED	1
#define SO_STATE_LOCKED		2
#define SO_STATE_UNLOCKED	3
#define SO_STATE_BRICKED	4

/* Dongle entry stored in TA whitelist */
struct so_dongle_entry {
	uint8_t  pubkey_hash[32];   /* SHA-256(public key DER)           */
	uint8_t  serial[4];        /* Dongle serial number (optional)    */
};

/* SO status returned by CMD_SO_GET_INFO */
struct so_status {
	uint32_t state;            /* SO_STATE_*                        */
	uint32_t dongle_count;     /* Number of registered dongles      */
	uint32_t fail_total;       /* Total SO-PIN failures (0..1000)   */
	uint32_t fail_consecutive; /* Consecutive failures (0..3)       */
	uint32_t cooldown_left;    /* Cooldown seconds remaining        */
	uint32_t reserved[3];      /* Reserved for future use           */
};

/* Output buffer format for CMD_SO_UNLOCK_REQ param[1]:
 *   [0..31]    challenge (32 bytes, TEE_GenerateRandom)
 *   [32..35]   dongle_count (uint32_t, little-endian)
 *   [36..67]   dongle[0].pubkey_hash (32 bytes)
 *   [68..71]   dongle[0].serial (4 bytes)
 *   [72..103]  dongle[1].pubkey_hash
 *   ... (repeats for each registered dongle)
 */
#define SO_CHG_BUF_SIZE     (32 + 4 + SO_DONGLE_MAX * 36)

#endif /* __TBOX_KEYSTORE_TA_H__ */
