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

#endif /* __TBOX_KEYSTORE_TA_H__ */
