/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __SECURE_TA_H__
#define __SECURE_TA_H__

/* UUID of the trusted application */
#define TA_SECURE_UUID \
		{ 0xf4e750bb, 0x1437, 0x4fbf, \
			{ 0x87, 0x85, 0x8d, 0x35, 0x80, 0xc3, 0x49, 0x04 } }
/*
 * TA_SECURE_CMD_READ_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data dumped from the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_CMD_READ_RAW		0

/*
 * TA_SECURE_CMD_WRITE_RAW - Create and fill a secure storage file
 * param[0] (memref) ID used the identify the persistent object
 * param[1] (memref) Raw data to be writen in the persistent object
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_CMD_WRITE_RAW		1

/*
 * TA_SECURE_CMD_DELETE - Delete a persistent object
 * param[0] (memref) ID used the identify the persistent object
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SECURE_CMD_DELETE        2

/*
 * in	params[0].value.a key size
 */
#define TA_ACIPHER_CMD_GEN_KEY          3

/*
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_ACIPHER_CMD_ENCRYPT		4

/*
 * in	params[0].memref.buffer key id
 * in	params[0].memref.size   key id size
 * in	params[1].value.a       key length
 */
#define TA_CMD_KEY_RSA_GEN		5

/*
 * in	params[0].memref.buffer key id
 * in	params[0].memref.size   key id size
 * out	params[1].memref.buffer key attr value
 * out	params[1].memref.size   key attr value size
 */
#define TA_CMD_KEY_BUFFER_GET       6

/*
 * in	params[0].memref  key id
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_CMD_CRYPTO_RSA_ENC       7

/*
* in	params[0].memref  key slot
* in	params[1].memref  input
* out	params[2].memref  output
*/
#define TA_CMD_CRYPTO_RSA_DEC       8

/*
* in	params[0].memref.buffer key id
* in	params[0].memref.size   key id size
* in	params[1].value.a       key length
*/
#define TA_CMD_KEY_AES_GEN          9

/*
* in	params[0].memref.buffer iv name
* in	params[0].memref.size   iv name size
* in	params[1].value.a       key length
*/
#define TA_CMD_KEY_AES_IV           10

/*
* in	params[0].memref  key id
* in	params[1].memref  input
* out	params[2].memref  output
*/
#define TA_CMD_CRYPTO_AES_ENC       11

/*
* in	params[0].memref  key slot
* in	params[1].memref  input
* out	params[2].memref  output
*/
#define TA_CMD_CRYPTO_AES_DEC       12


/*
* in	params[0].memref.buffer key id
* in	params[0].memref.size   key id size
* in	params[1].value.a       key length
*/
#define TA_CMD_KEY_SM2_PKE_GEN		13

/*
* in	params[0].memref.buffer key id
* in	params[0].memref.size   key id size
* in	params[1].value.a       key length
*/
#define TA_CMD_KEY_SM2_DSA_GEN		14

/*
* in	params[0].memref  key id
* in	params[1].memref  input
* out	params[2].memref  output
*/
#define TA_CMD_CRYPTO_SM2_PKE_ENC	15

/*
* in	params[0].memref  key id
* in	params[1].memref  input
* out	params[2].memref  output
*/
#define TA_CMD_CRYPTO_SM2_PKE_DEC	16

/*
* in	params[0].memref  key id
* in	params[1].memref  digest
* out	params[2].memref  sign
*/
#define TA_CMD_CRYPTO_SM2_DSA_SIGN	17

/*
* in	params[0].memref  key id
* in	params[1].memref  digest
* in	params[2].memref  sign
* out	params[1].value.a res
*/
#define TA_CMD_CRYPTO_SM2_DSA_VERIFY	18


#define TA_CMD_KEY_SM4_GEN			19

#define TA_CMD_CRYPTO_SM4_ENC		20

#define TA_CMD_CRYPTO_SM4_DEC		21

/*
* in	params[0].memref  key id
* in	params[1].memref  digest
* out	params[2].memref  sign
*/
#define TA_CMD_CRYPTO_RSA_SIGN		22

/*
* in	params[0].memref  key id
* in	params[1].memref  digest
* in	params[2].memref  sign
* out	params[1].value.a res
*/
#define TA_CMD_CRYPTO_RSA_VERIFY	23


#define TA_CMD_CRYPTO_SM3			24

#define TA_CMD_CRYPTO_SHA			25

#endif /* __SECURE_TA_H__ */
