/*
 * Copyright (c) 2014, hehe.zhou@trustonic.com
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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <key.h>
#include <store.h>

static TEE_Result sm2_arithmetic(TEE_ObjectHandle key, uint32_t mode, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len)
{
	TEE_Result res;

	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	uint32_t alg = 0;
	
	EMSG("%s enter", __func__);

	if (!key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1 error! res=0x%x", res);
		return res;
	}

	switch (mode)
	{
		case TEE_MODE_ENCRYPT:
		case TEE_MODE_DECRYPT:
			alg = TEE_ALG_SM2_PKE;
			break;
		case TEE_MODE_SIGN:
		case TEE_MODE_VERIFY:
			alg = TEE_ALG_SM2_DSA_SM3;
			break;
	}

    EMSG("%s key_info, keySize = %d, objectSize = %d, maxKeySize = %d, maxObjectSize = %d, dataSize = %d", __func__,
        key_info.keySize, key_info.objectSize, key_info.maxKeySize, key_info.maxObjectSize, key_info.dataSize);
	res = TEE_AllocateOperation(&op, alg, mode, key_info.maxKeySize);
	if (res) {
		EMSG("TEE_AllocateTransientObject error! res=0x%x", res);
		return res;
	}

	res = TEE_SetOperationKey(op, key);
	if (res) {
		EMSG("TEE_SetOperationKey error! res=0x%x", res);
		TEE_FreeOperation(op);
		return res;
	}

	switch (mode)
	{
		case TEE_MODE_ENCRYPT:
			res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricEncrypt error! res=0x%x", res);
			}
			break;
		case TEE_MODE_DECRYPT:
			res = TEE_AsymmetricDecrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricDecrypt error! res=0x%x", res);
			}
			break;
		case TEE_MODE_SIGN:
			res = TEE_AsymmetricSignDigest(op, NULL, 0, inbuf, inbuf_len, outbuf, outbuf_len);
			if (res) {
				EMSG("TEE_AllocateTransientObject error! res=0x%x", res);
			}
			break;
		case TEE_MODE_VERIFY:
			res = TEE_AsymmetricVerifyDigest(op, NULL, 0, inbuf, inbuf_len, outbuf, *outbuf_len);
			if (res) {
				EMSG("TEE_AsymmetricVerifyDigest error! res=0x%x", res);
			}
			break;
	}

	TEE_FreeOperation(op);
	
	EMSG("%s exit", __func__);
	return res;

}

#define SM2(name1,name2) \
TEE_Result sm2_##name1(TEE_ObjectHandle key, const void *inbuf, uint32_t inbuf_len, void *outbuf, size_t *outbuf_len) \
{ \
	return sm2_arithmetic(key, TEE_MODE_##name2, inbuf, inbuf_len, outbuf, outbuf_len); \
}

SM2(enc, ENCRYPT)
SM2(dec, DECRYPT)
SM2(sign, SIGN)
SM2(verify, VERIFY)
