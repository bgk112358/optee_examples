/*
 * Copyright (c) 2024
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
#include <sm4.h>

static uint8_t iv[16] = {0};

TEE_Result Sm4Encode(TEE_ObjectHandle key, uint32_t algorithm, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_OperationHandle op;
    size_t destLen;
    int outsize;
    uint32_t block = 128;
    TEE_ObjectInfo KeyInfo = {0};

    EMSG("%s enter", __func__);

    TEE_GetObjectInfo1(key, &KeyInfo);

    res = TEE_AllocateOperation(&op, algorithm, TEE_MODE_ENCRYPT, KeyInfo.maxObjectSize);
    if(res != TEE_SUCCESS) {
        EMSG("%s error 1, res = [%x]", __func__, res);
        return res;
    }

    res = TEE_SetOperationKey(op, key);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 2, res = [%x]", __func__, res);
        return res;
    }

    TEE_CipherInit(op, (const void *)iv, sizeof(iv));

    outsize = 0;
    destLen = out->len;

    res = TEE_CipherDoFinal(op, in.data, in.len, out->data, &destLen);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 4, res = [%x]", __func__, res);
        return res;
    }
    out->len = outsize + destLen;

    TEE_FreeOperation(op);

    EMSG("%s exit", __func__);
    return res;
}

TEE_Result Sm4Decode(TEE_ObjectHandle key, uint32_t algorithm, BUFFER in, BUFFER *out)
{
    TEE_Result res;
    TEE_OperationHandle op;
    size_t destLen;
    int outsize;
    uint32_t block = 128;
    TEE_ObjectInfo KeyInfo = {0};

    EMSG("%s enter", __func__);

    TEE_GetObjectInfo1(key, &KeyInfo);

    res = TEE_AllocateOperation(&op, algorithm, TEE_MODE_DECRYPT, KeyInfo.maxObjectSize);
    if(res != TEE_SUCCESS) {
        EMSG("%s error 1, res = [%x]", __func__, res);
        return res;
    }

    res = TEE_SetOperationKey(op, key);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 2, res = [%x]", __func__, res);
        return res;
    }

    TEE_CipherInit(op, (const void *)iv, sizeof(iv));

    outsize = 0;
    destLen = out->len;

    res = TEE_CipherDoFinal(op, in.data, in.len, out->data, &destLen);
    if(res != TEE_SUCCESS) {
        TEE_FreeOperation(op);
        EMSG("%s error 4, res = [%x]", __func__, res);
        return res;
    }
    out->len = outsize + destLen;

    TEE_FreeOperation(op);

    EMSG("%s exit", __func__);
    return res;
}