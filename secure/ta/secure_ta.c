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

#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

static TEE_Result delete_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	/*
	 * Check object exists and delete it
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META, /* we must be allowed to delete it */
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		return res;
	}

	TEE_CloseAndDeletePersistentObject1(object);
	TEE_Free(obj_id);

	return res;
}

static TEE_Result create_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_Result res;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;
	uint32_t obj_data_flag;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(data, params[1].memref.buffer, data_sz);

	/*
	 * Create object in secure storage and fill with data
	 */
	obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
			TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
			TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
			TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					obj_data_flag,
					TEE_HANDLE_NULL,
					NULL, 0,		/* we may not fill it right now */
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_WriteObjectData(object, data, data_sz);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_CloseAndDeletePersistentObject1(object);
	} else {
		TEE_CloseObject(object);
	}
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}

static TEE_Result read_raw_object(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *obj_id;
	size_t obj_id_sz;
	char *data;
	size_t data_sz;

	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj_id_sz = params[0].memref.size;
	obj_id = TEE_Malloc(obj_id_sz, 0);
	if (!obj_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(obj_id, params[0].memref.buffer, obj_id_sz);

	data_sz = params[1].memref.size;
	data = TEE_Malloc(data_sz, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					obj_id, obj_id_sz,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(obj_id);
		TEE_Free(data);
		return res;
	}

	res = TEE_GetObjectInfo1(object, &object_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create persistent object, res=0x%08x", res);
		goto exit;
	}

	if (object_info.dataSize > data_sz) {
		/*
		 * Provided buffer is too short.
		 * Return the expected size together with status "short buffer"
		 */
		params[1].memref.size = object_info.dataSize;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_ReadObjectData(object, data, object_info.dataSize,
				 &read_bytes);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, data, read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u",
				res, read_bytes, object_info.dataSize);
		goto exit;
	}

	/* Return the number of byte effectively filled */
	params[1].memref.size = read_bytes;
exit:
	TEE_CloseObject(object);
	TEE_Free(obj_id);
	TEE_Free(data);
	return res;
}



















struct acipher {
	TEE_ObjectHandle key;
};

static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

	TEE_FreeTransientObject(state->key);
	state->key = key;
	return TEE_SUCCESS;
}

static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	IMSG("cmd_enc 1");

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}
	IMSG("cmd_enc 2");
	inbuf = params[0].memref.buffer;
	inbuf_len = params[0].memref.size;
	outbuf = params[1].memref.buffer;
	outbuf_len = params[1].memref.size;
	IMSG("[bxq] inbuf_len = %d", inbuf_len);
	IMSG("[bxq] inbuf = 0x%02x", inbuf);
	IMSG("[bxq] outbuf_len = %d", outbuf_len);
	IMSG("[bxq] outbuf =0x%02x", outbuf);

	res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}
	IMSG("cmd_enc 3");
	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	IMSG("cmd_enc 4");
	res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf,
				    &outbuf_len);
	if (res) {
		if (res == TEE_ERROR_SHORT_BUFFER) {
			IMSG("[bxq] TEE_ERROR_SHORT_BUFFER");
		}
		
		EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[1].memref.size, res);
	}
	params[1].memref.size = outbuf_len;

	IMSG("cmd_enc 5");
out:
	IMSG("cmd_enc 6");
	TEE_FreeOperation(op);
	return res;

}

static TEE_Result secure_cmd_gen_key(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint8_t *key_slot_buf;
	size_t key_slot_size;
	uint32_t key_size;
    uint32_t obj_data_flag;
	TEE_ObjectHandle key_pair;
    TEE_ObjectHandle object;

	void *private_key_data = NULL;
	uint32_t private_key_size = 0;
	void *public_key_data = NULL;
	uint32_t public_key_size = 0;


	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_VALUE_INPUT,
											TEE_PARAM_TYPE_NONE,
											TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

    IMSG("[bxq] secure_cmd_gen_key 1");
	key_slot_size = params[0].memref.size;
	key_slot_buf = TEE_Malloc(key_slot_size, 0);
	if (!key_slot_buf) {
		return TEE_ERROR_OUT_OF_MEMORY;
    }

	TEE_MemMove(key_slot_buf, params[0].memref.buffer, key_slot_size);

    // 创建持久对象
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key_slot_buf, key_slot_size, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &object);
    if (res != TEE_SUCCESS) {
        // 持久对象不存在，创建新的
        obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
        TEE_DATA_FLAG_ACCESS_WRITE |		/* we can later write into the object */
        TEE_DATA_FLAG_ACCESS_WRITE_META |	/* we can later destroy or rename the object */
        TEE_DATA_FLAG_OVERWRITE;		/* destroy existing object of same ID */
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key_slot_buf, key_slot_size, obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
        TEE_Free(key_slot_buf);
        if (res != TEE_SUCCESS) {
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_key 2");
        key_size = params[1].value.a;

        IMSG("[bxq] secure_cmd_gen_key 3");
        res = TEE_AllocateTransientObject(key_type, key_size, &key_pair);
        if (res) {
            EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key_type, key_size, res);
            TEE_CloseObject(object);
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_key 4");
        res = TEE_GenerateKey(key_pair, key_size, NULL, 0);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key_size, res);
            TEE_CloseObject(object);
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_key 5");
        res = TEE_WriteObjectData(object, &key_pair, sizeof(key_pair));
        if (res != TEE_SUCCESS) {
            EMSG("TEE_WriteObjectData failed 0x%08x", res);
            TEE_CloseAndDeletePersistentObject1(object);
        } else {
            IMSG("[bxq] secure_cmd_gen_key 6");
            TEE_CloseObject(object);
        }
        IMSG("[bxq] secure_cmd_gen_key 7");
        TEE_FreeTransientObject(key_pair);
    } else {
        IMSG("[bxq] secure_cmd_gen_key 8");
        TEE_CloseObject(object);
        TEE_Free(key_slot_buf);
    }

	IMSG("[bxq] secure_cmd_gen_key 9");
	return res;
}


static TEE_Result secure_cmd_rsa_enc(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				        TEE_PARAM_TYPE_MEMREF_INPUT,
				        TEE_PARAM_TYPE_MEMREF_OUTPUT,
				        TEE_PARAM_TYPE_NONE);
	TEE_ObjectHandle object;
	TEE_ObjectInfo object_info;
	TEE_Result res;
	uint32_t read_bytes;
	char *key_slot_buf;
	size_t key_slot_size;
    const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
    TEE_OperationHandle op;
    TEE_ObjectInfo key_info;
    TEE_ObjectHandle key_pair;
    const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;

    IMSG("[bxq] secure_cmd_rsa_enc 1");
	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_slot_size = params[0].memref.size;
	key_slot_buf = TEE_Malloc(key_slot_size, 0);
	if (!key_slot_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(key_slot_buf, params[0].memref.buffer, key_slot_size);

	// private_key_size = params[1].memref.size;
	// private_key_data = TEE_Malloc(private_key_size, 0);
	// if (!private_key_data)
	// 	return TEE_ERROR_OUT_OF_MEMORY;

    IMSG("[bxq] secure_cmd_rsa_enc 2");
	/*
	 * Check the object exist and can be dumped into output buffer
	 * then dump it.
	 */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					key_slot_buf, key_slot_size,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_SHARE_READ,
					&object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open persistent object, res=0x%08x", res);
		TEE_Free(key_slot_buf);
		// TEE_Free(private_key_data);
		return res;
	}

    IMSG("[bxq] secure_cmd_rsa_enc 3");

	res = TEE_ReadObjectData(object, &key_pair, sizeof(key_pair), &read_bytes);
	if (res != TEE_SUCCESS || read_bytes != object_info.dataSize) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, sizeof(key_pair));
		goto exit;
	}

    IMSG("[bxq] secure_cmd_gen_key 4");
    res = TEE_GetObjectInfo1(key_pair, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

    inbuf = params[1].memref.buffer;
	inbuf_len = params[1].memref.size;
	outbuf = params[2].memref.buffer;
	outbuf_len = params[2].memref.size;
    IMSG("[bxq] secure_cmd_gen_key 5");
    res = TEE_AllocateOperation(&op, alg, TEE_MODE_ENCRYPT, key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#" PRIx32 ", %" PRId32 "): %#" PRIx32, alg, key_info.keySize, res);
		return res;
	}

    IMSG("[bxq] secure_cmd_gen_key 6");
	res = TEE_SetOperationKey(op, key_pair);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto exit;
	}

    IMSG("[bxq] secure_cmd_gen_key 7");
	res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf, inbuf_len, outbuf, &outbuf_len);
	if (res) {
		EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %" PRId32 "): %#" PRIx32, inbuf_len, params[1].memref.size, res);
	}

    /* Return the number of byte effectively filled */
	params[2].memref.size = outbuf_len;

    IMSG("[bxq] secure_cmd_gen_key 8");
exit:
	TEE_CloseObject(object);
	TEE_Free(key_slot_buf);
	TEE_FreeOperation(op);
	return res;
}




TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	IMSG("[bxq] TA_CreateEntryPoint");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	IMSG("[bxq] TA_DestroyEntryPoint");
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	struct acipher *state;
	IMSG("[bxq] TA_OpenSessionEntryPoint");

	/*
	 * Allocate and init state for the session.
	 */
	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;

	*session = state;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	struct acipher *state = session;
	IMSG("[bxq] TA_CloseSessionEntryPoint");

	TEE_FreeTransientObject(state->key);
	TEE_Free(state);
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {
	case TA_SECURE_CMD_WRITE_RAW:
		return create_raw_object(param_types, params);
	case TA_SECURE_CMD_READ_RAW:
		return read_raw_object(param_types, params);
	case TA_SECURE_CMD_DELETE:
		return delete_object(param_types, params);
	case TA_ACIPHER_CMD_GEN_KEY:
		return cmd_gen_key(session, param_types, params);
	case TA_ACIPHER_CMD_ENCRYPT:
		return cmd_enc(session, param_types, params);
	case TA_SECURE_CMD_GEN_KEY:
		IMSG("Command ID: TA_SECURE_CMD_GEN_KEY");
		return secure_cmd_gen_key(param_types, params);
	case TA_SECURE_CMD_RSA_ENC:
		IMSG("Command ID: TA_SECURE_CMD_RSA_ENC");
		return secure_cmd_rsa_enc(param_types, params);	
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
