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


typedef enum {
    RSA_MODULUS             =   0,
    RSA_PUBLIC_EXPONENT     =   1,
    RSA_PRIVATE_EXPONENT    =   2,
    RSA_PRIME1              =   3,
    RSA_PRIME2              =   4,
    RSA_EXPONENT1           =   5,
    RSA_EXPONENT2           =   6,
    RSA_COEFFICIENT         =   7,
    RSA_ATTR_END            =   8
} RSA_ATTR;

typedef enum {
    KEY_SIZE        =   0,
    REVERSE_1       =   1,
    REVERSE_2       =   2,
    REVERSE_3       =   3,
    CUS_PARAMS_END  =   4
} CUS_PARAMS;

const uint32_t tee_rsa_attr[] = {TEE_ATTR_RSA_MODULUS,
                            TEE_ATTR_RSA_PUBLIC_EXPONENT,
                            TEE_ATTR_RSA_PRIVATE_EXPONENT,
                            TEE_ATTR_RSA_PRIME1,
                            TEE_ATTR_RSA_PRIME2,
                            TEE_ATTR_RSA_EXPONENT1,
                            TEE_ATTR_RSA_EXPONENT2,
                            TEE_ATTR_RSA_COEFFICIENT
};

typedef struct {
    uint32_t params[CUS_PARAMS_END];
    uint32_t len[RSA_ATTR_END];
    uint8_t* data[RSA_ATTR_END];
} KEY_ATTR;

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

typedef struct data_stru {
	uint8_t *name;
	uint32_t len;
    uint32_t size;
	uint32_t type;
    TEE_ObjectHandle obj;
} KEY;

static TEE_Result secure_cmd_gen_aes_key(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    uint32_t obj_data_flag;
	KEY key;
    TEE_ObjectHandle object;
    TEE_OperationHandle operation;
    uint8_t *inbuf;
	uint32_t inbuf_len;
	uint8_t *outbuf;
	uint32_t outbuf_len;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_VALUE_INPUT,
											TEE_PARAM_TYPE_NONE,
											TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

    IMSG("[bxq] secure_cmd_gen_aes_key 1");
	key.type = TEE_TYPE_AES;
	key.len = params[0].memref.size;
	key.name = TEE_Malloc(key.len, 0);
	if (!key.name) {
		return TEE_ERROR_OUT_OF_MEMORY;
    }

    IMSG("[bxq] secure_cmd_gen_aes_key 2");
	(void)TEE_MemMove(key.name, params[0].memref.buffer, key.len);

    IMSG("[bxq] secure_cmd_gen_aes_key 3");
	// 创建持久对象
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, key.name, key.len, TEE_DATA_FLAG_ACCESS_READ, &object);
    if (res != TEE_SUCCESS) {
        // 持久对象不存在，创建新的
        obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |         /* we can later read the oject */
                        TEE_DATA_FLAG_ACCESS_WRITE |        /* we can later write into the object */
                        TEE_DATA_FLAG_ACCESS_WRITE_META |   /* we can later destroy or rename the object */
                        TEE_DATA_FLAG_OVERWRITE;            /* destroy existing object of same ID */

        IMSG("[bxq] secure_cmd_gen_aes_key 4");                
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, key.name, key.len, obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
        TEE_Free(key.name);
        if (res != TEE_SUCCESS) {
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_aes_key 5"); 
        key.size = params[1].value.a;

        IMSG("[bxq] secure_cmd_gen_aes_key 6, key.size = %d", key.size);
        res = TEE_AllocateTransientObject(key.type, key.size, &key.obj);
        if (res) {
            EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#" PRIx32, key.type, key.size, res);
            TEE_CloseObject(object);
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_aes_key 6"); 
        res = TEE_GenerateKey(key.obj, key.size, NULL, 0);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32, key.size, res);
            TEE_CloseObject(object);
            return res;
        }

        IMSG("[bxq] secure_cmd_gen_aes_key 7"); 
        res = TEE_AllocateOperation(&operation, TEE_ALG_AES_ECB_NOPAD, TEE_MODE_ENCRYPT, key.size);
		if(TEE_SUCCESS != res){
			EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
			return res;
		}

        IMSG("[bxq] secure_cmd_gen_aes_key 8"); 
        // ECB
		res = TEE_SetOperationKey(operation, key.obj);
		if(TEE_SUCCESS != res){
			EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
			return res;
		}

		TEE_CipherInit(operation, NULL, 0);

        inbuf = params[1].memref.buffer;
        inbuf_len = params[1].memref.size;
        outbuf = params[2].memref.buffer;
        outbuf_len = params[2].memref.size;

        IMSG("[bxq] secure_cmd_gen_aes_key 9"); 
        res = TEE_CipherUpdate(operation, inbuf, inbuf_len, outbuf, &outbuf_len);
        if(TEE_SUCCESS != res){
            EMSG("TEE_CipherUpdata() fail. res = %x.\n", res);
            return res;
        }

        // res = TEE_CipherDoFinal(operation, inbuf + inbuf_len, final_len, result + up_len, &final_len);
        // if(TEE_SUCCESS != res){
        //     EMSG("TEE_CipherDoFinal() fail. res = %x.\n", res);
        //     return res;
        // }
            

    } else {
        IMSG("[bxq] secure_cmd_gen_aes_key 10"); 
        TEE_CloseObject(object);
        TEE_Free(key.name);
    }

	return TEE_SUCCESS;
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

        IMSG("[bxq] secure_cmd_gen_key 3, key_size = %d", key_size);
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

        KEY_ATTR key_attr;
        key_attr.params[KEY_SIZE] = key_size;
        uint32_t buff_len = 0;
        uint32_t buff_head_len = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);

        IMSG("[bxq] secure_cmd_gen_key 5");
        for (size_t i = 0; i < RSA_ATTR_END; i++) {
            IMSG("[bxq] secure_cmd_gen_key 5.1.%d", i);
            // res = TEE_GetObjectBufferAttribute(key_pair, TEE_ATTR_RSA_MODULUS, NULL, &(key_attr.len[i]));
            res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], NULL, &(key_attr.len[i]));
            if(res != TEE_ERROR_SHORT_BUFFER){
                EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
                return res;
            }

            IMSG("[bxq] secure_cmd_gen_key 5.2.%d,  key_attr.len[%d] = %d", i, i, key_attr.len[i]);
            key_attr.data[i] = TEE_Malloc(key_attr.len[i], 0);
            if (!key_slot_buf) {
                EMSG("TEE_Malloc() fail.\n");
                return TEE_ERROR_OUT_OF_MEMORY;
                return res;
            }

            IMSG("[bxq] secure_cmd_gen_key 5.3.%d, key_attr.data[%d] = 0x%02x", i, i, key_attr.data[i]);
            res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], key_attr.data[i], &(key_attr.len[i]));
            if(TEE_SUCCESS != res){
                EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
                return res;
            }
            buff_len += key_attr.len[i];
            IMSG("[bxq] secure_cmd_gen_key 5.4.%d, key_attr.len[%d] = %d", i, i, key_attr.len[i]);

            IMSG_RAW("[bxq] key_attr.data[%d]: ", i);
            for (size_t j = 0; j < key_attr.len[i]; j++) {
                IMSG_RAW("0x%02x ", *(key_attr.data[i] + j));
            }
            IMSG("end");
        }
        TEE_FreeTransientObject(key_pair);

        IMSG("[bxq] secure_cmd_gen_key 6, buff_head_len = %d", buff_head_len);
        buff_len += buff_head_len;
        uint8_t *buff = TEE_Malloc(buff_len, 0);
        if (!buff) {
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        IMSG("[bxq] secure_cmd_gen_key 7, buff_len = %d", buff_len);
        TEE_MemMove(buff, &key_attr, buff_head_len);
        IMSG("[bxq] secure_cmd_gen_key 8, key_attr.data[0] = 0x%02x", key_attr.data[0]);
        TEE_MemMove(buff + buff_head_len, key_attr.data[0], key_attr.len[0]);
        IMSG("[bxq] secure_cmd_gen_key 9");
        TEE_Free(key_attr.data[0]);
        IMSG("[bxq] secure_cmd_gen_key 10");
        uint8_t *p = buff + buff_head_len;
        for (size_t i = 1; i < RSA_ATTR_END; i++) {
            IMSG("[bxq] secure_cmd_gen_key 10.1.%d", i);
            p += key_attr.len[i - 1];
            IMSG("[bxq] secure_cmd_gen_key 10.2.%d, p = 0x%02x, len[%d] = %d, len[%d] = %d", i, p, i - 1, key_attr.len[i - 1], i, key_attr.len[i]);
            TEE_MemMove(p, key_attr.data[i], key_attr.len[i]);
            TEE_Free(key_attr.data[i]);
        }

        IMSG_RAW("[bxq] key_attr: ");
        // for (size_t j = 0; j < buff_len; j++) {
        //     IMSG_RAW("0x%02x ", *(buff + j));
        // }
        IMSG("end");

        IMSG("[bxq] secure_cmd_gen_key 11");
        res = TEE_WriteObjectData(object, buff, buff_len);
        if (res != TEE_SUCCESS) {
            EMSG("TEE_WriteObjectData failed 0x%08x", res);
            TEE_CloseAndDeletePersistentObject1(object);
        } else {
            IMSG("[bxq] secure_cmd_gen_key 12");
            TEE_CloseObject(object);
        }

        TEE_Free(buff);
        IMSG("[bxq] secure_cmd_gen_key 13");
    } else {
        IMSG("[bxq] secure_cmd_gen_key 14");
        TEE_CloseObject(object);
        TEE_Free(key_slot_buf);
    }

	IMSG("[bxq] secure_cmd_gen_key 15");
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
    uint8_t *inbuf;
	uint32_t inbuf_len;
	uint8_t *outbuf;
	uint32_t outbuf_len;
	uint8_t *store_buf;
	uint32_t store_buf_len;
    TEE_Attribute attrs[8];    // modulus | pub expo
    TEE_Attribute prikey[3];    // modulus | pub expo | priv expo
    TEE_OperationHandle operation;
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

    IMSG("[bxq] secure_cmd_rsa_enc 2");
	TEE_MemMove(key_slot_buf, params[0].memref.buffer, key_slot_size);

    IMSG("[bxq] secure_cmd_rsa_enc 3");
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

    IMSG("[bxq] secure_cmd_rsa_enc 4");

    KEY_ATTR key_attr;
	res = TEE_ReadObjectData(object, &key_attr, sizeof(key_attr), &read_bytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, sizeof(key_attr));
		goto exit;
	}

    IMSG("[bxq] secure_cmd_rsa_enc 5, sizeof(key_attr) = %d, read_bytes = %d", sizeof(key_attr), read_bytes);
    store_buf_len = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        store_buf_len += key_attr.len[i];
    }
    
	store_buf = TEE_Malloc(store_buf_len, 0);
	if (!store_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
		EMSG("TEE_SeekObjectData failed 0x%08x", res);
		goto exit;
	}

    IMSG("[bxq] secure_cmd_rsa_enc 6, store_buf_len = %d", store_buf_len);
    res = TEE_ReadObjectData(object, store_buf, store_buf_len, &read_bytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, store_buf_len);
		goto exit;
	}

    // IMSG("[bxq] secure_cmd_rsa_enc 6.1 persistent, store_buf_len = %d, read_bytes = %d", store_buf_len, read_bytes);
    // for (size_t i = 0; i < read_bytes; i++) {
    //     IMSG("0x%02x ", *(store_buf + i));
    // }
    // IMSG("[bxq] secure_cmd_rsa_enc 6.2 end: ");

    IMSG("[bxq] secure_cmd_rsa_enc 7, store_buf_len = %d, read_bytes = %d", store_buf_len, read_bytes);
    uint32_t buff_head_len = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);;
    uint8_t *p = store_buf + buff_head_len;
    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        IMSG("[bxq] secure_cmd_rsa_enc 7.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] secure_cmd_rsa_enc 7.2.%d, p = 0x%02x", i, p);
    }

    IMSG("[bxq] secure_cmd_rsa_enc 8");

    IMSG("[bxq] secure_cmd_rsa_enc 9");
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, key_attr.data[RSA_MODULUS], key_attr.len[RSA_MODULUS]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_attr.data[RSA_PUBLIC_EXPONENT], key_attr.len[RSA_PUBLIC_EXPONENT]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_attr.data[RSA_PRIVATE_EXPONENT], key_attr.len[RSA_PRIVATE_EXPONENT]);

    TEE_InitRefAttribute(&attrs[3], TEE_ATTR_RSA_PRIME1, key_attr.data[RSA_PRIME1], key_attr.len[RSA_PRIME1]);
    TEE_InitRefAttribute(&attrs[4], TEE_ATTR_RSA_PRIME2, key_attr.data[RSA_PRIME2], key_attr.len[RSA_PRIME2]);
    TEE_InitRefAttribute(&attrs[5], TEE_ATTR_RSA_EXPONENT1, key_attr.data[RSA_EXPONENT1], key_attr.len[RSA_EXPONENT1]);
    TEE_InitRefAttribute(&attrs[6], TEE_ATTR_RSA_EXPONENT2, key_attr.data[RSA_EXPONENT2], key_attr.len[RSA_EXPONENT2]);
    TEE_InitRefAttribute(&attrs[7], TEE_ATTR_RSA_COEFFICIENT, key_attr.data[RSA_COEFFICIENT], key_attr.len[RSA_COEFFICIENT]);

    IMSG("[bxq] secure_cmd_rsa_enc 10, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_attr.params[KEY_SIZE], &key_pair);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        goto exit;
    }

    IMSG("[bxq] secure_cmd_rsa_enc 11");
    res = TEE_PopulateTransientObject(key_pair, attrs, 8);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        goto exit;  
    }

    uint32_t p_len;
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        IMSG("[bxq] secure_cmd_rsa_enc 11.1.%d", i);
        res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], NULL, &p_len);
        if(res != TEE_ERROR_SHORT_BUFFER){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.2.%d,  p_len[%d] = %d", i, i, p_len);
        p = TEE_Malloc(p_len, 0);
        if (!key_slot_buf) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.3.%d, p[%d] = 0x%02x", i, i, *p);
        res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], p, &p_len);
        if(TEE_SUCCESS != res){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_enc 11.4.%d, p_len[%d] = %d", i, i, p_len);

        IMSG_RAW("[bxq] p[%d]: ", i);
        for (size_t j = 0; j < p_len; j++) {
            IMSG_RAW("0x%02x ", *(p + j));
        }
        IMSG("end");

        TEE_Free(p);
    }

    IMSG("[bxq] secure_cmd_rsa_enc 12");
    res = TEE_GetObjectInfo1(key_pair, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

    IMSG("[bxq] secure_cmd_rsa_enc 13, key_info.keySize = %d", key_info.keySize);
    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, key_info.keySize);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }

    IMSG("[bxq] secure_cmd_rsa_enc 14");
    res = TEE_SetOperationKey(operation, key_pair);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        goto exit;
    }

    inbuf = params[1].memref.buffer;
	inbuf_len = params[1].memref.size;
	outbuf = params[2].memref.buffer;
	outbuf_len = params[2].memref.size;

    IMSG("[bxq] secure_cmd_rsa_enc 14.1 inbuf:");
    for (size_t i = 0; i < inbuf_len; i++) {
        IMSG("0x%02x ", *(inbuf + i));
    }
    IMSG("[bxq] secure_cmd_rsa_enc 14.2 end");
    

    IMSG("[bxq] secure_cmd_rsa_enc 15");
    res = TEE_AsymmetricEncrypt(operation, NULL, 0, inbuf, inbuf_len, outbuf, &outbuf_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
    } else if (res != TEE_ERROR_SHORT_BUFFER) {
        IMSG("[bxq] secure_cmd_rsa_enc 15.1, outbuf_len = %d, outbuf:", outbuf_len);
        for (size_t i = 0; i < outbuf_len; i++) {
            IMSG("0x%02x ", *(outbuf + i));
        }
        IMSG("[bxq] secure_cmd_rsa_enc 15.2 end");
    }

    /* Return the number of byte effectively filled */
	params[2].memref.size = outbuf_len;

    IMSG("[bxq] secure_cmd_rsa_enc 16");
exit:
    IMSG("[bxq] secure_cmd_rsa_enc 17");
	TEE_CloseObject(object);
	TEE_Free(key_slot_buf);
	TEE_FreeOperation(operation);
	return res;
}

TEE_Result secure_cmd_rsa_dec(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
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
    uint8_t *inbuf;
	uint32_t inbuf_len;
	uint8_t *outbuf;
	uint32_t outbuf_len;
	uint8_t *store_buf;
	uint32_t store_buf_len;
    TEE_Attribute attrs[8];    // modulus | pub expo
    TEE_Attribute prikey[3];    // modulus | pub expo | priv expo
    TEE_OperationHandle operation;
    TEE_ObjectInfo key_info;
    TEE_ObjectHandle key_pair;
    const uint32_t alg = TEE_ALG_RSAES_PKCS1_V1_5;

    IMSG("[bxq] secure_cmd_rsa_dec 1");
	/*
	 * Safely get the invocation parameters
	 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_slot_size = params[0].memref.size;
	key_slot_buf = TEE_Malloc(key_slot_size, 0);
	if (!key_slot_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

    IMSG("[bxq] secure_cmd_rsa_dec 2");
	TEE_MemMove(key_slot_buf, params[0].memref.buffer, key_slot_size);

    IMSG("[bxq] secure_cmd_rsa_dec 3");
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

    IMSG("[bxq] secure_cmd_rsa_dec 4");

    KEY_ATTR key_attr;
	res = TEE_ReadObjectData(object, &key_attr, sizeof(key_attr), &read_bytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, sizeof(key_attr));
		goto exit;
	}

    IMSG("[bxq] secure_cmd_rsa_dec 5, sizeof(key_attr) = %d, read_bytes = %d", sizeof(key_attr), read_bytes);
    store_buf_len = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        store_buf_len += key_attr.len[i];
    }
    
	store_buf = TEE_Malloc(store_buf_len, 0);
	if (!store_buf)
		return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
		EMSG("TEE_SeekObjectData failed 0x%08x", res);
		goto exit;
	}

    IMSG("[bxq] secure_cmd_rsa_dec 6, store_buf_len = %d", store_buf_len);
    res = TEE_ReadObjectData(object, store_buf, store_buf_len, &read_bytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, read_bytes, store_buf_len);
		goto exit;
	}

    // IMSG("[bxq] secure_cmd_rsa_dec 6.1 persistent, store_buf_len = %d, read_bytes = %d", store_buf_len, read_bytes);
    // for (size_t i = 0; i < read_bytes; i++) {
    //     IMSG("0x%02x ", *(store_buf + i));
    // }
    // IMSG("[bxq] secure_cmd_rsa_dec 6.2 end: ");

    IMSG("[bxq] secure_cmd_rsa_dec 7, store_buf_len = %d, read_bytes = %d", store_buf_len, read_bytes);
    uint32_t buff_head_len = sizeof(uint32_t) * (RSA_ATTR_END + CUS_PARAMS_END);;
    uint8_t *p = store_buf + buff_head_len;
    key_attr.data[0] = p;
    for (size_t i = 0; i < RSA_ATTR_END - 1; i++) {
        IMSG("[bxq] secure_cmd_rsa_dec 7.1.%d, len[%d] = %d", i, i, key_attr.len[i]);
        p += key_attr.len[i];
        key_attr.data[i + 1] = p;
        IMSG("[bxq] secure_cmd_rsa_dec 7.2.%d, p = 0x%02x", i, p);
    }

    IMSG("[bxq] secure_cmd_rsa_dec 8");

    IMSG("[bxq] secure_cmd_rsa_dec 9");
    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, key_attr.data[RSA_MODULUS], key_attr.len[RSA_MODULUS]);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_attr.data[RSA_PUBLIC_EXPONENT], key_attr.len[RSA_PUBLIC_EXPONENT]);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_attr.data[RSA_PRIVATE_EXPONENT], key_attr.len[RSA_PRIVATE_EXPONENT]);

    TEE_InitRefAttribute(&attrs[3], TEE_ATTR_RSA_PRIME1, key_attr.data[RSA_PRIME1], key_attr.len[RSA_PRIME1]);
    TEE_InitRefAttribute(&attrs[4], TEE_ATTR_RSA_PRIME2, key_attr.data[RSA_PRIME2], key_attr.len[RSA_PRIME2]);
    TEE_InitRefAttribute(&attrs[5], TEE_ATTR_RSA_EXPONENT1, key_attr.data[RSA_EXPONENT1], key_attr.len[RSA_EXPONENT1]);
    TEE_InitRefAttribute(&attrs[6], TEE_ATTR_RSA_EXPONENT2, key_attr.data[RSA_EXPONENT2], key_attr.len[RSA_EXPONENT2]);
    TEE_InitRefAttribute(&attrs[7], TEE_ATTR_RSA_COEFFICIENT, key_attr.data[RSA_COEFFICIENT], key_attr.len[RSA_COEFFICIENT]);

    IMSG("[bxq] secure_cmd_rsa_dec 10, key_attr.params[KEY_SIZE] = %d", key_attr.params[KEY_SIZE]);
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_attr.params[KEY_SIZE], &key_pair);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        goto exit;
    }

    IMSG("[bxq] secure_cmd_rsa_dec 11");
    res = TEE_PopulateTransientObject(key_pair, attrs, 8);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        goto exit;  
    }

    uint32_t p_len;
    for (size_t i = 0; i < RSA_ATTR_END; i++) {
        IMSG("[bxq] secure_cmd_rsa_dec 11.1.%d", i);
        res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], NULL, &p_len);
        if(res != TEE_ERROR_SHORT_BUFFER){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_dec 11.2.%d,  p_len[%d] = %d", i, i, p_len);
        p = TEE_Malloc(p_len, 0);
        if (!key_slot_buf) {
            EMSG("TEE_Malloc() fail.\n");
            return TEE_ERROR_OUT_OF_MEMORY;
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_dec 11.3.%d, p[%d] = 0x%02x", i, i, *p);
        res = TEE_GetObjectBufferAttribute(key_pair, op_attr[i], p, &p_len);
        if(TEE_SUCCESS != res){
            EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
            return res;
        }

        IMSG("[bxq] secure_cmd_rsa_dec 11.4.%d, p_len[%d] = %d", i, i, p_len);

        IMSG_RAW("[bxq] p[%d]: ", i);
        for (size_t j = 0; j < p_len; j++) {
            IMSG_RAW("0x%02x ", *(p + j));
        }
        IMSG("end");

        TEE_Free(p);
    }

    IMSG("[bxq] secure_cmd_rsa_dec 12");
    res = TEE_GetObjectInfo1(key_pair, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

    IMSG("[bxq] secure_cmd_rsa_dec 13, key_info.keySize = %d", key_info.keySize);
    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT, key_info.keySize);
    if(TEE_SUCCESS != res) {
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }

    IMSG("[bxq] secure_cmd_rsa_dec 14");
    res = TEE_SetOperationKey(operation, key_pair);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        goto exit;
    }

    inbuf = params[1].memref.buffer;
	inbuf_len = params[1].memref.size;
	outbuf = params[2].memref.buffer;
	outbuf_len = params[2].memref.size;

    IMSG("[bxq] secure_cmd_rsa_dec 14.1 inbuf:");
    for (size_t i = 0; i < inbuf_len; i++) {
        IMSG("0x%02x ", *(inbuf + i));
    }
    IMSG("[bxq] secure_cmd_rsa_dec 14.2 end");
    

    IMSG("[bxq] secure_cmd_rsa_dec 15");
    res = TEE_AsymmetricDecrypt(operation, NULL, 0, inbuf, inbuf_len, outbuf, &outbuf_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
    } else if (res != TEE_ERROR_SHORT_BUFFER) {
        IMSG("[bxq] secure_cmd_rsa_dec 15.1, outbuf_len = %d, outbuf:", outbuf_len);
        for (size_t i = 0; i < outbuf_len; i++) {
            IMSG("0x%02x ", *(outbuf + i));
        }
        IMSG("[bxq] secure_cmd_rsa_dec 15.2 end");
    }

    /* Return the number of byte effectively filled */
	params[2].memref.size = outbuf_len;

    IMSG("[bxq] secure_cmd_rsa_dec 16");
exit:
    IMSG("[bxq] secure_cmd_rsa_dec 17");
	TEE_CloseObject(object);
	TEE_Free(key_slot_buf);
	TEE_FreeOperation(operation);
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
	case TA_SECURE_CMD_RSA_DEC:
		IMSG("Command ID: TA_SECURE_CMD_RSA_DEC");
		return secure_cmd_rsa_dec(param_types, params);
	case TA_SECURE_CMD_GEN_AES_KEY:
		IMSG("Command ID: TA_SECURE_CMD_GEN_AES_KEY");
		return secure_cmd_gen_aes_key(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
