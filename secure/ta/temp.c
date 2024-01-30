#include <inttypes.h>
#include <asymmetry_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <string.h>


static TEE_Result Asymmetry_RSA_auto(uint32_t param_types, TEE_Param params[4]){
    EMSG("Enter auto-TA...\n");
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle prikey_obj, pubkey_obj;
    TEE_OperationHandle enc_op, dec_op;
    TEE_Attribute pubkey[2];
    size_t size = 512, size2 = 512;
    uint32_t key_len = 512, _type = 0, i = 0;
    uint32_t in_len = 3, enc_len = 0, dec_len = 0;
    char datain[] = "123";
    char encrypt[key_len], decrypt[key_len];
    void* buffer  = (void*)TEE_Malloc(key_len, 0);
    void* buffer2 = (void*)TEE_Malloc(key_len, 0);

    _type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, 
                TEE_PARAM_TYPE_NONE, 
                TEE_PARAM_TYPE_NONE, 
                TEE_PARAM_TYPE_NONE);
    if(_type != param_types){
        EMSG("Param type error.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    enc_len = key_len;
    dec_len = key_len;
    
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_len, &prikey_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_AllocateTransientObject() pass...\n");

    res = TEE_GenerateKey(prikey_obj, key_len, NULL, 0);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GenerateKey() fail. res = %x.\n", res);
		goto exit;
    }
    EMSG("TEE_GenerateKey() pass...\n");

    res = TEE_GetObjectBufferAttribute(prikey_obj, TEE_ATTR_RSA_MODULUS, buffer, &size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(prikey_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer2, &size2);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_GetObjectBufferAttribute() pass...\n");

    TEE_InitRefAttribute(&pubkey[0], TEE_ATTR_RSA_MODULUS, buffer, size);
    TEE_InitRefAttribute(&pubkey[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, buffer2, size2);
    EMSG("TEE_InitRefAttribute() pass...\n");
    EMSG("size = %d, size2 = %d.", size, size2);

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_len, &pubkey_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_AllocateTransientObject() pass...\n");

    res = TEE_PopulateTransientObject(pubkey_obj, pubkey, 2);
    if(TEE_SUCCESS != res){
        EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_PopulateTransientObject() pass...\n");

    res = TEE_AllocateOperation(&enc_op, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, TEE_MODE_ENCRYPT, key_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("set enc_op...");
    res = TEE_SetOperationKey(enc_op, pubkey_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        goto exit;
    }

    res = TEE_AllocateOperation(&dec_op, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1, TEE_MODE_DECRYPT, key_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("set dec_op...");
    res = TEE_SetOperationKey(dec_op, prikey_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_SetOperationKey pass...\n");

    res = TEE_AsymmetricEncrypt(enc_op, NULL, 0, datain, in_len, encrypt, &enc_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_AsymmetricEncrypt pass...\n");
    EMSG("enc_len = %d.\n", enc_len);
    for(i = 0; i < enc_len; i++){
        EMSG("%02x ", encrypt[i]);
    }

    EMSG("in_len = %d, out_len = %d.\n", in_len, enc_len);
    res = TEE_AsymmetricDecrypt(dec_op, NULL, 0, encrypt, enc_len, decrypt, &dec_len);
    if(TEE_SUCCESS != res){
        EMSG("TEE_AsymmetricDecrypt() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("TEE_AsymmetricDecrypt pass...\n");
    EMSG("dec_len = %d.\n", dec_len);
    for(i = 0; i < dec_len; i++){
        EMSG("%02x ", decrypt[i]);
    }

exit:
	TEE_FreeTransientObject(prikey_obj);
	TEE_FreeTransientObject(pubkey_obj);
	TEE_FreeOperation(enc_op);
	TEE_FreeOperation(dec_op);
    TEE_Free(buffer);
    TEE_Free(buffer2);

    return res;
}

static TEE_Result Asymmetry_RSA_keygen(uint32_t param_types, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle key_obj;
    uint32_t _type = 0;

    _type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT);
    if(_type != param_types){
        EMSG("Param type error.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, params[0].value.a, &key_obj);
	if(TEE_SUCCESS != res){
		EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
		goto exit;
	}

    res = TEE_GenerateKey(key_obj, params[0].value.a, NULL, 0);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GenerateKey() fail. res = %x.\n", res);
		goto exit;
    }
    
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_MODULUS, params[1].memref.buffer, &params[1].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("params[1].memref.size = %d.", params[1].memref.size);
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, params[2].memref.buffer, &params[2].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("params[2].memref.size = %d.", params[2].memref.size);
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_PRIVATE_EXPONENT, params[3].memref.buffer, &params[3].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    EMSG("params[3].memref.size = %d.", params[3].memref.size);

exit:
	TEE_FreeTransientObject(key_obj);
	return res;
}

static TEE_Result Asymmetry_RSA_impl(uint32_t param_types, TEE_Param params[4], int enc){
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle key_obj;
    TEE_OperationHandle operation;
    TEE_Attribute pubkey[2], prikey[3];                    //modulus | pub expo | priv expo
    uint32_t _type = 0;
    _type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,   //origin dataIn
                TEE_PARAM_TYPE_MEMREF_INOUT,               //encrypted dataOut or signature as dataIn
                TEE_PARAM_TYPE_MEMREF_INPUT,               //key struct
                TEE_PARAM_TYPE_MEMREF_INPUT);              //key length | padding algorithm | lengthes of key data
    if(_type != param_types){
        EMSG("Param type error.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    size_t in_len = params[0].memref.size;

    size_t out_len = params[1].memref.size;
    char *dataout = (char *)TEE_Malloc(out_len, 0);
    if(NULL == dataout){
		EMSG("dataout = TEE_Malloc = NULL.\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
    char *key_str = (char *)params[2].memref.buffer;
    uint32_t *num_str = (uint32_t *)params[3].memref.buffer;
    
    switch(enc){
        case TEE_MODE_ENCRYPT:
            TEE_InitRefAttribute(&pubkey[0], TEE_ATTR_RSA_MODULUS, key_str, *(num_str+2));
            TEE_InitRefAttribute(&pubkey[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_str + *(num_str+2), *(num_str+3));

            res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, *(num_str+0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, pubkey, 2);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;  
            }
            res = TEE_AllocateOperation(&operation, *(num_str+1), TEE_MODE_ENCRYPT, *(num_str+0));
            break;
        case TEE_MODE_DECRYPT:
            TEE_InitRefAttribute(&prikey[0], TEE_ATTR_RSA_MODULUS, key_str, *(num_str+2));
            TEE_InitRefAttribute(&prikey[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_str + *(num_str+2), *(num_str+3));
            TEE_InitRefAttribute(&prikey[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_str + *(num_str+2) + *(num_str+3), *(num_str+4));

            res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, *(num_str+0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, prikey, 3);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, *(num_str+1), TEE_MODE_DECRYPT, *(num_str+0));
            break;
        case TEE_MODE_SIGN:
            TEE_InitRefAttribute(&prikey[0], TEE_ATTR_RSA_MODULUS, key_str, *(num_str+2));
            TEE_InitRefAttribute(&prikey[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_str + *(num_str+2), *(num_str+3));
            TEE_InitRefAttribute(&prikey[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, key_str + *(num_str+2) + *(num_str+3), *(num_str+4));
            res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, *(num_str+0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, prikey, 3);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, *(num_str+1), TEE_MODE_SIGN, *(num_str+0));
            break;
        case TEE_MODE_VERIFY:
            TEE_InitRefAttribute(&pubkey[0], TEE_ATTR_RSA_MODULUS, key_str, *(num_str+2));
            TEE_InitRefAttribute(&pubkey[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, key_str + *(num_str+2), *(num_str+3));
            res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, *(num_str+0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, pubkey, 2);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, *(num_str+1), TEE_MODE_VERIFY, *(num_str+0));
            break;
        default:
            break;
    }
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }
    res = TEE_SetOperationKey(operation, key_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail. res = %x.\n", res);
        goto exit;
    }

    switch(enc){
        case TEE_MODE_ENCRYPT:
            res = TEE_AsymmetricEncrypt(operation, NULL, 0, (char*)params[0].memref.buffer, in_len, dataout, &out_len);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AsymmetricEncrypt() fail. res = %x.\n", res);
                goto exit;
            }
            break;
        case TEE_MODE_DECRYPT:
            res = TEE_AsymmetricDecrypt(operation, NULL, 0, (char*)params[0].memref.buffer, in_len, dataout, &out_len);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AsymmetricDecrypt() fail. res = %x.\n", res);
                goto exit;
            }
            break;
        case TEE_MODE_SIGN:
            res = TEE_AsymmetricSignDigest(operation, NULL, 0, params[0].memref.buffer, in_len, dataout, &out_len);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AsymmetricSignDigest() fail. res = %x.\n", res);
                goto exit;
            }
            break;
        case TEE_MODE_VERIFY: 
            res = TEE_AsymmetricVerifyDigest(operation, NULL, 0, params[0].memref.buffer, in_len, params[1].memref.buffer, params[1].memref.size);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AsymmetricVerifyDigest() fail. res = %x.\n", res);
            }

            goto exit;
        default:
            break;
    }
    
    //assign tht result
    TEE_MemMove(params[1].memref.buffer, dataout, out_len);
    params[1].memref.size = out_len;
    
exit:
    // TEE_Free(datain);
	TEE_Free(dataout);	
	TEE_FreeTransientObject(key_obj);
	TEE_FreeOperation(operation);

    return res;
}

static TEE_Result Asymmetry_ECC_keygen(uint32_t param_types, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    TEE_Attribute attr; 
    TEE_ObjectHandle key_obj;
    uint32_t _type = 0;

    _type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT, 
                TEE_PARAM_TYPE_MEMREF_INOUT);
    if(_type != param_types){
        EMSG("Param type error.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    EMSG("params[0].value = %d, %x.", params[0].value.a, params[0].value.b);
    res = TEE_AllocateTransientObject(params[0].value.b, params[0].value.a, &key_obj);
	if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateTransientObject() fail.\n");
        goto exit;
    }

    // TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_SM2, 0);       // shouldn't have this param in key struct in optee-os_v3.17.0

    // res = TEE_GenerateKey(key_obj, params[0].value.a, &attr, 1);
    res = TEE_GenerateKey(key_obj, params[0].value.a, NULL, 0);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GenerateKey() fail.\n");
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_X, params[1].memref.buffer, &params[1].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_Y, params[2].memref.buffer, &params[2].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PRIVATE_VALUE, params[3].memref.buffer, &params[3].memref.size);
    if(TEE_SUCCESS != res){
        EMSG("TEE_GetObjectBufferAttribute() fail. res = %x.\n", res);
        goto exit;
    }

exit:
	TEE_FreeTransientObject(key_obj);

	return res;
}
static TEE_Result Asymmetry_ECC_impl(uint32_t param_types, TEE_Param params[4], int mode){
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle key_obj;
    TEE_OperationHandle operation;
    TEE_Attribute pubkey[3], prikey[4];              // pub x | pub y | priv value
    uint32_t _type = 0;

    _type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,   //origin dataIn
                TEE_PARAM_TYPE_MEMREF_INOUT,               //encrypted dataOut or signature as dataIn
                TEE_PARAM_TYPE_MEMREF_INPUT,               //key struct
                TEE_PARAM_TYPE_MEMREF_INPUT);              //key length | algorithm | lengthes of key data successively
    if(_type != param_types){
        EMSG("Param type error.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t in_len = params[0].memref.size;
    char* data_in = (char *)params[0].memref.buffer;
    uint32_t out_len = params[1].memref.size;
    char* data_out = (char *)TEE_Malloc(params[1].memref.size, 0);
    if(NULL == data_out){
		EMSG("data_out = TEE_Malloc = NULL.\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
    char *key_str = (char *)params[2].memref.buffer;
    uint32_t *num_str = (uint32_t *)params[3].memref.buffer;

    switch(mode){
        case TEE_MODE_ENCRYPT:
            TEE_InitRefAttribute(&pubkey[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_str, *(num_str+1));
            TEE_InitRefAttribute(&pubkey[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_str + *(num_str+1), *(num_str+2));
            // TEE_InitValueAttribute(&pubkey[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_SM2, 0);       // shouldn't have this param in key struct in optee-os_v3.17.0

            res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_PUBLIC_KEY, *(num_str + 0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail.\n");
                goto exit;
            }
            // res = TEE_PopulateTransientObject(key_obj, pubkey, 3);
            res = TEE_PopulateTransientObject(key_obj, pubkey, 2);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT, *(num_str + 0));
            break;
        case TEE_MODE_DECRYPT:
            TEE_InitRefAttribute(&prikey[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_str, *(num_str+1));
            TEE_InitRefAttribute(&prikey[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_str + *(num_str+1), *(num_str+2));
            TEE_InitRefAttribute(&prikey[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_str + *(num_str+1) + *(num_str+2), *(num_str+3));
            // TEE_InitValueAttribute(&prikey[3], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_SM2, 0);       // shouldn't have this param in key struct in optee-os_v3.17.0

            res = TEE_AllocateTransientObject(TEE_TYPE_SM2_PKE_KEYPAIR, *(num_str + 0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail.\n");
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, prikey, 3);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT, *(num_str + 0));
            break;
        case TEE_MODE_SIGN:
            TEE_InitRefAttribute(&prikey[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_str, *(num_str+1));
            TEE_InitRefAttribute(&prikey[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_str + *(num_str+1), *(num_str+2));
            TEE_InitRefAttribute(&prikey[2], TEE_ATTR_ECC_PRIVATE_VALUE, key_str + *(num_str+1) + *(num_str+2), *(num_str+3));
            // TEE_InitValueAttribute(&prikey[3], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_SM2, 0);       // shouldn't have this param in key struct in optee-os_v3.17.0

            res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_KEYPAIR, *(num_str + 0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail.\n");
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, prikey, 3);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, TEE_ALG_SM2_DSA_SM3, TEE_MODE_SIGN, *(num_str + 0));
            break;
        case TEE_MODE_VERIFY:
            TEE_InitRefAttribute(&pubkey[0], TEE_ATTR_ECC_PUBLIC_VALUE_X, key_str, *(num_str+1));
            TEE_InitRefAttribute(&pubkey[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_str + *(num_str+1), *(num_str+2));
            // TEE_InitValueAttribute(&pubkey[2], TEE_ATTR_ECC_CURVE, TEE_ECC_CURVE_SM2, 0);       // shouldn't have this param in key struct in optee-os_v3.17.0
             
            res = TEE_AllocateTransientObject(TEE_TYPE_SM2_DSA_PUBLIC_KEY, *(num_str + 0), &key_obj);
            if(TEE_SUCCESS != res){
                EMSG("TEE_AllocateTransientObject() fail.\n");
                goto exit;
            }
            res = TEE_PopulateTransientObject(key_obj, pubkey, 2);
            if(TEE_SUCCESS != res){
                EMSG("TEE_PopulateTransientObject() fail. res = %x.\n", res);
                goto exit;
            }
            res = TEE_AllocateOperation(&operation, TEE_ALG_SM2_DSA_SM3, TEE_MODE_VERIFY, *(num_str + 0));
            break;
        default:
            break;
    }
    if(TEE_SUCCESS != res){
        EMSG("TEE_AllocateOperation() fail. res = %x.\n", res);
        goto exit;
    }

    res = TEE_SetOperationKey(operation, key_obj);
    if(TEE_SUCCESS != res){
        EMSG("TEE_SetOperationKey() fail.\n");
        goto exit;
    }
    switch(mode){
        case TEE_MODE_ENCRYPT:
            res = TEE_AsymmetricEncrypt(operation, NULL, 0, data_in, in_len, data_out, &out_len);
            break;
        case TEE_MODE_DECRYPT:
            res = TEE_AsymmetricDecrypt(operation, NULL, 0, data_in, in_len, data_out, &out_len);
            break;
        case TEE_MODE_SIGN:
            res = TEE_AsymmetricSignDigest(operation, NULL, 0, data_in, in_len, data_out, &out_len);
            break;
        case TEE_MODE_VERIFY:
            res = TEE_AsymmetricVerifyDigest(operation, NULL, 0, data_in, in_len, params[1].memref.buffer, params[1].memref.size);
            if(TEE_SUCCESS == res){
                params[1].memref.size = 0;
                goto exit;
            }
            else if(TEE_ERROR_SIGNATURE_INVALID == res){
                params[1].memref.size = 1;
                res = TEE_SUCCESS;
                goto exit;    
            }
            goto exit;
        default:
            break;
    }
    if(TEE_SUCCESS != res){
        EMSG("TEE_AsymmetryFuction fail.\n");
        goto exit;
    }

    //assign tht result
    TEE_MemMove(params[1].memref.buffer, data_out, out_len);
    params[1].memref.size = out_len;
exit:
    TEE_Free(data_out);	
	TEE_FreeTransientObject(key_obj);
	TEE_FreeOperation(operation);

    return res;
}


TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	/* Nothing to do */
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
				      uint32_t command, 
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command) {

    //RSA
    case TA_ASYMMETRY_RSA_KEYGEN:
        return Asymmetry_RSA_keygen(param_types, params);
        break;

	case TA_ASYMMETRY_RSA_ENCRYPT:
		return Asymmetry_RSA_impl(param_types, params, TEE_MODE_ENCRYPT);
        break;

	case TA_ASYMMETRY_RSA_DECRYPT:
		return Asymmetry_RSA_impl(param_types, params, TEE_MODE_DECRYPT);
        break;
        
    case TA_ASYMMETRY_RSA_SIGN:
		return Asymmetry_RSA_impl(param_types, params, TEE_MODE_SIGN);
        break;

    case TA_ASYMMETRY_RSA_VERIFY:
		return Asymmetry_RSA_impl(param_types, params, TEE_MODE_VERIFY);
        break;

    case TA_ASYMMETRY_RSA_AUTO:
        return Asymmetry_RSA_auto(param_types, params);
        break;

    //ECC
    case TA_ASYMMETRY_ECC_KEYGEN:
        return Asymmetry_ECC_keygen(param_types, params);
        break;

	case TA_ASYMMETRY_ECC_ENCRYPT:
		return Asymmetry_ECC_impl(param_types, params, TEE_MODE_ENCRYPT);
        break;

	case TA_ASYMMETRY_ECC_DECRYPT:
		return Asymmetry_ECC_impl(param_types, params, TEE_MODE_DECRYPT);
        break;
        
    case TA_ASYMMETRY_ECC_SIGN:
		return Asymmetry_ECC_impl(param_types, params, TEE_MODE_SIGN);
        break;

    case TA_ASYMMETRY_ECC_VERIFY:
		return Asymmetry_ECC_impl(param_types, params, TEE_MODE_VERIFY);
        break;

	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
