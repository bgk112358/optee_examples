#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <key.h>
#include <rsa.h>
#include <aes.h>
#include <sm2.h>
#include <sm4.h>


static TEE_Result cmd_key_rsa_gen(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_rsa_gen 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    // IMSG("[bxq] secure_cmd_gen_key 2, keyPair =  0x%02x", keyPair);
    res = KeyGen(TEE_TYPE_RSA_KEYPAIR, keyParam, &keyPair);
    // IMSG("[bxq] secure_cmd_gen_key 3, keyPair =  0x%02x", keyPair);

    return res;
}

static TEE_Result cmd_key_aes_gen(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_aes_gen 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;
    TEE_MemMove(keyParam.iv, params[2].memref.buffer, params[2].memref.size);

    // IMSG("[bxq] cmd_key_aes_gen 2, keyPair =  0x%02x", keyPair);
    res = KeyGen(TEE_TYPE_AES, keyParam, &keyPair);
    // IMSG("[bxq] cmd_key_aes_gen 3, keyPair =  0x%02x", keyPair);

    return res;
}

static TEE_Result cmd_key_sm2_pke_gen(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_sm2_pke_gen 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    // IMSG("[bxq] cmd_key_sm2_pke_gen 2, keyPair =  0x%02x", keyPair);
    res = KeyGen(TEE_TYPE_SM2_PKE_KEYPAIR, keyParam, &keyPair);
    // IMSG("[bxq] cmd_key_sm2_pke_gen 3, keyPair =  0x%02x", keyPair);

    return res;
}

static TEE_Result cmd_key_sm2_dsa_gen(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_sm2_dsa_gen 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    // IMSG("[bxq] cmd_key_sm2_dsa_gen 2, keyPair =  0x%02x", keyPair);
    res = KeyGen(TEE_TYPE_SM2_DSA_KEYPAIR, keyParam, &keyPair);
    // IMSG("[bxq] cmd_key_sm2_dsa_gen 3, keyPair =  0x%02x", keyPair);

    return res;
}

static TEE_Result cmd_key_sm4_gen(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_sm4_gen 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    // IMSG("[bxq] cmd_key_sm4_gen 2, keyPair =  0x%02x", keyPair);
    res = KeyGen(TEE_TYPE_SM4, keyParam, &keyPair);
    // IMSG("[bxq] cmd_key_sm4_gen 3, keyPair =  0x%02x", keyPair);

    return res;
}


static TEE_Result cmd_key_buffer_get(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;
    KEY_PARAM keyParam;
    uint32_t keyParamLen;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_buffer_get 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    // IMSG("[bxq] cmd_key_buffer_get 2, keyPair =  0x%02x", keyPair);
    res = KeyRestoreValue(keyParam.id, keyParam.idLen, &keyParam, keyParamLen);
    // IMSG("[bxq] cmd_key_buffer_get 3, keyPair =  0x%02x", keyPair);

    return res;
}

static TEE_Result cmd_crypto_rsa_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    // 还原密钥10,000次未遇到内存问题
    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("KeyRestore() fail. res = %x.\n", res);
        TEE_Free(keyParam.id);
        return res;
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = RsaEncode(key, in, &out);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("RsaEncode fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        TEE_Free(keyParam.id);
        return res;
    }

    /* Return the number of byte effectively filled */
	params[2].memref.size = out.len;

    TEE_FreeTransientObject(key);
    TEE_Free(keyParam.id);
    return res;
}

static TEE_Result cmd_crypto_rsa_dec(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_rsa_dec() fail. res = %x.\n", res);
        TEE_Free(keyParam.id);
        return res;
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = RsaDecode(key, in, &out);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("cmd_crypto_rsa_dec fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        TEE_Free(keyParam.id);
        return res;
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    TEE_FreeTransientObject(key);
    TEE_Free(keyParam.id);
    return res;
}

static TEE_Result cmd_crypto_aes_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_aes_enc() fail. res = %x.\n", res);
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = AesEncode(key, TEE_ALG_AES_CBC_NOPAD, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_aes_enc fail. res = %x.\n", res);
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    return res;
}

static TEE_Result cmd_crypto_aes_dec(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_crypto_aes_dec 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_aes_dec() fail. res = %x.\n", res);
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = AesDecode(key, TEE_ALG_AES_CBC_NOPAD, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_aes_dec fail. res = %x.\n", res);
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    return res;
}

static TEE_Result cmd_key_sm2_pke_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_sm2_pke_enc 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_key_sm2_pke_enc() fail. res = %x.\n", res);
    }

    // IMSG("[bxq] cmd_key_sm2_pke_enc 2");
    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = sm2_enc(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_key_sm2_pke_enc fail. res = %x.\n", res);
    }

    // IMSG("[bxq] cmd_key_sm2_pke_enc 3, res = 0x%x", res);

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    return res;
}


static TEE_Result cmd_key_sm2_pke_dec(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_key_sm2_pke_dec 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_key_sm2_pke_dec() fail. res = %x.\n", res);
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = sm2_dec(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_key_sm2_pke_dec fail. res = %x.\n", res);
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    return res;
}

static TEE_Result cmd_key_sm2_dsa_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    return TEE_SUCCESS;
}

static TEE_Result cmd_key_sm2_dsa_dec(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    return TEE_SUCCESS;
}

static TEE_Result cmd_crypto_sm4_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_crypto_sm4_enc 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_enc() fail. res = %x.\n", res);
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    // IMSG("[bxq] cmd_crypto_sm4_enc 2, out.len = %d", out.len);

    res = Sm4Encode(key, TEE_ALG_SM4_CTR, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_enc fail. res = %x.\n", res);
    }

    // IMSG("[bxq] cmd_crypto_sm4_enc 3, out.len = %d", out.len);

    /* Return the number of byte effectively filled */
	params[2].memref.size = out.len;

    return res;
}

static TEE_Result cmd_crypto_sm4_dec(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // IMSG("[bxq] cmd_crypto_sm4_dec 1");
    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_dec() fail. res = %x.\n", res);
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = Sm4Decode(key, TEE_ALG_SM4_CTR, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_dec fail. res = %x.\n", res);
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;

    return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	// IMSG("[bxq] TA_CreateEntryPoint");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	// IMSG("[bxq] TA_DestroyEntryPoint");

}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	// IMSG("[bxq] TA_OpenSessionEntryPoint");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	// IMSG("[bxq] TA_CloseSessionEntryPoint");
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *session,
                                      uint32_t command,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    switch (command) {
    case TA_SECURE_CMD_WRITE_RAW:
        return TEE_SUCCESS; // create_raw_object(param_types, params);
    case TA_SECURE_CMD_READ_RAW:
        return TEE_SUCCESS; // read_raw_object(param_types, params);
    case TA_SECURE_CMD_DELETE:
        return TEE_SUCCESS; // delete_object(param_types, params);
    case TA_ACIPHER_CMD_GEN_KEY:
        return TEE_SUCCESS; // cmd_gen_key(session, param_types, params);
    case TA_ACIPHER_CMD_ENCRYPT:
        return TEE_SUCCESS; // cmd_enc(session, param_types, params);
    case TA_CMD_KEY_RSA_GEN:
        // IMSG("Command ID: TA_CMD_KEY_RSA_GEN");
        return cmd_key_rsa_gen(param_types, params);
    case TA_CMD_KEY_BUFFER_GET:
        // IMSG("Command ID: TA_CMD_KEY_BUFFER_GET");
        return cmd_key_buffer_get(param_types, params);
    case TA_CMD_CRYPTO_RSA_ENC:
        // IMSG("Command ID: TA_CMD_CRYPTO_RSA_ENC");
        return cmd_crypto_rsa_enc(param_types, params);	
    case TA_CMD_CRYPTO_RSA_DEC:
        // IMSG("Command ID: TA_CMD_CRYPTO_RSA_DEC");
        return cmd_crypto_rsa_dec(param_types, params);
    case TA_CMD_KEY_AES_GEN:
        // IMSG("Command ID: TA_CMD_KEY_AES_GEN");
        return cmd_key_aes_gen(param_types, params);
    case TA_CMD_CRYPTO_AES_ENC:
        // IMSG("Command ID: TA_CMD_CRYPTO_AES_ENC");
        return cmd_crypto_aes_enc(param_types, params);
    case TA_CMD_CRYPTO_AES_DEC:
        // IMSG("Command ID: TA_CMD_CRYPTO_AES_DEC");
        return cmd_crypto_aes_dec(param_types, params);
    case TA_CMD_KEY_SM2_PKE_GEN:
        // IMSG("Command ID: TA_CMD_KEY_SM2_PKE_GEN");
        return cmd_key_sm2_pke_gen(param_types, params);
    case TA_CMD_KEY_SM2_DSA_GEN:
        // IMSG("Command ID: TA_CMD_KEY_SM2_DSA_GEN");
        return cmd_key_sm2_dsa_gen(param_types, params);
    case TA_CMD_CRYPTO_SM2_PKE_ENC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM2_PKE_ENC");
        return cmd_key_sm2_pke_enc(param_types, params);
    case TA_CMD_CRYPTO_SM2_PKE_DEC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM2_PKE_DEC");
        return cmd_key_sm2_pke_dec(param_types, params);
    case TA_CMD_CRYPTO_SM2_DSA_ENC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM2_DSA_ENC");
        return cmd_key_sm2_dsa_enc(param_types, params);
    case TA_CMD_CRYPTO_SM2_DSA_DEC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM2_DSA_DEC");
        return cmd_key_sm2_dsa_dec(param_types, params);
    case TA_CMD_KEY_SM4_GEN:
        // IMSG("Command ID: TA_CMD_KEY_SM4_GEN");
        return cmd_key_sm4_gen(param_types, params);
    case TA_CMD_CRYPTO_SM4_ENC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM4_ENC");
        return cmd_crypto_sm4_enc(param_types, params);
     case TA_CMD_CRYPTO_SM4_DEC:
        // IMSG("Command ID: TA_CMD_CRYPTO_SM4_DEC");
        return cmd_crypto_sm4_dec(param_types, params);       
    default:
        EMSG("Command ID 0x%x is not supported", command);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
