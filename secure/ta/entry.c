#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <key.h>
#include <rsa.h>
#include <aes.h>
#include <sm2.h>
#include <sm4.h>
#include <hash.h>


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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        EMSG("TEE_Malloc fail");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    res = KeyGen(TEE_TYPE_RSA_KEYPAIR, keyParam, &keyPair);

    TEE_Free(keyParam.id);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;
    TEE_MemMove(keyParam.iv, params[2].memref.buffer, params[2].memref.size);

    res = KeyGen(TEE_TYPE_AES, keyParam, &keyPair);

    TEE_Free(keyParam.id);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    res = KeyGen(TEE_TYPE_SM2_PKE_KEYPAIR, keyParam, &keyPair);

    TEE_Free(keyParam.id);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    res = KeyGen(TEE_TYPE_SM2_DSA_KEYPAIR, keyParam, &keyPair);

    TEE_Free(keyParam.id);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    keyParam.keySize = params[1].value.a;

    res = KeyGen(TEE_TYPE_SM4, keyParam, &keyPair);

    TEE_Free(keyParam.id);
    return res;
}

static TEE_Result cmd_key_buffer_get(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    KEY_PARAM keyParam;

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

    return TEE_SUCCESS;
}

static TEE_Result cmd_crypto_rsa_enc(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
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

    TEE_Result res = KeyRestore(keyParam.id, keyParam.idLen, &key);
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

    res = RsaDecode(key, in, &out);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("RsaDecode fail. res = %x.\n", res);
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

static TEE_Result cmd_crypto_rsa_signature(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
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
        TEE_Free(keyParam.id);
        return res;
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = rsa_sign(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("rsa_sign fail. res = %x.\n", res);
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

static TEE_Result cmd_crypto_rsa_verify(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_OUTPUT);
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
        TEE_Free(keyParam.id);
        return res;
    }

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    res = rsa_verify(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SIGNATURE_INVALID) {
        EMSG("cmd_crypto_aes_enc fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        TEE_Free(keyParam.id);
        return res;
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;
    params[3].value.a = res;

    TEE_FreeTransientObject(key);
    TEE_Free(keyParam.id);
    return TEE_SUCCESS;
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

    res = AesEncode(key, TEE_ALG_AES_CBC_NOPAD, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("AesEncode fail. res = %x.\n", res);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

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

    res = AesDecode(key, TEE_ALG_AES_CBC_NOPAD, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("AesDecode fail. res = %x.\n", res);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

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

    res = sm2_enc(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS) {
        EMSG("sm2_enc fail. res = %x.\n", res);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

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

    res = sm2_dec(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS) {
        EMSG("sm2_dec fail. res = %x.\n", res);
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

static TEE_Result cmd_crypto_sm2_dsa_sign(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
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

    res = sm2_sign(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER) {
        EMSG("rsa_sign fail. res = %x.\n", res);
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

static TEE_Result cmd_crypto_sm2_dsa_verify(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    KEY_PARAM keyParam;
    TEE_ObjectHandle key;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_VALUE_OUTPUT);
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

    res = sm2_verify(key, in.data, in.len, out.data, &out.len);
    if(res != TEE_SUCCESS && res != TEE_ERROR_SIGNATURE_INVALID) {
        EMSG("sm2_verify fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        TEE_Free(keyParam.id);
        return res;
    }

    /* Return the number of byte effectively filled */
    params[2].memref.size = out.len;
    params[3].value.a = res;

    TEE_FreeTransientObject(key);
    TEE_Free(keyParam.id);
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
    EMSG("cmd_crypto_sm4_enc. 1");

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);
    EMSG("cmd_crypto_sm4_enc. 2");

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_enc() fail. res = %x.\n", res);
        TEE_Free(keyParam.id);
        return res;
    }

    EMSG("cmd_crypto_sm4_enc. 3");

    BUFFER in;
    BUFFER out;
    in.len = params[1].memref.size;
    in.data = params[1].memref.buffer;
    out.len = params[2].memref.size;
    out.data = params[2].memref.buffer;

    EMSG("cmd_crypto_sm4_enc. 4");
    res = Sm4Encode(key, TEE_ALG_SM4_CTR, in, &out);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_enc fail. res = %x.\n", res);
        TEE_FreeTransientObject(key);
        TEE_Free(keyParam.id);
        return res;
    }

    /* Return the number of byte effectively filled */
	params[2].memref.size = out.len;

    EMSG("cmd_crypto_sm4_enc. 5");
    TEE_FreeTransientObject(key);
    TEE_Free(keyParam.id);
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

    keyParam.idLen = params[0].memref.size;
    keyParam.id = TEE_Malloc(keyParam.idLen, 0);
    if (!keyParam.id) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyParam.id, params[0].memref.buffer, keyParam.idLen);

    res = KeyRestore(keyParam.id, keyParam.idLen, &key);
    if(res != TEE_SUCCESS) {
        EMSG("cmd_crypto_sm4_dec() fail. res = %x.\n", res);
        TEE_Free(keyParam.id);
        return res;
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

static TEE_Result cmd_crypto_sm3(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;

    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_NONE,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    res = sm3(params[0].memref.buffer, params[0].memref.size,
                   params[1].memref.buffer, &params[1].memref.size);
    return res;
}

static TEE_Result cmd_crypto_sha(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                            TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                            TEE_PARAM_TYPE_VALUE_INPUT,
                                            TEE_PARAM_TYPE_NONE);
    if (pt != exp_pt) {
        EMSG("exp_pt fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[2].value.a == 256) {
        res = sha256(params[0].memref.buffer, params[0].memref.size,
                     params[1].memref.buffer, &params[1].memref.size);
    } else {
        EMSG("params[2].value.a fail\n");
        res = TEE_ERROR_BAD_PARAMETERS;
    }

    return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
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
        return cmd_key_rsa_gen(param_types, params);
    case TA_CMD_KEY_BUFFER_GET:
        // IMSG("Command ID: TA_CMD_KEY_BUFFER_GET");
        return cmd_key_buffer_get(param_types, params);
    case TA_CMD_CRYPTO_RSA_ENC:
        return cmd_crypto_rsa_enc(param_types, params);	
    case TA_CMD_CRYPTO_RSA_DEC:
        return cmd_crypto_rsa_dec(param_types, params);
    case TA_CMD_KEY_AES_GEN:
        return cmd_key_aes_gen(param_types, params);
    case TA_CMD_CRYPTO_AES_ENC:
        return cmd_crypto_aes_enc(param_types, params);
    case TA_CMD_CRYPTO_AES_DEC:
        return cmd_crypto_aes_dec(param_types, params);
    case TA_CMD_KEY_SM2_PKE_GEN:
        return cmd_key_sm2_pke_gen(param_types, params);
    case TA_CMD_KEY_SM2_DSA_GEN:
        return cmd_key_sm2_dsa_gen(param_types, params);
    case TA_CMD_CRYPTO_SM2_PKE_ENC:
        return cmd_key_sm2_pke_enc(param_types, params);
    case TA_CMD_CRYPTO_SM2_PKE_DEC:
        return cmd_key_sm2_pke_dec(param_types, params);
    case TA_CMD_CRYPTO_SM2_DSA_SIGN:
        return cmd_crypto_sm2_dsa_sign(param_types, params);
    case TA_CMD_CRYPTO_SM2_DSA_VERIFY:
        return cmd_crypto_sm2_dsa_verify(param_types, params);
    case TA_CMD_KEY_SM4_GEN:
        return cmd_key_sm4_gen(param_types, params);
    case TA_CMD_CRYPTO_SM4_ENC:
        return cmd_crypto_sm4_enc(param_types, params);
     case TA_CMD_CRYPTO_SM4_DEC:
        return cmd_crypto_sm4_dec(param_types, params);
    case TA_CMD_CRYPTO_RSA_SIGN:
        return cmd_crypto_rsa_signature(param_types, params);
    case TA_CMD_CRYPTO_RSA_VERIFY:
        return cmd_crypto_rsa_verify(param_types, params);
    case TA_CMD_CRYPTO_SM3:
        return cmd_crypto_sm3(param_types, params);
    case TA_CMD_CRYPTO_SHA:
        return cmd_crypto_sha(param_types, params);
    default:
        EMSG("Command ID 0x%x is not supported", command);
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
