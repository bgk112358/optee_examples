#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <key.h>
#include <rsa.h>

static TEE_Result secure_cmd_gen_key(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
    TEE_Result res;
    TEE_ObjectHandle keyPair;

	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_VALUE_INPUT,
											TEE_PARAM_TYPE_NONE,
											TEE_PARAM_TYPE_NONE);
	if (pt != exp_pt) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

    IMSG("[bxq] secure_cmd_gen_key 1");
	uint32_t keyIDLen = params[0].memref.size;
	uint8_t *keyID = TEE_Malloc(keyIDLen, 0);
	if (!keyID) {
		return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_MemMove(keyID, params[0].memref.buffer, keyIDLen);

    uint32_t keySize = params[1].value.a;

    IMSG("[bxq] secure_cmd_gen_key 2, keyPair =  0x%02x", keyPair);

    res = Key_Gen(TEE_TYPE_RSA_KEYPAIR, keySize, &keyPair);

    IMSG("[bxq] secure_cmd_gen_key 3, keyPair =  0x%02x", keyPair);


    // BUFFER in;
    // BUFFER out;

    // in.data = params[1].memref.buffer;
    // in.len = params[1].memref.size;
    // out.data = params[2].memref.buffer;
    // out.len = params[2].memref.size;

    // res = Rsa_Encode(keyPair, in, &out);

	return res;
}



TEE_Result TA_CreateEntryPoint(void)
{
	IMSG("[bxq] TA_CreateEntryPoint");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	IMSG("[bxq] TA_DestroyEntryPoint");

}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void __unused **session)
{
	IMSG("[bxq] TA_OpenSessionEntryPoint");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *session)
{
	IMSG("[bxq] TA_CloseSessionEntryPoint");
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
	case TA_SECURE_CMD_GEN_KEY:
		IMSG("Command ID: TA_SECURE_CMD_GEN_KEY");
		return secure_cmd_gen_key(param_types, params);
	case TA_SECURE_CMD_RSA_ENC:
		IMSG("Command ID: TA_SECURE_CMD_RSA_ENC");
		return TEE_SUCCESS; // secure_cmd_rsa_enc(param_types, params);	
	case TA_SECURE_CMD_RSA_DEC:
		IMSG("Command ID: TA_SECURE_CMD_RSA_DEC");
		return TEE_SUCCESS; // secure_cmd_rsa_dec(param_types, params);
	case TA_SECURE_CMD_GEN_AES_KEY:
		IMSG("Command ID: TA_SECURE_CMD_GEN_AES_KEY");
		return TEE_SUCCESS; // secure_cmd_gen_aes_key(param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", command);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
