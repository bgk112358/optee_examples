#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

TEE_Result Store_WriteKey(const uint8_t *keyID, uint32_t keyIDLen,
    const uint8_t *keyAttr, uint32_t keyAttrLen, int32_t *code) {
    TEE_ObjectHandle object;
    TEE_Result res;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &object);
    if (res != TEE_SUCCESS) {
        uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |     /* we can later read the oject */
        TEE_DATA_FLAG_ACCESS_WRITE |                    /* we can later write into the object */
        TEE_DATA_FLAG_ACCESS_WRITE_META |               /* we can later destroy or rename the object */
        TEE_DATA_FLAG_OVERWRITE;                        /* destroy existing object of same ID */
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
            obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
        if (res != TEE_SUCCESS) {
            return res;
        }
    }

    IMSG("[bxq] secure_cmd_gen_key 11");
    res = TEE_WriteObjectData(object, keyAttr, keyAttrLen);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_WriteObjectData failed 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object);
        return res;
    } else {
        IMSG("[bxq] secure_cmd_gen_key 12");
        TEE_CloseObject(object);
    }

    return TEE_SUCCESS;
}


TEE_Result Store_ReadKey(const uint8_t *keyID, uint32_t keyIDLen,
    uint8_t **keyData, uint32_t *keyDataLen, int32_t *code) {
    TEE_ObjectHandle object;
    TEE_Attribute attr;
    TEE_Result res;

    
    IMSG("[bxq] Store_ReadKey 1");
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        return res;
    }

    IMSG("[bxq] Store_ReadKey 2");
    res = TEE_GetObjectInfo1(object, &attr);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get object info, res=0x%08x", res);
        return res;
    }

    IMSG("[bxq] Store_ReadKey 3");
    // 获取持久化对象的数据长度
    uint32_t dataLen = attr.content.ref.length;

    IMSG("[bxq] Store_ReadKey 4, dataLen = %d", dataLen);

    uint8_t *data = TEE_Malloc(dataLen, 0);
	if (!data)
		return TEE_ERROR_OUT_OF_MEMORY;

    res = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
		EMSG("TEE_SeekObjectData failed 0x%08x", res);
        TEE_Free(data);
		return res;
	}

    IMSG("[bxq] Store_ReadKey 5");
    uint32_t readBytes;
    res = TEE_ReadObjectData(object, data, dataLen, &readBytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %" PRIu32 " over %u", res, readBytes, dataLen);
        TEE_Free(data);
		return res;
	}

    IMSG_RAW("[bxq] Store_ReadKey 6, readBytes = %d, key_attr: ", readBytes);
    for (size_t j = 0; j < readBytes; j++) {
        IMSG_RAW("0x%02x ", *(data + j));
    }
    IMSG("end Store_ReadKey");

    IMSG_RAW("[bxq] Store_ReadKey 7, data = 0x%p", data);
    
    *keyData = data;
    *keyDataLen = readBytes;
    TEE_CloseObject(object);
}