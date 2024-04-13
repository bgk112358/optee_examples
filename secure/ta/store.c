#include <inttypes.h>
#include <secure_ta.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "store.h"

TEE_Result Store_WriteKey(const uint8_t *keyID, size_t keyIDLen,
    const uint8_t *keyAttr, size_t keyAttrLen) {
    TEE_ObjectHandle object;
    TEE_Result res;

    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
                                   TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE, &object);
    if (res != TEE_SUCCESS) {
        uint32_t obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |    /* we can later read the oject */
        TEE_DATA_FLAG_ACCESS_WRITE |                            /* we can later write into the object */
        TEE_DATA_FLAG_ACCESS_WRITE_META |                       /* we can later destroy or rename the object */
        TEE_DATA_FLAG_OVERWRITE;                                /* destroy existing object of same ID */
        res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
                                         obj_data_flag, TEE_HANDLE_NULL, NULL, 0, &object);
        if (res != TEE_SUCCESS) {
            return res;
        }
    }

    res = TEE_WriteObjectData(object, keyAttr, keyAttrLen);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_WriteObjectData failed 0x%08x", res);
        TEE_CloseAndDeletePersistentObject1(object);
        return res;
    }

    TEE_CloseObject(object);
    return TEE_SUCCESS;
}


TEE_Result Store_ReadKey(const uint8_t *keyID, size_t keyIDLen,
                         uint8_t **keyData, size_t *keyDataLen) {
    TEE_ObjectHandle object;
    TEE_ObjectInfo objectInfo;
    TEE_Result res;

    EMSG("Store_ReadKey. 1");
    res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, keyID, keyIDLen,
                                   TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &object);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to open persistent object, res=0x%08x", res);
        return res;
    }

    EMSG("Store_ReadKey. 2");
    
    res = TEE_GetObjectInfo1(object, &objectInfo);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to get object info, res=0x%08x", res);
        TEE_CloseObject(object);
        return res;
    }

    EMSG("Store_ReadKey. 3, dataSize; = %ld", objectInfo.dataSize);
    size_t dataLen = objectInfo.dataSize;
    uint8_t *data = (uint8_t *)TEE_Malloc(dataLen + 1, 0);
	if (!data) {
        TEE_CloseObject(object);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    EMSG("Store_ReadKey. 4");
    res = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
    if (res != TEE_SUCCESS) {
		EMSG("TEE_SeekObjectData failed 0x%08x", res);
        TEE_Free(data);
        TEE_CloseObject(object);
		return res;
	}

    EMSG("Store_ReadKey. 5");
    size_t readBytes;
    res = TEE_ReadObjectData(object, data, dataLen, &readBytes);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_ReadObjectData failed 0x%08x, read %ld" PRIu32 " over %lu", res, readBytes, dataLen);
        TEE_Free(data);
        TEE_CloseObject(object);
		return res;
	}
    
    EMSG("Store_ReadKey. 6, dataLen = %ld, readBytes = %ld", dataLen, readBytes);
    *keyData = data;
    *keyDataLen = readBytes;

    EMSG("Store_ReadKey. 7");
    TEE_CloseObject(object);
    return TEE_SUCCESS;
}