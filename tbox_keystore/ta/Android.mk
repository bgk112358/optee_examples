LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tbox_keystore-ta
LOCAL_MODULE_FILENAME := f8e9209a-3c7d-4d6b-a15e-7f328b11c049
LOCAL_SRC_FILES := entry.c pin_mgr.c keystore.c acl.c crypto_ops.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
include $(BUILD_OPTEE_TA)
