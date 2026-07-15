LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tbox_keystore
LOCAL_SRC_FILES := host/keystore_client.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/ta/include $(LOCAL_PATH)/host/include
include $(BUILD_EXECUTABLE)
