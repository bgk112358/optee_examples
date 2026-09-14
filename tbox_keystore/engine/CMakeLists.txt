cmake_minimum_required(VERSION 3.10)
project(tbox_keystore_engine C)

# set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../three_part/openssl/out)
set(OPENSSL_DIR		/opt/ql-ol-crosstool/sysroots/cortexa7hf-neon-vfpv4-poky-linux-gnueabi/usr/lib)
set(OPENSSL_INCLUDE_DIR /opt/ql-ol-crosstool/sysroots/cortexa7hf-neon-vfpv4-poky-linux-gnueabi/usr/include)
#find_package(OpenSSL 1.1 REQUIRED)

#set(TEEC_INCLUDE_DIR "/home/test0923/workspace/optee400/optee_client/export-ca_arm64/include"
#    CACHE PATH "TEE Client API headers")
#set(TEEC_LIB_DIR "/home/test0923/workspace/optee400/optee_client/export-ca_arm64/lib"
#    CACHE PATH "TEE Client API libraries")
set(TA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ta/include"
    CACHE PATH "TA shared header")

include_directories(
    ${TEEC_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${TA_INCLUDE_DIR}
)

add_library(engkeystore SHARED e_tbox_keystore.c)
target_link_libraries(engkeystore
    crypto
    teec
    dl
)
