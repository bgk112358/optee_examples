cmake_minimum_required(VERSION 3.10)
project(aes_crypt C)

set(TA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ta")
set(TEEC_DIR /home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64)

add_executable(aes_crypt aes_crypt.c)

target_include_directories(aes_crypt
    PRIVATE ${TA_DIR}/include
    PRIVATE ${TEEC_DIR}/include
)

target_link_directories(aes_crypt
    PRIVATE ${TEEC_DIR}/lib
)

target_link_libraries(aes_crypt
    PRIVATE teec
)
