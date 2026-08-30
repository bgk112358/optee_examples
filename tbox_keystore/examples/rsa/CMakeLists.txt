cmake_minimum_required(VERSION 3.10)
project(rsa_crypt C)

set(TA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ta")
set(TEEC_DIR /home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64)
set(OPENSSL_DIR /home/test0923/workspace/OP-TEE/three_part/openssl/out)

add_executable(rsa_crypt rsa_crypt.c)

target_include_directories(rsa_crypt
    PRIVATE ${TA_DIR}/include
    PRIVATE ${TEEC_DIR}/include
    PRIVATE ${OPENSSL_DIR}/include
)

target_link_directories(rsa_crypt
    PRIVATE ${TEEC_DIR}/lib
    PRIVATE ${OPENSSL_DIR}/lib
)

target_link_libraries(rsa_crypt
    PRIVATE teec crypto
)
