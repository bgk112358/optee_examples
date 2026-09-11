cmake_minimum_required(VERSION 3.10)
project(rsa_crypt C)

set(TA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ta")
set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../three_part/openssl/out)

link_directories(
    PRIVATE ${TEEC_DIR}/lib
    PRIVATE ${OPENSSL_DIR}/lib
)

add_executable(rsa_crypt rsa_crypt.c)

target_include_directories(rsa_crypt
    PRIVATE ${TA_DIR}/include
    PRIVATE ${OPENSSL_DIR}/include
)

target_link_libraries(rsa_crypt
    PRIVATE teec crypto
)
