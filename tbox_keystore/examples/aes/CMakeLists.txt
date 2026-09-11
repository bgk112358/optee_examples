cmake_minimum_required(VERSION 3.10)
project(aes_crypt C)

set(TA_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../ta")

link_directories(${TEEC_DIR}/lib)

add_executable(aes_crypt aes_crypt.c)

target_include_directories(aes_crypt
    PRIVATE ${TA_DIR}/include
)
target_link_libraries(aes_crypt
    PRIVATE teec
)
