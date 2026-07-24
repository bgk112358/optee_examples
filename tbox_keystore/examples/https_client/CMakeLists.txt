cmake_minimum_required(VERSION 3.10)
project(https_client C)
find_package(OpenSSL 1.1 REQUIRED)

set(ENGINE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../engine")
set(ENGINE_BUILD "${ENGINE_DIR}/build")

include_directories(${OPENSSL_INCLUDE_DIR} ${ENGINE_DIR})

add_executable(https_client https_client.c)
target_link_libraries(https_client
    ${OPENSSL_LIBRARIES}
    ${ENGINE_BUILD}/libe_tbox_keystore.so
)
