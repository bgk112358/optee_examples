cmake_minimum_required(VERSION 3.10)
project(engine_test C)
find_package(OpenSSL 1.1 REQUIRED)

set(ENGINE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../engine")
set(ENGINE_BUILD "${ENGINE_DIR}/build")

include_directories(${OPENSSL_INCLUDE_DIR} ${ENGINE_DIR})

add_executable(engine_test engine_test.c)
target_link_libraries(engine_test
    ${OPENSSL_LIBRARIES}
    ${ENGINE_BUILD}/libe_tbox_keystore.so
)
