cmake_minimum_required(VERSION 3.10)
project(tls_mutual_auth C)

# set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../three_part/openssl/out)
set(OPENSSL_DIR		/opt/ql-ol-crosstool/sysroots/cortexa7hf-neon-vfpv4-poky-linux-gnueabi/usr/lib)
set(OPENSSL_INCLUDE_DIR /opt/ql-ol-crosstool/sysroots/cortexa7hf-neon-vfpv4-poky-linux-gnueabi/usr/include)
# find_package(OpenSSL 1.1 REQUIRED)

set(ENGINE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../engine")
set(ENGINE_BUILD "${ENGINE_DIR}/build")

include_directories(
    ${OPENSSL_INCLUDE_DIR}
    ${ENGINE_DIR}
)

add_executable(tls_mutual_auth tls_mutual_auth.c)
target_link_libraries(tls_mutual_auth
    ${ENGINE_BUILD}/libengkeystore.so
    ssl
    crypto
    dl
    pthread
)
