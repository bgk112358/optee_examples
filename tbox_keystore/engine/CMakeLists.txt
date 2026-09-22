cmake_minimum_required(VERSION 3.10)
project(tbox_keystore_engine C)

# ---------------------------------------------------------------------------
# OpenSSL 用显式路径，不用 find_package(OpenSSL)：
#   本文件会被两种上下文引入 —— ① 项目构建（../CMakeLists.txt 的
#   add_subdirectory）② 各示例自带构建（示例里 add_subdirectory(../../engine)）。
#   在这种交叉编译场景下 find_package 会找到宿主的 x86_64 OpenSSL，
#   链接必然失败。显式指定交叉产物路径在各种上下文下行为一致。
# ---------------------------------------------------------------------------
set(OPENSSL_DIR "/home/test0923/workspace/OP-TEE/three_part/openssl/out"
    CACHE PATH "cross-built OpenSSL (libssl/libcrypto)")

set(TEEC_INCLUDE_DIR "/home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64/include"
    CACHE PATH "TEE Client API headers")
set(TEEC_LIB_DIR "/home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64/lib"
    CACHE PATH "TEE Client API libraries")
set(TA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ta/include"
    CACHE PATH "TA shared header")

# 产物：libengkeystore.so（目标名 engkeystore）
add_library(engkeystore SHARED e_tbox_keystore.c)

target_include_directories(engkeystore PRIVATE
    ${TEEC_INCLUDE_DIR}
    ${OPENSSL_DIR}/include
    ${TA_INCLUDE_DIR}
)

target_link_directories(engkeystore PRIVATE ${OPENSSL_DIR}/lib)

target_link_libraries(engkeystore PRIVATE
    ssl
    crypto
    ${TEEC_LIB_DIR}/libteec.a
    ${CMAKE_DL_LIBS}
)

install(TARGETS engkeystore
    LIBRARY DESTINATION /usr/lib/engines-1.1/
)
