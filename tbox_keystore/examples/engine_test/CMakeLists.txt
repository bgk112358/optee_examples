cmake_minimum_required(VERSION 3.10)
project(engine_test C)

# ---------------------------------------------------------------------------
# OpenSSL 用显式路径，不要用 find_package(OpenSSL)：
#   交叉编译时 find_package 会找到宿主的 x86_64 OpenSSL，编译/链接必然失败。
#   与 engine/CMakeLists.txt、examples/rsa 保持同一套写法。
#   （examples/dongle_test 是例外——它在开发机上跑，故意用宿主 OpenSSL。）
# ---------------------------------------------------------------------------
set(OPENSSL_DIR "/home/test0923/workspace/OP-TEE/three_part/openssl/out"
    CACHE PATH "cross-built OpenSSL (libssl/libcrypto)")

# 引擎作为子目录编进来 —— 示例自包含：单独 cmake && make 即可，
# 不需要先去 engine/build 单独构建一次。
# 产物在此示例的构建目录下（libengkeystore.so）。
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../engine engine_build)

add_executable(engine_test engine_test.c)
target_include_directories(engine_test PRIVATE ${OPENSSL_DIR}/include)
target_link_directories(engine_test PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries(engine_test
    ssl crypto
    engkeystore            # → libengkeystore.so
)
