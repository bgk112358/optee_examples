cmake_minimum_required(VERSION 3.10)
project(tbox_mqtts C)

# ---------------------------------------------------------------------------
# OpenSSL 用显式路径，不要用 find_package(OpenSSL)：
#   交叉编译时 find_package 会找到宿主的 x86_64 OpenSSL，编译/链接必然失败。
#   与 engine/CMakeLists.txt、examples/rsa 保持同一套写法。
#   （examples/dongle_test 是例外——它在开发机上跑，故意用宿主 OpenSSL。）
# ---------------------------------------------------------------------------
set(OPENSSL_DIR "/home/test0923/workspace/OP-TEE/three_part/openssl/out"
    CACHE PATH "cross-built OpenSSL (libssl/libcrypto)")

set(TEEC_INCLUDE_DIR "/home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64/include"
    CACHE PATH "TEE Client API headers")

# ---- paho (patched, installed from three_part/mqtt) ----
set(PAHO_DIR "/home/test0923/workspace/OP-TEE/three_part/mqtt/out"
    CACHE PATH "paho.mqtt.c install prefix")

# ---- tbox_keystore ENGINE (libengkeystore.so) ----
# 引擎作为子目录编进来 —— 本示例自包含，单独 cmake && make 即可。
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../engine engine_build)

include_directories(
    ${TEEC_INCLUDE_DIR}
    ${OPENSSL_DIR}/include
    ${PAHO_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}          # ssl_config.h
)

link_directories(
    ${OPENSSL_DIR}/lib
    ${PAHO_DIR}/lib
)

# ---- Common SSL config (shared by pub + sub) ----
add_library(ssl_config STATIC ssl_config.c)
target_link_libraries(ssl_config
    ssl crypto
    engkeystore   # ENGINE_load_tbox_keystore, ENGINE_by_id, etc. → libengkeystore.so
)

# ---- mqtts_pub ----
add_executable(mqtts_pub mqtts_pub.c)
target_link_libraries(mqtts_pub
    ssl_config
    eng-paho-mqtt3cs   # sync + SSL (patched: SSLSocket_setExternalConfigCallback)
)

# ---- mqtts_sub ----
add_executable(mqtts_sub mqtts_sub.c)
target_link_libraries(mqtts_sub
    ssl_config
    eng-paho-mqtt3cs
)

# ---- tcpprobe_mqtt — paho TCP smoke test (no SSL, no ENGINE) ----
add_executable(tcpprobe_mqtt tcpprobe_mqtt.c)
target_link_libraries(tcpprobe_mqtt eng-paho-mqtt3c)

# ---- gen_csr — CSR generator (ENGINE-signed) ----
add_executable(gen_csr gen_csr.c)
target_link_libraries(gen_csr
    ssl_config
)

# ---- Tests ----
enable_testing()

# gen_csr — CSR generation smoke test (needs TA key provisioned)
add_test(NAME mqtt_gen_csr
    COMMAND gen_csr pub-key tbox-test /tmp/test.csr
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(mqtt_gen_csr PROPERTIES LABELS "mqtt")

# Full MQTTS end-to-end test
add_test(NAME mqtt_e2e
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/test/mqtt_run_test.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(mqtt_e2e PROPERTIES LABELS "mqtt")

# ---- Install ----
install(TARGETS mqtts_pub mqtts_sub gen_csr
    RUNTIME DESTINATION /usr/bin/
)
