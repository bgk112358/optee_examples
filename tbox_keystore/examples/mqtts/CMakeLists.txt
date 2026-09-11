cmake_minimum_required(VERSION 3.10)
project(tbox_mqtts C)

find_package(OpenSSL 1.1 REQUIRED)

set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../three_part/openssl/out)

# ---- paho (patched, installed from three_part/mqtt) ----
set(PAHO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../three_part/mqtt/out"
    CACHE PATH "paho.mqtt.c install prefix")

# ---- tbox_keystore ENGINE (built from ../engine) ----
set(ENGINE_BUILD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../engine/build"
    CACHE PATH "e_tbox_keystore build directory")

include_directories(
    ${TEEC_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PAHO_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}          # ssl_config.h
)

link_directories(
    ${PAHO_DIR}/lib
    ${ENGINE_BUILD_DIR}
)

# ---- Common SSL config (shared by pub + sub) ----
add_library(ssl_config STATIC ssl_config.c)
target_link_libraries(ssl_config
    ${OPENSSL_DIR}/lib/libssl.a
    ${OPENSSL_DIR}/lib/libcrypto.a
    engkeystore   # ENGINE_load_tbox_keystore, ENGINE_by_id, etc.
    pthread
    dl
)

# ---- mqtts_pub ----
add_executable(mqtts_pub mqtts_pub.c)
target_link_libraries(mqtts_pub
    ssl_config
    paho-mqtt3cs       # sync + SSL (patched: SSLSocket_setExternalConfigCallback)
)

# ---- mqtts_sub ----
add_executable(mqtts_sub mqtts_sub.c)
target_link_libraries(mqtts_sub
    ssl_config
    paho-mqtt3cs
)

# ---- tcpprobe_mqtt — paho TCP smoke test (no SSL, no ENGINE) ----
add_executable(tcpprobe_mqtt tcpprobe_mqtt.c)
target_link_libraries(tcpprobe_mqtt paho-mqtt3c)

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
