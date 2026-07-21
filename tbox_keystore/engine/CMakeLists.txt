cmake_minimum_required(VERSION 3.10)
project(tbox_keystore_engine C)

# ---- OpenSSL 1.1.x ----
find_package(OpenSSL 1.1 REQUIRED)

# ---- TEEC paths ----
set(TEEC_INCLUDE_DIR "/home/test0923/workspace/optee400/optee_client/export-ca_arm64/include"
    CACHE PATH "TEE Client API headers")
set(TEEC_LIB_DIR "/home/test0923/workspace/optee400/optee_client/export-ca_arm64/lib"
    CACHE PATH "TEE Client API libraries")

# ---- TA shared header ----
set(TA_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ta/include"
    CACHE PATH "TA shared header (tbox_keystore_ta.h)")

include_directories(
    ${TEEC_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${TA_INCLUDE_DIR}
)

# ============================================================
#  Target 1 — e_tbox_keystore.so  (the ENGINE)
# ============================================================
add_library(e_tbox_keystore SHARED e_tbox_keystore.c)
target_link_libraries(e_tbox_keystore
    ${OPENSSL_LIBRARIES}
    ${TEEC_LIB_DIR}/libteec.a
    ${CMAKE_DL_LIBS}
)

# ============================================================
#  Target 2 — tls_mutual_auth  (TLS mutual-auth demo)
# ============================================================
add_executable(tls_mutual_auth tls_mutual_auth.c)
target_link_libraries(tls_mutual_auth
    ${OPENSSL_LIBRARIES}
    e_tbox_keystore
)

# ============================================================
#  Target 3 — engine_test  (ENGINE smoke-test)
# ============================================================
add_executable(engine_test test/engine_test.c)
target_link_libraries(engine_test
    ${OPENSSL_LIBRARIES}
    e_tbox_keystore
)

# ============================================================
#  Target 4 — https_client  (HTTPS client via ENGINE)
# ============================================================
add_executable(https_client test/https_client.c)
target_link_libraries(https_client
    ${OPENSSL_LIBRARIES}
    e_tbox_keystore
)

# ============================================================
#  Install
# ============================================================
install(TARGETS e_tbox_keystore
    LIBRARY DESTINATION /usr/lib/engines-1.1/
)
install(TARGETS tls_mutual_auth engine_test https_client
    RUNTIME DESTINATION /usr/bin/
)
