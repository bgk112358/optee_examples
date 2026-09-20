project(dongle_test C)

# This test has NO TEE/TA dependency: it exercises the dongle plugin loader
# and the dummy backend entirely in userspace, so it builds and runs on the
# DEVELOPMENT machine.  Use the system OpenSSL (matching headers + libs) —
# do NOT point it at three_part/openssl/out, which is a cross build for
# aarch64 and would fail to link here.
find_package(OpenSSL REQUIRED)

set(DONGLE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../host/dongle")

# ---- The dummy backend, built as a PLUGIN ----
# The test no longer links backends in: it drives them through the same
# dlopen loader the CA uses, so the plugin path is exercised too.
# Produces `dummy.so` next to the test binary (see setup_plugin_dir()).
add_library(dummy_plugin_for_test SHARED ${DONGLE_DIR}/dongle_dummy.c)
set_target_properties(dummy_plugin_for_test PROPERTIES
                      PREFIX ""
                      OUTPUT_NAME "dummy")
target_include_directories(dummy_plugin_for_test PRIVATE ${DONGLE_DIR} ${OPENSSL_INCLUDE_DIR})
target_link_libraries(dummy_plugin_for_test PRIVATE OpenSSL::Crypto)

# ---- The test itself: loader + assertions ----
add_executable(${PROJECT_NAME}
    dongle_test.c
    ${DONGLE_DIR}/dongle_factory.c      # the plugin loader
)

target_include_directories(${PROJECT_NAME}
    PRIVATE ${DONGLE_DIR}
    PRIVATE ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE OpenSSL::Crypto ${CMAKE_DL_LIBS}
)

add_dependencies(${PROJECT_NAME} dummy_plugin_for_test)
