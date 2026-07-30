project(optee_example_tbox_keystore C)

set(OPENSSL_DIR /home/test0923/workspace/three_part/openssl/out)

set (SRC
    host/keystore_client.c
    host/dongle/dongle_factory.c
    host/dongle/dongle_dummy.c
    host/dongle/dongle_yubikey.c
)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE host/dongle
                           PRIVATE ${OPENSSL_DIR}/include)

target_link_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_DIR}/lib)

target_link_libraries (${PROJECT_NAME} PRIVATE teec ssl crypto)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
