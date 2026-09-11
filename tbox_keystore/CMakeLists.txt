project(optee_example_tbox_keystore C)

set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../three_part/openssl/out)

set(SRC
    host/keystore_client.c
    host/dongle/dongle_factory.c
    host/dongle/dongle_dummy.c
    host/dongle/dongle_yubikey.c
)

link_directories(${OPENSSL_DIR}/lib)

add_executable(${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE host/dongle
                           PRIVATE ${OPENSSL_DIR}/include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec ssl crypto)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
