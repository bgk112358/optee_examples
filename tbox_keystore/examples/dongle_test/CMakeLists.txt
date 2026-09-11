project(dongle_test C)

set(OPENSSL_DIR /home/test0923/workspace/OP-TEE/three_part/openssl/out)

set(SRC
    dongle_test.c
    ../../host/dongle/dongle_factory.c
    ../../host/dongle/dongle_dummy.c
    ../../host/dongle/dongle_yubikey.c
)

add_executable(${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
    PRIVATE ../../host/dongle
    PRIVATE ${OPENSSL_DIR}/include
)

target_link_directories(${PROJECT_NAME}
    PRIVATE ${OPENSSL_DIR}/lib
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE ssl crypto
)
