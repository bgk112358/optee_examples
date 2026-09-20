project(keystore C)

set(OPENSSL_DIR /home/test0923/workspace/OP-TEE/three_part/openssl/out)

# ---- Dongle subsystem (plugins + key generator) ----
# Pulled in here so a single `make` in the project build dir produces
# everything.  Everything in dongle/ is independent of the CA except the
# loader below, which the CA has to link.
add_subdirectory(dongle)

# ---- The CA (command-line tool) ----
# dongle_factory.c is the plugin LOADER: it lives in dongle/ but is linked
# into the CA, because the CA is what dlopen()s the plugins at run time.
set (SRC
    host/keystore_client.c
    dongle/dongle_factory.c
)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE dongle
                           PRIVATE ${OPENSSL_DIR}/include)

target_link_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_DIR}/lib)

# CMAKE_DL_LIBS: dlopen/dlsym for the dongle plugin loader
target_link_libraries (${PROJECT_NAME} PRIVATE teec ssl crypto ${CMAKE_DL_LIBS})

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
