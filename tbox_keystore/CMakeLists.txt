project(keystore C)

set(OPENSSL_DIR /home/test0923/workspace/OP-TEE/three_part/openssl/out)

# NOTE: backends are NO LONGER linked into the CA — they are plugins loaded
# at run time by dongle_factory.c (see docs/32 §5-§7).  dongle_dummy.c is
# built as `dummy.so` below; dongle_yubikey.c is pending removal (P8).
set (SRC
    host/keystore_client.c
    host/dongle/dongle_factory.c
)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE host/dongle
                           PRIVATE ${OPENSSL_DIR}/include)

target_link_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_DIR}/lib)

# CMAKE_DL_LIBS: dlopen/dlsym for the run-time dongle plugin loader
target_link_libraries (${PROJECT_NAME} PRIVATE teec ssl crypto ${CMAKE_DL_LIBS})

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})

# ---- Standalone dummy-dongle key generator ----
# Runs ON THE TARGET (QEMU / real board) where the `openssl` *command* is
# usually absent.  It links libcrypto — which is already required by the CA,
# so it is guaranteed to be present wherever the CA runs — instead of
# shelling out to the openssl CLI.
#
#   target$ ./dummy_genkey [/path/to/dummy-dongle-key.pem]
add_executable (dummy_genkey host/dongle/dongle_dummy.c)
target_compile_definitions (dummy_genkey PRIVATE GENKEY_MAIN)
target_include_directories (dummy_genkey
                            PRIVATE host/dongle
                            PRIVATE ${OPENSSL_DIR}/include)
target_link_directories (dummy_genkey PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries (dummy_genkey PRIVATE ssl crypto)

# ---- Dummy dongle backend as a loadable PLUGIN ----
# Emits `dummy.so` (PREFIX "" → no "lib" prefix) so that it lands in the
# plugin directory as <name>.so alongside its companion key <name>.key,
# which is what makes "drop the files in the directory" == "plug in the
# dongle" (docs/32 §6).  Loaded at run time by dongle_factory.c.
add_library (dummy_plugin SHARED host/dongle/dongle_dummy.c)
set_target_properties (dummy_plugin PROPERTIES
                       PREFIX ""
                       OUTPUT_NAME "dummy")
target_include_directories (dummy_plugin
                            PRIVATE host/dongle
                            PRIVATE ${OPENSSL_DIR}/include)
target_link_directories (dummy_plugin PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries (dummy_plugin PRIVATE ssl crypto)

install (TARGETS dummy_plugin DESTINATION /usr/lib/tbox/dongle)

# ---- Remote signing dongle as a loadable PLUGIN ----
# The private key lives on an external host (PC / cloud); the device only
# forwards the challenge over ssh.  Needs no OpenSSL: it never handles key
# material locally (docs/32 §7).
add_library (remote_plugin SHARED host/dongle/dongle_remote.c)
set_target_properties (remote_plugin PROPERTIES
                       PREFIX ""
                       OUTPUT_NAME "remote")
target_include_directories (remote_plugin PRIVATE host/dongle)
target_link_libraries (remote_plugin PRIVATE ${CMAKE_DL_LIBS})

install (TARGETS remote_plugin DESTINATION /usr/lib/tbox/dongle)
