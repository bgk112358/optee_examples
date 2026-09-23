# ---------------------------------------------------------------------------
# Dongle subsystem — plugin backends + the dummy key generator.
#
# Everything here is INDEPENDENT of the CA: the plugins are standalone shared
# objects that only know the contract in dongle_ops.h.  None of them includes
# or references anything from host/.
#
# The one exception is dongle_factory.c (the plugin loader): it lives here
# because it belongs to this layer, but it is linked INTO the CA — that is
# declared in ../CMakeLists.txt, not here.
#
# This file can be configured standalone, and is also pulled in by the parent
# via add_subdirectory(), which is how the project build picks up its targets.
# ---------------------------------------------------------------------------

project(dongle C)

set(OPENSSL_DIR /home/test0923/workspace/OP-TEE/three_part/openssl/out
    CACHE PATH "cross-built OpenSSL (needed by the dummy plugin)")

# Install location on the target: "drop a .so in the directory" ==
# "plug the dongle in" (docs/32 §6/§7).
set(DONGLE_PLUGIN_DIR "/oemdata/opt/optee/dongle"
    CACHE PATH "where plugins are installed on the target")

# ---- dummy.so — local soft dongle (dev / CI) ----
add_library (dummy_plugin SHARED dongle_dummy.c)
set_target_properties (dummy_plugin PROPERTIES
                       PREFIX ""              # dumb.so, not libdummy.so
                       OUTPUT_NAME "dummy")
target_include_directories (dummy_plugin
                            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                            PRIVATE ${OPENSSL_DIR}/include)
target_link_directories (dummy_plugin PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries (dummy_plugin PRIVATE ssl crypto)
install (TARGETS dummy_plugin DESTINATION ${DONGLE_PLUGIN_DIR})

# ---- remote.so — remote signing dongle over ssh (PC / cloud) ----
# Needs no OpenSSL: the private key never exists locally.
add_library (remote_plugin SHARED dongle_remote.c)
set_target_properties (remote_plugin PROPERTIES
                       PREFIX ""
                       OUTPUT_NAME "remote")
target_include_directories (remote_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries (remote_plugin PRIVATE ${CMAKE_DL_LIBS})
install (TARGETS remote_plugin DESTINATION ${DONGLE_PLUGIN_DIR})

# ---- dummy_genkey — generate a dummy dongle key ON THE TARGET ----
# Target images usually have no `openssl` command; this links libcrypto
# (already present wherever the CA runs) instead of shelling out.
#
#   target$ ./dummy_genkey [/path/to/dummy-dongle-key.pem]
#   target$ ./dummy_genkey --pubout <key.pem> [<out.der>]
add_executable (dummy_genkey dongle_dummy.c)
target_compile_definitions (dummy_genkey PRIVATE GENKEY_MAIN)
target_include_directories (dummy_genkey
                            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                            PRIVATE ${OPENSSL_DIR}/include)
target_link_directories (dummy_genkey PRIVATE ${OPENSSL_DIR}/lib)
target_link_libraries (dummy_genkey PRIVATE ssl crypto)
