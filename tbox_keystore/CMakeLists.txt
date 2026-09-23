project(keystore C)

set(OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../three_part/openssl/out)

# ---- Dongle subsystem (plugins + key generator) ----
# Pulled in here so a single `make` in the project build dir produces
# everything.  Everything in dongle/ is independent of the CA except the
# loader below, which the CA has to link.
add_subdirectory(dongle)

# ---- OpenSSL ENGINE (libengkeystore.so) ----
# Also pulled in here so the project-level build produces it too.
# 各示例也会用 add_subdirectory 自行引入它（示例自包含，可单独构建）。
add_subdirectory(engine)

# ---- The CA (command-line tool) ----
# dongle_factory.c is the plugin LOADER: it lives in dongle/ but is linked
# into the CA, because the CA is what dlopen()s the plugins at run time.
set (SRC
    host/keystore_client.c
    dongle/dongle_factory.c
)

link_directories(${OPENSSL_DIR}/lib)

add_executable(${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
                           PRIVATE ta/include
                           PRIVATE dongle
                           PRIVATE ${OPENSSL_DIR}/include)

# CMAKE_DL_LIBS: dlopen/dlsym for the dongle plugin loader
target_link_libraries (${PROJECT_NAME} PRIVATE teec ssl crypto ${CMAKE_DL_LIBS})

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
