# Host (CA) build — requires TEEC_EXPORT from optee_client
if(NOT DEFINED TEEC_EXPORT)
    set(TEEC_EXPORT /usr)
endif()

include_directories(${TEEC_EXPORT}/include)

add_executable(tbox_keystore keystore_client.c)
target_link_libraries(tbox_keystore teec)
target_include_directories(tbox_keystore PRIVATE
    ${CMAKE_SOURCE_DIR}/ta/include)
