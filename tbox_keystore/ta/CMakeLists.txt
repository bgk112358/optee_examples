# TA build — uses OP-TEE TA dev kit
# Set TA_DEV_KIT_DIR before configuring, e.g.:
#   cmake -DTA_DEV_KIT_DIR=/path/to/export-user_ta ..

if(NOT DEFINED TA_DEV_KIT_DIR)
    message(FATAL_ERROR "TA_DEV_KIT_DIR not set")
endif()

set(TA_SRC
    entry.c
    pin_mgr.c
    keystore.c
    acl.c
    crypto_ops.c
)

include(${TA_DEV_KIT_DIR}/cmake/OpteeTaTargets.cmake)

add_optee_ta(
    NAME tbox_keystore
    UUID f8e9209a-3c7d-4d6b-a15e-7f328b11c049
    SOURCES ${TA_SRC}
)
