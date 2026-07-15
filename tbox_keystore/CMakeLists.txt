cmake_minimum_required(VERSION 3.10)
project(tbox_keystore C)

set(CMAKE_C_STANDARD 11)

# Shared header
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ta/include)

# CA (host)
add_subdirectory(host)

# TA
add_subdirectory(ta)
