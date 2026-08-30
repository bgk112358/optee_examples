cmake_minimum_required (VERSION 3.2)
project (optee_examples C)

############# QEMU BUILD CA GUIDE #############
# test0923@test0923-PC:~/workspace/OP-TEE/optee_examples_AG519M/build$ rm -rf *
# test0923@test0923-PC:~/workspace/OP-TEE/optee_examples_AG519M/build$ cmake -DCMAKE_C_COMPILER=/home/test0923/workspace/OP-TEE/optee400/toolchains/aarch64/bin/aarch64-linux-gnu-gcc ..
# test0923@test0923-PC:~/workspace/OP-TEE/optee_examples_AG519M/build$ make
############################################

# https://cmake.org/Wiki/CMake_Useful_Variables
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

include_directories(/home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64/include)
link_directories(/home/test0923/workspace/OP-TEE/optee400/optee_client/export-ca_arm64/lib)

include(GNUInstallDirs)

add_compile_options (-Wall)
#add_compile_options (
#	-Wall -Wbad-function-cast -Wcast-align
#	-Werror-implicit-function-declaration -Wextra
#	-Wfloat-equal -Wformat-nonliteral -Wformat-security
#	-Wformat=2 -Winit-self -Wmissing-declarations
#	-Wmissing-format-attribute -Wmissing-include-dirs
#	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs
#	-Wpointer-arith -Wshadow -Wstrict-prototypes
#	-Wswitch-default -Wunsafe-loop-optimizations
#	-Wwrite-strings -Werror -fPIC
#)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

file(GLOB dirs *)
foreach(dir ${dirs})
	if(EXISTS ${dir}/CMakeLists.txt)
		add_subdirectory(${dir})
	endif()
endforeach()
