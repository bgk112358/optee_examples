# OP-TEE Sample Applications
This git contains source code for sample host and Trusted Application that can
be used directly in the OP-TEE project.

All official OP-TEE documentation has moved to http://optee.readthedocs.io. The
information that used to be here in this git can be found under
[optee_examples].

// OP-TEE core maintainers

[optee_examples]: https://optee.readthedocs.io/en/latest/building/gits/optee_examples/optee_examples.html


// QEMU构建ca
test0923@test0923-PC:~/workspace/OP-TEE/optee_examples_AG519M/build$ cmake -DCMAKE_C_COMPILER=/home/test0923/workspace/OP-TEE/optee400/toolchains/aarch64/bin/aarch64-linux-gnu-gcc ..

test0923@test0923-PC:~/workspace/OP-TEE/optee_examples_AG519M/build$ make