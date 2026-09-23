# ---------------------------------------------------------------------------
# NOTE: the canonical build is CMake — see ../CMakeLists.txt.  It produces
# the CA (`keystore`), the key generator (`dummy_genkey`) and the dongle
# plugins (`dummy.so`, `remote.so`).
#
# This Makefile is now a thin wrapper so `cd host && make` keeps working
# with a SINGLE build definition.  It previously carried its own compile
# rules, which had two real bugs:
#
#   - `CC ?= $(CROSS_COMPILE)gcc` never fired: CC is a make *built-in*, so
#     `?=` is a no-op.  The build silently used the host `cc` and then
#     failed to link the aarch64 libteec.
#   - the cross-built OpenSSL (three_part/openssl/out) was never added to
#     the include/link paths, so it pulled in the host OpenSSL instead.
#
# Both go away now that CMake owns the build.
# ---------------------------------------------------------------------------

CROSS_COMPILE ?= /home/test0923/workspace/OP-TEE/optee400/toolchains/aarch64/bin/aarch64-none-linux-gnu-

# The canonical build dir is the PROJECT-level one (optee_examples_AG519M/build):
# its top-level CMakeLists.txt is what supplies the TEE Client include/lib
# paths, so tbox_keystore cannot be configured standalone.
BUILD_DIR ?= $(abspath ../../build)
SRC_DIR   ?= $(abspath ../..)

.PHONY: all plugins clean gen-dummy-key

# Configure once (only if the build dir has not been set up yet, so we never
# fight with an already-cached compiler).
define cmake_configure
	@mkdir -p $(BUILD_DIR)
	@[ -f $(BUILD_DIR)/CMakeCache.txt ] || \
		( cd $(BUILD_DIR) && cmake $(SRC_DIR) -DCMAKE_C_COMPILER=$(CROSS_COMPILE)gcc )
endef

# CA + key generator
all:
	$(cmake_configure)
	@$(MAKE) -C $(BUILD_DIR) keystore dummy_genkey

# Dongle plugins (dummy.so, remote.so)
plugins:
	$(cmake_configure)
	@$(MAKE) -C $(BUILD_DIR) dummy_plugin remote_plugin

clean:
	@$(MAKE) -C $(BUILD_DIR) clean 2>/dev/null || true

# ---------------------------------------------------------------------------
# Host-side development helper: generate a dummy dongle key ON THE DEV MACHINE.
# This uses the `openssl` command, which is normally ABSENT on the target
# (QEMU / real board).  On the target, build and use the `dummy_genkey`
# CMake target instead — it links libcrypto directly.
# ---------------------------------------------------------------------------
.PHONY: gen-dummy-key
gen-dummy-key:
	@mkdir -p /tmp
	@echo "Generating RSA-2048 key for dummy dongle (host-side)..."
	openssl genrsa -out /tmp/dummy-dongle-key.pem 2048
	@echo "Key written to /tmp/dummy-dongle-key.pem"
	@echo "Note: on the target use ./dummy_genkey instead (no openssl CLI there)."
