CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

# ---- Dongle backend selection ----
# DONGLE_BACKENDS: space-separated list of backends to compile.
#   dongle_dummy   — local P-256 key file (dev/CI, links -lssl -lcrypto)
#   dongle_yubikey — YubiKey via ykman CLI fallback (no extra deps)
#
# Default: dummy only (development)
DONGLE_BACKENDS ?= dongle_dummy

# ---- Source files ----
OBJS  = keystore_client.o
OBJS += dongle/dongle_factory.o

# Conditionally add backend objects
ifeq ($(findstring dongle_dummy,$(DONGLE_BACKENDS)),dongle_dummy)
	OBJS += dongle/dongle_dummy.o
	LDADD += -lssl -lcrypto
endif
ifeq ($(findstring dongle_yubikey,$(DONGLE_BACKENDS)),dongle_yubikey)
	OBJS += dongle/dongle_yubikey.o
endif

CFLAGS += -Wall -I../ta/include
CFLAGS += -I$(TEEC_EXPORT)/include
LDADD += -lteec -L$(TEEC_EXPORT)/lib

BINARY = tbox_keystore

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Helper: generate a dummy dongle key for development
.PHONY: gen-dummy-key
gen-dummy-key:
	@mkdir -p $${HOME}/.tbox
	@echo "Generating P-256 key for dummy dongle..."
	openssl ecparam -genkey -name prime256v1 -noout | \
		openssl pkcs8 -topk8 -nocrypt -out $${HOME}/.tbox/dummy-dongle-key.pem
	@echo "Key written to $${HOME}/.tbox/dummy-dongle-key.pem"
