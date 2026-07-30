#!/bin/sh
# ============================================================
# SO-PIN + Dongle Lifecycle Integration Test
#
# Prerequisites:
#   - TEE + TA deployed on target (QEMU or real device)
#   - tbox_keystore binary in PATH
#   - Dummy dongle key generated (make gen-dummy-key)
#
# Run:  ./test_so_lifecycle.sh
# ============================================================

set -e

# ---- Config ----
PIN="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
SO_PIN="f1e2d3c4b5a60718293a4b5c6d7e8f90"
WRONG_PIN="00000000000000000000000000000000"
CLI="${CLI:-optee_example_tbox_keystore}"
TMP_DIR="/tmp/tbox_so_test"
PASS=0
FAIL=0

# ---- Helpers ----
ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); exit 1; }
info() { echo "--- $1 ---"; }

check_ok() {
    _desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        ok "$_desc"
    else
        fail "$_desc"
    fi
}

check_fail() {
    _desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        fail "$_desc (expected failure, got success)"
    else
        ok "$_desc (expected failure)"
    fi
}

# ---- Setup ----
setup() {
    info "Setup"
    mkdir -p "$TMP_DIR"

    # Ensure dummy key exists
    if [ ! -f "/tmp/dummy-dongle-key.pem" ]; then
        info "Generating dummy dongle key..."
        openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null | \
            openssl pkcs8 -topk8 -nocrypt -out "/tmp/dummy-dongle-key.pem" 2>/dev/null
        ok "Dummy key generated"
    fi

    # Provision device identity
    $CLI --init-pin "$PIN"
    ok "PIN initialized"

    $CLI --gen-rsa device-key --size 2048 --sign --decrypt
    ok "RSA key generated"

    $CLI --gen-aes ota-key --size 256 --decrypt
    ok "AES key generated"
}

# ---- Phase A: SO Provisioning ----
test_so_provision() {
    info "SO provisioning"

    # Init SO-PIN
    $CLI --init-so-pin "$SO_PIN"
    ok "SO-PIN initialized"

    # Provision dongle from connected dongle
    $CLI --provision-dongle --dongle dummy
    ok "Dongle provisioned (auto-detect)"

    # Create a second dummy key and provision from file
    openssl ecparam -genkey -name prime256v1 2>/dev/null | \
        openssl pkey -pubout -outform DER -out "$TMP_DIR/dongle2.der" 2>/dev/null
    $CLI --provision-dongle-from-file "$TMP_DIR/dongle2.der"
    ok "Second dongle provisioned (from file)"

    # Check SO info
    out=$($CLI --so-info 2>/dev/null || true)
    echo "$out" | grep -q "PROVISIONED" && ok "SO state: PROVISIONED" || fail "SO state not PROVISIONED"
    echo "$out" | grep -q "2 registered" && ok "Dongle count: 2" || fail "Dongle count not 2"
}

# ---- Phase B: Lock + SO Unlock ----
test_so_unlock() {
    info "Lock and SO unlock"

    # Lock TA
    $CLI --lock
    ok "TA locked"

    # Write operations should fail after lock
    check_fail "Write after lock" $CLI --gen-rsa test-key --size 2048

    # SO unlock
    $CLI --so-unlock --so-pin "$SO_PIN" --dongle dummy
    ok "SO unlock"

    # SO info should show UNLOCKED
    out=$($CLI --so-info 2>/dev/null || true)
    echo "$out" | grep -q "UNLOCKED" && ok "SO state: UNLOCKED" || fail "SO state not UNLOCKED"

    # Write operations should succeed after unlock
    $CLI --gen-rsa test-key --size 2048 --sign
    ok "Write after SO unlock"
    $CLI --delete test-key
    ok "Cleanup test key"
}

# ---- Phase C: Re-lock ----
test_so_relock() {
    info "SO re-lock"

    $CLI --so-lock
    ok "SO re-locked"

    out=$($CLI --so-info 2>/dev/null || true)
    echo "$out" | grep -q "LOCKED" && ok "SO state: LOCKED" || fail "SO state not LOCKED"

    # Write should fail again
    check_fail "Write after SO re-lock" $CLI --gen-rsa test-key2 --size 2048
}

# ---- Phase D: Error paths ----
test_error_paths() {
    info "Error paths"

    # Wrong PIN
    check_fail "Wrong SO-PIN" $CLI --so-unlock --so-pin "$WRONG_PIN" --dongle dummy

    out=$($CLI --so-info 2>/dev/null || true)
    echo "$out" | grep -q "1 consecutive" && ok "Consecutive failures: 1" || fail "Consecutive failures not 1"

    # Wrong PIN again
    check_fail "Wrong SO-PIN #2" $CLI --so-unlock --so-pin "$WRONG_PIN" --dongle dummy
    # Wrong PIN #3 triggers cooldown
    check_fail "Wrong SO-PIN #3" $CLI --so-unlock --so-pin "$WRONG_PIN" --dongle dummy

    out=$($CLI --so-info 2>/dev/null || true)
    echo "$out" | grep -q "Cooldown" && ok "Cooldown active" || fail "Cooldown not active"

    # Wrong dongle index
    # (skip if only 2 dongles — we expect failure for index 99 anyway)
    check_fail "Invalid dongle index" $CLI --so-unlock --so-pin "$SO_PIN" --dongle dummy --dongle-index 99
}

# ---- Phase E: Recover after cooldown ----
# Skipped by default — requires waiting 60 seconds.
# Uncomment to run manually:
# test_recover_after_cooldown() {
#     info "Waiting 60s for cooldown..."
#     sleep 60
#     $CLI --so-unlock --so-pin "$SO_PIN" --dongle dummy
#     ok "SO unlock after cooldown"
#     $CLI --so-lock
# }

# ---- Teardown ----
teardown() {
    info "Teardown"
    rm -rf "$TMP_DIR"
    ok "Test temp files removed"
}

# ---- Main ----
echo "============================================"
echo " SO-PIN + Dongle Lifecycle Integration Test"
echo "============================================"
echo ""

setup
test_so_provision
test_so_unlock
test_so_relock
test_error_paths
teardown

echo ""
echo "============================================"
echo " Results: $PASS passed, $FAIL failed"
echo "============================================"

exit $FAIL
