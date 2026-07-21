#!/bin/sh
# ============================================================
#  TLS Mutual Auth — 端到端测试
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
TLS_BIN="${ENGINE_DIR}/build/tls_mutual_auth"

if [ ! -x "$TLS_BIN" ]; then
    echo "ERROR: tls_mutual_auth not found at $TLS_BIN"
    echo "Build with:  cd $ENGINE_DIR && mkdir -p build && cd build && cmake .. && make"
    exit 1
fi

# Clean up any stale server from a previous run
pkill -f tls_mutual_auth 2>/dev/null || true
sleep 0.5

echo "========================================="
echo " Starting TLS mutual-auth test"
echo "========================================="
echo ""

# Start server in background
echo "[TEST] Starting TLS server (TEE-backed key: server-key)..."
$TLS_BIN --server &
SERVER_PID=$!
sleep 2

# Run client
echo ""
echo "[TEST] Starting TLS client (TEE-backed key: client-key)..."
if $TLS_BIN --client; then
    echo ""
    echo "========================================="
    echo " TEST PASSED"
    echo " Both sides' CertificateVerify were"
    echo " signed inside OP-TEE via ENGINE."
    echo "========================================="
    RET=0
else
    echo ""
    echo "========================================="
    echo " TEST FAILED"
    echo "========================================="
    RET=1
fi

# Clean up server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

exit $RET
