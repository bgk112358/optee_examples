#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
TLS="$ENGINE_DIR/tls_mutual_auth"

if [ ! -x "$TLS" ]; then
    echo "ERROR: tls_mutual_auth not found at $TLS"
    exit 1
fi

pkill -f tls_mutual_auth 2>/dev/null || true
sleep 0.5

echo "========================================="
echo " Starting TLS mutual-auth test"
echo "========================================="
echo ""

echo "[TEST] Starting TLS server (TEE-backed key: server-key)..."
$TLS --server &
SERVER_PID=$!
sleep 2

echo ""
echo "[TEST] Starting TLS client (TEE-backed key: client-key)..."
if $TLS --client; then
    echo ""
    echo "========================================="
    echo " TEST PASSED"
    echo "========================================="
    RET=0
else
    echo ""
    echo "========================================="
    echo " TEST FAILED"
    echo "========================================="
    RET=1
fi

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

exit $RET
