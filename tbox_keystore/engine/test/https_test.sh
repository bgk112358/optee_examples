#!/bin/sh
# ============================================================
#  HTTPS mutual-auth test
#
#  Server: openssl s_server (software key)
#  Client: https_client (TEE-backed key via tbox_keystore ENGINE)
#
#  Prerequisites:
#    ./setup_keys.sh               (TA keys + client cert)
#    ./gen_sw_cert.sh              (server software key + cert)
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
CLIENT="$ENGINE_DIR/https_client"
SERVER_KEY="/tmp/server-sw.key"
SERVER_CRT="/tmp/server-sw.crt"
CLIENT_CRT="/tmp/tbox-client.crt"
PORT=9443

if [ ! -x "$CLIENT" ]; then
    echo "ERROR: https_client not found at $CLIENT"
    echo "Build with: cd $ENGINE_DIR && mkdir -p build && cd build && cmake .. && make"
    exit 1
fi

# Clean up stale server
pkill -f "openssl s_server.*$PORT" 2>/dev/null || true
sleep 0.5

echo "========================================="
echo " HTTPS mutual-auth test"
echo " Server: openssl s_server (software key)"
echo " Client: https_client (TEE ENGINE key)"
echo "========================================="
echo ""

# Start server (background)
echo "[TEST] Starting openssl s_server on :$PORT ..."
openssl s_server \
    -4 \
    -accept "127.0.0.1:$PORT" \
    -cert "$SERVER_CRT" \
    -key "$SERVER_KEY" \
    -CAfile "$CLIENT_CRT" \
    -verify 1 -Verify 1 \
    -www -quiet \
    &
SERVER_PID=$!
sleep 2

# Run client
echo ""
echo "[TEST] Running https_client (TEE-backed key: client-key) ..."
RET=0
if $CLIENT; then
    echo ""
    echo "========================================="
    echo " TEST PASSED"
    echo " https_client completed HTTPS GET via"
    echo " tbox_keystore ENGINE."
    echo "========================================="
else
    echo ""
    echo "========================================="
    echo " TEST FAILED"
    echo "========================================="
    RET=1
fi

# Cleanup
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

exit $RET
