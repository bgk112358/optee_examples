#!/bin/sh
# MQTTS mutual-auth test — CA-signed certs.
#
# Prerequisites:
#   1. TA keys provisioned → ./mqtt_ta_setup_keys.sh
#   2. Certs generated    → ./mqtt_gen_certs.sh
#   3. EMQX configured with broker.crt + broker.key + root-ca.crt
#   4. gen_csr, mqtts_pub, mqtts_sub compiled
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"
PUB="$SRC_DIR/mqtts_pub"
SUB="$SRC_DIR/mqtts_sub"
BROKER="192.168.100.48"
PORT=8883
TOPIC="tbox/test"

if [ ! -x "$PUB" ] || [ ! -x "$SUB" ]; then
    echo "ERROR: mqtts_pub/mqtts_sub not found"
    echo "Build: cd $SRC_DIR && mkdir -p build && cd build && cmake .. && make"
    exit 1
fi

for f in /tmp/pub.crt /tmp/sub.crt /tmp/root-ca.crt; do
    if [ ! -f "$f" ]; then
        echo "ERROR: $f not found — run ./test/mqtt_gen_certs.sh first"
        exit 1
    fi
done

echo "========================================="
echo " MQTTS CA-signed certs test"
echo " Broker: $BROKER:$PORT"
echo " Topic:  $TOPIC"
echo " Pub key: pub-key (TA)  Cert: pub.crt"
echo " Sub key: sub-key (TA)  Cert: sub.crt"
echo " Trust : root-ca.crt"
echo "========================================="
echo ""

# Start sub in background
echo "[TEST] Starting subscriber (TEE key: sub-key)..."
$SUB "$BROKER" "$PORT" "$TOPIC" 30 &
SUB_PID=$!
sleep 2

# Publish
echo ""
echo "[TEST] Running publisher (TEE key: pub-key)..."
if $PUB "$BROKER" "$PORT" "$TOPIC" "hello from tbox (TA-signed)"; then
    echo ""
    echo "========================================="
    echo " TEST PASSED"
    echo " Pub/Sub both used CA-signed certs"
    echo " via tbox_keystore ENGINE"
    echo "========================================="
    RET=0
else
    echo ""
    echo "========================================="
    echo " TEST FAILED"
    echo "========================================="
    RET=1
fi

wait $SUB_PID 2>/dev/null || true
exit $RET
