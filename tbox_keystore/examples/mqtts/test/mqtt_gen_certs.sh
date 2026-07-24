#!/bin/sh
# ============================================================
#  Generate CA-signed certificates for MQTTS mutual auth.
#
#  Prerequisites:
#    TA keys provisioned: pub-key, sub-key (run ta_setup_keys.sh)
#    gen_csr compiled
#
#  Output (all under /tmp):
#    root-ca.crt / root-ca.key    Root CA
#    broker.crt  / broker.key     Broker (CA-signed, software key)
#    pub.crt                      Publisher  (CA-signed, TA key)
#    sub.crt                      Subscriber (CA-signed, TA key)
#
#  After this script:
#    - Copy root-ca.crt, broker.crt, broker.key to EMQX server
#    - pub.crt, sub.crt, root-ca.crt stay on device
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(dirname "$SCRIPT_DIR")"
GEN_CSR="$SRC_DIR/build/gen_csr"
TBOX="optee_example_tbox_keystore"

CA_KEY=/tmp/root-ca.key
CA_CRT=/tmp/root-ca.crt
BROKER_KEY=/tmp/broker.key
BROKER_CRT=/tmp/broker.crt
PUB_CSR=/tmp/pub.csr
SUB_CSR=/tmp/sub.csr
PUB_CRT=/tmp/pub.crt
SUB_CRT=/tmp/sub.crt

# ---- 1. Root CA ----
echo "=== [1/5] Generating Root CA ==="
"$SCRIPT_DIR/mqtt_gen_root_ca.sh"

# ---- 2. Broker (software key) ----
echo ""
echo "=== [2/5] Broker certificate (software key) ==="
openssl genrsa -out "$BROKER_KEY" 2048
openssl req -new -key "$BROKER_KEY" -out /tmp/broker.csr \
    -subj "/CN=tbox-broker"
openssl x509 -req -in /tmp/broker.csr \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$BROKER_CRT" -days 3650
rm -f /tmp/broker.csr
echo "    Broker cert: $BROKER_CRT"

# ---- 3. Publisher (TA key) ----
echo ""
echo "=== [3/5] Publisher certificate (TA key: pub-key) ==="
if [ ! -x "$GEN_CSR" ]; then
    echo "ERROR: gen_csr not built — run: cd $SRC_DIR/build && cmake .. && make"
    exit 1
fi
$GEN_CSR pub-key tbox-pub "$PUB_CSR"
openssl x509 -req -in "$PUB_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$PUB_CRT" -days 3650
rm -f "$PUB_CSR"
echo "    Publisher cert: $PUB_CRT"

# ---- 4. Subscriber (TA key) ----
echo ""
echo "=== [4/5] Subscriber certificate (TA key: sub-key) ==="
$GEN_CSR sub-key tbox-sub "$SUB_CSR"
openssl x509 -req -in "$SUB_CSR" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$SUB_CRT" -days 3650
rm -f "$SUB_CSR"
echo "    Subscriber cert: $SUB_CRT"

# ---- 5. Summary ----
echo ""
echo "=========================================="
echo " DONE — certs under /tmp/"
echo "=========================================="
echo ""
echo "  CA:      $CA_CRT"
echo "  Broker:  $BROKER_CRT / $BROKER_KEY"
echo "  Pub:     $PUB_CRT"
echo "  Sub:     $SUB_CRT"
echo ""
echo "EMQX config:"
echo "  ssl.certfile  = $BROKER_CRT"
echo "  ssl.keyfile   = $BROKER_KEY"
echo "  ssl.cacertfile = $CA_CRT"
echo "  ssl.verify    = verify_peer"
