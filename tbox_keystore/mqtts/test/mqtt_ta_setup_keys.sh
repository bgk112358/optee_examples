#!/bin/sh
# Provision MQTT keys into TA.
# pub-key + sub-key = two independent processes, no concurrency conflict.
set -e

TBOX="optee_example_tbox_keystore"

echo "=== Step 1: Init PIN ==="
$TBOX --init-pin 31323334

echo ""
echo "=== Step 2: Generate pub + sub RSA keys ==="
$TBOX --gen-rsa pub-key --size 2048 --sign --decrypt
$TBOX --gen-rsa sub-key --size 2048 --sign --decrypt

echo ""
echo "=== Step 3: Verify ==="
$TBOX --info pub-key
$TBOX --info sub-key

echo ""
echo "=== Step 4: Lock TA ==="
$TBOX --lock

echo ""
echo "=== Done. TA keys provisioned. ==="
echo "    Next: ./test/mqtt_gen_certs.sh"
