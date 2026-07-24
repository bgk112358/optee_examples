#!/bin/sh
set -e

TBOX="optee_example_tbox_keystore"
TLS="tls_mutual_auth"

echo "=== Step 1: Init PIN ==="
$TBOX --init-pin 31323334

echo ""
echo "=== Step 2: Generate server and client RSA keys ==="
$TBOX --gen-rsa server-key --size 2048 --sign --decrypt
$TBOX --gen-rsa client-key --size 2048 --sign --decrypt

echo ""
echo "=== Step 3: Verify keys ==="
$TBOX --info server-key
$TBOX --info client-key

echo ""
echo "=== Step 4: Generate TLS certs (one process, both keys) ==="
$TLS --gen-certs

echo ""
echo "=== Step 5: Lock TA ==="
$TBOX --lock

echo ""
echo "=== Done. ==="
echo "    Now run:  ./test/run_test.sh"
