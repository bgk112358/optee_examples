#!/bin/sh
# ============================================================
#  TLS Mutual Auth — 测试前置: 生成 TEE 业务密钥
# ============================================================
set -e

TBOX="./tbox_keystore"

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
echo "=== Step 4: Lock TA ==="
$TBOX --lock

echo ""
echo "=== Done. TA is provisioned and locked. ==="
echo "    Now run:  ./test/run_test.sh"
