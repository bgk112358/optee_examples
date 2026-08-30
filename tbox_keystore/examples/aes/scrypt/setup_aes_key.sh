#!/bin/sh
# setup_aes_key.sh - 前置准备：灌装 PIN + 生成 AES 文件加密密钥
#
# 依赖：TBox Keystore CA (optee_example_tbox_keystore) 已部署在设备上
set -e

TBOX="optee_example_tbox_keystore"
LABEL="${1:-file-key}"       # 默认密钥标签
PIN="${2:-31323334}"         # 默认 PIN (hex: "1234")

echo "=== Step 1: Init PIN ==="
$TBOX --init-pin "$PIN"

echo ""
echo "=== Step 2: Generate AES key (256-bit, encrypt+decrypt perms) ==="
# 若已存在会因禁止覆盖而失败，先删除
$TBOX --delete "$LABEL" 2>/dev/null || true
$TBOX --gen-aes "$LABEL" --size 256 --encrypt --decrypt

echo ""
echo "=== Step 3: Verify ==="
$TBOX --info "$LABEL"

echo ""
echo "=== Done. Now run:  ./aes_crypt encrypt --key $LABEL --in <file> --out <file> --iv zero|random ==="
