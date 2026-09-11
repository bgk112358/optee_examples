#!/bin/sh
# setup_rsa_key.sh - 前置准备：灌装 PIN + 生成 RSA-2048 签名/验签密钥
#
# 依赖：TBox Keystore CA (optee_example_tbox_keystore) 已部署在设备上
set -e

TBOX="optee_example_tbox_keystore"
LABEL="${1:-rsa-key}"        # 默认密钥标签
PIN="${2:-31323334}"         # 默认 PIN (hex: "1234")

echo "=== Step 1: Init PIN ==="
$TBOX --init-pin "$PIN"

echo ""
echo "=== Step 2: Generate RSA-2048 key (sign perm; verify perm is default) ==="
# 若已存在会因禁止覆盖而失败，先删除
$TBOX --delete "$LABEL" 2>/dev/null || true
# 注意：--gen-rsa 不支持 --verify 选项；VERIFY/EXPORT_PUB 权限默认自动带上
$TBOX --gen-rsa "$LABEL" --size 2048 --sign --decrypt

echo ""
echo "=== Step 3: Verify ==="
$TBOX --info "$LABEL"

echo ""
echo "=== Done. Now run:  ./rsa_crypt sign --key $LABEL --in <file> --out <sig> [--bench-sec 1] ==="
