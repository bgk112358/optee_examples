#!/bin/bash
#
# TBox Keystore Provisioning Script (example)
#
# This script simulates the factory provisioning flow:
#   1. Initialize PIN
#   2. Generate device identity key (RSA)
#   3. Generate OTA decryption key (AES, decrypt-only)
#   4. Export RSA public key for CA signing
#   5. Lock the TA
#
# Usage: ./provision.sh <pin-hex>
#

set -e

PIN="${1}"
if [ -z "$PIN" ]; then
    echo "Usage: $0 <pin-hex>"
    echo "  e.g. $0 a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    exit 1
fi

CLIENT="./tbox_keystore"

echo "========================================="
echo " TBox Keystore Provisioning"
echo "========================================="
echo ""

# Step 1: Initialize PIN
echo "[1/5] Initializing PIN..."
$CLIENT --init-pin "$PIN"

# Step 2: Generate device identity key (RSA-2048)
echo "[2/5] Generating device identity key (RSA-2048)..."
$CLIENT --gen-rsa device-key --size 2048 --sign --decrypt

# Step 3: Generate OTA decryption key (AES-256, decrypt only)
echo "[3/5] Generating OTA decryption key (AES-256)..."
$CLIENT --gen-aes ota-key --size 256 --decrypt

# Step 4: Export public key for CA certificate signing
echo "[4/5] Exporting device public key..."
$CLIENT --export-pub device-key --out device-key.pub

# Step 5: Lock TA
echo "[5/5] Locking TA..."
$CLIENT --lock

echo ""
echo "========================================="
echo " Provisioning complete!"
echo ""
echo " Public key: device-key.pub"
echo "   → Send this to your CA for signing."
echo ""
echo " Next steps on the device:"
echo "   1. Verify: $CLIENT --info device-key"
echo "   2. Verify: $CLIENT --info ota-key"
echo "   3. Sign test: $CLIENT --sign device-key --data \$(echo -n test | xxd -p)"
echo "========================================="
