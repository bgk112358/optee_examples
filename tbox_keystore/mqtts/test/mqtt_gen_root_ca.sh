#!/bin/sh
# Generate Root CA key + self-signed certificate.
# All broker/dev certs are signed by this CA.
set -e

CA_KEY=/tmp/root-ca.key
CA_CRT=/tmp/root-ca.crt

echo "=== Generating Root CA key ==="
openssl genrsa -out "$CA_KEY" 2048

echo ""
echo "=== Generating Root CA self-signed certificate ==="
openssl req -new -x509 -key "$CA_KEY" -out "$CA_CRT" -days 3650 \
    -subj "/CN=tbox-root-ca"

echo ""
echo "=== Done ==="
echo "    CA key:  $CA_KEY"
echo "    CA cert: $CA_CRT"
