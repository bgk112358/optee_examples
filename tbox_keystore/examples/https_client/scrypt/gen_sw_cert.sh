#!/bin/sh
# Generate a software RSA key + self-signed certificate for
# the TLS server side (openssl s_server).  This key is NOT in TA.
set -e

KEY=/tmp/server-sw.key
CRT=/tmp/server-sw.crt

echo "=== Generating server software RSA key ==="
openssl genrsa -out "$KEY" 2048

echo ""
echo "=== Generating self-signed server certificate ==="
openssl req -new -x509 -key "$KEY" -out "$CRT" -days 3650 \
    -subj "/CN=tbox-server-sw" \
    -addext "subjectAltName=IP:127.0.0.1"

echo ""
echo "=== Done ==="
echo "    Server key:  $KEY"
echo "    Server cert: $CRT"
