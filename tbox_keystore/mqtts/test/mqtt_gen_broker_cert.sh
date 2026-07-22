#!/bin/sh
# Generate broker key + self-signed certificate for EMQX.
# SAN is set to 127.0.0.1 for local deployment.
set -e

KEY=/tmp/broker.key
CRT=/tmp/broker.crt

echo "=== Generating broker RSA key ==="
openssl genrsa -out "$KEY" 2048

echo ""
echo "=== Generating self-signed broker certificate ==="
openssl req -new -x509 -key "$KEY" -out "$CRT" -days 3650 \
    -subj "/CN=emqx-broker" \
    -addext "subjectAltName=IP:127.0.0.1"

echo ""
echo "=== Done ==="
echo "    Broker key:  $KEY"
echo "    Broker cert: $CRT"
echo ""
echo "EMQX config snippet:"
echo "  listeners.ssl.default.certfile  = $CRT"
echo "  listeners.ssl.default.keyfile   = $KEY"
echo "  listeners.ssl.default.cacertfile = /tmp/tbox-client.crt"
echo "  listeners.ssl.default.verify     = verify_peer"
echo "  listeners.ssl.default.fail_if_no_peer_cert = true"
