#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

if [[ -f ca.pem && -f ca.key && -f server.pem && -f server.key ]]; then
  echo "TLS certs already exist in $DIR"
  exit 0
fi

openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/CN=Benchmark CA" -out ca.pem

openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr

cat > san.ext <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -sha256 -extfile san.ext

rm -f server.csr san.ext ca.srl
chmod 600 *.key

echo "Generated TLS certs in $DIR"
