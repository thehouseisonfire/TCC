#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

certs_valid() {
  [[ -f ca.pem && -f ca.key && -f server.pem && -f server.key ]] || return 1
  openssl x509 -in ca.pem -noout -text \
    | grep -q "CA:TRUE" || return 1
  openssl x509 -in ca.pem -noout -text \
    | grep -q "Certificate Sign, CRL Sign" || return 1
  openssl x509 -in server.pem -noout -text \
    | grep -q "CA:FALSE" || return 1
  openssl x509 -in server.pem -noout -text \
    | grep -q "TLS Web Server Authentication" || return 1
}

if [[ "$FORCE" -eq 0 ]] && certs_valid; then
  chmod 644 server.key
  echo "TLS certs already exist in $DIR"
  exit 0
fi

rm -f ca.pem ca.key server.pem server.key server.csr ca.srl ca_ext.cnf server_ext.cnf

cat > ca_ext.cnf <<'CAEOF'
[ca_extensions]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
CAEOF

openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -subj "/CN=Benchmark CA" -out ca.pem \
  -extensions ca_extensions -config ca_ext.cnf

openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr

cat > server_ext.cnf <<'EOF'
[server_extensions]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,DNS:authz,DNS:token-issuer,DNS:mosquitto,IP:127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -sha256 \
  -extfile server_ext.cnf -extensions server_extensions

rm -f server.csr ca.srl ca_ext.cnf server_ext.cnf
chmod 600 *.key
chmod 644 server.key

echo "Generated TLS certs in $DIR"
