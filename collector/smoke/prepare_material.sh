#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this test-only preparation script as root (for UID 2000 ownership)." >&2
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "The Synology host must provide the openssl command for this test." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME_DIR="${SCRIPT_DIR}/runtime"
DATA_DIR="${RUNTIME_DIR}/data"
CLIENT_DIR="${RUNTIME_DIR}/client"
TLS_DIR="${DATA_DIR}/tls"
AUTH_DIR="${DATA_DIR}/auth"
CONFIG_FILE="${RUNTIME_DIR}/openssl.cnf"

if [ -e "${RUNTIME_DIR}" ] || [ -L "${RUNTIME_DIR}" ]; then
    echo "Refusing to overwrite an existing smoke runtime directory." >&2
    exit 1
fi

umask 077
mkdir -p "${CLIENT_DIR}" "${TLS_DIR}" "${AUTH_DIR}"

cat > "${CONFIG_FILE}" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no

[subject]
CN = collector

[extensions]
subjectAltName = @names
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
extendedKeyUsage = serverAuth

[names]
DNS.1 = collector
EOF

openssl req \
    -x509 \
    -newkey rsa:3072 \
    -sha256 \
    -nodes \
    -days 1 \
    -config "${CONFIG_FILE}" \
    -keyout "${TLS_DIR}/server.key" \
    -out "${TLS_DIR}/server.crt" \
    >/dev/null 2>&1

TOKEN=$(openssl rand -hex 32)
TOKEN_DIGEST=$(printf '%s' "${TOKEN}" | openssl dgst -sha256 -r | awk '{print $1}')
printf '%s' "${TOKEN}" > "${CLIENT_DIR}/token"

cat > "${AUTH_DIR}/client.json" <<EOF
{
  "schema_version": "1",
  "token_sha256": "${TOKEN_DIGEST}",
  "meter_id": "mtr_7f93b3e31d514db18cd62c0fcaa19a8e",
  "scopes": ["health:read", "measurements:read", "status:read"]
}
EOF

rm -f "${CONFIG_FILE}"
chown -R 2000:2000 "${RUNTIME_DIR}"
chmod 0700 "${RUNTIME_DIR}" "${DATA_DIR}" "${CLIENT_DIR}" "${TLS_DIR}" "${AUTH_DIR}"
chmod 0600 "${CLIENT_DIR}/token" "${TLS_DIR}/server.key" "${AUTH_DIR}/client.json"
chmod 0644 "${TLS_DIR}/server.crt"

echo "Prepared temporary offline smoke material without printing the token."
