#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RUNTIME_DIR="${SCRIPT_DIR}/runtime"

if [ -L "${RUNTIME_DIR}" ]; then
    echo "Refusing to clean a symbolic-link smoke runtime directory." >&2
    exit 1
fi

rm -f \
    "${RUNTIME_DIR}/client/token" \
    "${RUNTIME_DIR}/data/auth/client.json" \
    "${RUNTIME_DIR}/data/tls/server.key" \
    "${RUNTIME_DIR}/data/tls/server.crt" \
    "${RUNTIME_DIR}/openssl.cnf"
rmdir \
    "${RUNTIME_DIR}/client" \
    "${RUNTIME_DIR}/data/auth" \
    "${RUNTIME_DIR}/data/tls" \
    "${RUNTIME_DIR}/data" \
    "${RUNTIME_DIR}" \
    2>/dev/null || true

echo "Removed temporary offline smoke material."
