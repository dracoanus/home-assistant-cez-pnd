#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "${SCRIPT_DIR}"

cleanup_on_exit() {
    docker compose -f compose.yaml down --remove-orphans >/dev/null 2>&1 || true
    if [ -d runtime ] && [ ! -L runtime ]; then
        sh ./cleanup_material.sh >/dev/null 2>&1 || true
    fi
}
trap cleanup_on_exit EXIT INT TERM

docker compose -f compose.yaml config >/dev/null
sh ./prepare_material.sh
docker compose -f compose.yaml build --pull=false collector
docker compose -f compose.yaml up -d collector
docker compose -f compose.yaml run --rm smoke-client
docker compose -f compose.yaml stop --timeout 10 collector

COLLECTOR_LOG=$(docker compose -f compose.yaml logs --no-color collector)
printf '%s\n' "${COLLECTOR_LOG}"
printf '%s\n' "${COLLECTOR_LOG}" | grep -F '"event":"service_started"' >/dev/null
printf '%s\n' "${COLLECTOR_LOG}" | grep -F '"event":"service_stopped"' >/dev/null

docker compose -f compose.yaml down --remove-orphans
sh ./cleanup_material.sh
trap - EXIT INT TERM
echo "PASS: Collector stopped cleanly and the temporary material was removed."
