#!/bin/sh
set -eu

exec /opt/tls/bin/tls_benchmark \
  --classical-host "${CLASSICAL_HOST:-classical-tls}" \
  --classical-port "${CLASSICAL_PORT:-4433}" \
  --hybrid-host "${HYBRID_HOST:-hybrid-tls}" \
  --hybrid-port "${HYBRID_PORT:-4434}" \
  --p256-host "${P256_HOST:-hybrid-p256-tls}" \
  --p256-port "${P256_PORT:-4435}" \
  --dashboard-host "${DASHBOARD_HOST:-dashboard}" \
  --dashboard-port "${DASHBOARD_PORT:-8000}" \
  --cafile "${CA_FILE:-/opt/tls/certs/server.crt}" \
  --iterations "${ITERATIONS:-100}" \
  --warmup "${WARMUP:-10}" \
  "$@"
