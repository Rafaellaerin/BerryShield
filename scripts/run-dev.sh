#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export BERRYSHIELD_ENV=${BERRYSHIELD_ENV:-development}
export BERRYSHIELD_SIGNING_SECRET=${BERRYSHIELD_SIGNING_SECRET:-development-only-change-me-32-bytes-minimum}
export BERRYSHIELD_SITE_KEY=${BERRYSHIELD_SITE_KEY:-bs_dev_public}
export BERRYSHIELD_SITE_SECRET=${BERRYSHIELD_SITE_SECRET:-bs_dev_secret_change_me}
export BERRYSHIELD_ALLOWED_HOSTS=${BERRYSHIELD_ALLOWED_HOSTS:-localhost,127.0.0.1}
export BERRYSHIELD_BIND_IP_PREFIX=${BERRYSHIELD_BIND_IP_PREFIX:-false}
export BERRYSHIELD_REPUTATION_URL=${BERRYSHIELD_REPUTATION_URL:-http://127.0.0.1:8081}

echo 'Start reputation in another terminal:'
echo "  cd $ROOT/services/reputation && PYTHONPATH=. python -m berry_reputation"
echo 'Starting gateway on :8080'
cd "$ROOT/services/gateway"
exec go run .
