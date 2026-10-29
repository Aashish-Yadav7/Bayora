#!/usr/bin/env bash
# One-command local demo (no Docker): ./scripts/dev.sh
set -e
export BAYORA_AUTH_SECRET="${BAYORA_AUTH_SECRET:-$(python3 -c 'import secrets;print(secrets.token_hex(32))')}"
export BAYORA_RED_WORKER_TOKEN="${BAYORA_RED_WORKER_TOKEN:-red-demo-credential-0001}"
export BAYORA_BLUE_WORKER_TOKEN="${BAYORA_BLUE_WORKER_TOKEN:-blue-demo-credential-001}"
export BAYORA_EVALUATOR_TOKEN="${BAYORA_EVALUATOR_TOKEN:-eval-demo-credential-0001}"
export BAYORA_DEV_HEADER_AUTH=1 BAYORA_SEED_DEMO=1
[ -d node_modules ] || npm install
npm run dev
