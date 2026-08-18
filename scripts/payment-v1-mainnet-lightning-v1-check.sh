#!/usr/bin/env bash

# Focused source-readiness check for the Mainnet Lightning V1 profile.
# It deliberately does not render a deployment, contact Core/CLN, start a
# service, invoke a browser, or create/pay an invoice.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/payment-v1-mainnet-lightning-v1-check.sh

Runs the smallest browserless source-readiness checks for Mainnet Lightning V1:
  - the versioned bpir-admin profile and read-only command contract;
  - deployment-template and rendered-artifact source contracts; and
  - the Web shared-issuer BAT separation and BOLT11 acquisition contracts.

All Cargo commands are locked and offline. This is not the full Payment V1 CI
profile and is not evidence of a rendered bundle, remote host, Mainnet CLN
node, liquidity, funds, payment, or production activation.
EOF
}

case "${1:-}" in
  "") ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

if [[ ! -f Cargo.toml || ! -f web/package.json || ! -f docs/payment/MAINNET_LIGHTNING_V1_RUNBOOK.md ]]; then
  echo "payment-v1-mainnet-lightning-v1-check: repository root validation failed" >&2
  exit 1
fi

echo "[mainnet-lightning-v1] Rust profile and read-only CLI contract"
cargo test --locked --offline -p bpir-admin mainnet_lightning

echo "[mainnet-lightning-v1] deployment source and rendered-artifact contracts"
node --check scripts/payment-v1-deployment-template-gate.mjs
node scripts/payment-v1-deployment-template-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.mjs
node --test --test-concurrency=1 scripts/payment-v1-rendered-artifact-gate.test.mjs

echo "[mainnet-lightning-v1] Web shared-issuer BAT and BOLT11 acquisition contracts"
(cd web && npm run test:contract:shared-bat-two-provider)

echo "payment-v1-mainnet-lightning-v1-check: source-ready checks complete (offline Cargo; no browser, remote node, funds, or activation)"
