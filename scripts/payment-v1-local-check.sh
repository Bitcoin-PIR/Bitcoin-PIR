#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/payment-v1-local-check.sh [--quick|--full]

Runs BitcoinPIR payment-v1 checks without contacting payment infrastructure or
using real funds. Cargo is forced offline; full mode requires a preinstalled
`wasm-pack`/`wasm-bindgen` toolchain and refuses to bootstrap it from the
network.

  --quick  Five-method × five-workload matrix plus focused persistence and fake-Lightning checks.
           It never starts a listener.
  --full   The complete offline payment-platform Rust suite, operator tooling,
           loopback-only unified-server process E2E and WASM checks, plus web
           typecheck/tests/bundle.
           This is the default.

Full mode starts only temporary unified-server listeners explicitly bound to
127.0.0.1; the process test kills and waits for every child. Neither mode
contacts a Lightning node or Cashu mint, publishes to a Nostr relay, deploys a
server, uses real funds, or modifies source files. Cargo, the JavaScript package
manager, and tests may update their normal local build caches (for example
target/ and web/node_modules cache metadata).
EOF
}

mode="full"
case "${1:-}" in
  "") ;;
  --quick) mode="quick" ;;
  --full) mode="full" ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

if [[ ! -f Cargo.toml || ! -f docs/payment/IMPLEMENTATION_STATUS.md ]]; then
  echo "payment-v1-local-check: repository root validation failed" >&2
  exit 1
fi

echo "[1/5] canonical five-method x five-workload admission matrix"
cargo test --offline -p pir-runtime-core --test service_admission_matrix

echo "[2/5] real provider-store receipt/BAT adapters and durable replay boundary"
cargo test --offline -p pir-payment-crypto --features provider-store \
  --test provider_store_bat_adapter
cargo test --offline -p pir-runtime-core --test service_admission_matrix \
  direct_receipt_production_committer_spend_survives_store_restart

echo "[3/5] Free, standard Cashu, and experimental ARC persistence/concurrency"
cargo test --offline -p pir-service-store free_ip_rate_limit
cargo test --offline -p pir-cashu-client
cargo test --offline -p pir-arc-adapter

echo "[4/5] fake-Lightning, quote/claim lifecycle, and native/WASM client boundaries"
cargo test --offline -p pir-lightning-backend
cargo test --offline -p pir-issuer-core
cargo test --offline -p pir-issuer-service
cargo test --offline -p payment-issuer
cargo test --offline -p pir-sdk-client --all-targets
cargo test --offline -p pir-sdk-wasm --lib

if [[ "$mode" == "quick" ]]; then
  echo "[5/5] quick mode complete (no network, no funds)"
  exit 0
fi

echo "[5/7] full offline platform, operator tooling, and server wiring"
cargo test --offline \
  -p pir-channel \
  -p pir-service-protocol \
  -p pir-service-store \
  -p pir-payment-crypto \
  -p pir-lightning-backend \
  -p pir-issuer-store \
  -p pir-issuer-core \
  -p pir-issuer-credentials \
  -p pir-issuer-clearing \
  -p pir-issuer-service \
  -p pir-provider-clearing-client \
  -p pir-cashu-client \
  -p pir-arc-adapter \
  -p pir-directory-nostr \
  -p pir-runtime-core \
  -p pir-sdk-client \
  -p pir-sdk-wasm \
  -p payment-issuer \
  -p bpir-admin
cargo test --offline -p runtime --bin unified_server
cargo test --offline -p runtime --test payment_v1_process_e2e
cargo check --offline -p runtime --bin unified_server

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/bpir-payment-v1-fixture.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT HUP INT TERM
scripts/fixtures/generate-payment-v1-no-funds.sh "$fixture_root/generated"
test -s "$fixture_root/generated/fixture.json"

echo "[6/7] WASM target and generated binding boundary"
cargo check --offline --target wasm32-unknown-unknown -p pir-sdk-wasm
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "payment-v1-local-check: wasm-pack is required in full mode" >&2
  exit 1
fi
CARGO_NET_OFFLINE=true wasm-pack build crates/sdk/wasm \
  --target web --out-dir pkg --mode no-install -- --offline

if [[ ! -d web/node_modules ]]; then
  echo "payment-v1-local-check: web/node_modules is absent; refusing network install" >&2
  echo "Install pinned web dependencies separately, then rerun --full." >&2
  exit 1
fi

echo "[7/7] web strict typecheck, unit tests, and production bundle"
(cd web && npm run build && npm test && npm run build-web)

echo "payment-v1-local-check: full mode complete (no network, no funds)"
