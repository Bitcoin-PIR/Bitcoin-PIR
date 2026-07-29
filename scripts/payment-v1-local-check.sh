#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/payment-v1-local-check.sh [--quick|--full]

Runs BitcoinPIR payment-v1 checks without contacting payment infrastructure or
using real funds. Cargo is forced offline; full mode requires a preinstalled
`wasm-pack`/`wasm-bindgen` toolchain and refuses to bootstrap it from the
network.

  --quick  Five-method × five-workload matrix plus focused persistence,
           directory-relay, deployment-template and fake-Lightning checks.
           It starts no service process; unit tests may briefly bind loopback
           TCP or Unix-domain listeners.
  --full   The default offline payment-platform Rust suite, operator tooling,
           loopback-only unified-server process E2E (including strict-TLS
           Standard Cashu and authenticated direct TEE-ORAM), WASM checks,
           web typecheck/tests/bundle, a local
           Chromium multi-tab vault test, a real-WASM/loopback no-funds issuer
           acquisition test, and a browser -> two independent issuers -> two
           real provider-gate test. This is the default.

Full mode starts only temporary unified-server, rollback-authority,
deterministic test-only TLS/NUT-03 mint, Vite and fake issuer listeners
explicitly bound to 127.0.0.1; the tests kill and wait for every child. Neither
mode contacts an external Lightning node or Cashu mint, publishes to a Nostr
relay, deploys a server, uses real funds, or modifies source files. Quick mode
starts no persistent service process. Cargo, the JavaScript package manager,
and tests may update their normal local build caches (for example target/ and
web/node_modules cache metadata).
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
cargo test --locked --offline -p pir-runtime-core --test service_admission_matrix

echo "[2/5] real provider-store receipt/BAT adapters and durable replay boundary"
cargo test --locked --offline -p pir-strict-https
cargo test --locked --offline -p pir-private-files
cargo test --locked --offline -p pir-rollback-authority-protocol
cargo test --locked --offline -p pir-rollback-authority-client
cargo test --locked --offline -p pir-rollback-authority-store
cargo test --locked --offline -p rollback-authority
cargo test --locked --offline -p pir-payment-crypto --features provider-store \
  --test provider_store_bat_adapter
cargo test --locked --offline -p pir-runtime-core --test service_admission_matrix \
  direct_receipt_production_committer_spend_survives_store_restart

echo "[3/5] Free, standard Cashu, and experimental ARC persistence/concurrency"
cargo test --locked --offline -p pir-service-store free_ip_rate_limit
cargo test --locked --offline -p pir-cashu-client
cargo test --locked --offline -p pir-cashu-custody
cargo test --locked --offline -p pir-arc-adapter --features provider-store

echo "[4/5] fake-Lightning, quote/claim lifecycle, and native/WASM client boundaries"
cargo test --locked --offline -p bitcoinpir-directory-relay
cargo test --locked --offline -p bitcoinpir-cln-rpc-guard
cargo test --locked --offline -p pir-lightning-backend
cargo test --locked --offline -p pir-issuer-core
cargo test --locked --offline -p pir-issuer-service
cargo test --locked --offline -p payment-issuer
cargo test --locked --offline -p payment-issuer --features test-only-fake-lightning
cargo run --locked --offline -p payment-issuer \
  --features test-only-fake-lightning -- serve-fake --help >/dev/null
cargo test --locked --offline -p pir-sdk-client --all-targets
cargo test --locked --offline -p pir-sdk-wasm --lib
node --check scripts/payment-v1-deployment-template-gate.mjs
node --test scripts/payment-v1-deployment-template-gate.test.mjs
node scripts/payment-v1-deployment-template-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.test.mjs
node --check scripts/payment-v1-linux-runtime-evidence.mjs
node --check scripts/payment-v1-linux-runtime-evidence.test.mjs
node --test \
  scripts/payment-v1-rendered-artifact-gate.test.mjs \
  scripts/payment-v1-linux-runtime-evidence.test.mjs

if [[ "$mode" == "quick" ]]; then
  echo "[5/5] quick mode complete (no external network, no funds)"
  exit 0
fi

echo "[5/9] full offline platform, operator tooling, and server wiring"
cargo test --locked --offline \
  -p pir-channel \
  -p pir-strict-https \
  -p pir-private-files \
  -p pir-rollback-authority-protocol \
  -p pir-rollback-authority-client \
  -p pir-rollback-authority-store \
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
  -p pir-cashu-custody \
  -p pir-arc-adapter \
  -p pir-directory-nostr \
  -p bitcoinpir-directory-relay \
  -p bitcoinpir-cln-rpc-guard \
  -p pir-runtime-core \
  -p pir-sdk-client \
  -p pir-sdk-wasm \
  -p payment-issuer \
  -p rollback-authority \
  -p bpir-admin
cargo test --locked --offline -p runtime --lib hint_pool
cargo test --locked --offline -p runtime --bin unified_server
cargo test --locked --offline -p runtime \
  --features test-only-unsafe-query-logging \
  --bin unified_server \
  service_admission_dispatch_tests::explicit_debug_feature_cli_parser_recognizes_unsafe_logging_flag \
  -- --exact
cargo test --locked --offline -p runtime --test payment_v1_process_e2e
cargo test --locked --offline -p runtime --test payment_v1_methods_process_e2e
cargo test --locked --offline -p runtime --test payment_v1_harmony_pool_process_e2e
cargo test --locked --offline -p runtime --features cuckoo-oram \
  --test payment_v1_tee_oram_process_e2e
cargo test --locked --offline -p bitcoinpir-directory-relay \
  --test payment_v1_two_relay_process_e2e \
  two_relay_real_process_catalog_e2e \
  -- --exact --ignored
cargo test --locked --offline -p pir-rollback-authority-client \
  --features test-only-webpki-root \
  test_only_webpki_root_requires_owner_only_regular_file
test_root_release_log="$(mktemp "${TMPDIR:-/tmp}/bpir-test-root-release.XXXXXX")"
if cargo check --locked --offline --release -p pir-strict-https \
  --features test-only-webpki-root >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: test-only WebPKI root compiled in release mode" >&2
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release \
  -p pir-strict-https --features test-only-webpki-root \
  >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: test-only WebPKI root compiled in assertions-enabled release mode" >&2
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if cargo check --locked --offline --release -p payment-issuer \
  --features remote-authority-process-e2e >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: payment-issuer test-only remote-authority feature compiled in release mode" >&2
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if cargo check --locked --offline --release -p runtime \
  --features remote-authority-process-e2e >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: runtime test-only remote-authority feature compiled in release mode" >&2
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if cargo run --locked --offline --release -p payment-issuer -- \
  serve-fake --help >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: default release payment-issuer accepted serve-fake" >&2
  exit 1
fi
grep -F "unrecognized subcommand 'serve-fake'" "$test_root_release_log" >/dev/null
if cargo check --locked --offline --release -p payment-issuer \
  --features test-only-fake-lightning >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: fake Lightning compiled in release mode" >&2
  exit 1
fi
grep -F 'test-only-fake-lightning must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release \
  -p payment-issuer --features test-only-fake-lightning \
  >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: fake Lightning compiled in assertions-enabled release mode" >&2
  exit 1
fi
grep -F 'test-only-fake-lightning must never be compiled into a production release' \
  "$test_root_release_log" >/dev/null
if cargo check --locked --offline --release -p runtime \
  --features test-only-unsafe-query-logging \
  >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: unsafe query logging compiled in release mode" >&2
  exit 1
fi
# The backticks are literal compiler-diagnostic bytes, not shell syntax.
# shellcheck disable=SC2016
grep -F 'feature `test-only-unsafe-query-logging` is restricted to Cargo' \
  "$test_root_release_log" >/dev/null
if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release \
  -p runtime --features test-only-unsafe-query-logging \
  >"$test_root_release_log" 2>&1; then
  echo "payment-v1-local-check: unsafe query logging compiled in assertions-enabled release mode" >&2
  exit 1
fi
# The backticks are literal compiler-diagnostic bytes, not shell syntax.
# shellcheck disable=SC2016
grep -F 'feature `test-only-unsafe-query-logging` is restricted to Cargo' \
  "$test_root_release_log" >/dev/null
rm -f -- "$test_root_release_log"
cargo test --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --test payment_v1_process_e2e \
  remote_authority_process::remote_authority_real_process_tls_provider_e2e \
  -- --exact
cargo clippy --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --bin unified_server \
  --test payment_v1_process_e2e \
  --no-deps \
  -- -D warnings
cargo test --locked --offline -p payment-issuer \
  --features remote-authority-process-e2e \
  --test remote_authority_process_e2e \
  payment_issuer_remote_authority_real_process_tls_e2e \
  -- --exact
cargo clippy --locked --offline -p payment-issuer \
  --features remote-authority-process-e2e \
  --all-targets \
  --no-deps \
  -- -D warnings
cargo clippy --locked --offline -p payment-issuer \
  --features test-only-fake-lightning \
  --all-targets \
  --no-deps \
  -- -D warnings
cargo check --locked --offline -p runtime --bin unified_server

echo "[6/9] Standard Cashu and shared-issuer signed-pin TLS process boundaries"
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_process_tls_two_provider_e2e \
  -- --exact
cargo clippy --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --bin unified_server \
  --test payment_v1_standard_cashu_process_e2e \
  --no-deps \
  -- -D warnings
cashu_boundary_log="$(mktemp "${TMPDIR:-/tmp}/bpir-cashu-boundary.XXXXXX")"
trap 'rm -f -- "$cashu_boundary_log"' EXIT HUP INT TERM
if cargo run --locked --offline -p runtime --bin unified_server -- \
  --test-only-service-https-root-pem /does/not/exist \
  >"$cashu_boundary_log" 2>&1; then
  echo "payment-v1-local-check: normal unified_server accepted the test-only Cashu root flag" >&2
  rm -f -- "$cashu_boundary_log"
  exit 1
fi
grep -F 'unknown argument: --test-only-service-https-root-pem' \
  "$cashu_boundary_log" >/dev/null
if cargo check --locked --offline --release -p runtime \
  --features standard-cashu-process-e2e >"$cashu_boundary_log" 2>&1; then
  echo "payment-v1-local-check: Standard Cashu test-only root feature compiled in release mode" >&2
  rm -f -- "$cashu_boundary_log"
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$cashu_boundary_log" >/dev/null
if cargo check --locked --offline --release -p runtime \
  --features shared-issuer-process-e2e >"$cashu_boundary_log" 2>&1; then
  echo "payment-v1-local-check: shared-issuer test-only root feature compiled in release mode" >&2
  rm -f -- "$cashu_boundary_log"
  exit 1
fi
grep -F 'test-only-webpki-root must never be compiled into a production release' \
  "$cashu_boundary_log" >/dev/null
rm -f -- "$cashu_boundary_log"
trap - EXIT HUP INT TERM

issuer_e2e_target_dir="$repo_root/target/payment-issuer-shared-e2e"
cargo build --locked --offline \
  -p payment-issuer \
  --features test-only-fake-lightning \
  --bin payment-issuer \
  --target-dir "$issuer_e2e_target_dir"
BITCOINPIR_PAYMENT_ISSUER_BIN="$issuer_e2e_target_dir/debug/payment-issuer" \
  cargo test --locked --offline \
    -p runtime \
    --features shared-issuer-process-e2e \
    --test payment_v1_shared_issuer_process_e2e \
    shared_issuer_real_process_tls_e2e -- --exact
cargo clippy --locked --offline \
  -p runtime \
  --features shared-issuer-process-e2e \
  --bin unified_server \
  --test payment_v1_shared_issuer_process_e2e \
  --no-deps -- -D warnings

fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/bpir-payment-v1-fixture.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT HUP INT TERM
scripts/fixtures/generate-payment-v1-no-funds.sh "$fixture_root/generated"
test -s "$fixture_root/generated/fixture.json"
if [[ ! -d web/node_modules ]]; then
  echo "payment-v1-local-check: web/node_modules is absent; refusing network install" >&2
  echo "Install pinned web dependencies separately, then rerun --full." >&2
  exit 1
fi
node --check scripts/payment-v1-nostr-readback.mjs
node --test scripts/payment-v1-nostr-readback.test.mjs
node scripts/payment-v1-nostr-readback.mjs --help >/dev/null
node --check scripts/payment-v1-pages-deploy-gate.mjs
node scripts/payment-v1-pages-deploy-gate.mjs
node --check scripts/payment-v1-deployment-template-gate.mjs
node --test scripts/payment-v1-deployment-template-gate.test.mjs
node scripts/payment-v1-deployment-template-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.test.mjs
node --check scripts/payment-v1-linux-runtime-evidence.mjs
node --check scripts/payment-v1-linux-runtime-evidence.test.mjs
node --test \
  scripts/payment-v1-rendered-artifact-gate.test.mjs \
  scripts/payment-v1-linux-runtime-evidence.test.mjs

echo "[7/9] warnings denied in dedicated Payment V1 crates and tools"
cargo clippy --locked --offline --all-targets --no-deps \
  -p pir-strict-https \
  -p pir-private-files \
  -p pir-rollback-authority-protocol \
  -p pir-rollback-authority-client \
  -p pir-rollback-authority-store \
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
  -p pir-cashu-custody \
  -p pir-arc-adapter \
  -p pir-directory-nostr \
  -p bitcoinpir-directory-relay \
  -p bitcoinpir-cln-rpc-guard \
  -p payment-issuer \
  -p rollback-authority \
  -p bpir-admin \
  -- -D warnings
cargo clippy --locked --offline -p runtime \
  --bin unified_server \
  --test payment_v1_process_e2e \
  --test payment_v1_methods_process_e2e \
  --test payment_v1_harmony_pool_process_e2e \
  --no-deps \
  -- -D warnings
cargo clippy --locked --offline -p runtime \
  --features test-only-unsafe-query-logging \
  --bin unified_server \
  --no-deps \
  -- -D warnings
cargo clippy --locked --offline -p runtime \
  --features cuckoo-oram \
  --bin unified_server \
  --test payment_v1_tee_oram_process_e2e \
  --no-deps \
  -- -D warnings

echo "[8/9] WASM target and generated binding boundary"
cargo check --locked --offline --target wasm32-unknown-unknown -p pir-sdk-wasm
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "payment-v1-local-check: wasm-pack is required in full mode" >&2
  exit 1
fi
CARGO_NET_OFFLINE=true wasm-pack build crates/sdk/wasm \
  --target web --out-dir pkg --mode no-install --no-opt \
  -- --locked --offline

echo "[9/9] web typecheck, unit tests, bundle, and local Chromium payment boundaries"
(cd web \
  && npm run build \
  && npm test \
  && npm run build-web \
  && npm run test:e2e:payment-vault \
  && npm run test:e2e:payment-real-issuer \
  && npm run test:e2e:payment-two-provider)

echo "payment-v1-local-check: full mode complete (no external network, no funds)"
