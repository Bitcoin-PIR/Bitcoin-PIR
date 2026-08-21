#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/payment-v1-local-check.sh [--quick|--pr|--deploy-template-audit|--browser|--full]

Runs BitcoinPIR payment-v1 checks without contacting payment infrastructure or
using real funds. Cargo is forced offline; `--pr` and browser profiles require
a preinstalled `wasm-pack`/`wasm-bindgen` toolchain and refuse to bootstrap it
from the network.

  --quick  Default. One focused service-admission Rust test; no deployment
           template audit, browser, external network, or service process.
  --pr     Deterministic offline payment-platform Rust suite, loopback-only
           process E2E, WASM validation, Web typecheck, unit tests, and bundle.
           It does not run --quick first, deployment-template audits, or a browser.
  --deploy-template-audit
           Explicit opt-in static deployment/template, renderer, runtime-evidence,
           publisher, namespace, Caddy, and directory-relay gate audit. It does
           not build, deploy, contact infrastructure, or run Chromium.
  --browser
           Explicit opt-in: run the --pr profile, then local Chromium payment
           boundaries. Requires preinstalled web dependencies and Chromium.
  --full   Compatibility alias for --browser. It is explicit opt-in and never
           the default.

The browser profiles add only local Chromium multi-tab vault, real-WASM loopback
no-funds issuer, and two-provider payment E2E tests on top of `--pr`.

The `--pr` profile is the normal deterministic CI-equivalent local entry. It
includes the offline payment-platform Rust suite, operator tooling, loopback-only
unified-server process E2E (including strict-TLS Standard Cashu and authenticated
direct TEE-ORAM), WASM checks, and Web typecheck/tests/bundle; it contains no
browser E2E.

The `--pr` profile starts only temporary directory-relay, unified-server,
rollback-authority, test-only TLS/NUT-03 mint and fake issuer listeners explicitly
bound to 127.0.0.1. Browser profiles additionally start Vite and Playwright;
the tests kill and wait for every child. No profile contacts an external Lightning
node or Cashu mint, publishes to a public Nostr relay, deploys a server, uses real
funds, or modifies source files. Quick mode starts no persistent service process.
Cargo, the JavaScript package manager, and tests may update their normal local
build caches (for example target/ and web/node_modules cache metadata).
EOF
}

mode="quick"
case "${1:-}" in
  "") ;;
  --quick) mode="quick" ;;
  --pr) mode="pr" ;;
  --deploy-template-audit) mode="deploy-template-audit" ;;
  --browser) mode="browser" ;;
  --full) mode="full" ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$repo_root"

if [[ ! -f Cargo.toml || ! -f docs/PRODUCTION_OPERATIONS.md ]]; then
  echo "payment-v1-local-check: repository root validation failed" >&2
  exit 1
fi

run_quick_checks() {
echo "[quick] focused service-admission matrix"
cargo test --locked --offline -p pir-runtime-core --test service_admission_matrix
}

run_pr_checks() {
echo "[pr] deterministic offline platform, operator tooling, and server wiring"
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
# These feature-only boundaries are not covered by the default package run above.
cargo test --locked --offline -p pir-payment-crypto --features provider-store \
  --test provider_store_bat_adapter
cargo test --locked --offline -p pir-arc-adapter --features provider-store
cargo test --locked --offline -p payment-issuer --features test-only-fake-lightning
cargo run --locked --offline -p payment-issuer \
  --features test-only-fake-lightning -- serve-fake --help >/dev/null
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
cargo test --locked --offline -p runtime --test payment_v1_onion_process_e2e
cargo test --locked --offline \
  --manifest-path vendor/bitcoinpir-oram/Cargo.toml
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
cargo test --locked --offline -p runtime \
  --features remote-authority-process-e2e \
  --test payment_v1_process_e2e \
  three_authority_process::three_authority_real_process_topology_e2e \
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

echo "[pr] Standard Cashu, complete method/backend matrix, and shared-issuer TLS boundaries"
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_standard_cashu_process_e2e \
  standard_cashu_real_process_tls_two_provider_e2e \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_process_e2e \
  all_non_receipt_methods_commit_before_real_harmony_query_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_harmony_pool_process_e2e \
  all_non_receipt_methods_restore_pre_dispatch_and_burn_on_real_hint_dispatch \
  -- --exact
cargo test --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --test payment_v1_onion_process_e2e \
  all_non_receipt_methods_commit_before_real_onion_job_and_replay_after_restart \
  -- --exact
cargo test --locked --offline -p runtime \
  --features cuckoo-oram,standard-cashu-process-e2e \
  --test payment_v1_tee_oram_process_e2e \
  all_non_receipt_methods_commit_before_real_tee_oram_and_replay_after_restart \
  -- --exact
cargo clippy --locked --offline -p runtime \
  --features standard-cashu-process-e2e \
  --bin unified_server \
  --test payment_v1_standard_cashu_process_e2e \
  --test payment_v1_process_e2e \
  --test payment_v1_harmony_pool_process_e2e \
  --test payment_v1_onion_process_e2e \
  --no-deps \
  -- -D warnings
cargo clippy --locked --offline -p runtime \
  --features cuckoo-oram,standard-cashu-process-e2e \
  --bin unified_server \
  --test payment_v1_tee_oram_process_e2e \
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
cargo build --locked --offline \
  -p bpir-admin \
  --bin bpir-admin \
  --target-dir "$issuer_e2e_target_dir"
BITCOINPIR_PAYMENT_ISSUER_BIN="$issuer_e2e_target_dir/debug/payment-issuer" \
BITCOINPIR_BPIR_ADMIN_BIN="$issuer_e2e_target_dir/debug/bpir-admin" \
  cargo test --locked --offline \
    -p runtime \
    --features shared-issuer-process-e2e \
    --test payment_v1_shared_issuer_process_e2e
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
node scripts/payment-v1-nostr-readback.mjs --help >/dev/null
echo "[pr] warnings denied in dedicated Payment V1 crates and tools"
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
  --test payment_v1_onion_process_e2e \
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

echo "[pr] WASM target and generated binding boundary"
cargo check --locked --offline --target wasm32-unknown-unknown -p pir-sdk-wasm
if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "payment-v1-local-check: wasm-pack is required in the --pr and browser profiles" >&2
  exit 1
fi
CARGO_NET_OFFLINE=true wasm-pack build crates/sdk/wasm \
  --target web --out-dir pkg --mode no-install --no-opt \
  -- --locked --offline
}

run_deploy_template_audit() {
echo "[deploy-template-audit] static deployment and renderer contracts"
node --check scripts/payment-v1-pages-deploy-gate.mjs
node scripts/payment-v1-pages-deploy-gate.mjs
node --check scripts/payment-v1-deployment-template-gate.mjs
node scripts/payment-v1-deployment-template-gate.mjs
bash -n scripts/build-payment-v1-directory-relay.sh
bash scripts/build-payment-v1-directory-relay.sh --help >/dev/null
node --check scripts/payment-v1-directory-relay-artifact-gate.mjs
node --check scripts/payment-v1-rendered-artifact-gate.mjs
}

run_web_checks() {
echo "[web] typecheck, unit tests, and production bundle"
(cd web \
  && npm run build \
  && npm test \
  && npm run build-web)
}

run_browser_checks() {
echo "[browser] local Chromium payment boundaries"
(cd web \
  && npm run test:e2e:payment-vault \
  && npm run test:e2e:payment-real-issuer \
  && npm run test:e2e:payment-two-provider)
}

case "$mode" in
  quick)
    run_quick_checks
    echo "payment-v1-local-check: quick profile complete (no external network, no funds, no browser)"
    ;;
  pr)
    run_pr_checks
    run_web_checks
    echo "payment-v1-local-check: pr profile complete (no external network, no funds, no browser)"
    ;;
  deploy-template-audit)
    run_deploy_template_audit
    echo "payment-v1-local-check: deploy-template-audit profile complete (no external network, no funds, no browser)"
    ;;
  browser|full)
    run_pr_checks
    run_web_checks
    run_browser_checks
    echo "payment-v1-local-check: $mode profile complete (no external network, no funds)"
    ;;
esac
