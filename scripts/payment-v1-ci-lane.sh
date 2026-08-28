#!/usr/bin/env bash
# Partition the protocol-and-persistence CI contract into independently cached
# lanes. Keep commands here explicit: the workflow semantic gate inventories
# them, while YAML owns only runner setup, cache statistics, and artifacts.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/payment-v1-ci-lane.sh --lane <core|runtime-default-security|runtime-features|issuer-directory-tools>
USAGE
}

if [[ $# -eq 1 && $1 == --help ]]; then
  usage
  exit 0
fi
[[ $# -eq 2 && $1 == --lane ]] || { usage >&2; exit 2; }
lane=$2
# GitHub Actions supplies RUNNER_TEMP; retain a bounded local fallback for
# syntax/help and intentional local lane runs.
runner_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}

case "$lane" in
  core)
    cargo test --timings --locked --offline -p pir-channel -p pir-strict-https -p pir-private-files -p pir-service-protocol -p pir-service-store -p pir-payment-crypto -p pir-lightning-backend -p pir-issuer-store -p pir-issuer-core -p pir-issuer-credentials -p pir-issuer-clearing -p pir-issuer-service -p pir-arc-adapter -p pir-directory-nostr -p bitcoinpir-cln-rpc-guard -p pir-runtime-core -p pir-sdk-client -p pir-sdk-wasm -p payment-issuer -p bpir-admin
    rustup_home="$(rustup show home)"; cargo_home="${CARGO_HOME:-${HOME}/.cargo}"; cargo_bin="$(command -v cargo)"; root_test_target="$(mktemp -d "${runner_temp}/bpir-admin-root-target.XXXXXX")"; trap 'sudo rm -rf -- "$root_test_target"' EXIT
    sudo env PATH="$PATH" RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" CARGO_TARGET_DIR="$root_test_target" BPIR_REQUIRE_ROOT_CREDENTIAL_TEST=1 "$cargo_bin" test --locked --offline -p bpir-admin lightning_staging::tests::protected_config_real_linux_uid_gid_and_mode_contract -- --exact --nocapture
    cargo test --locked --offline -p pir-payment-crypto --features provider-store --test provider_store_bat_adapter
    cargo test --locked --offline -p pir-arc-adapter --features provider-store
    cargo clippy --timings --locked --offline --all-targets --no-deps -p pir-strict-https -p pir-private-files -p pir-service-protocol -p pir-service-store -p pir-payment-crypto -p pir-lightning-backend -p pir-issuer-store -p pir-issuer-core -p pir-issuer-credentials -p pir-issuer-clearing -p pir-issuer-service -p pir-provider-clearing-client -p pir-cashu-client -p pir-cashu-custody -p pir-arc-adapter -p pir-directory-nostr -p bitcoinpir-cln-rpc-guard -p payment-issuer -p bpir-admin -- -D warnings
    cargo test --locked --offline -p pir-service-protocol --test payment_v1_adversarial; cargo test --locked --offline -p pir-runtime-core --test service_admission_adversarial;     ;;
  runtime-default-security)
    cargo check --timings --locked --offline -p runtime --bin unified_server; cargo test --locked --offline -p runtime --lib hint_pool; cargo test --locked --offline -p runtime --bin unified_server
    cargo clippy --locked --offline -p runtime --bin unified_server --no-deps -- -D warnings
    cargo clippy --locked --offline -p runtime --features test-only-unsafe-query-logging --bin unified_server --no-deps -- -D warnings
    log_file="$(mktemp "${runner_temp}/bpir-release-security.XXXXXX")"; trap 'rm -f -- "$log_file"' EXIT
    for spec in 'pir-strict-https test-only-webpki-root test-only-webpki-root must never be compiled into a production release' 'runtime test-only-unsafe-query-logging feature `test-only-unsafe-query-logging` is restricted to Cargo'; do read -r package feature diagnostic <<<"$spec"; if cargo check --locked --offline --release -p "$package" --features "$feature" >"$log_file" 2>&1; then exit 1; fi; grep -F "$diagnostic" "$log_file" >/dev/null; if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release -p "$package" --features "$feature" >"$log_file" 2>&1; then exit 1; fi; grep -F "$diagnostic" "$log_file" >/dev/null; done
    ;;
  runtime-features)
    cargo test --timings --locked --offline --manifest-path vendor/bitcoinpir-oram/Cargo.toml
    cargo check --locked --offline -p runtime --features cuckoo-oram --all-targets
    cargo clippy --locked --offline -p runtime --features cuckoo-oram --bin unified_server --no-deps -- -D warnings
    ;;
  issuer-directory-tools)
    cargo test --timings --locked --offline -p payment-issuer --features test-only-fake-lightning; cargo run --locked --offline -p payment-issuer --features test-only-fake-lightning -- serve-fake --help >/dev/null; cargo clippy --locked --offline -p payment-issuer --features test-only-fake-lightning --all-targets --no-deps -- -D warnings
    log_file="$(mktemp "${runner_temp}/bpir-fake-lightning-release.XXXXXX")"; trap 'rm -f -- "$log_file"' EXIT; if cargo run --locked --offline --release -p payment-issuer -- serve-fake --help >"$log_file" 2>&1; then exit 1; fi; grep -F "unrecognized subcommand 'serve-fake'" "$log_file" >/dev/null; if cargo check --locked --offline --release -p payment-issuer --features test-only-fake-lightning >"$log_file" 2>&1; then exit 1; fi; grep -F 'test-only-fake-lightning must never be compiled into a production release' "$log_file" >/dev/null; if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release -p payment-issuer --features test-only-fake-lightning >"$log_file" 2>&1; then exit 1; fi; grep -F 'test-only-fake-lightning must never be compiled into a production release' "$log_file" >/dev/null
    cargo test --locked --offline -p pir-cashu-client --features insecure-dev-sqlite-store --test cdk_nut03_interop --no-run
    fixture_root="$(mktemp -d "${runner_temp}/bpir-payment-v1-fixture.XXXXXX")"; trap 'rm -f -- "$log_file"; rm -rf -- "$fixture_root"' EXIT; scripts/fixtures/generate-payment-v1-no-funds.sh "$fixture_root/generated"; test -s "$fixture_root/generated/fixture.json"
    bash -n scripts/payment-v1-cdk-regtest-e2e.sh; grep -F 'standard_cashu_real_cdk_browser_provider_two_server_e2e' scripts/payment-v1-cdk-regtest-e2e.sh >/dev/null; grep -F 'standard_cashu_cdk_tls_proxy_subprocess' apps/server/tests/payment_v1_standard_cashu_process_e2e.rs >/dev/null; grep -F 'total_mint_amount=$((expected_amount * 2))' scripts/payment-v1-cdk-regtest-e2e.sh >/dev/null; bash -n scripts/payment-v1-cln-regtest-e2e.sh; bash scripts/payment-v1-cln-regtest-e2e.sh --help | grep -F -- '--acknowledge-local-regtest-only' >/dev/null; test -s web/e2e/payment-two-provider-cln-joined.spec.ts; test -s web/playwright.payment-cln-joined.config.ts; grep -F 'playwright.payment-cln-joined.config.ts' web/package.json >/dev/null; grep -F "BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND = 'fake'" web/playwright.payment-two-provider.config.ts >/dev/null; grep -F "BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND = 'cln-regtest'" web/playwright.payment-cln-joined.config.ts >/dev/null
    ;;
  *) usage >&2; exit 2 ;;
esac
