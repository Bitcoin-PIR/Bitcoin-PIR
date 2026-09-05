#!/usr/bin/env bash
# Partition the Rust CI contract into independently cached lanes. Keep
# commands here explicit: the workflow YAML owns only runner setup, cache
# statistics, and artifacts.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: scripts/rust-ci-lane.sh --lane <core|runtime-default-security|runtime-features>
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
    cargo test --timings --locked --offline -p pir-channel -p pir-private-files -p pir-runtime-core -p pir-sdk-client -p pir-sdk-wasm -p payment-issuer -p bpir-admin
    cargo clippy --timings --locked --offline --all-targets --no-deps -p pir-private-files -p payment-issuer -p bpir-admin -- -D warnings
    ;;
  runtime-default-security)
    cargo check --timings --locked --offline -p runtime --bin unified_server; cargo test --locked --offline -p runtime --lib hint_pool; cargo test --locked --offline -p runtime --bin unified_server
    cargo clippy --locked --offline -p runtime --bin unified_server --no-deps -- -D warnings
    cargo clippy --locked --offline -p runtime --features test-only-unsafe-query-logging --bin unified_server --no-deps -- -D warnings
    # The privacy-dangerous logging feature must never compile into a release
    # profile, with or without debug assertions.
    log_file="$(mktemp "${runner_temp}/bpir-release-security.XXXXXX")"; trap 'rm -f -- "$log_file"' EXIT
    diagnostic='feature `test-only-unsafe-query-logging` is restricted to Cargo'
    if cargo check --locked --offline --release -p runtime --features test-only-unsafe-query-logging >"$log_file" 2>&1; then exit 1; fi
    grep -F "$diagnostic" "$log_file" >/dev/null
    if RUSTFLAGS='-C debug-assertions=yes' cargo check --locked --offline --release -p runtime --features test-only-unsafe-query-logging >"$log_file" 2>&1; then exit 1; fi
    grep -F "$diagnostic" "$log_file" >/dev/null
    ;;
  runtime-features)
    cargo test --timings --locked --offline --manifest-path vendor/bitcoinpir-oram/Cargo.toml
    cargo check --locked --offline -p runtime --features cuckoo-oram --all-targets
    cargo clippy --locked --offline -p runtime --features cuckoo-oram --bin unified_server --no-deps -- -D warnings
    ;;
  *) usage >&2; exit 2 ;;
esac
