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

case "$lane" in
  core)
    cargo fmt --all -- --check
    cargo test --timings --locked --offline -p pir-core -p pir-channel -p pir-runtime-core -p pir-sdk -p pir-sdk-client -p pir-sdk-wasm -p pir-identity -p pir-attest-verify -p pir-db-attest -p pir-credit -p bpir-admin
    cargo clippy --timings --locked --offline --all-targets --no-deps -p pir-core -p pir-credit -p bpir-admin -- -D warnings
    ;;
  runtime-default-security)
    cargo check --timings --locked --offline -p runtime --bin unified_server; cargo test --locked --offline -p runtime --lib hint_pool; cargo test --locked --offline -p runtime --bin unified_server; cargo test --locked --offline -p runtime --test unified_server_cli
    cargo clippy --locked --offline -p runtime --bin unified_server --no-deps -- -D warnings
    cargo clippy --locked --offline -p runtime --features test-only-unsafe-query-logging --bin unified_server --no-deps -- -D warnings
    ;;
  runtime-features)
    cargo test --timings --locked --offline --manifest-path vendor/bitcoinpir-oram/Cargo.toml
    cargo check --locked --offline -p runtime --features cuckoo-oram --all-targets
    cargo clippy --locked --offline -p runtime --features cuckoo-oram --bin unified_server --no-deps -- -D warnings
    ;;
  *) usage >&2; exit 2 ;;
esac
