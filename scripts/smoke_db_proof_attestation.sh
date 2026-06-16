#!/usr/bin/env bash
# Smoke-test the attested-builder database proof binding.
#
# This script is intentionally read-only. It verifies the local mirrored proof
# directory, then verifies live PIR servers if requested. It does not SSH,
# deploy binaries, edit databases.toml, or restart services.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORKSPACE_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$WORKSPACE_ROOT"

PROOF_DIR="deploy/attested-builder-runs/delta_940611_948454_sev_snp"
DB_ID=1
RUN_LIVE=1
SERVERS=(
    "wss://weikeng1.bitcoinpir.org"
    "wss://weikeng2.bitcoinpir.org"
)

EXPECT_ARGS=(
    --expect-build-kind delta
    --expect-from-height 940611
    --expect-height 948454
    --expect-from-block-hash 000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99
    --expect-block-hash 00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4
    --expect-muhash cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee
    --expect-bucket-root e2ba2eee6788424309a95f771893d5401cc8e3ceec6188dc2708900e211a910a
    --expect-onion-root f86baa3966a61cdcd70d8c0ad9bed233f591806eb351db2ae35ac0192a3fe997
    --expect-builder-binary-sha256 34a677847b9be6580385c73f163279c81561772f8d3ad782d0ca08f1c01fad4a
    --expect-builder-git-commit 01e8db91d76037cd5562fce85c40e832ad156431
    --expect-network-magic f9beb4d9
    --expect-params-hash 2b3e488c04433ed8bd293fd3adab72b49bf52346b81160365486d76f9b4d4e39
)

usage() {
    cat <<'USAGE'
Usage:
  scripts/smoke_db_proof_attestation.sh [options]

Options:
  --proof-dir PATH       Local proof directory to verify first.
  --server URL           Live server to verify. Repeatable. Replaces defaults.
  --db-id N              Database id for live proof requests. Default: 1.
  --local-only           Verify only the local proof dir.
  --help                 Show this help.

Default live servers:
  wss://weikeng1.bitcoinpir.org
  wss://weikeng2.bitcoinpir.org
USAGE
}

CUSTOM_SERVERS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --proof-dir)
            PROOF_DIR="$2"
            shift 2
            ;;
        --server)
            if [[ "$CUSTOM_SERVERS" -eq 0 ]]; then
                SERVERS=()
                CUSTOM_SERVERS=1
            fi
            SERVERS+=("$2")
            shift 2
            ;;
        --db-id)
            DB_ID="$2"
            shift 2
            ;;
        --local-only)
            RUN_LIVE=0
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -d "$PROOF_DIR" ]]; then
    echo "proof directory not found: $PROOF_DIR" >&2
    exit 1
fi

echo "==> verifying local DB proof: $PROOF_DIR"
cargo run -p bpir-admin -- db-proof verify \
    --proof-dir "$PROOF_DIR" \
    "${EXPECT_ARGS[@]}"

if [[ "$RUN_LIVE" -eq 0 ]]; then
    echo
    echo "local proof smoke passed; live checks skipped"
    exit 0
fi

echo
for server in "${SERVERS[@]}"; do
    echo "==> verifying live DB proof: $server db_id=$DB_ID"
    cargo run -p bpir-admin -- db-proof verify-live \
        --server "$server" \
        --db-id "$DB_ID" \
        "${EXPECT_ARGS[@]}"
    echo
done

echo "DB proof smoke passed"
