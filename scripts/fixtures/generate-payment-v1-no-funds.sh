#!/bin/sh
set -eu

usage() {
    echo "usage: $0 OUTPUT_DIRECTORY [--force]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
fixture_output=$1
force_flag=${2-}
[ -z "$force_flag" ] || [ "$force_flag" = "--force" ] || usage

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/../.." && pwd)

if [ -n "$force_flag" ]; then
    exec cargo run \
        --locked \
        --offline \
        --manifest-path "$repository_root/Cargo.toml" \
        -p bpir-admin \
        -- \
        payment-v1-no-funds-fixture \
        --acknowledge-deterministic-test-keys \
        --out "$fixture_output" \
        --force
fi

exec cargo run \
    --locked \
    --offline \
    --manifest-path "$repository_root/Cargo.toml" \
    -p bpir-admin \
    -- \
    payment-v1-no-funds-fixture \
    --acknowledge-deterministic-test-keys \
    --out "$fixture_output"
