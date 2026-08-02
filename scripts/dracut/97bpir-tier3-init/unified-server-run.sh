#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Base topology flags mirror deploy/systemd/pir-vpsbg.service. The measured
# Payment V1 suffix below is intentionally VPSBG-specific: it enables the
# db0-only Free-PoW + Hetzner shared-issuer BAT/ARC functional beta.
#   --port 8091
#   --role secondary   (DPF queries + HarmonyPIR query phase, no OnionPIR)
#   --serve-queries    (pir2 is queries-only per the production topology
#                       — see memory: project_pir1_hint_pir2_query_split.md.
#                       No --serve-hints, no --pool-size: hints come from
#                       pir1/Hetzner instead. Required by the startup
#                       validation in unified_server::main since 2026-05-13;
#                       without it the binary exits code 2 → runit crash-loop.)
#   --config /home/pir/data/databases.toml   (loaded from rootfs via
#                                             bpir-tier3-init's bind mount)
#   --direct-oram-db 0=... / 1=...
#                       direct ORAM images are regenerated during measured
#                       startup from proof-bound direct inputs. The input/proof
#                       paths and ORAM runtime parameters are baked into this
#                       measured UKI run script.
#   --admin-pubkey-hex <op key>   (auth for REQ_ADMIN_DB_UPLOAD etc.)
#
# Runs as root — Tier 3 initramfs has no /etc/passwd, so dropping
# privs to a `pir` user via chpst -u would need an `/etc/passwd`
# file with a numeric UID. Punted to a future hardening pass.
# /dev/sev-guest is owned root:root 0600 by default, so root access
# is required to read attestation reports anyway.

# shellcheck shell=sh

# Wait for the bind-mounted /home/pir/data to actually be available.
# The takeover init mounts it before starting runsvdir, but runit
# might race on cold-start. Give it a few seconds.
i=0
while [ ! -r /home/pir/data/databases.toml ] && [ "$i" -lt 30 ]; do
    sleep 0.5
    i=$((i + 1))
done
if [ ! -r /home/pir/data/databases.toml ]; then
    echo "[unified-server-run] FATAL: /home/pir/data/databases.toml missing — bind mount failed?" >&2
    sleep 5
    exit 1
fi

ORAMCTL=/usr/local/bin/oramctl
if [ ! -x "$ORAMCTL" ] && [ -x /home/pir/BitcoinPIR/vendor/bitcoinpir-oram/target/release/oramctl ]; then
    ORAMCTL=/home/pir/BitcoinPIR/vendor/bitcoinpir-oram/target/release/oramctl
fi
UNIFIED_SERVER=/usr/local/bin/unified_server
if [ ! -x "$UNIFIED_SERVER" ] && [ -x /home/pir/BitcoinPIR/target/release/unified_server ]; then
    UNIFIED_SERVER=/home/pir/BitcoinPIR/target/release/unified_server
fi

# Prefer an explicitly measured identity pair when one is present. The
# persistent data-mount fallback remains for existing Tier 3 deployments.
# The selected cert is signed for the public Payment V1 stable server ID.
IDENTITY_KEY_PATH=/home/pir/data/pir2-identity.key
IDENTITY_CERT_PATH=/home/pir/data/pir2.cert
if [ -r /etc/bitcoinpir/identity/server.key ] && [ -r /etc/bitcoinpir/identity/server.cert ]; then
    IDENTITY_KEY_PATH=/etc/bitcoinpir/identity/server.key
    IDENTITY_CERT_PATH=/etc/bitcoinpir/identity/server.cert
fi

# The functional-beta policy embedded below advertises only db0 DPF-PIR.
# Do not hold that usable path behind the separate Direct-ORAM ceremony: the
# currently mounted db0 proof is V1 and deliberately lacks the typed
# `direct_oram` data required by the newer Direct-ORAM bootstrap.  Direct ORAM
# remains below as an explicit future path once a new attested full-build has
# supplied that evidence; changing this constant requires a new measured UKI
# review and release.
VPSBG_DPF_ONLY_FUNCTIONAL_BETA=1

ORAM_BOOT_ROOT=/home/pir/data/.oram-boot
ORAM_BUILD_LOG_DIR=/home/pir/data/oram-boot-logs
ORAM_STAGING_DIR="$ORAM_BOOT_ROOT/staging.$$"
ORAM_CURRENT_DIR="$ORAM_BOOT_ROOT/current"
ORAM_FULL_DIR="$ORAM_CURRENT_DIR/db0-mainnet-948454"
ORAM_DELTA_DIR="$ORAM_CURRENT_DIR/db1-delta-940611-948454"
TRUSTED_INPUT_ROOT=/run/bitcoinpir-oram-inputs
TRUSTED_STATE_ROOT=/run/bitcoinpir-oram-state
ORAM_FULL_TRUSTED_STATE_DIR="$TRUSTED_STATE_ROOT/db0-mainnet-948454"
ORAM_DELTA_TRUSTED_STATE_DIR="$TRUSTED_STATE_ROOT/db1-delta-940611-948454"

ORAM_PACK=16
ORAM_LEAF_DIVISOR=2
ORAM_BUCKET_SIZE=2
ORAM_STASH_CAPACITY=128
ORAM_CACHE_LEVELS=0
ORAM_AUTH_TRUSTED_LEVELS=1
ORAM_AUTH_HASH_PAGE_SIZE=4096
DIRECT_INDEX_SLOTS_PER_BIN=4
DIRECT_INDEX_HASH_FNS=2
DIRECT_INDEX_LOAD_FACTOR=0.95
DIRECT_INDEX_SEED=8030603977422561841

MAINNET_EXPECTED_MUHASH=cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee
MAINNET_EXPECTED_INDEX_SHA256=d0b9573488abdda8e17dc52bb52bf5ff11520b4511683020f5f1a22bc8d8d26c
MAINNET_EXPECTED_CHUNKS_SHA256=9a81a02bf82af49414b5f2ae6380c97c1f231fcac6890b605f6cde22b0adc521
DELTA_EXPECTED_FROM_MUHASH=aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b
DELTA_EXPECTED_FROM_HEIGHT=940611
DELTA_EXPECTED_FROM_BLOCK_HASH=000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99
DELTA_EXPECTED_BHTM_TREE_ROOT=babeea635812c3b1a2d5f352ab0a5d1ee8a4e9c668c43c05d6603ef3c3766ba6
DELTA_BHTM_FROM_LEAF_PROOF=/usr/share/bitcoinpir/proofs/height-940611.leaf-proof.json
DELTA_EXPECTED_MUHASH=cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee
DELTA_EXPECTED_INDEX_SHA256=e06fc3dedf30096124888acef3024f21a9c049d59fd8c7d518aaf8a58ac6aa16
DELTA_EXPECTED_CHUNKS_SHA256=536acb605396056118c7c0836988f369c5abbfc3f7e90732ad93e819d5188e0a

fatal() {
    echo "[unified-server-run] FATAL: $*" >&2
    sleep 5
    exit 1
}

require_file() {
    [ -r "$1" ] || fatal "required file missing or unreadable: $1"
}

first_existing_dir() {
    for path in "$@"; do
        if [ -d "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

first_existing_file() {
    for path in "$@"; do
        if [ -r "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

direct_input_hash() {
    awk -v name="$1" '$2 == name || $2 == "./" name { print $1; exit }' "$2"
}

sha256_path() {
    sha256sum "$1" | awk '{ print $1 }'
}

random_seed_hex() {
    require_file /dev/urandom
    seed="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | od -An -tx1 -v | tr -d ' \n')"
    case "$seed" in
        *[!0-9a-f]*)
            fatal "failed to read 32-byte ORAM seed from /dev/urandom"
            ;;
    esac
    [ "${#seed}" -eq 64 ] || fatal "failed to read 32-byte ORAM seed from /dev/urandom"
    echo "$seed"
}

safe_remove_boot_path() {
    case "$1" in
        "$ORAM_BOOT_ROOT"/*) rm -rf "$1" || fatal "failed to remove $1" ;;
        *) fatal "refusing to remove path outside ORAM_BOOT_ROOT: $1" ;;
    esac
}

safe_remove_runtime_path() {
    case "$1" in
        "$TRUSTED_INPUT_ROOT"|"$TRUSTED_INPUT_ROOT"/*|"$TRUSTED_STATE_ROOT"|"$TRUSTED_STATE_ROOT"/*)
            rm -rf "$1" || fatal "failed to remove $1"
            ;;
        *) fatal "refusing to remove path outside trusted runtime roots: $1" ;;
    esac
}

cleanup_build_staging() {
    safe_remove_boot_path "$ORAM_STAGING_DIR"
    safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
    safe_remove_runtime_path "$TRUSTED_STATE_ROOT"
}

copy_to_trusted_runtime() {
    copy_source_path="$1"
    copy_destination_path="$2"
    require_file "$copy_source_path"
    dd if="$copy_source_path" of="$copy_destination_path" bs=1048576 2>>"$log_file" \
        || fatal "failed to copy $3 into SEV-protected tmpfs"
}

build_direct_oram() {
    db_label="$1"
    source_dir="$2"
    out_dir="$3"
    db_evidence="$4"
    db_manifest="$5"
    root_bundle="$6"
    expected_muhash="$7"
    expected_from_muhash="$8"
    expected_index_sha="$9"
    expected_chunks_sha="${10}"
    trusted_state_dir="${11}"
    log_file="$ORAM_BUILD_LOG_DIR/${db_label}.build-direct.log"
    source_index_file="$source_dir/utxo_chunks_index_nodust.bin"
    source_chunks_file="$source_dir/utxo_chunks_nodust.bin"
    sha_file="$source_dir/direct-inputs.sha256"
    require_file "$source_index_file"
    require_file "$source_chunks_file"
    require_file "$db_evidence"
    require_file "$db_manifest"
    require_file "$root_bundle"

    if [ -r "$sha_file" ]; then
        file_index_sha="$(direct_input_hash utxo_chunks_index_nodust.bin "$sha_file")"
        file_chunks_sha="$(direct_input_hash utxo_chunks_nodust.bin "$sha_file")"
        [ "$file_index_sha" = "$expected_index_sha" ] || fatal "$db_label direct index hash in $sha_file does not match measured startup pin"
        [ "$file_chunks_sha" = "$expected_chunks_sha" ] || fatal "$db_label direct chunks hash in $sha_file does not match measured startup pin"
    fi
    [ -n "$expected_index_sha" ] || fatal "$db_label direct index hash pin missing"
    [ -n "$expected_chunks_sha" ] || fatal "$db_label direct chunks hash pin missing"

    trusted_input_dir="$TRUSTED_INPUT_ROOT/$db_label"
    mkdir -p "$trusted_input_dir" "$trusted_state_dir" \
        || fatal "failed to create trusted tmpfs directories for $db_label"
    : >"$log_file" || fatal "failed to create $log_file"
    copy_to_trusted_runtime "$source_index_file" \
        "$trusted_input_dir/utxo_chunks_index_nodust.bin" "$db_label index source"
    copy_to_trusted_runtime "$source_chunks_file" \
        "$trusted_input_dir/utxo_chunks_nodust.bin" "$db_label chunks source"
    copy_to_trusted_runtime "$db_evidence" \
        "$trusted_input_dir/build-evidence.bin" "$db_label DB evidence"
    copy_to_trusted_runtime "$db_manifest" \
        "$trusted_input_dir/server-db-MANIFEST.toml" "$db_label exact server DB manifest"
    copy_to_trusted_runtime "$root_bundle" \
        "$trusted_input_dir/root-bundle-payload.bin" "$db_label root bundle"
    index_file="$trusted_input_dir/utxo_chunks_index_nodust.bin"
    chunks_file="$trusted_input_dir/utxo_chunks_nodust.bin"
    db_evidence="$trusted_input_dir/build-evidence.bin"
    db_manifest="$trusted_input_dir/server-db-MANIFEST.toml"
    root_bundle="$trusted_input_dir/root-bundle-payload.bin"
    trusted_index_sha="$(sha256_path "$index_file")"
    trusted_chunks_sha="$(sha256_path "$chunks_file")"
    [ "$trusted_index_sha" = "$expected_index_sha" ] \
        || fatal "$db_label trusted tmpfs index copy hash mismatch"
    [ "$trusted_chunks_sha" = "$expected_chunks_sha" ] \
        || fatal "$db_label trusted tmpfs chunks copy hash mismatch"

    mkdir -p "$out_dir" || fatal "failed to create $out_dir"
    echo "[unified-server-run] regenerating $db_label direct ORAM from trusted tmpfs into $out_dir; trusted state: $trusted_state_dir" >&2
    if [ -n "$expected_from_muhash" ]; then
        "$ORAMCTL" build-direct \
            --index-file "$index_file" \
            --chunks-file "$chunks_file" \
            --out-dir "$out_dir" \
            --trusted-state-dir "$trusted_state_dir" \
            --level all \
            --pack "$ORAM_PACK" \
            --leaf-divisor "$ORAM_LEAF_DIVISOR" \
            --bucket-size "$ORAM_BUCKET_SIZE" \
            --stash-capacity "$ORAM_STASH_CAPACITY" \
            --cache-levels "$ORAM_CACHE_LEVELS" \
            --index-slots-per-bin "$DIRECT_INDEX_SLOTS_PER_BIN" \
            --index-hash-fns "$DIRECT_INDEX_HASH_FNS" \
            --index-load-factor "$DIRECT_INDEX_LOAD_FACTOR" \
            --index-seed "$DIRECT_INDEX_SEED" \
            --encrypted \
            --key-hex "$ORAM_PAGE_KEY_HEX" \
            --auth-store \
            --auth-layout sidecar \
            --auth-trusted-levels "$ORAM_AUTH_TRUSTED_LEVELS" \
            --auth-hash-page-size "$ORAM_AUTH_HASH_PAGE_SIZE" \
            --db-build-evidence "$db_evidence" \
            --server-db-manifest "$db_manifest" \
            --root-bundle-payload "$root_bundle" \
            --expected-muhash "$expected_muhash" \
            --expected-from-muhash "$expected_from_muhash" \
            --from-bhtm-leaf-proof "$DELTA_BHTM_FROM_LEAF_PROOF" \
            --expected-from-height "$DELTA_EXPECTED_FROM_HEIGHT" \
            --expected-from-block-hash "$DELTA_EXPECTED_FROM_BLOCK_HASH" \
            --expected-bhtm-tree-root "$DELTA_EXPECTED_BHTM_TREE_ROOT" \
            --expected-index-sha256 "$expected_index_sha" \
            --expected-chunks-sha256 "$expected_chunks_sha" \
            --strict-source-binding \
            >"$log_file" 2>&1 || {
                tail -80 "$log_file" >&2 || true
                fatal "$db_label direct ORAM regeneration failed; full log: $log_file"
            }
    else
        "$ORAMCTL" build-direct \
            --index-file "$index_file" \
            --chunks-file "$chunks_file" \
            --out-dir "$out_dir" \
            --trusted-state-dir "$trusted_state_dir" \
            --level all \
            --pack "$ORAM_PACK" \
            --leaf-divisor "$ORAM_LEAF_DIVISOR" \
            --bucket-size "$ORAM_BUCKET_SIZE" \
            --stash-capacity "$ORAM_STASH_CAPACITY" \
            --cache-levels "$ORAM_CACHE_LEVELS" \
            --index-slots-per-bin "$DIRECT_INDEX_SLOTS_PER_BIN" \
            --index-hash-fns "$DIRECT_INDEX_HASH_FNS" \
            --index-load-factor "$DIRECT_INDEX_LOAD_FACTOR" \
            --index-seed "$DIRECT_INDEX_SEED" \
            --encrypted \
            --key-hex "$ORAM_PAGE_KEY_HEX" \
            --auth-store \
            --auth-layout sidecar \
            --auth-trusted-levels "$ORAM_AUTH_TRUSTED_LEVELS" \
            --auth-hash-page-size "$ORAM_AUTH_HASH_PAGE_SIZE" \
            --db-build-evidence "$db_evidence" \
            --server-db-manifest "$db_manifest" \
            --root-bundle-payload "$root_bundle" \
            --expected-muhash "$expected_muhash" \
            --expected-index-sha256 "$expected_index_sha" \
            --expected-chunks-sha256 "$expected_chunks_sha" \
            --strict-source-binding \
            >"$log_file" 2>&1 || {
                tail -80 "$log_file" >&2 || true
                fatal "$db_label direct ORAM regeneration failed; full log: $log_file"
            }
    fi
    safe_remove_runtime_path "$trusted_input_dir"
    echo "[unified-server-run] regenerated $db_label direct ORAM; log: $log_file" >&2
}

verify_direct_oram_publish() {
    published_dir="$1"
    trusted_state_dir="$2"
    db_label="$3"
    for level in direct-index direct-chunk; do
        require_file "$published_dir/$level.meta.oram"
        require_file "$published_dir/$level.payload.oram"
        require_file "$published_dir/$level.meta.hash.oram"
        require_file "$published_dir/$level.payload.hash.oram"
        require_file "$trusted_state_dir/$level.state"
        require_file "$trusted_state_dir/$level.auth.state"
        require_file "$trusted_state_dir/$level.metadata"
    done
    echo "[unified-server-run] verified published $db_label direct ORAM paths" >&2
}

[ -x "$UNIFIED_SERVER" ] || fatal "$UNIFIED_SERVER missing from UKI"
if [ "$VPSBG_DPF_ONLY_FUNCTIONAL_BETA" = 1 ]; then
    echo "[unified-server-run] starting VPSBG db0 DPF-only functional beta; Direct ORAM is not advertised" >&2
    exec "$UNIFIED_SERVER" \
        --port 8091 \
        --role secondary \
        --serve-queries \
        --config /home/pir/data/databases.toml \
        --admin-pubkey-hex 87d454db85266e10e55ed8b68417de9d79ceb1d5d944bae831a7877627efdad3 \
        --vcek-dir /home/pir/data/vcek \
        --identity-key-path "$IDENTITY_KEY_PATH" \
        --identity-cert-path "$IDENTITY_CERT_PATH" \
        --identity-server-id pir2-vpsbg-dpf-v1 \
        --require-service-auth-v1 \
        --service-policy /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/service-policy.bin \
        --service-provider-id-hex 85bfdd55b1408402bcad886568b732818a32472747226aa009839d45e0b96cac \
        --service-policy-key-hex 73c5889ee3bb11b79a7628bad1aa24be927f6e047abadd6dd6ce38e45bb0cfd5 \
        --service-store /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/provider.sqlite3 \
        --service-rollback-authority /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/rollback.sqlite3 \
        --allow-local-service-rollback-authority-dev \
        --service-shared-authorization /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-clearing-authorization.bin \
        --service-shared-issuer-approval /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-clearing-approval.bin \
        --service-shared-operator-key-hex 7ecb7900928f30efbf548a13c8d0b4fff5a580c7a145b003866580e42d9dc9cb \
        --service-shared-issuer-settlement-key-hex 248df8866b89b05dbb5d1a2ebec398e4281d9f0e152073570965cd2fbdc422b7 \
        --service-shared-clearing-key /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/provider-clearing-signing.key \
        --service-shared-idempotency-key /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-redeem-idempotency.key \
        --service-shared-minimum-authorization-epoch 1 \
        --allow-experimental-arc \
        --service-max-concurrent-auth 4 \
        --service-max-concurrent-online-v2full-auth 0 \
        --service-pre-auth-timeout-ms 60000 \
        2>&1
fi

[ -x "$ORAMCTL" ] || fatal "$ORAMCTL missing from UKI"
require_file "$DELTA_BHTM_FROM_LEAF_PROOF"
mkdir -p "$ORAM_BOOT_ROOT" "$ORAM_BUILD_LOG_DIR" || fatal "failed to create ORAM boot directories"
for stale_staging in "$ORAM_BOOT_ROOT"/staging.*; do
    [ -e "$stale_staging" ] || continue
    safe_remove_boot_path "$stale_staging"
done
safe_remove_boot_path "$ORAM_CURRENT_DIR"
safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
safe_remove_runtime_path "$TRUSTED_STATE_ROOT"
mkdir -p "$ORAM_STAGING_DIR" || fatal "failed to create $ORAM_STAGING_DIR"
mkdir -p "$TRUSTED_INPUT_ROOT" "$TRUSTED_STATE_ROOT" \
    || fatal "failed to create SEV-protected ORAM runtime directories"
ORAM_PAGE_KEY_HEX="$(random_seed_hex)"
trap cleanup_build_staging EXIT

MAINNET_SOURCE_DIR="$(first_existing_dir \
    /home/pir/data/oram-inputs/checkpoints/948454 \
    /home/pir/data/attested-builder-runs/mainnet_948454_oram_948454_sev_snp/oram-direct-inputs \
    /home/pir/data/attestations/mainnet_948454_oram_sev_snp/run/oram-direct-inputs)" \
    || fatal "mainnet direct-input directory missing"
MAINNET_DB_EVIDENCE="$(first_existing_file \
    /home/pir/data/attestations/mainnet_948454_oram_sev_snp/run/build-evidence.bin \
    /home/pir/data/attested-builder-runs/mainnet_948454_oram_948454_sev_snp/build-evidence.bin)" \
    || fatal "mainnet build-evidence.bin missing"
MAINNET_DB_MANIFEST="$(first_existing_file \
    /home/pir/data/attestations/mainnet_948454_oram_sev_snp/run/server-db/MANIFEST.toml \
    /home/pir/data/attested-builder-runs/mainnet_948454_oram_948454_sev_snp/server-db/MANIFEST.toml)" \
    || fatal "mainnet exact server-db/MANIFEST.toml missing"
MAINNET_ROOT_BUNDLE="$(first_existing_file \
    /home/pir/data/attestations/mainnet_948454_oram_sev_snp/run/root-bundle-payload.bin \
    /home/pir/data/attested-builder-runs/mainnet_948454_oram_948454_sev_snp/root-bundle-payload.bin)" \
    || fatal "mainnet root-bundle-payload.bin missing"

DELTA_SOURCE_DIR="$(first_existing_dir \
    /home/pir/data/oram-inputs/deltas/940611_948454_canonical_20260615 \
    /home/pir/data/attested-builder-runs/delta_940611_948454_delta_940611_948454_sev_snp/oram-direct-inputs \
    /home/pir/data/attestations/delta_940611_948454_sev_snp/oram-direct-inputs)" \
    || fatal "delta direct-input directory missing"
DELTA_DB_EVIDENCE="$(first_existing_file \
    /home/pir/data/attestations/delta_940611_948454_sev_snp/build-evidence.bin \
    /home/pir/data/attested-builder-runs/delta_940611_948454_delta_940611_948454_sev_snp/build-evidence.bin)" \
    || fatal "delta build-evidence.bin missing"
DELTA_DB_MANIFEST="$(first_existing_file \
    /home/pir/data/attestations/delta_940611_948454_sev_snp/server-db/MANIFEST.toml \
    /home/pir/data/attested-builder-runs/delta_940611_948454_delta_940611_948454_sev_snp/server-db/MANIFEST.toml)" \
    || fatal "delta exact server-db/MANIFEST.toml missing"
DELTA_ROOT_BUNDLE="$(first_existing_file \
    /home/pir/data/attestations/delta_940611_948454_sev_snp/root-bundle-payload.bin \
    /home/pir/data/attested-builder-runs/delta_940611_948454_delta_940611_948454_sev_snp/root-bundle-payload.bin)" \
    || fatal "delta root-bundle-payload.bin missing"

build_direct_oram mainnet-948454 "$MAINNET_SOURCE_DIR" "$ORAM_STAGING_DIR/db0-mainnet-948454" \
    "$MAINNET_DB_EVIDENCE" "$MAINNET_DB_MANIFEST" "$MAINNET_ROOT_BUNDLE" "$MAINNET_EXPECTED_MUHASH" "" \
    "$MAINNET_EXPECTED_INDEX_SHA256" "$MAINNET_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_FULL_TRUSTED_STATE_DIR"
build_direct_oram delta-940611-948454 "$DELTA_SOURCE_DIR" "$ORAM_STAGING_DIR/db1-delta-940611-948454" \
    "$DELTA_DB_EVIDENCE" "$DELTA_DB_MANIFEST" "$DELTA_ROOT_BUNDLE" "$DELTA_EXPECTED_MUHASH" "$DELTA_EXPECTED_FROM_MUHASH" \
    "$DELTA_EXPECTED_INDEX_SHA256" "$DELTA_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_DELTA_TRUSTED_STATE_DIR"

mv "$ORAM_STAGING_DIR" "$ORAM_CURRENT_DIR" || fatal "failed to publish regenerated ORAM image"
verify_direct_oram_publish "$ORAM_FULL_DIR" "$ORAM_FULL_TRUSTED_STATE_DIR" mainnet-948454
verify_direct_oram_publish "$ORAM_DELTA_DIR" "$ORAM_DELTA_TRUSTED_STATE_DIR" delta-940611-948454
safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
trap - EXIT

# VPSBG is query-only and has no Harmony V2 hint pool, so the measured
# invocation keeps online V2Full authorization disabled (limit 0).
exec "$UNIFIED_SERVER" \
    --port 8091 \
    --role secondary \
    --serve-queries \
    --config /home/pir/data/databases.toml \
    --direct-oram-db "0=$ORAM_FULL_DIR" \
    --direct-oram-db "1=$ORAM_DELTA_DIR" \
    --direct-oram-trusted-state-db "0=$ORAM_FULL_TRUSTED_STATE_DIR" \
    --direct-oram-trusted-state-db "1=$ORAM_DELTA_TRUSTED_STATE_DIR" \
    --direct-oram-drain-per-access 2 \
    --direct-oram-access-budget 75 \
    --direct-oram-cache-levels 0 \
    --direct-oram-encrypted \
    --direct-oram-key-hex "$ORAM_PAGE_KEY_HEX" \
    --direct-oram-auth-store \
    --admin-pubkey-hex 87d454db85266e10e55ed8b68417de9d79ceb1d5d944bae831a7877627efdad3 \
    --vcek-dir /home/pir/data/vcek \
    --identity-key-path "$IDENTITY_KEY_PATH" \
    --identity-cert-path "$IDENTITY_CERT_PATH" \
    --identity-server-id pir2-vpsbg-dpf-v1 \
    --require-service-auth-v1 \
    --service-policy /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/service-policy.bin \
    --service-provider-id-hex 85bfdd55b1408402bcad886568b732818a32472747226aa009839d45e0b96cac \
    --service-policy-key-hex 73c5889ee3bb11b79a7628bad1aa24be927f6e047abadd6dd6ce38e45bb0cfd5 \
    --service-store /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/provider.sqlite3 \
    --service-rollback-authority /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/rollback.sqlite3 \
    --allow-local-service-rollback-authority-dev \
    --service-shared-authorization /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-clearing-authorization.bin \
    --service-shared-issuer-approval /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-clearing-approval.bin \
    --service-shared-operator-key-hex 7ecb7900928f30efbf548a13c8d0b4fff5a580c7a145b003866580e42d9dc9cb \
    --service-shared-issuer-settlement-key-hex 248df8866b89b05dbb5d1a2ebec398e4281d9f0e152073570965cd2fbdc422b7 \
    --service-shared-clearing-key /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/provider-clearing-signing.key \
    --service-shared-idempotency-key /home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/shared-redeem-idempotency.key \
    --service-shared-minimum-authorization-epoch 1 \
    --allow-experimental-arc \
    --service-max-concurrent-auth 4 \
    --service-max-concurrent-online-v2full-auth 0 \
    --service-pre-auth-timeout-ms 60000 \
    2>&1
# --identity-* (operator-signed identity / REQ_ANNOUNCE): a measured fallback
# may be supplied at UKI build time; otherwise the bind-mounted rootfs paths
# remain valid. The operator signing key is never embedded. The certificate
# server_id MUST remain pir2-vpsbg-dpf-v1, matching the public bootstrap.
