#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Base topology flags mirror deploy/systemd/pir-vpsbg.service. The measured
# Payment V1 suffix below is intentionally VPSBG-specific: it enables the
# db0 Free-PoW + Hetzner shared-issuer BAT/ARC functional beta, with an
# independently served Harmony query scope when its signed policy advertises
# one.
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

TIER3_DATA_ROOT=/home/pir/data
TIER3_DATABASES_CONFIG="$TIER3_DATA_ROOT/databases.toml"
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

# Existing deployments load their signed policy from the mutable data mount.
# A release may instead embed the same public policy in the UKI so its exact
# Free offer set changes atomically with the attested runtime.  Issuer keys,
# payment bindings, stores, and databases remain on the data mount.
SERVICE_POLICY_PATH=/home/pir/data/payment-v1/vpsbg-premium-free-pow-beta/service-policy.bin
if [ -r /etc/bitcoinpir/payment/service-policy.bin ]; then
    SERVICE_POLICY_PATH=/etc/bitcoinpir/payment/service-policy.bin
fi

# This measured constant selects exactly one startup path. The active v2
# generation now carries proof-bound Direct inputs for both databases, so a
# future UKI built from this script must fail closed into the Direct profile.
# Changing the profile requires a new measured UKI review and release.
VPSBG_RUNTIME_PROFILE=direct-oram-v1

ORAM_BOOT_ROOT=/home/pir/data/.oram-boot
ORAM_BUILD_LOG_DIR=/home/pir/data/oram-boot-logs
ORAM_BOOT_ID_FILE=${BPIR_ORAM_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
ORAM_PUBLISHED_MARKER="$ORAM_BUILD_LOG_DIR/oram-published.boot-id.env"
ORAM_WATCHDOG_PHASE_FILE="$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.phase"
ORAM_SERVER_RUNTIME_LOG="$ORAM_BUILD_LOG_DIR/unified-server.runtime.log"
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
ORAM_DB0_MAX_SECONDS=480
ORAM_DB1_MAX_SECONDS=180
ORAM_TOTAL_MAX_SECONDS=900
ORAM_HEARTBEAT_INTERVAL_SECONDS=15
ORAM_HEARTBEAT_DEADLINE_SECONDS=90
ORAM_KILL_GRACE_SECONDS=5
ORAM_SUPERVISOR=/usr/local/bin/direct-oram-supervisor
ORAM_SERVER_READY_HOST=127.0.0.1
ORAM_SERVER_READY_PORT=8091
ORAM_ACTIVE_SUPERVISOR_PID_FILE="$TRUSTED_STATE_ROOT/active-supervisor.pid"
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

read_current_boot_id() {
    ORAM_BOOT_ID=$(cat "$ORAM_BOOT_ID_FILE" 2>/dev/null || true)
    case "$ORAM_BOOT_ID" in
        ????????-????-????-????-????????????) ;;
        *) return 1 ;;
    esac
    case "$ORAM_BOOT_ID" in
        *[!0-9a-f-]*) return 1 ;;
    esac
}

published_marker_matches_current_boot() {
    [ -e "$ORAM_PUBLISHED_MARKER" ] || return 1
    marker_boot_id=$(awk -F= '$1 == "boot_id" { if (++seen == 1) print $2; else exit 2 } END { if (seen != 1) exit 1 }' "$ORAM_PUBLISHED_MARKER") \
        || fatal "published ORAM marker is malformed; refusing destructive retry"
    marker_status=$(awk -F= '$1 == "status" { if (++seen == 1) print $2; else exit 2 } END { if (seen != 1) exit 1 }' "$ORAM_PUBLISHED_MARKER") \
        || fatal "published ORAM marker is malformed; refusing destructive retry"
    [ "$marker_status" = published ] \
        || fatal "published ORAM marker has unsupported status; refusing destructive retry"
    [ "$marker_boot_id" = "$ORAM_BOOT_ID" ]
}

write_current_boot_published_marker() {
    marker_tmp="$ORAM_PUBLISHED_MARKER.tmp.$$"
    umask 077
    {
        printf 'boot_id=%s\n' "$ORAM_BOOT_ID"
        printf 'status=published\n'
        printf 'published_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$marker_tmp" || fatal "failed to write published ORAM marker"
    chmod 600 "$marker_tmp" || fatal "failed to protect published ORAM marker"
    mv "$marker_tmp" "$ORAM_PUBLISHED_MARKER" || fatal "failed to publish ORAM marker"
}

write_watchdog_phase() {
    watchdog_phase="$1"
    {
        printf 'phase=%s\n' "$watchdog_phase"
        printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$ORAM_WATCHDOG_PHASE_FILE.tmp" || fatal "failed to write watchdog phase"
    mv "$ORAM_WATCHDOG_PHASE_FILE.tmp" "$ORAM_WATCHDOG_PHASE_FILE" \
        || fatal "failed to publish watchdog phase"
}

start_unified_server_runtime_log() {
    umask 077
    : >>"$ORAM_SERVER_RUNTIME_LOG" || fatal "failed to open unified_server runtime log"
    chmod 600 "$ORAM_SERVER_RUNTIME_LOG" || fatal "failed to protect unified_server runtime log"
    {
        printf '\n[unified-server-run] attempt boot_id=%s started_at=%s\n' \
            "$ORAM_BOOT_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >>"$ORAM_SERVER_RUNTIME_LOG" || fatal "failed to write unified_server runtime log header"
    exec >>"$ORAM_SERVER_RUNTIME_LOG" 2>&1
}

require_file() {
    [ -r "$1" ] || fatal "required file missing or unreadable: $1"
}

direct_input_hash() {
    awk -v name="$1" '$2 == name || $2 == "./" name { print $1; exit }' "$2"
}

sha256_path() {
    sha256sum "$1" | awk '{ print $1 }'
}

# Extract a quoted path from the selected [[database]] entry without evaluating
# mutable-rootfs TOML as shell.  The generation helper emits this canonical
# shape; rejecting exotic TOML is intentional because this measured boot path
# must fail closed rather than guess a different database/proof pairing.
toml_database_path() {
    database_index="$1"
    field_name="$2"
    awk -v target="$database_index" -v field="$field_name" '
        BEGIN { current = -1; seen = 0 }
        /^[[:space:]]*\[\[database\]\][[:space:]]*(#.*)?$/ { current++; next }
        current == target {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (line ~ ("^" field "[[:space:]]*=")) {
                sub(("^" field "[[:space:]]*=[[:space:]]*"), "", line)
                if (line !~ /^"[^"]*"[[:space:]]*(#.*)?$/ || seen) exit 2
                sub(/^"/, "", line)
                sub(/"[[:space:]]*(#.*)?$/, "", line)
                value = line
                seen = 1
            }
        }
        END {
            if (seen != 1) exit 1
            print value
        }
    ' "$TIER3_DATABASES_CONFIG"
}

resolve_tier3_data_path() {
    raw_path="$1"
    case "$raw_path" in
        ''|*[!A-Za-z0-9_./-]*) fatal "database catalog path contains unsupported characters" ;;
    esac
    case "/$raw_path/" in
        */../*|*/./*) fatal "database catalog path must not contain dot segments: $raw_path" ;;
    esac
    case "$raw_path" in
        /*) resolved_path="$raw_path" ;;
        *) resolved_path="$TIER3_DATA_ROOT/$raw_path" ;;
    esac
    case "$resolved_path" in
        "$TIER3_DATA_ROOT"/*) ;;
        *) fatal "database catalog path escapes $TIER3_DATA_ROOT: $raw_path" ;;
    esac
    printf '%s\n' "$resolved_path"
}

load_active_database_generation() {
    database_index="$1"
    database_label="$2"
    runtime_raw="$(toml_database_path "$database_index" path)" \
        || fatal "$database_label path missing or non-canonical in $TIER3_DATABASES_CONFIG"
    proof_raw="$(toml_database_path "$database_index" proof_dir)" \
        || fatal "$database_label proof_dir missing or non-canonical in $TIER3_DATABASES_CONFIG"
    ACTIVE_DB_RUNTIME_DIR="$(resolve_tier3_data_path "$runtime_raw")"
    ACTIVE_DB_PROOF_DIR="$(resolve_tier3_data_path "$proof_raw")"
    require_file "$ACTIVE_DB_RUNTIME_DIR/MANIFEST.toml"
    require_file "$ACTIVE_DB_PROOF_DIR/server-db/MANIFEST.toml"
    cmp -s "$ACTIVE_DB_RUNTIME_DIR/MANIFEST.toml" \
        "$ACTIVE_DB_PROOF_DIR/server-db/MANIFEST.toml" \
        || fatal "$database_label runtime/proof MANIFEST bytes differ"
    require_file "$ACTIVE_DB_PROOF_DIR/build-evidence.bin"
    require_file "$ACTIVE_DB_PROOF_DIR/root-bundle-payload.bin"
    require_file "$ACTIVE_DB_PROOF_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin"
    require_file "$ACTIVE_DB_PROOF_DIR/oram-direct-inputs/utxo_chunks_nodust.bin"
    require_file "$ACTIVE_DB_PROOF_DIR/oram-direct-inputs/direct-inputs.sha256"
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
    [ -n "${ORAM_TOTAL_WATCHDOG_PID:-}" ] \
        && kill "$ORAM_TOTAL_WATCHDOG_PID" 2>/dev/null || true
    [ -n "${ORAM_TOTAL_WATCHDOG_PID:-}" ] \
        && wait "$ORAM_TOTAL_WATCHDOG_PID" 2>/dev/null || true
    if [ -r "$ORAM_ACTIVE_SUPERVISOR_PID_FILE" ]; then
        active_supervisor_pid=$(cat "$ORAM_ACTIVE_SUPERVISOR_PID_FILE" 2>/dev/null || echo 0)
        case "$active_supervisor_pid" in ''|*[!0-9]*) active_supervisor_pid=0 ;; esac
        [ "$active_supervisor_pid" -gt 1 ] \
            && kill -TERM "$active_supervisor_pid" 2>/dev/null || true
        [ "$active_supervisor_pid" -gt 1 ] \
            && wait "$active_supervisor_pid" 2>/dev/null || true
    fi
    safe_remove_boot_path "$ORAM_STAGING_DIR"
    safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
    safe_remove_runtime_path "$TRUSTED_STATE_ROOT"
}

start_total_watchdog() {
    parent_pid=$$
    (
        total_deadline=$(( $(date -u +%s) + ORAM_TOTAL_MAX_SECONDS ))
        while [ "$(date -u +%s)" -lt "$total_deadline" ]; do
            kill -0 "$parent_pid" 2>/dev/null || exit 0
            if nc -z -w 1 "$ORAM_SERVER_READY_HOST" "$ORAM_SERVER_READY_PORT" >/dev/null 2>&1; then
                {
                    printf 'status=ready\n'
                    printf 'phase=server-readiness\n'
                    printf 'reason=port-ready\n'
                    printf 'timeout_seconds=%s\n' "$ORAM_TOTAL_MAX_SECONDS"
                    printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                } >"$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env.tmp"
                mv "$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env.tmp" \
                    "$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env"
                exit 0
            fi
            sleep 1
        done
        watchdog_phase=direct-oram-bootstrap
        if [ -r "$ORAM_WATCHDOG_PHASE_FILE" ]; then
            recorded_phase=$(awk -F= '$1 == "phase" { print $2; exit }' "$ORAM_WATCHDOG_PHASE_FILE" 2>/dev/null || true)
            case "$recorded_phase" in direct-oram-build|server-readiness) watchdog_phase=$recorded_phase ;; esac
        fi
        {
            printf 'status=timed_out\n'
            printf 'phase=%s\n' "$watchdog_phase"
            printf 'reason=total-timeout\n'
            printf 'timeout_seconds=%s\n' "$ORAM_TOTAL_MAX_SECONDS"
            printf 'updated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        } >"$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env.tmp"
        mv "$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env.tmp" \
            "$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.status.env"
        if [ -r "$ORAM_ACTIVE_SUPERVISOR_PID_FILE" ]; then
            supervisor_pid=$(cat "$ORAM_ACTIVE_SUPERVISOR_PID_FILE" 2>/dev/null || echo 0)
            case "$supervisor_pid" in ''|*[!0-9]*) supervisor_pid=0 ;; esac
            [ "$supervisor_pid" -gt 1 ] && kill -TERM "$supervisor_pid" 2>/dev/null || true
        fi
        sleep "$ORAM_KILL_GRACE_SECONDS"
        [ "${supervisor_pid:-0}" -gt 1 ] \
            && kill -KILL "$supervisor_pid" 2>/dev/null || true
        kill -TERM "$parent_pid" 2>/dev/null || true
        sleep "$ORAM_KILL_GRACE_SECONDS"
        kill -KILL "$parent_pid" 2>/dev/null || true
    ) </dev/null >/dev/null 2>&1 &
    ORAM_TOTAL_WATCHDOG_PID=$!
}

stop_total_watchdog() {
    [ -n "${ORAM_TOTAL_WATCHDOG_PID:-}" ] || return 0
    kill "$ORAM_TOTAL_WATCHDOG_PID" 2>/dev/null || true
    wait "$ORAM_TOTAL_WATCHDOG_PID" 2>/dev/null || true
    ORAM_TOTAL_WATCHDOG_PID=
}

run_supervised_direct_build() {
    supervised_label=$1
    supervised_timeout=$2
    supervised_out_dir=$3
    supervised_log_file=$4
    shift 4
    "$ORAM_SUPERVISOR" "$supervised_label" "$supervised_timeout" \
        "$ORAM_HEARTBEAT_INTERVAL_SECONDS" "$ORAM_HEARTBEAT_DEADLINE_SECONDS" \
        "$ORAM_KILL_GRACE_SECONDS" "$ORAM_BUILD_LOG_DIR" "$supervised_out_dir" \
        "$supervised_log_file" -- "$@" &
    supervisor_pid=$!
    printf '%s\n' "$supervisor_pid" >"$ORAM_ACTIVE_SUPERVISOR_PID_FILE.tmp"
    mv "$ORAM_ACTIVE_SUPERVISOR_PID_FILE.tmp" "$ORAM_ACTIVE_SUPERVISOR_PID_FILE"
    wait "$supervisor_pid"
    supervised_status=$?
    rm -f "$ORAM_ACTIVE_SUPERVISOR_PID_FILE"
    return "$supervised_status"
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
    build_timeout_seconds="${12}"
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
        run_supervised_direct_build "$db_label" "$build_timeout_seconds" \
            "$out_dir" "$log_file" "$ORAMCTL" build-direct \
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
            --strict-source-binding || {
                tail -80 "$log_file" >&2 || true
                fatal "$db_label direct ORAM regeneration failed; full log: $log_file"
            }
    else
        run_supervised_direct_build "$db_label" "$build_timeout_seconds" \
            "$out_dir" "$log_file" "$ORAMCTL" build-direct \
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
            --strict-source-binding || {
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
case "$VPSBG_RUNTIME_PROFILE" in
dpf-only-functional-beta-v1)
    umask 077
    mkdir -p "$ORAM_BUILD_LOG_DIR" || fatal "failed to create unified_server runtime log directory"
    chmod 700 "$ORAM_BUILD_LOG_DIR" || fatal "failed to protect unified_server runtime log directory"
    read_current_boot_id || fatal "kernel boot_id missing or invalid"
    start_unified_server_runtime_log
    echo "[unified-server-run] starting VPSBG db0 functional beta; Direct ORAM is not advertised" >&2
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
        --service-policy "$SERVICE_POLICY_PATH" \
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
        --connection-idle-timeout-ms 300000 \
        --service-pre-auth-timeout-ms 300000 \
        2>&1
    ;;
direct-oram-v1)
    ;;
*)
    fatal "unsupported measured VPSBG runtime profile: $VPSBG_RUNTIME_PROFILE"
    ;;
esac

[ -x "$ORAMCTL" ] || fatal "$ORAMCTL missing from UKI"
[ -x "$ORAM_SUPERVISOR" ] || fatal "$ORAM_SUPERVISOR missing from UKI"
require_file "$DELTA_BHTM_FROM_LEAF_PROOF"
umask 077
mkdir -p "$ORAM_BOOT_ROOT" "$ORAM_BUILD_LOG_DIR" || fatal "failed to create ORAM boot directories"
chmod 700 "$ORAM_BUILD_LOG_DIR" || fatal "failed to protect ORAM boot log directory"
read_current_boot_id || fatal "kernel boot_id missing or invalid"
if published_marker_matches_current_boot; then
    echo "[unified-server-run] ORAM was already published for boot $ORAM_BOOT_ID; refusing destructive retry" >&2
    exit 0
fi
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
ORAM_TOTAL_WATCHDOG_PID=
trap cleanup_build_staging EXIT
trap 'exit 124' HUP INT TERM
write_watchdog_phase direct-oram-build
start_total_watchdog

load_active_database_generation 0 db0
MAINNET_SOURCE_DIR="$ACTIVE_DB_PROOF_DIR/oram-direct-inputs"
MAINNET_DB_EVIDENCE="$ACTIVE_DB_PROOF_DIR/build-evidence.bin"
MAINNET_DB_MANIFEST="$ACTIVE_DB_PROOF_DIR/server-db/MANIFEST.toml"
MAINNET_ROOT_BUNDLE="$ACTIVE_DB_PROOF_DIR/root-bundle-payload.bin"

load_active_database_generation 1 db1
DELTA_SOURCE_DIR="$ACTIVE_DB_PROOF_DIR/oram-direct-inputs"
DELTA_DB_EVIDENCE="$ACTIVE_DB_PROOF_DIR/build-evidence.bin"
DELTA_DB_MANIFEST="$ACTIVE_DB_PROOF_DIR/server-db/MANIFEST.toml"
DELTA_ROOT_BUNDLE="$ACTIVE_DB_PROOF_DIR/root-bundle-payload.bin"

build_direct_oram mainnet-948454 "$MAINNET_SOURCE_DIR" "$ORAM_STAGING_DIR/db0-mainnet-948454" \
    "$MAINNET_DB_EVIDENCE" "$MAINNET_DB_MANIFEST" "$MAINNET_ROOT_BUNDLE" "$MAINNET_EXPECTED_MUHASH" "" \
    "$MAINNET_EXPECTED_INDEX_SHA256" "$MAINNET_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_FULL_TRUSTED_STATE_DIR" "$ORAM_DB0_MAX_SECONDS"
build_direct_oram delta-940611-948454 "$DELTA_SOURCE_DIR" "$ORAM_STAGING_DIR/db1-delta-940611-948454" \
    "$DELTA_DB_EVIDENCE" "$DELTA_DB_MANIFEST" "$DELTA_ROOT_BUNDLE" "$DELTA_EXPECTED_MUHASH" "$DELTA_EXPECTED_FROM_MUHASH" \
    "$DELTA_EXPECTED_INDEX_SHA256" "$DELTA_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_DELTA_TRUSTED_STATE_DIR" "$ORAM_DB1_MAX_SECONDS"

mv "$ORAM_STAGING_DIR" "$ORAM_CURRENT_DIR" || fatal "failed to publish regenerated ORAM image"
verify_direct_oram_publish "$ORAM_FULL_DIR" "$ORAM_FULL_TRUSTED_STATE_DIR" mainnet-948454
verify_direct_oram_publish "$ORAM_DELTA_DIR" "$ORAM_DELTA_TRUSTED_STATE_DIR" delta-940611-948454
safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
write_current_boot_published_marker
write_watchdog_phase server-readiness
trap - EXIT
trap - HUP INT TERM
start_unified_server_runtime_log

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
    --service-policy "$SERVICE_POLICY_PATH" \
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
    --service-max-concurrent-auth 4 \
    --service-max-concurrent-online-v2full-auth 0 \
    --connection-idle-timeout-ms 300000 \
    --service-pre-auth-timeout-ms 300000 \
    2>&1
# --identity-* (operator-signed identity / REQ_ANNOUNCE): a measured fallback
# may be supplied at UKI build time; otherwise the bind-mounted rootfs paths
# remain valid. The operator signing key is never embedded. The certificate
# server_id MUST remain pir2-vpsbg-dpf-v1, matching the public bootstrap.
