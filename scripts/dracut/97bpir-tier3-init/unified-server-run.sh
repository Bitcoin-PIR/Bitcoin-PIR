#!/bin/sh
# runit service: BitcoinPIR unified_server.
#
# Lives at /etc/sv/unified_server/run inside the initramfs. runsvdir
# starts this; runit restarts on exit (1s default backoff).
#
# Base topology flags mirror deploy/systemd/pir-vpsbg.service. The measured
# sealed profile is intentionally VPSBG-specific: observe/enroll/probe finish
# inertly before database access, while Ready opens its measurement-bound
# identity and BAT V2 clearing keys before Direct ORAM construction and again
# in the final long-lived server process.
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

ORAMCTL=/usr/local/bin/oramctl
TIER3_DATA_ROOT=/home/pir/data
TIER3_DATABASES_CONFIG="$TIER3_DATA_ROOT/databases.toml"
UNIFIED_SERVER=/usr/local/bin/unified_server

# The sealed profile accepts only public artifacts plus its ciphertext
# envelope from the untrusted data mount.  No private identity/clearing input
# is embedded in the UKI or read from the mutable rootfs as plaintext.
PIR2_SEALED_ROOT=${BPIR_PIR2_SNP_SEALED_ROOT:-$TIER3_DATA_ROOT/pir2-sealed}
PIR2_SEALED_STARTUP_CONFIG=${BPIR_PIR2_SNP_SEALED_STARTUP_CONFIG:-$PIR2_SEALED_ROOT/startup.env}
PIR2_SEALED_RELEASE_PATH="$PIR2_SEALED_ROOT/release.bin"
PIR2_SEALED_ENVELOPE_PATH="$PIR2_SEALED_ROOT/credentials.envelope.bin"
PIR2_SEALED_RECEIPT_DIR="$PIR2_SEALED_ROOT/receipts"
PIR2_SEALED_MARKER_DIR="$PIR2_SEALED_ROOT/markers"
PIR2_SEALED_ATTEMPT_DIR=${BPIR_PIR2_SNP_SEALED_ATTEMPT_ROOT:-/run/bitcoinpir-pir2-sealed}
PIR2_SEALED_IDENTITY_CERT_PATH="$PIR2_SEALED_ROOT/identity.cert"
PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH="$PIR2_SEALED_ROOT/provider-accounting-authorization.bin"
PIR2_SEALED_ISSUER_APPROVAL_PATH="$PIR2_SEALED_ROOT/issuer-accounting-approval.bin"
SERVICE_POLICY_PATH=/etc/bitcoinpir/payment/service-policy.bin
PIR2_SEALED_ARTIFACT_SET_MAX_BYTES=8192
PIR2_SEALED_ARTIFACT_SET_MAX_RETAINED_POLICIES=8
PIR2_SEALED_ARTIFACT_SET_MAX_RETAINED_CLASSES=8
PIR2_SEALED_INERT_SUCCESS_EXIT_CODE=42
PIR2_SEALED_OPERATOR_KEY_HEX=30e02d80704f77099ae342a428ab22e1176baf61b4a0593b1783289e5cb5b63c
PIR2_SEALED_ISSUER_SETTLEMENT_KEY_HEX=9ab315056cdabf821c41d2bb57a8ab180481436f439c5ef4131c000b448c2763
PIR2_SEALED_PROVIDER_ID_HEX=a6465c49877dcc7062f383085ddf0479c76af8b2aee28bf3d3a40f4f202d888d
PIR2_SEALED_POLICY_KEY_HEX=791d6e18d6ed2147a0925ec23a157e7ef1f9314d7add7d13b179ef14c16e91b2

# This measured constant selects exactly one startup path. The active v2
# generation now carries proof-bound Direct inputs for both databases, so a
# future UKI built from this script must fail closed into the Direct profile.
# Changing the profile requires a new measured UKI review and release.
VPSBG_RUNTIME_PROFILE=pir2-snp-sealed-v1

ORAM_BOOT_ROOT=/home/pir/data/.oram-boot
ORAM_BUILD_LOG_DIR=/home/pir/data/oram-boot-logs
ORAM_BOOT_ID_FILE=${BPIR_ORAM_BOOT_ID_FILE:-/proc/sys/kernel/random/boot_id}
ORAM_PUBLISHED_MARKER="$ORAM_BUILD_LOG_DIR/oram-published.boot-id.env"
ORAM_WATCHDOG_PHASE_FILE="$ORAM_BUILD_LOG_DIR/direct-oram-bootstrap.phase"
ORAM_STATUS_HTTP_ROOT=/run/bitcoinpir-oram-status-api
ORAM_STATUS_JSON_FILE="$ORAM_STATUS_HTTP_ROOT/status.json"
ORAM_STATUS_HTTPD_PID_FILE=/run/bitcoinpir-oram-status-api.pid
ORAM_STATUS_HTTPD=/usr/bin/busybox
ORAM_STATUS_HTTPD_HOST=127.0.0.1
ORAM_STATUS_HTTPD_PORT=8091
ORAM_STATUS_HTTPD_PID=
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
ORAM_STATUS_STARTED_AT_EPOCH=
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
    if [ -n "${ORAM_STATUS_STARTED_AT_EPOCH:-}" ] && [ -d "$ORAM_STATUS_HTTP_ROOT" ]; then
        write_direct_oram_status_json failed "${2:-$ORAM_TOTAL_MAX_SECONDS}" "${3:-bootstrap-failed}" || true
    fi
    echo "[unified-server-run] FATAL: $1" >&2
    sleep 5
    exit 1
}

write_direct_oram_status_json() {
    stage_name=$1
    hard_stop_seconds=$2
    status_reason=$3
    now_epoch=$(date -u +%s)
    status_tmp="$ORAM_STATUS_JSON_FILE.tmp.$$"
    {
        printf '{"schema_version":1,"stage":"%s","started_at_epoch":%s,' \
            "$stage_name" "$ORAM_STATUS_STARTED_AT_EPOCH"
        printf '"updated_at_epoch":%s,"hard_stop_seconds":%s,"reason":"%s"}\n' \
            "$now_epoch" "$hard_stop_seconds" "$status_reason"
    } >"$status_tmp" || return 1
    chmod 600 "$status_tmp" || return 1
    mv "$status_tmp" "$ORAM_STATUS_JSON_FILE"
}

prepare_direct_oram_status_api() {
    case "$ORAM_STATUS_HTTP_ROOT" in
        /run/bitcoinpir-oram-status-api) ;;
        *) fatal "unsupported Direct ORAM status API root: $ORAM_STATUS_HTTP_ROOT" ;;
    esac
    rm -rf "$ORAM_STATUS_HTTP_ROOT" || fatal "failed to clear Direct ORAM status API root"
    mkdir -p "$ORAM_STATUS_HTTP_ROOT" || fatal "failed to create Direct ORAM status API root"
    chmod 700 "$ORAM_STATUS_HTTP_ROOT" || fatal "failed to protect Direct ORAM status API root"
}

stop_direct_oram_status_api() {
    [ -n "${ORAM_STATUS_HTTPD_PID:-}" ] || return 0
    kill "$ORAM_STATUS_HTTPD_PID" 2>/dev/null || true
    wait "$ORAM_STATUS_HTTPD_PID" 2>/dev/null || true
    ORAM_STATUS_HTTPD_PID=
    rm -f "$ORAM_STATUS_HTTPD_PID_FILE"
}

start_direct_oram_status_api() {
    [ -x "$ORAM_STATUS_HTTPD" ] || fatal "$ORAM_STATUS_HTTPD missing from UKI"
    "$ORAM_STATUS_HTTPD" httpd -f \
        -p "$ORAM_STATUS_HTTPD_HOST:$ORAM_STATUS_HTTPD_PORT" \
        -h "$ORAM_STATUS_HTTP_ROOT" </dev/null >/dev/null 2>&1 &
    ORAM_STATUS_HTTPD_PID=$!
    printf '%s\n' "$ORAM_STATUS_HTTPD_PID" >"$ORAM_STATUS_HTTPD_PID_FILE" \
        || fatal "failed to record Direct ORAM status API process"
    chmod 600 "$ORAM_STATUS_HTTPD_PID_FILE" || fatal "failed to protect Direct ORAM status API process"
}

remove_direct_oram_status_api_root() {
    case "$ORAM_STATUS_HTTP_ROOT" in
        /run/bitcoinpir-oram-status-api) rm -rf "$ORAM_STATUS_HTTP_ROOT" || return 1 ;;
        *) return 1 ;;
    esac
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

read_exact_public_config_value() {
    config_key=$1
    config_value=$(awk -F= -v key="$config_key" '
        $1 == key { if (++seen == 1) value = substr($0, length(key) + 2); else exit 2 }
        END { if (seen != 1 || value == "") exit 1; print value }
    ' "$PIR2_SEALED_STARTUP_CONFIG") \
        || fatal "sealed startup config must contain exactly one non-empty $config_key"
    printf '%s\n' "$config_value"
}

validate_lower_hex() {
    hex_value=$1
    hex_length=$2
    hex_label=$3
    case "$hex_value" in
        *[!0-9a-f]*) fatal "$hex_label must be canonical lowercase hex" ;;
    esac
    [ "${#hex_value}" -eq "$hex_length" ] || fatal "$hex_label has the wrong length"
    case "$hex_value" in
        *[1-9a-f]*) ;;
        *) fatal "$hex_label must not be all zero" ;;
    esac
}

load_pir2_sealed_startup_config() {
    env_configured=false
    for env_value in \
        "${BPIR_PIR2_SNP_SEALED_PROFILE:-}" \
        "${BPIR_PIR2_SNP_SEALED_PHASE:-}" \
        "${BPIR_PIR2_SNP_SEALED_ORDINAL:-}" \
        "${BPIR_PIR2_SNP_SEALED_VERIFIER_NONCE_HEX:-}" \
        "${BPIR_PIR2_SNP_SEALED_POLICY_DIGEST_HEX:-}" \
        "${BPIR_PIR2_SNP_SEALED_CLASS_DIGEST_HEX:-}" \
        "${BPIR_PIR2_SNP_SEALED_ARTIFACT_SET_PATH:-}" \
        "${BPIR_PIR2_SNP_SEALED_ARTIFACT_SET_SHA256:-}" \
        "${BPIR_PIR2_SNP_SEALED_MINIMUM_AUTHORIZATION_EPOCH:-}"; do
        [ -z "$env_value" ] || env_configured=true
    done

    if [ "$env_configured" = true ]; then
        PIR2_SEALED_PROFILE=${BPIR_PIR2_SNP_SEALED_PROFILE:-}
        PIR2_SEALED_PHASE=${BPIR_PIR2_SNP_SEALED_PHASE:-}
        PIR2_SEALED_ORDINAL=${BPIR_PIR2_SNP_SEALED_ORDINAL:-}
        PIR2_SEALED_VERIFIER_NONCE_HEX=${BPIR_PIR2_SNP_SEALED_VERIFIER_NONCE_HEX:-}
        PIR2_SEALED_POLICY_DIGEST_HEX=${BPIR_PIR2_SNP_SEALED_POLICY_DIGEST_HEX:-}
        PIR2_SEALED_CLASS_DIGEST_HEX=${BPIR_PIR2_SNP_SEALED_CLASS_DIGEST_HEX:-}
        PIR2_SEALED_ARTIFACT_SET_PATH=${BPIR_PIR2_SNP_SEALED_ARTIFACT_SET_PATH:-}
        PIR2_SEALED_ARTIFACT_SET_SHA256=${BPIR_PIR2_SNP_SEALED_ARTIFACT_SET_SHA256:-}
        PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH=${BPIR_PIR2_SNP_SEALED_MINIMUM_AUTHORIZATION_EPOCH:-}
        for env_value in \
            "$PIR2_SEALED_PROFILE" "$PIR2_SEALED_PHASE" "$PIR2_SEALED_ORDINAL" \
            "$PIR2_SEALED_VERIFIER_NONCE_HEX" "$PIR2_SEALED_POLICY_DIGEST_HEX" \
            "$PIR2_SEALED_CLASS_DIGEST_HEX" "$PIR2_SEALED_ARTIFACT_SET_PATH" \
            "$PIR2_SEALED_ARTIFACT_SET_SHA256" "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH"; do
            [ -n "$env_value" ] || fatal "partial pir2 sealed environment configuration"
        done
    else
        require_file "$PIR2_SEALED_STARTUP_CONFIG"
        unknown_config_key=$(awk -F= '
            $1 != "schema" && $1 != "profile" && $1 != "phase" && $1 != "ordinal" &&
            $1 != "verifier_nonce_hex" && $1 != "current_policy_digest_hex" &&
            $1 != "class_digest_hex" && $1 != "artifact_set_path" &&
            $1 != "artifact_set_sha256" && $1 != "minimum_authorization_epoch" {
                print $1; exit
            }
        ' "$PIR2_SEALED_STARTUP_CONFIG")
        [ -z "$unknown_config_key" ] \
            || fatal "sealed startup config contains unsupported key: $unknown_config_key"
        config_schema=$(read_exact_public_config_value schema)
        [ "$config_schema" = bitcoinpir-pir2-sealed-startup-v2 ] \
            || fatal "sealed startup config has unsupported schema"
        PIR2_SEALED_PROFILE=$(read_exact_public_config_value profile)
        PIR2_SEALED_PHASE=$(read_exact_public_config_value phase)
        PIR2_SEALED_ORDINAL=$(read_exact_public_config_value ordinal)
        PIR2_SEALED_VERIFIER_NONCE_HEX=$(read_exact_public_config_value verifier_nonce_hex)
        PIR2_SEALED_POLICY_DIGEST_HEX=$(read_exact_public_config_value current_policy_digest_hex)
        PIR2_SEALED_CLASS_DIGEST_HEX=$(read_exact_public_config_value class_digest_hex)
        PIR2_SEALED_ARTIFACT_SET_PATH=$(read_exact_public_config_value artifact_set_path)
        PIR2_SEALED_ARTIFACT_SET_SHA256=$(read_exact_public_config_value artifact_set_sha256)
        PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH=$(read_exact_public_config_value minimum_authorization_epoch)
    fi

    [ "$PIR2_SEALED_PROFILE" = "$VPSBG_RUNTIME_PROFILE" ] \
        || fatal "sealed startup profile must be $VPSBG_RUNTIME_PROFILE"
    case "$PIR2_SEALED_PHASE" in
        observe|enroll|probe|ready) ;;
        *) fatal "sealed startup phase must be observe, enroll, probe, or ready" ;;
    esac
    case "$PIR2_SEALED_ORDINAL" in
        ''|*[!0-9]*|0) fatal "sealed startup ordinal must be a non-zero integer" ;;
    esac
    case "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH" in
        ''|*[!0-9]*|0) fatal "sealed minimum authorization epoch must be a non-zero integer" ;;
    esac
    validate_lower_hex "$PIR2_SEALED_VERIFIER_NONCE_HEX" 64 "sealed verifier nonce"
    validate_lower_hex "$PIR2_SEALED_POLICY_DIGEST_HEX" 64 "sealed current policy digest"
    validate_lower_hex "$PIR2_SEALED_CLASS_DIGEST_HEX" 64 "sealed class digest"
    validate_lower_hex "$PIR2_SEALED_ARTIFACT_SET_SHA256" 64 "sealed public artifact-set sha256"
    [ "$PIR2_SEALED_ARTIFACT_SET_PATH" = "$PIR2_SEALED_ROOT/public-artifact-set.env" ] \
        || fatal "sealed public artifact-set path is outside the fixed pir2 root"
}

validate_pir2_public_artifact_set() {
    if [ ! -e "$PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH" ]; then
        [ -f "$PIR2_SEALED_ARTIFACT_SET_PATH" ] && [ ! -L "$PIR2_SEALED_ARTIFACT_SET_PATH" ] \
            || fatal "pir2 public artifact set must be a non-symlink regular file"
        artifact_set_tmp="$PIR2_SEALED_ATTEMPT_DIR/.public-artifact-set-$PIR2_BOOT_ID_HEX.$$.tmp"
        [ ! -e "$artifact_set_tmp" ] || fatal "pir2 trusted artifact-set temporary path exists"
        umask 077
        dd if="$PIR2_SEALED_ARTIFACT_SET_PATH" of="$artifact_set_tmp" bs=8192 count=2 2>/dev/null \
            || fatal "failed to snapshot pir2 public artifact set"
        chmod 600 "$artifact_set_tmp" || {
            rm -f "$artifact_set_tmp"
            fatal "failed to protect pir2 public artifact-set snapshot"
        }
        artifact_snapshot_size=$(wc -c <"$artifact_set_tmp" | tr -d '[:space:]') \
            || fatal "failed to measure pir2 public artifact-set snapshot"
        case "$artifact_snapshot_size" in
            ''|*[!0-9]*) rm -f "$artifact_set_tmp"; fatal "pir2 public artifact-set snapshot size is invalid" ;;
        esac
        [ "$artifact_snapshot_size" -le "$PIR2_SEALED_ARTIFACT_SET_MAX_BYTES" ] || {
            rm -f "$artifact_set_tmp"
            fatal "pir2 public artifact set exceeds its byte bound"
        }
        artifact_snapshot_sha256=$(sha256sum "$artifact_set_tmp" | awk '{ print $1 }') \
            || fatal "failed to hash pir2 public artifact-set snapshot"
        [ "$artifact_snapshot_sha256" = "$PIR2_SEALED_ARTIFACT_SET_SHA256" ] || {
            rm -f "$artifact_set_tmp"
            fatal "pir2 public artifact set does not match startup sha256"
        }
        if ! ln "$artifact_set_tmp" "$PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH"; then
            rm -f "$artifact_set_tmp"
            fatal "failed to publish trusted pir2 public artifact-set snapshot"
        fi
        rm -f "$artifact_set_tmp" \
            || fatal "failed to remove pir2 public artifact-set temporary path"
    fi
    [ -f "$PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH" ] \
        && [ ! -L "$PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH" ] \
        || fatal "trusted pir2 public artifact set is not a non-symlink regular file"
    PIR2_ACTIVE_ARTIFACT_SET_PATH=$PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH
    artifact_set_size=$(wc -c <"$PIR2_ACTIVE_ARTIFACT_SET_PATH" | tr -d '[:space:]') \
        || fatal "failed to measure pir2 public artifact set"
    case "$artifact_set_size" in
        ''|*[!0-9]*) fatal "pir2 public artifact set size is invalid" ;;
    esac
    [ "$artifact_set_size" -le "$PIR2_SEALED_ARTIFACT_SET_MAX_BYTES" ] \
        || fatal "pir2 public artifact set exceeds its byte bound"
    artifact_set_sha256=$(sha256sum "$PIR2_ACTIVE_ARTIFACT_SET_PATH" | awk '{ print $1 }') \
        || fatal "failed to hash pir2 public artifact set"
    [ "$artifact_set_sha256" = "$PIR2_SEALED_ARTIFACT_SET_SHA256" ] \
        || fatal "pir2 public artifact set does not match startup sha256"
    awk -F= \
        -v max_policies="$PIR2_SEALED_ARTIFACT_SET_MAX_RETAINED_POLICIES" \
        -v max_classes="$PIR2_SEALED_ARTIFACT_SET_MAX_RETAINED_CLASSES" '
        NR == 1 {
            if ($0 != "schema=bitcoinpir-pir2-bat-v2-public-artifact-set-v1") exit 1
            next
        }
        NF != 4 { exit 1 }
        NR == 2 {
            if ($1 != "current_policy") exit 1
            stage = 1
            next
        }
        $1 == "retained_policy" {
            if (stage != 1 || (previous_policy != "" && $0 <= previous_policy)) exit 1
            previous_policy = $0
            retained_policies++
            if (retained_policies > max_policies) exit 1
            next
        }
        $1 == "current_class" {
            if (stage != 1) exit 1
            stage = 2
            current_classes++
            next
        }
        $1 == "retained_class" {
            if (stage < 2 || current_classes != 1 || (previous_class != "" && $0 <= previous_class)) exit 1
            stage = 3
            previous_class = $0
            retained_classes++
            if (retained_classes > max_classes) exit 1
            next
        }
        $1 == "accounting_authorization" {
            if ((stage != 2 && stage != 3) || current_classes != 1 || accounting_authorizations != 0) exit 1
            stage = 4
            accounting_authorizations++
            next
        }
        $1 == "accounting_approval" {
            if (stage != 4 || accounting_authorizations != 1 || accounting_approvals != 0) exit 1
            stage = 5
            accounting_approvals++
            next
        }
        { exit 1 }
        END {
            if (NR < 5 || stage != 5 || current_classes != 1 || accounting_authorizations != 1 || accounting_approvals != 1) exit 1
        }
    ' "$PIR2_ACTIVE_ARTIFACT_SET_PATH" \
        || fatal "pir2 public artifact set is not canonical or bounded"

    artifact_seen_digests=" "
    while IFS= read -r artifact_line; do
        artifact_kind=${artifact_line%%=*}
        [ "$artifact_kind" != schema ] || continue
        artifact_spec=${artifact_line#*=}
        artifact_digest=${artifact_spec%%=*}
        artifact_remainder=${artifact_spec#*=}
        artifact_file_sha256=${artifact_remainder%%=*}
        artifact_path=${artifact_remainder#*=}
        validate_lower_hex "$artifact_digest" 64 "pir2 public artifact protocol digest"
        validate_lower_hex "$artifact_file_sha256" 64 "pir2 public artifact file sha256"
        case "$artifact_seen_digests" in
            *" $artifact_digest "*) fatal "pir2 public artifact set repeats a protocol digest" ;;
        esac
        artifact_seen_digests="$artifact_seen_digests$artifact_digest "
        case "$artifact_path" in
            *" "*|*"="*|*".."*) fatal "pir2 public artifact path is not canonical" ;;
        esac
        case "$artifact_kind:$artifact_path" in
            current_policy:$SERVICE_POLICY_PATH) ;;
            retained_policy:$PIR2_SEALED_ROOT/public/policies/$artifact_digest.bin) ;;
            current_class:$PIR2_SEALED_ROOT/public/classes/$artifact_digest.bin) ;;
            retained_class:$PIR2_SEALED_ROOT/public/classes/$artifact_digest.bin) ;;
            accounting_authorization:$PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH) ;;
            accounting_approval:$PIR2_SEALED_ISSUER_APPROVAL_PATH) ;;
            *) fatal "pir2 public artifact path is outside its role-specific root" ;;
        esac
        [ -f "$artifact_path" ] && [ ! -L "$artifact_path" ] \
            || fatal "pir2 public artifact must be a non-symlink regular file: $artifact_path"
        artifact_actual_sha256=$(sha256sum "$artifact_path" | awk '{ print $1 }') \
            || fatal "failed to hash pir2 public artifact: $artifact_path"
        [ "$artifact_actual_sha256" = "$artifact_file_sha256" ] \
            || fatal "pir2 public artifact file sha256 mismatch: $artifact_path"
        if [ "$artifact_kind" = current_policy ]; then
            [ "$artifact_digest" = "$PIR2_SEALED_POLICY_DIGEST_HEX" ] \
                || fatal "pir2 artifact set current policy does not match startup"
        elif [ "$artifact_kind" = current_class ]; then
            [ "$artifact_digest" = "$PIR2_SEALED_CLASS_DIGEST_HEX" ] \
                || fatal "pir2 artifact set current class does not match startup"
        fi
    done <"$PIR2_ACTIVE_ARTIFACT_SET_PATH"
}

run_pir2_with_public_artifacts() {
    artifact_execution_mode=$1
    shift
    [ -f "$PIR2_ACTIVE_ARTIFACT_SET_PATH" ] && [ ! -L "$PIR2_ACTIVE_ARTIFACT_SET_PATH" ] \
        || fatal "trusted pir2 public artifact-set snapshot is unavailable"
    while IFS= read -r artifact_line; do
        artifact_kind=${artifact_line%%=*}
        [ "$artifact_kind" != schema ] || continue
        artifact_spec=${artifact_line#*=}
        artifact_digest=${artifact_spec%%=*}
        artifact_remainder=${artifact_spec#*=}
        artifact_path=${artifact_remainder#*=}
        case "$artifact_kind" in
            current_policy)
                set -- "$@" --service-storeless-bat-v2-policy-digest-hex "$artifact_digest"
                ;;
            retained_policy)
                set -- "$@" --service-storeless-bat-v2-retained-policy "$artifact_digest=$artifact_path"
                ;;
            current_class|retained_class)
                set -- "$@" --service-storeless-bat-v2-class "$artifact_digest=$artifact_path"
                ;;
            accounting_authorization|accounting_approval)
                :
                ;;
            *) fatal "pir2 public artifact set changed after validation" ;;
        esac
    done <"$PIR2_ACTIVE_ARTIFACT_SET_PATH"
    if [ "$artifact_execution_mode" = exec ]; then
        exec "$@"
    fi
    [ "$artifact_execution_mode" = child ] \
        || fatal "unsupported pir2 public artifact execution mode"
    "$@"
}

read_pir2_current_boot() {
    PIR2_BOOT_ID=$(cat "$ORAM_BOOT_ID_FILE" 2>/dev/null || true)
    case "$PIR2_BOOT_ID" in
        ????????-????-????-????-????????????) ;;
        *) fatal "kernel boot_id missing or invalid" ;;
    esac
    case "$PIR2_BOOT_ID" in
        *[!0-9a-f-]*) fatal "kernel boot_id must use canonical lowercase hex" ;;
    esac
    PIR2_BOOT_ID_HEX=$(printf '%s' "$PIR2_BOOT_ID" | tr -d -)
    PIR2_SEALED_RECEIPT_PATH="$PIR2_SEALED_RECEIPT_DIR/inert-$PIR2_BOOT_ID_HEX.bin"
    PIR2_SEALED_MARKER_PATH="$PIR2_SEALED_MARKER_DIR/inert-$PIR2_BOOT_ID_HEX.env"
    PIR2_SEALED_READY_PREFLIGHT_RECEIPT_PATH="$PIR2_SEALED_RECEIPT_DIR/ready-preflight-$PIR2_BOOT_ID_HEX.bin"
    PIR2_SEALED_READY_PREFLIGHT_MARKER_PATH="$PIR2_SEALED_MARKER_DIR/ready-preflight-$PIR2_BOOT_ID_HEX.env"
    PIR2_SEALED_READY_RUNTIME_RECEIPT_PATH="$PIR2_SEALED_RECEIPT_DIR/ready-runtime-$PIR2_BOOT_ID_HEX.bin"
    PIR2_SEALED_READY_RUNTIME_MARKER_PATH="$PIR2_SEALED_MARKER_DIR/ready-runtime-$PIR2_BOOT_ID_HEX.env"
    PIR2_SEALED_TERMINAL_TOKEN_PATH="$PIR2_SEALED_ATTEMPT_DIR/terminal-$PIR2_BOOT_ID_HEX.env"
    PIR2_SEALED_READY_PREFLIGHT_TOKEN_PATH="$PIR2_SEALED_ATTEMPT_DIR/ready-preflight-$PIR2_BOOT_ID_HEX.env"
    PIR2_SEALED_TRUSTED_ARTIFACT_SET_PATH="$PIR2_SEALED_ATTEMPT_DIR/public-artifact-set-$PIR2_BOOT_ID_HEX.env"
}

prepare_pir2_sealed_attempt_dir() {
    umask 077
    mkdir -p "$PIR2_SEALED_ATTEMPT_DIR" \
        || fatal "failed to create pir2 sealed authoritative attempt directory"
    [ -d "$PIR2_SEALED_ATTEMPT_DIR" ] && [ ! -L "$PIR2_SEALED_ATTEMPT_DIR" ] \
        || fatal "pir2 sealed authoritative attempt path is not a non-symlink directory"
    chmod 700 "$PIR2_SEALED_ATTEMPT_DIR" \
        || fatal "failed to protect pir2 sealed authoritative attempt directory"
}

read_exact_attempt_token_value() {
    attempt_token_path=$1
    attempt_token_key=$2
    awk -F= -v key="$attempt_token_key" '
        $1 == key { if (++seen == 1) value = substr($0, length(key) + 2); else exit 2 }
        END { if (seen != 1 || value == "") exit 1; print value }
    ' "$attempt_token_path"
}

authoritative_attempt_token_matches_current_attempt() {
    attempt_token_path=$1
    expected_token_kind=$2
    expected_token_phase=$3
    [ -e "$attempt_token_path" ] || return 1
    [ -f "$attempt_token_path" ] && [ ! -L "$attempt_token_path" ] \
        || fatal "pir2 sealed authoritative attempt token is not a non-symlink regular file"
    attempt_token_lines=$(wc -l <"$attempt_token_path" | tr -d '[:space:]')
    [ "$attempt_token_lines" = 12 ] \
        || fatal "pir2 sealed authoritative attempt token has unexpected fields"
    attempt_token_schema=$(read_exact_attempt_token_value "$attempt_token_path" schema) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_kind=$(read_exact_attempt_token_value "$attempt_token_path" kind) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_phase=$(read_exact_attempt_token_value "$attempt_token_path" phase) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_boot_id=$(read_exact_attempt_token_value "$attempt_token_path" boot_id) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_ordinal=$(read_exact_attempt_token_value "$attempt_token_path" ordinal) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_nonce=$(read_exact_attempt_token_value "$attempt_token_path" verifier_nonce_hex) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_policy=$(read_exact_attempt_token_value "$attempt_token_path" current_policy_digest_hex) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_class=$(read_exact_attempt_token_value "$attempt_token_path" class_digest_hex) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_artifact_set=$(read_exact_attempt_token_value "$attempt_token_path" artifact_set_sha256) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_minimum_epoch=$(read_exact_attempt_token_value "$attempt_token_path" minimum_authorization_epoch) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_receipt_digest=$(read_exact_attempt_token_value "$attempt_token_path" receipt_protocol_digest) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    attempt_token_receipt_sha256=$(read_exact_attempt_token_value "$attempt_token_path" receipt_file_sha256) \
        || fatal "pir2 sealed authoritative attempt token is malformed"
    [ "$attempt_token_schema" = bitcoinpir-pir2-sealed-authoritative-attempt-v2 ] \
        && [ "$attempt_token_kind" = "$expected_token_kind" ] \
        && [ "$attempt_token_phase" = "$expected_token_phase" ] \
        && [ "$attempt_token_boot_id" = "$PIR2_BOOT_ID_HEX" ] \
        && [ "$attempt_token_ordinal" = "$PIR2_SEALED_ORDINAL" ] \
        && [ "$attempt_token_nonce" = "$PIR2_SEALED_VERIFIER_NONCE_HEX" ] \
        && [ "$attempt_token_policy" = "$PIR2_SEALED_POLICY_DIGEST_HEX" ] \
        && [ "$attempt_token_class" = "$PIR2_SEALED_CLASS_DIGEST_HEX" ] \
        && [ "$attempt_token_artifact_set" = "$PIR2_SEALED_ARTIFACT_SET_SHA256" ] \
        && [ "$attempt_token_minimum_epoch" = "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH" ] \
        || fatal "pir2 sealed authoritative attempt token does not match the current attempt"
    validate_lower_hex "$attempt_token_receipt_digest" 64 "authoritative receipt protocol digest"
    validate_lower_hex "$attempt_token_receipt_sha256" 64 "authoritative receipt file sha256"
}

read_child_audit_evidence() {
    audit_receipt_path=$1
    audit_marker_path=$2
    audit_expected_phase=$3
    [ -f "$audit_receipt_path" ] && [ ! -L "$audit_receipt_path" ] && [ -s "$audit_receipt_path" ] \
        || fatal "measured child exited 42 without a non-empty regular receipt"
    [ -f "$audit_marker_path" ] && [ ! -L "$audit_marker_path" ] && [ -r "$audit_marker_path" ] \
        || fatal "measured child exited 42 without a regular audit marker"
    audit_marker_lines=$(wc -l <"$audit_marker_path" | tr -d '[:space:]')
    [ "$audit_marker_lines" = 5 ] || fatal "measured child audit marker has unexpected fields"
    audit_marker_schema=$(read_exact_attempt_token_value "$audit_marker_path" schema) \
        || fatal "measured child audit marker is malformed"
    audit_marker_phase=$(read_exact_attempt_token_value "$audit_marker_path" phase) \
        || fatal "measured child audit marker is malformed"
    audit_marker_boot_id=$(read_exact_attempt_token_value "$audit_marker_path" boot_id) \
        || fatal "measured child audit marker is malformed"
    PIR2_CHILD_RECEIPT_PROTOCOL_DIGEST=$(read_exact_attempt_token_value "$audit_marker_path" receipt_digest) \
        || fatal "measured child audit marker is malformed"
    audit_marker_exit_code=$(read_exact_attempt_token_value "$audit_marker_path" exit_code) \
        || fatal "measured child audit marker is malformed"
    [ "$audit_marker_schema" = bitcoinpir-pir2-sealed-inert-success-v1 ] \
        && [ "$audit_marker_phase" = "$audit_expected_phase" ] \
        && [ "$audit_marker_boot_id" = "$PIR2_BOOT_ID_HEX" ] \
        && [ "$audit_marker_exit_code" = "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE" ] \
        || fatal "measured child audit marker does not match the current attempt"
    validate_lower_hex "$PIR2_CHILD_RECEIPT_PROTOCOL_DIGEST" 64 "measured child receipt protocol digest"
    PIR2_CHILD_RECEIPT_FILE_SHA256=$(sha256sum "$audit_receipt_path" | awk '{ print $1 }') \
        || fatal "failed to hash measured child receipt"
    validate_lower_hex "$PIR2_CHILD_RECEIPT_FILE_SHA256" 64 "measured child receipt file sha256"
}

write_authoritative_attempt_token() {
    authoritative_token_path=$1
    authoritative_token_kind=$2
    authoritative_token_phase=$3
    [ ! -e "$authoritative_token_path" ] \
        || fatal "pir2 sealed authoritative attempt token already exists"
    authoritative_token_tmp="$PIR2_SEALED_ATTEMPT_DIR/.${authoritative_token_kind}-${PIR2_BOOT_ID_HEX}.$$.tmp"
    [ ! -e "$authoritative_token_tmp" ] \
        || fatal "pir2 sealed authoritative attempt temporary path already exists"
    umask 077
    if ! {
        printf 'schema=bitcoinpir-pir2-sealed-authoritative-attempt-v2\n'
        printf 'kind=%s\n' "$authoritative_token_kind"
        printf 'phase=%s\n' "$authoritative_token_phase"
        printf 'boot_id=%s\n' "$PIR2_BOOT_ID_HEX"
        printf 'ordinal=%s\n' "$PIR2_SEALED_ORDINAL"
        printf 'verifier_nonce_hex=%s\n' "$PIR2_SEALED_VERIFIER_NONCE_HEX"
        printf 'current_policy_digest_hex=%s\n' "$PIR2_SEALED_POLICY_DIGEST_HEX"
        printf 'class_digest_hex=%s\n' "$PIR2_SEALED_CLASS_DIGEST_HEX"
        printf 'artifact_set_sha256=%s\n' "$PIR2_SEALED_ARTIFACT_SET_SHA256"
        printf 'minimum_authorization_epoch=%s\n' "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH"
        printf 'receipt_protocol_digest=%s\n' "$PIR2_CHILD_RECEIPT_PROTOCOL_DIGEST"
        printf 'receipt_file_sha256=%s\n' "$PIR2_CHILD_RECEIPT_FILE_SHA256"
    } >"$authoritative_token_tmp"; then
        rm -f "$authoritative_token_tmp"
        fatal "failed to write pir2 sealed authoritative attempt token"
    fi
    chmod 600 "$authoritative_token_tmp" || {
        rm -f "$authoritative_token_tmp"
        fatal "failed to protect pir2 sealed authoritative attempt token"
    }
    if ! ln "$authoritative_token_tmp" "$authoritative_token_path"; then
        rm -f "$authoritative_token_tmp"
        fatal "failed to atomically publish pir2 sealed authoritative attempt token"
    fi
    rm -f "$authoritative_token_tmp" \
        || fatal "failed to remove pir2 sealed authoritative attempt temporary path"
}

prepare_pir2_sealed_output_dirs() {
    umask 077
    mkdir -p "$PIR2_SEALED_ROOT" "$PIR2_SEALED_RECEIPT_DIR" "$PIR2_SEALED_MARKER_DIR" \
        || fatal "failed to create pir2 sealed output directories"
    for sealed_dir in "$PIR2_SEALED_ROOT" "$PIR2_SEALED_RECEIPT_DIR" "$PIR2_SEALED_MARKER_DIR"; do
        [ -d "$sealed_dir" ] && [ ! -L "$sealed_dir" ] \
            || fatal "pir2 sealed output path is not a non-symlink directory: $sealed_dir"
    done
    chmod 700 "$PIR2_SEALED_ROOT" "$PIR2_SEALED_RECEIPT_DIR" "$PIR2_SEALED_MARKER_DIR" \
        || fatal "failed to protect pir2 sealed output directories"
}

run_pir2_sealed_inert_phase() {
    if [ "$PIR2_SEALED_PHASE" = observe ]; then
        "$UNIFIED_SERVER" \
            --port 8091 \
            --role secondary \
            --serve-queries \
            --pir2-snp-sealed-preflight-only \
            --pir2-snp-sealed-envelope "$PIR2_SEALED_ENVELOPE_PATH" \
            --pir2-snp-sealed-receipt "$PIR2_SEALED_RECEIPT_PATH" \
            --pir2-snp-sealed-marker "$PIR2_SEALED_MARKER_PATH" \
            --pir2-snp-sealed-phase "$PIR2_SEALED_PHASE" \
            --pir2-snp-sealed-ordinal "$PIR2_SEALED_ORDINAL" \
            --pir2-snp-sealed-verifier-nonce-hex "$PIR2_SEALED_VERIFIER_NONCE_HEX" \
            --pir2-snp-sealed-current-boot-id-hex "$PIR2_BOOT_ID_HEX"
    else
        require_file "$PIR2_SEALED_RELEASE_PATH"
        "$UNIFIED_SERVER" \
            --port 8091 \
            --role secondary \
            --serve-queries \
            --pir2-snp-sealed-preflight-only \
            --pir2-snp-sealed-release "$PIR2_SEALED_RELEASE_PATH" \
            --pir2-snp-sealed-envelope "$PIR2_SEALED_ENVELOPE_PATH" \
            --pir2-snp-sealed-receipt "$PIR2_SEALED_RECEIPT_PATH" \
            --pir2-snp-sealed-marker "$PIR2_SEALED_MARKER_PATH" \
            --pir2-snp-sealed-phase "$PIR2_SEALED_PHASE" \
            --pir2-snp-sealed-ordinal "$PIR2_SEALED_ORDINAL" \
            --pir2-snp-sealed-verifier-nonce-hex "$PIR2_SEALED_VERIFIER_NONCE_HEX" \
            --pir2-snp-sealed-current-boot-id-hex "$PIR2_BOOT_ID_HEX"
    fi
    sealed_status=$?
    [ "$sealed_status" -eq "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE" ] \
        || fatal "pir2 sealed $PIR2_SEALED_PHASE dispatcher failed with exit $sealed_status"
    read_child_audit_evidence \
        "$PIR2_SEALED_RECEIPT_PATH" "$PIR2_SEALED_MARKER_PATH" "$PIR2_SEALED_PHASE"
    write_authoritative_attempt_token \
        "$PIR2_SEALED_TERMINAL_TOKEN_PATH" terminal "$PIR2_SEALED_PHASE"
    authoritative_attempt_token_matches_current_attempt \
        "$PIR2_SEALED_TERMINAL_TOKEN_PATH" terminal "$PIR2_SEALED_PHASE" \
        || fatal "failed to read back pir2 sealed terminal attempt token"
    exit "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE"
}

run_pir2_sealed_ready_preflight() {
    if authoritative_attempt_token_matches_current_attempt \
        "$PIR2_SEALED_READY_PREFLIGHT_TOKEN_PATH" ready-preflight ready; then
        echo "[unified-server-run] reusing authoritative current-attempt pir2 sealed Ready-preflight success" >&2
        return 0
    fi
    run_pir2_with_public_artifacts child "$UNIFIED_SERVER" \
        --port 8091 \
        --role secondary \
        --serve-queries \
        --pir2-snp-sealed-preflight-only \
        --pir2-snp-sealed-release "$PIR2_SEALED_RELEASE_PATH" \
        --pir2-snp-sealed-envelope "$PIR2_SEALED_ENVELOPE_PATH" \
        --pir2-snp-sealed-receipt "$PIR2_SEALED_READY_PREFLIGHT_RECEIPT_PATH" \
        --pir2-snp-sealed-marker "$PIR2_SEALED_READY_PREFLIGHT_MARKER_PATH" \
        --pir2-snp-sealed-phase ready \
        --pir2-snp-sealed-ordinal "$PIR2_SEALED_ORDINAL" \
        --pir2-snp-sealed-verifier-nonce-hex "$PIR2_SEALED_VERIFIER_NONCE_HEX" \
        --pir2-snp-sealed-current-boot-id-hex "$PIR2_BOOT_ID_HEX" \
        --pir2-snp-sealed-identity-cert "$PIR2_SEALED_IDENTITY_CERT_PATH" \
        --pir2-snp-sealed-accounting-authorization "$PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH" \
        --pir2-snp-sealed-issuer-approval "$PIR2_SEALED_ISSUER_APPROVAL_PATH" \
        --service-storeless-bat-v2-accounting-authorization "$PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH" \
        --service-storeless-bat-v2-issuer-approval "$PIR2_SEALED_ISSUER_APPROVAL_PATH" \
        --service-storeless-bat-v2-operator-key-hex "$PIR2_SEALED_OPERATOR_KEY_HEX" \
        --service-storeless-bat-v2-issuer-settlement-key-hex "$PIR2_SEALED_ISSUER_SETTLEMENT_KEY_HEX" \
        --service-storeless-bat-v2-minimum-authorization-epoch "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH"
    sealed_status=$?
    [ "$sealed_status" -eq "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE" ] \
        || fatal "pir2 sealed Ready preflight failed with exit $sealed_status"
    read_child_audit_evidence \
        "$PIR2_SEALED_READY_PREFLIGHT_RECEIPT_PATH" \
        "$PIR2_SEALED_READY_PREFLIGHT_MARKER_PATH" ready
    write_authoritative_attempt_token \
        "$PIR2_SEALED_READY_PREFLIGHT_TOKEN_PATH" ready-preflight ready
    authoritative_attempt_token_matches_current_attempt \
        "$PIR2_SEALED_READY_PREFLIGHT_TOKEN_PATH" ready-preflight ready \
        || fatal "failed to read back pir2 sealed Ready-preflight attempt token"
    echo "[unified-server-run] pir2 sealed Ready preflight passed; opened keys were dropped before ORAM" >&2
}

wait_for_databases_config() {
    i=0
    while [ ! -r "$TIER3_DATABASES_CONFIG" ] && [ "$i" -lt 30 ]; do
        sleep 0.5
        i=$((i + 1))
    done
    [ -r "$TIER3_DATABASES_CONFIG" ] \
        || fatal "$TIER3_DATABASES_CONFIG missing — bind mount failed?"
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
    proof_v1_raw="$(toml_database_path "$database_index" proof_dir)" \
        || fatal "$database_label proof_dir missing or non-canonical in $TIER3_DATABASES_CONFIG"
    proof_v2_raw="$(toml_database_path "$database_index" proof_v2_dir)" \
        || fatal "$database_label proof_v2_dir missing or non-canonical in $TIER3_DATABASES_CONFIG"
    ACTIVE_DB_RUNTIME_DIR="$(resolve_tier3_data_path "$runtime_raw")"
    ACTIVE_DB_PROOF_V1_DIR="$(resolve_tier3_data_path "$proof_v1_raw")"
    ACTIVE_DB_PROOF_V2_DIR="$(resolve_tier3_data_path "$proof_v2_raw")"
    require_file "$ACTIVE_DB_RUNTIME_DIR/MANIFEST.toml"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/server-db/MANIFEST.toml"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/build-evidence.bin"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/root-bundle-payload.bin"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/build-evidence.sev-snp-report.bin"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/database.manifest.sha256"
    require_file "$ACTIVE_DB_PROOF_V1_DIR/all-artifacts.manifest.sha256"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/server-db/MANIFEST.toml"
    cmp -s "$ACTIVE_DB_RUNTIME_DIR/MANIFEST.toml" \
        "$ACTIVE_DB_PROOF_V2_DIR/server-db/MANIFEST.toml" \
        || fatal "$database_label runtime/proof-v2 MANIFEST bytes differ"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/build-evidence.bin"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/root-bundle-payload.bin"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/oram-direct-inputs/utxo_chunks_index_nodust.bin"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/oram-direct-inputs/utxo_chunks_nodust.bin"
    require_file "$ACTIVE_DB_PROOF_V2_DIR/oram-direct-inputs/direct-inputs.sha256"
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
    stop_direct_oram_status_api || true
    remove_direct_oram_status_api_root || true
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
            # The initramfs busybox nc does not implement OpenBSD nc's -z.
            # An EOF-only connection is portable across both implementations
            # and still proves that the server has completed TCP bind/listen.
            if [ ! -r "$ORAM_STATUS_HTTPD_PID_FILE" ] \
                && nc -w 1 "$ORAM_SERVER_READY_HOST" "$ORAM_SERVER_READY_PORT" </dev/null >/dev/null 2>&1; then
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
                fatal "$db_label direct ORAM regeneration failed; full log: $log_file" \
                    "$build_timeout_seconds" build-failed
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
                fatal "$db_label direct ORAM regeneration failed; full log: $log_file" \
                    "$build_timeout_seconds" build-failed
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
# BusyBox ash provides the required ulimit builtin in the measured initramfs.
# shellcheck disable=SC3045
ulimit -c 0 || fatal "failed to disable core dumps before pir2 sealed startup"
PIR2_PROC_SWAPS=${BPIR_PIR2_PROC_SWAPS:-/proc/swaps}
require_file "$PIR2_PROC_SWAPS"
active_swap_rows=$(awk 'NR > 1 { count++ } END { print count + 0 }' "$PIR2_PROC_SWAPS") \
    || fatal "failed to inspect active swap before pir2 sealed startup"
[ "$active_swap_rows" = 0 ] || fatal "active swap is forbidden for pir2 sealed startup"
read_pir2_current_boot
load_pir2_sealed_startup_config
prepare_pir2_sealed_output_dirs
prepare_pir2_sealed_attempt_dir
case "$PIR2_SEALED_PHASE" in
observe|enroll|probe)
    [ ! -e "$PIR2_SEALED_READY_PREFLIGHT_TOKEN_PATH" ] \
        || fatal "Ready-preflight token already exists for this boot; refusing a phase change"
    if authoritative_attempt_token_matches_current_attempt \
        "$PIR2_SEALED_TERMINAL_TOKEN_PATH" terminal "$PIR2_SEALED_PHASE"; then
        echo "[unified-server-run] pir2 sealed terminal attempt already completed for boot $PIR2_BOOT_ID" >&2
        exit "$PIR2_SEALED_INERT_SUCCESS_EXIT_CODE"
    fi
    # These phases are terminal and inert.  This is deliberately before the
    # databases.toml wait, policy/auth loading, ORAM cleanup/build, and every
    # listener-capable final invocation.
    run_pir2_sealed_inert_phase
    ;;
ready)
    [ ! -e "$PIR2_SEALED_TERMINAL_TOKEN_PATH" ] \
        || fatal "terminal token already exists for this boot; refusing a phase change"
    # Hash/canonicality validation happens immediately before the Ready child.
    # The resulting exact set digest is part of the current-boot authoritative
    # token; inert phases still avoid opening any policy/class artifact.
    validate_pir2_public_artifact_set
    # The child process strictly opens the envelope, verifies all three public
    # authorizations, writes a separate current-boot receipt, drops both keys
    # on exit 42, and returns control here before any database/ORAM access.
    run_pir2_sealed_ready_preflight
    ;;
esac

[ -x "$ORAMCTL" ] || fatal "$ORAMCTL missing from UKI"
[ -x "$ORAM_SUPERVISOR" ] || fatal "$ORAM_SUPERVISOR missing from UKI"
require_file "$DELTA_BHTM_FROM_LEAF_PROOF"
require_file "$SERVICE_POLICY_PATH"
wait_for_databases_config
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

load_active_database_generation 0 db0
MAINNET_SOURCE_DIR="$ACTIVE_DB_PROOF_V2_DIR/oram-direct-inputs"
MAINNET_DB_EVIDENCE="$ACTIVE_DB_PROOF_V2_DIR/build-evidence.bin"
MAINNET_DB_MANIFEST="$ACTIVE_DB_PROOF_V2_DIR/server-db/MANIFEST.toml"
MAINNET_ROOT_BUNDLE="$ACTIVE_DB_PROOF_V2_DIR/root-bundle-payload.bin"

load_active_database_generation 1 db1
DELTA_SOURCE_DIR="$ACTIVE_DB_PROOF_V2_DIR/oram-direct-inputs"
DELTA_DB_EVIDENCE="$ACTIVE_DB_PROOF_V2_DIR/build-evidence.bin"
DELTA_DB_MANIFEST="$ACTIVE_DB_PROOF_V2_DIR/server-db/MANIFEST.toml"
DELTA_ROOT_BUNDLE="$ACTIVE_DB_PROOF_V2_DIR/root-bundle-payload.bin"

prepare_direct_oram_status_api
ORAM_STATUS_STARTED_AT_EPOCH=$(date -u +%s)
write_direct_oram_status_json input-validation "$ORAM_DB0_MAX_SECONDS" none \
    || fatal "failed to publish Direct ORAM input-validation status"
start_direct_oram_status_api
start_total_watchdog
write_direct_oram_status_json db0-build "$ORAM_DB0_MAX_SECONDS" none \
    || fatal "failed to publish Direct ORAM db0-build status"
build_direct_oram mainnet-948454 "$MAINNET_SOURCE_DIR" "$ORAM_STAGING_DIR/db0-mainnet-948454" \
    "$MAINNET_DB_EVIDENCE" "$MAINNET_DB_MANIFEST" "$MAINNET_ROOT_BUNDLE" "$MAINNET_EXPECTED_MUHASH" "" \
    "$MAINNET_EXPECTED_INDEX_SHA256" "$MAINNET_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_FULL_TRUSTED_STATE_DIR" "$ORAM_DB0_MAX_SECONDS"
write_direct_oram_status_json db1-build "$ORAM_DB1_MAX_SECONDS" none \
    || fatal "failed to publish Direct ORAM db1-build status"
build_direct_oram delta-940611-948454 "$DELTA_SOURCE_DIR" "$ORAM_STAGING_DIR/db1-delta-940611-948454" \
    "$DELTA_DB_EVIDENCE" "$DELTA_DB_MANIFEST" "$DELTA_ROOT_BUNDLE" "$DELTA_EXPECTED_MUHASH" "$DELTA_EXPECTED_FROM_MUHASH" \
    "$DELTA_EXPECTED_INDEX_SHA256" "$DELTA_EXPECTED_CHUNKS_SHA256" \
    "$ORAM_DELTA_TRUSTED_STATE_DIR" "$ORAM_DB1_MAX_SECONDS"

write_direct_oram_status_json publish "$ORAM_TOTAL_MAX_SECONDS" none \
    || fatal "failed to publish Direct ORAM publish status"
mv "$ORAM_STAGING_DIR" "$ORAM_CURRENT_DIR" || fatal "failed to publish regenerated ORAM image"
verify_direct_oram_publish "$ORAM_FULL_DIR" "$ORAM_FULL_TRUSTED_STATE_DIR" mainnet-948454
verify_direct_oram_publish "$ORAM_DELTA_DIR" "$ORAM_DELTA_TRUSTED_STATE_DIR" delta-940611-948454
safe_remove_runtime_path "$TRUSTED_INPUT_ROOT"
write_current_boot_published_marker
write_watchdog_phase server-readiness
stop_direct_oram_status_api || fatal "Direct ORAM status API did not release port 8091"
remove_direct_oram_status_api_root || fatal "failed to remove Direct ORAM status API root"
trap - EXIT
trap - HUP INT TERM
start_unified_server_runtime_log

# VPSBG is query-only and has no Harmony V2 hint pool, so the measured
# invocation keeps online V2Full authorization disabled (limit 0).
# Revalidate the mutable-mount public bytes after the bounded ORAM build. The
# Rust loader then repeats canonical/signature/digest/member/role-key checks in
# the final Ready process; the audit receipt is evidence, not runtime authority.
validate_pir2_public_artifact_set
run_pir2_with_public_artifacts exec "$UNIFIED_SERVER" \
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
    --pir2-snp-sealed-require-ready \
    --pir2-snp-sealed-release "$PIR2_SEALED_RELEASE_PATH" \
    --pir2-snp-sealed-envelope "$PIR2_SEALED_ENVELOPE_PATH" \
    --pir2-snp-sealed-receipt "$PIR2_SEALED_READY_RUNTIME_RECEIPT_PATH" \
    --pir2-snp-sealed-marker "$PIR2_SEALED_READY_RUNTIME_MARKER_PATH" \
    --pir2-snp-sealed-phase ready \
    --pir2-snp-sealed-ordinal "$PIR2_SEALED_ORDINAL" \
    --pir2-snp-sealed-verifier-nonce-hex "$PIR2_SEALED_VERIFIER_NONCE_HEX" \
    --pir2-snp-sealed-current-boot-id-hex "$PIR2_BOOT_ID_HEX" \
    --pir2-snp-sealed-identity-cert "$PIR2_SEALED_IDENTITY_CERT_PATH" \
    --pir2-snp-sealed-accounting-authorization "$PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH" \
    --pir2-snp-sealed-issuer-approval "$PIR2_SEALED_ISSUER_APPROVAL_PATH" \
    --require-service-auth-v1 \
    --service-policy "$SERVICE_POLICY_PATH" \
    --service-provider-id-hex "$PIR2_SEALED_PROVIDER_ID_HEX" \
    --service-policy-key-hex "$PIR2_SEALED_POLICY_KEY_HEX" \
    --service-storeless-bat-v2-accounting-authorization "$PIR2_SEALED_ACCOUNTING_AUTHORIZATION_PATH" \
    --service-storeless-bat-v2-issuer-approval "$PIR2_SEALED_ISSUER_APPROVAL_PATH" \
    --service-storeless-bat-v2-operator-key-hex "$PIR2_SEALED_OPERATOR_KEY_HEX" \
    --service-storeless-bat-v2-issuer-settlement-key-hex "$PIR2_SEALED_ISSUER_SETTLEMENT_KEY_HEX" \
    --service-storeless-bat-v2-minimum-authorization-epoch "$PIR2_SEALED_MINIMUM_AUTHORIZATION_EPOCH" \
    --service-max-concurrent-auth 4 \
    --service-max-concurrent-online-v2full-auth 0 \
    --connection-idle-timeout-ms 300000 \
    --service-pre-auth-timeout-ms 300000 \
    2>&1
