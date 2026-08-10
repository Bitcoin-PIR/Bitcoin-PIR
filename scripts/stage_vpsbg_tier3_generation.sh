#!/usr/bin/env bash
# Stage complete, attested VPSBG Tier 3 database generations without changing
# the active catalog.  The candidate catalog is directly activatable later by
# atomically replacing /home/pir/data/databases.toml during a maintenance boot.

set -euo pipefail
umask 077

usage() {
    cat <<'USAGE'
usage: stage_vpsbg_tier3_generation.sh \
  --generation NAME --db0-output DIR --db1-output DIR \
  --db0-name NAME --db0-type full|delta --db0-base-height N --db0-height N \
  --db1-name NAME --db1-type full|delta --db1-base-height N --db1-height N \
  [--data-root DIR] [--candidate-config PATH]

Each --dbN-output must be one complete attested build output containing:
  server-db/MANIFEST.toml, build-evidence.bin, root-bundle-payload.bin,
  build-evidence.sev-snp-report.bin, database.manifest.sha256,
  all-artifacts.manifest.sha256, and oram-direct-inputs/.

The helper stages each output under DATA_ROOT/generations/NAME/dbN and writes
a candidate catalog.  It never replaces DATA_ROOT/databases.toml.
USAGE
}

fail() {
    echo "[stage-vpsbg-tier3-generation] ERROR: $*" >&2
    exit 1
}

require_value() {
    [ "$#" -ge 2 ] || fail "missing value for $1"
    printf '%s' "$2"
}

require_safe_name() {
    case "$2" in
        ''|*[!A-Za-z0-9._=-]*) fail "$1 contains unsupported characters" ;;
    esac
}

require_type() {
    case "$2" in
        full|delta) ;;
        *) fail "$1 must be full or delta" ;;
    esac
}

require_unsigned_integer() {
    case "$2" in
        ''|*[!0-9]*) fail "$1 must be a non-negative integer" ;;
    esac
}

require_file() {
    [ -r "$1" ] || fail "required file missing or unreadable: $1"
}

require_directory() {
    [ -d "$1" ] || fail "required directory missing: $1"
}

validate_output() {
    output="$1"
    label="$2"
    require_directory "$output"
    for rel in \
        server-db/MANIFEST.toml \
        build-evidence.bin \
        root-bundle-payload.bin \
        build-evidence.sev-snp-report.bin \
        database.manifest.sha256 \
        all-artifacts.manifest.sha256 \
        oram-direct-inputs/utxo_chunks_index_nodust.bin \
        oram-direct-inputs/utxo_chunks_nodust.bin \
        oram-direct-inputs/direct-inputs.sha256; do
        require_file "$output/$rel"
    done
}

GENERATION=''
DB0_OUTPUT=''
DB1_OUTPUT=''
DB0_NAME=''
DB1_NAME=''
DB0_TYPE=''
DB1_TYPE=''
DB0_BASE_HEIGHT=''
DB1_BASE_HEIGHT=''
DB0_HEIGHT=''
DB1_HEIGHT=''
DATA_ROOT=/home/pir/data
CANDIDATE_CONFIG=''

while [ "$#" -gt 0 ]; do
    case "$1" in
        --generation) GENERATION="$(require_value "$@")"; shift 2 ;;
        --db0-output) DB0_OUTPUT="$(require_value "$@")"; shift 2 ;;
        --db1-output) DB1_OUTPUT="$(require_value "$@")"; shift 2 ;;
        --db0-name) DB0_NAME="$(require_value "$@")"; shift 2 ;;
        --db1-name) DB1_NAME="$(require_value "$@")"; shift 2 ;;
        --db0-type) DB0_TYPE="$(require_value "$@")"; shift 2 ;;
        --db1-type) DB1_TYPE="$(require_value "$@")"; shift 2 ;;
        --db0-base-height) DB0_BASE_HEIGHT="$(require_value "$@")"; shift 2 ;;
        --db1-base-height) DB1_BASE_HEIGHT="$(require_value "$@")"; shift 2 ;;
        --db0-height) DB0_HEIGHT="$(require_value "$@")"; shift 2 ;;
        --db1-height) DB1_HEIGHT="$(require_value "$@")"; shift 2 ;;
        --data-root) DATA_ROOT="$(require_value "$@")"; shift 2 ;;
        --candidate-config) CANDIDATE_CONFIG="$(require_value "$@")"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

for spec in \
    "generation:$GENERATION" \
    "db0 name:$DB0_NAME" \
    "db1 name:$DB1_NAME"; do
    require_safe_name "${spec%%:*}" "${spec#*:}"
done
require_type "db0 type" "$DB0_TYPE"
require_type "db1 type" "$DB1_TYPE"
for spec in \
    "db0 base height:$DB0_BASE_HEIGHT" \
    "db0 height:$DB0_HEIGHT" \
    "db1 base height:$DB1_BASE_HEIGHT" \
    "db1 height:$DB1_HEIGHT"; do
    require_unsigned_integer "${spec%%:*}" "${spec#*:}"
done

validate_output "$DB0_OUTPUT" db0
validate_output "$DB1_OUTPUT" db1

STAGE_ROOT="$DATA_ROOT/generations"
FINAL_DIR="$STAGE_ROOT/$GENERATION"
STAGING_DIR="$STAGE_ROOT/.${GENERATION}.staging.$$"
if [ -z "$CANDIDATE_CONFIG" ]; then
    CANDIDATE_CONFIG="$DATA_ROOT/databases.toml.candidate-$GENERATION"
fi

[ ! -e "$FINAL_DIR" ] || fail "refusing to overwrite existing generation: $FINAL_DIR"
[ ! -e "$STAGING_DIR" ] || fail "staging path already exists: $STAGING_DIR"
[ ! -e "$CANDIDATE_CONFIG" ] || fail "refusing to overwrite candidate config: $CANDIDATE_CONFIG"
mkdir -p "$STAGE_ROOT"

cleanup() {
    if [ -n "${STAGING_DIR:-}" ] && [ -d "$STAGING_DIR" ]; then
        rm -rf "$STAGING_DIR"
    fi
}
trap cleanup EXIT

mkdir "$STAGING_DIR"
mkdir "$STAGING_DIR/db0" "$STAGING_DIR/db1"
cp -a "$DB0_OUTPUT/." "$STAGING_DIR/db0/"
cp -a "$DB1_OUTPUT/." "$STAGING_DIR/db1/"

for db in db0 db1; do
    source_output="$DB0_OUTPUT"
    [ "$db" = db0 ] || source_output="$DB1_OUTPUT"
    # The staged runtime path is deliberately the exact server-db tree inside
    # the staged proof output.  Compare it to the source before publishing so
    # the candidate catalog cannot pair a regenerated runtime manifest with
    # attested proof sidecars from another build.
    cmp -s "$source_output/server-db/MANIFEST.toml" \
        "$STAGING_DIR/$db/server-db/MANIFEST.toml" \
        || fail "$db runtime/proof MANIFEST bytes differ after staging"
done

candidate_tmp="$CANDIDATE_CONFIG.tmp.$$"
trap 'rm -f "$candidate_tmp"; cleanup' EXIT
cat >"$candidate_tmp" <<EOF
# Candidate only; stage_vpsbg_tier3_generation.sh never activates this file.

[[database]]
name = "$DB0_NAME"
type = "$DB0_TYPE"
path = "$STAGE_ROOT/$GENERATION/db0/server-db"
proof_dir = "$STAGE_ROOT/$GENERATION/db0"
base_height = $DB0_BASE_HEIGHT
height = $DB0_HEIGHT

[[database]]
name = "$DB1_NAME"
type = "$DB1_TYPE"
path = "$STAGE_ROOT/$GENERATION/db1/server-db"
proof_dir = "$STAGE_ROOT/$GENERATION/db1"
base_height = $DB1_BASE_HEIGHT
height = $DB1_HEIGHT
EOF

mv "$STAGING_DIR" "$FINAL_DIR"
STAGING_DIR=''
mv "$candidate_tmp" "$CANDIDATE_CONFIG"

echo "[stage-vpsbg-tier3-generation] staged generation: $FINAL_DIR"
echo "[stage-vpsbg-tier3-generation] candidate catalog (not active): $CANDIDATE_CONFIG"
