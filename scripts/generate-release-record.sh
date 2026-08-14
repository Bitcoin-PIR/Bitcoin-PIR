#!/usr/bin/env bash
# Generate a schema-v1 production release record
# (docs/data-retention/production-release-image-<ID>.env).
#
# Fills every field it can compute locally:
#   - recorded_at from the clock
#   - uki_name / uki_bytes / uki_sha256 from the UKI file
#   - unified_server_sha256 / oramctl_sha256 / service_policy_sha256 from
#     the UKI's sibling .meta file (build_uki_tier3.sh output), if present
#   - runtime_git_revision / web_pin_git_revision from flags (or HEAD)
# Everything else (measurement, db manifests, acceptance evidence) must be
# supplied via flags or filled in by hand afterwards — the script writes
# TODO markers and lists them, and a record with TODO fields is not
# complete release evidence.
#
# Usage:
#   scripts/generate-release-record.sh --uki deploy/uki/<name>.efi --image-id 265 \
#       [--server-id 25285] \
#       [--runtime-rev <commit>] [--web-pin-rev <commit>] \
#       [--measurement <hex>] \
#       [--db0-manifest-sha256 <hex>] [--db1-manifest-sha256 <hex>] \
#       [--acceptance <tag>] \
#       [--out <path>] [--force]
#
# Read-only apart from writing the record file. Field reference:
# docs/data-retention/release-record.env.template
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

uki="" image_id="" server_id="TODO"
runtime_rev="" web_pin_rev=""
measurement="TODO" db0="TODO" db1="TODO" acceptance="TODO"
out="" force=0

usage() { sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --uki)                 uki="$2"; shift 2 ;;
        --image-id)            image_id="$2"; shift 2 ;;
        --server-id)           server_id="$2"; shift 2 ;;
        --runtime-rev)         runtime_rev="$2"; shift 2 ;;
        --web-pin-rev)         web_pin_rev="$2"; shift 2 ;;
        --measurement)         measurement="$2"; shift 2 ;;
        --db0-manifest-sha256) db0="$2"; shift 2 ;;
        --db1-manifest-sha256) db1="$2"; shift 2 ;;
        --acceptance)          acceptance="$2"; shift 2 ;;
        --out)                 out="$2"; shift 2 ;;
        --force)               force=1; shift ;;
        -h|--help)             usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[ -n "$uki" ] && [ -n "$image_id" ] \
    || { echo "ERROR: --uki and --image-id are required" >&2; exit 2; }
[ -f "$uki" ] || { echo "ERROR: UKI file not found: $uki" >&2; exit 2; }

# sha256 across macOS (shasum) and Linux (sha256sum).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Portable byte size (BSD stat vs GNU stat).
bytes_of() {
    if stat -f %z "$1" >/dev/null 2>&1; then stat -f %z "$1"; else stat -c %s "$1"; fi
}

# Pull a key out of the UKI's sibling .meta file; TODO when absent.
meta="$uki.meta"
meta_get() {
    local val=""
    if [ -f "$meta" ]; then
        val="$(sed -n "s/^$1=//p" "$meta" | head -n 1)"
    fi
    printf '%s' "${val:-TODO}"
}

rev_or_head() {
    if [ -n "$1" ]; then printf '%s' "$1"; else git -C "$REPO_ROOT" rev-parse HEAD; fi
}

recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
uki_name="$(basename "$uki")"
uki_bytes="$(bytes_of "$uki")"
uki_sha256="$(sha256_of "$uki")"
runtime_git_revision="$(rev_or_head "$runtime_rev")"
web_pin_git_revision="$(rev_or_head "$web_pin_rev")"
unified_server_sha256="$(meta_get binary_sha256)"
oramctl_sha256="$(meta_get oramctl_sha256)"
service_policy_sha256="$(meta_get service_policy_sha256)"

if [ ! -f "$meta" ]; then
    echo "NOTE: no sibling .meta file at $meta — binary/policy hashes left as TODO" >&2
fi

[ -n "$out" ] || out="$REPO_ROOT/docs/data-retention/production-release-image-$image_id.env"
if [ -e "$out" ] && [ "$force" -ne 1 ]; then
    echo "ERROR: $out already exists (pass --force to overwrite)" >&2
    exit 1
fi

cat > "$out" <<EOF
schema_version=1
recorded_at=$recorded_at
vpsbg_server_id=$server_id
vpsbg_image_id=$image_id
uki_name=$uki_name
uki_bytes=$uki_bytes
uki_sha256=$uki_sha256
runtime_git_revision=$runtime_git_revision
web_pin_git_revision=$web_pin_git_revision
unified_server_sha256=$unified_server_sha256
oramctl_sha256=$oramctl_sha256
service_policy_sha256=$service_policy_sha256
measurement=$measurement
db0_server_manifest_sha256=$db0
db1_server_manifest_sha256=$db1
browser_acceptance=$acceptance
EOF

echo "wrote $out"
todos="$(sed -n 's/^\([a-z0-9_]*\)=TODO$/\1/p' "$out")"
if [ -n "$todos" ]; then
    echo "incomplete — fill in these fields before treating this as release evidence:"
    # shellcheck disable=SC2086
    printf '  %s\n' $todos
else
    echo "all schema-v1 fields filled."
fi
