#!/usr/bin/env bash
# Archive a generated UKI and optional metadata.
#
# Usage:
#   scripts/archive_uki_artifact.sh <kind> <artifact.efi> [key=value ...]
#
# Environment:
#   UKI_ARCHIVE_DIR             local archive dir; default /home/pir/uki-archive/<kind>
#   UKI_ARCHIVE_REMOTE          optional ssh target, e.g. pir-hetzner:/home/pir/uki-archive/<kind>
#   UKI_ARCHIVE_REMOTE_REQUIRED truthy by default when UKI_ARCHIVE_REMOTE is set
#   UKI_ARCHIVE_LABEL           optional extra label in the archived filename

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <kind> <artifact.efi> [key=value ...]" >&2
    exit 2
fi

kind=$1
artifact=$2
shift 2

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|yes|YES|y|Y) return 0 ;;
        *) return 1 ;;
    esac
}

require_tool() {
    local tool=$1
    command -v "$tool" >/dev/null 2>&1 || {
        echo "error: $tool not installed" >&2
        exit 1
    }
}

sanitize() {
    printf '%s' "$1" | sed 's/[^A-Za-z0-9._=-]/_/g'
}

hash_one() {
    sha256sum "$1" | awk '{print $1}'
}

size_bytes() {
    stat -c '%s' "$1" 2>/dev/null || stat -f '%z' "$1"
}

require_tool awk
require_tool cp
require_tool date
require_tool mkdir
require_tool sed
require_tool sha256sum

[ -f "$artifact" ] || {
    echo "error: UKI artifact not found: $artifact" >&2
    exit 1
}

safe_kind=$(sanitize "$kind")
label=${UKI_ARCHIVE_LABEL:-$safe_kind}
safe_label=$(sanitize "$label")
stamp=$(date -u +%Y%m%dT%H%M%SZ)
sha=$(hash_one "$artifact")
short_sha=${sha:0:12}

archive_dir=${UKI_ARCHIVE_DIR:-/home/pir/uki-archive/$safe_kind}
archive_name="${safe_label}-${stamp}-${short_sha}.efi"
archive_out="$archive_dir/$archive_name"

mkdir -p "$archive_dir"
cp -f "$artifact" "$archive_out"
chmod 0644 "$archive_out"
printf '%s  %s\n' "$sha" "$archive_name" > "$archive_out.sha256"

{
    printf 'kind=%s\n' "$safe_kind"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'hostname=%s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'source=%s\n' "$artifact"
    printf 'archive=%s\n' "$archive_out"
    printf 'sha256=%s\n' "$sha"
    printf 'size_bytes=%s\n' "$(size_bytes "$artifact")"
    for kv in "$@"; do
        case "$kv" in
            *=*) printf '%s\n' "$kv" ;;
            *) echo "warning: ignoring non key=value archive metadata: $kv" >&2 ;;
        esac
    done
} > "$archive_out.meta"

echo "archived UKI:             $archive_out"
echo "archived UKI sha256:      $sha"

remote=${UKI_ARCHIVE_REMOTE:-}
if [ -n "$remote" ]; then
    require_tool tar
    remote_required=${UKI_ARCHIVE_REMOTE_REQUIRED:-1}
    remote_host=${remote%%:*}
    remote_dir=${remote#*:}
    if [ -z "$remote_host" ] || [ -z "$remote_dir" ] || [ "$remote_host" = "$remote_dir" ]; then
        echo "error: UKI_ARCHIVE_REMOTE must look like host:/absolute/path" >&2
        exit 1
    fi
    case "$remote_dir" in
        /*) ;;
        *)
            echo "error: UKI_ARCHIVE_REMOTE path must be absolute: $remote_dir" >&2
            exit 1
            ;;
    esac

    if COPYFILE_DISABLE=1 tar -C "$archive_dir" -cf - "$archive_name" "$archive_name.sha256" "$archive_name.meta" |
        ssh "$remote_host" "mkdir -p '$remote_dir' && tar -C '$remote_dir' -xf -"; then
        echo "mirrored UKI archive:     $remote/$archive_name"
    elif is_truthy "$remote_required"; then
        echo "error: failed to mirror UKI archive to $remote" >&2
        exit 1
    else
        echo "warning: failed to mirror UKI archive to $remote" >&2
    fi
fi
