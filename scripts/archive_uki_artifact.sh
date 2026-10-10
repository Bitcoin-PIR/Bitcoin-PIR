#!/usr/bin/env bash
# Archive a generated UKI with its .sha256 and a key=value .meta file.
#
# usage: scripts/archive_uki_artifact.sh <kind> <artifact.efi> [key=value ...]
#
#   UKI_ARCHIVE_DIR     archive dir; default /home/pir/uki-archive/<kind>
#   UKI_ARCHIVE_REMOTE  optional host:/absolute/path that gets a copy too
#   UKI_ARCHIVE_LABEL   filename label; default <kind>
set -euo pipefail

[ "$#" -ge 2 ] || { echo "usage: $0 <kind> <artifact.efi> [key=value ...]" >&2; exit 2; }
kind=$1
artifact=$2
shift 2

sha=$(sha256sum "$artifact" | awk '{print $1}')
archive_dir=${UKI_ARCHIVE_DIR:-/home/pir/uki-archive/$kind}
name="${UKI_ARCHIVE_LABEL:-$kind}-$(date -u +%Y%m%dT%H%M%SZ)-${sha:0:12}.efi"

mkdir -p "$archive_dir"
cp -f "$artifact" "$archive_dir/$name"
chmod 0644 "$archive_dir/$name"
printf '%s  %s\n' "$sha" "$name" >"$archive_dir/$name.sha256"
{
    printf 'kind=%s\n' "$kind"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'hostname=%s\n' "$(hostname)"
    printf 'source=%s\n' "$artifact"
    printf 'archive=%s\n' "$archive_dir/$name"
    printf 'sha256=%s\n' "$sha"
    printf 'size_bytes=%s\n' "$(wc -c <"$artifact" | tr -d ' ')"
    printf '%s\n' "$@"
} >"$archive_dir/$name.meta"

echo "archived UKI:             $archive_dir/$name"
echo "archived UKI sha256:      $sha"

if [ -n "${UKI_ARCHIVE_REMOTE:-}" ]; then
    ssh "${UKI_ARCHIVE_REMOTE%%:*}" "mkdir -p '${UKI_ARCHIVE_REMOTE#*:}'"
    scp "$archive_dir/$name" "$archive_dir/$name.sha256" "$archive_dir/$name.meta" "$UKI_ARCHIVE_REMOTE/"
    echo "mirrored UKI archive:     $UKI_ARCHIVE_REMOTE/$name"
fi
