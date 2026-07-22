#!/usr/bin/env bash
# Fail-closed content gate for a fully extracted Tier 3 initramfs.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <extracted-initramfs-root> <expected-unified-server-sha256>" >&2
    exit 2
fi

ROOT=$(cd "$1" && pwd)
EXPECTED_SHA=$2
case "$EXPECTED_SHA" in *[!0-9a-f]*|'') echo "error: expected SHA-256 is malformed" >&2; exit 2 ;; esac
[ "${#EXPECTED_SHA}" -eq 64 ] || { echo "error: expected SHA-256 must have 64 hex digits" >&2; exit 2; }

# Resolve a path as it will resolve *inside* the initramfs. Plain shell tests
# such as `[ -x "$ROOT/usr/bin/foo" ]` are unsafe for Nix layouts: an absolute
# symlink to /nix/store can accidentally resolve through the build host's
# store even when that target was never packed into the initramfs.
resolve_initramfs_path() {
    local logical=$1 component target candidate joined last_index hops=0
    local -a pending resolved target_parts
    case "$logical" in /*) ;; *) return 1 ;; esac
    IFS=/ read -r -a pending <<< "${logical#/}"
    resolved=()

    while [ "${#pending[@]}" -gt 0 ]; do
        component=${pending[0]}
        pending=("${pending[@]:1}")
        case "$component" in
            ''|.) continue ;;
            ..)
                [ "${#resolved[@]}" -gt 0 ] || return 1
                last_index=$((${#resolved[@]} - 1))
                unset "resolved[$last_index]"
                resolved=("${resolved[@]}")
                continue
                ;;
        esac
        resolved+=("$component")
        joined=$(IFS=/; printf '%s' "${resolved[*]}")
        candidate=$ROOT/$joined
        if [ -L "$candidate" ]; then
            target=$(readlink "$candidate") || return 1
            hops=$((hops + 1))
            [ "$hops" -le 64 ] || return 1
            last_index=$((${#resolved[@]} - 1))
            unset "resolved[$last_index]"
            resolved=("${resolved[@]}")
            case "$target" in
                /*) resolved=(); target=${target#/} ;;
            esac
            IFS=/ read -r -a target_parts <<< "$target"
            pending=("${target_parts[@]}" "${pending[@]}")
        fi
    done

    joined=$(IFS=/; printf '%s' "${resolved[*]}")
    printf '%s/%s\n' "$ROOT" "$joined"
}

required_executables=(
    /sbin/bpir-tier3-init
    /bin/sh
    /usr/bin/busybox
    /usr/bin/runsvdir
    /usr/bin/runsv
    /usr/bin/sv
    /usr/local/bin/unified_server
    /usr/local/bin/cloudflared
    /usr/local/bin/bpir-ready-check
    /usr/local/bin/bpir-read-tunnel-token
    /etc/sv/unified_server/run
    /etc/sv/unified_server/finish
    /etc/sv/unified_server_watchdog/run
    /etc/sv/cloudflared/run
)
for path in "${required_executables[@]}"; do
    resolved=$(resolve_initramfs_path "$path") || {
        echo "error: unsafe or unresolvable initramfs path: $path" >&2
        exit 1
    }
    if [ ! -f "$resolved" ] || [ ! -x "$resolved" ]; then
        echo "error: required executable missing from initramfs: $path" >&2
        exit 1
    fi
done

server_binary=$(resolve_initramfs_path /usr/local/bin/unified_server)
busybox_binary=$(resolve_initramfs_path /usr/bin/busybox)
actual_sha=$(sha256sum "$server_binary" | awk '{print $1}')
if [ "$actual_sha" != "$EXPECTED_SHA" ]; then
    echo "error: baked unified_server SHA mismatch" >&2
    echo "  expected: $EXPECTED_SHA" >&2
    echo "  actual:   $actual_sha" >&2
    exit 1
fi

runner=$(resolve_initramfs_path /etc/sv/unified_server/run)
cloudflared=$(resolve_initramfs_path /etc/sv/cloudflared/run)
init=$(resolve_initramfs_path /sbin/bpir-tier3-init)

for required in --startup-diagnostics-file --startup-attempt --ready-file; do
    grep -q -- "$required" "$runner" || {
        echo "error: unified_server runner missing $required" >&2
        exit 1
    }
done
if grep -q -- 'nc -z' "$cloudflared"; then
    echo "error: obsolete nc -z readiness probe remains in cloudflared runner" >&2
    exit 1
fi
grep -q -- 'bpir-ready-check' "$cloudflared" || {
    echo "error: cloudflared runner does not use full-tuple readiness" >&2
    exit 1
}
grep -q -- 'unified_server_watchdog' "$init" || {
    echo "error: PID 1 does not activate the startup watchdog" >&2
    exit 1
}

busybox_applets=$("$busybox_binary" --list)
for applet in awk cat chmod cp dd dmesg grep head ln ls mkdir mv readlink reboot rm sleep stat sync tail timeout; do
    grep -x "$applet" <<< "$busybox_applets" >/dev/null || {
        echo "error: baked BusyBox lacks required applet: $applet" >&2
        exit 1
    }
done

# `sync -d PATH` is intentionally used instead of `sync -f PATH`: BusyBox
# maps the former to fdatasync(2), while the latter is syncfs(2) and would
# flush the entire filesystem containing the ORAM images.
sync_probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/bpir-sync-probe.XXXXXX")
sync_probe=$sync_probe_dir/file
trap 'rm -rf "$sync_probe_dir"' EXIT
printf 'probe\n' > "$sync_probe"
"$busybox_binary" sync -d "$sync_probe" || {
    echo "error: baked BusyBox does not support single-path sync -d" >&2
    exit 1
}
"$busybox_binary" sync -d "$sync_probe_dir" || {
    echo "error: baked BusyBox does not support directory sync -d" >&2
    exit 1
}
rm -rf "$sync_probe_dir"
trap - EXIT

echo "Tier 3 initramfs diagnostics content verified"
echo "unified_server sha256: $actual_sha"
