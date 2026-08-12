#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$script_dir/vpsbg-production-status.sh"
root="$(mktemp -d "${TMPDIR:-/tmp}/bpir-vpsbg-status.XXXXXX")"
trap 'rm -rf "$root"' EXIT
write() { printf '%s\n' "$2" >"$1"; }

write "$root/servers.json" '{"data":[{"id":25285}]}'
write "$root/server.json" '{"id":25285,"hostname":"pir-server-vpsbg","status":"active","virtualization":"kvm","state":{"running":true,"node_reachable":true,"amd_sev_level":3,"measured_boot":{"kernel_image":{"id":229,"name":"bpir-tier3-20260812.efi","size":12345,"in_use":true,"created_at":"2026-08-12T00:00:00Z"}}}}'
write "$root/status.json" '{"schema_version":1,"stage":"db1-build","started_at_epoch":100,"updated_at_epoch":140,"hard_stop_seconds":900,"reason":"none"}'
actual="$($script --root "$root")"
grep -qx 'production_status=v3' <<<"$actual"
grep -qx 'control_plane_server_id=25285' <<<"$actual"
grep -qx 'control_plane_hostname=pir-server-vpsbg' <<<"$actual"
grep -qx 'control_plane_state=active' <<<"$actual"
grep -qx 'control_plane_virtualization=kvm' <<<"$actual"
grep -qx 'control_plane_reachable=true' <<<"$actual"
grep -qx 'control_plane_running=true' <<<"$actual"
grep -qx 'control_plane_sev_level=3' <<<"$actual"
grep -qx 'boot_mode=measured' <<<"$actual"
grep -qx 'image_id=229' <<<"$actual"
grep -qx 'image_name=bpir-tier3-20260812.efi' <<<"$actual"
grep -qx 'oram_status_source=offline-evidence' <<<"$actual"
grep -qx 'oram_stage=db1-build' <<<"$actual"
grep -qx 'oram_started_at_epoch=100' <<<"$actual"
grep -qx 'oram_updated_at_epoch=140' <<<"$actual"
grep -qx 'oram_hard_stop_seconds=900' <<<"$actual"
grep -qx 'oram_reason=none' <<<"$actual"

rm "$root/status.json"
missing="$($script --root "$root")"
grep -qx 'oram_status_source=unavailable' <<<"$missing"
grep -qx 'oram_stage=unavailable' <<<"$missing"

write "$root/servers.json" '{"data":[{"id":1},{"id":2}]}'
if "$script" --root "$root" >/dev/null 2>&1; then echo 'ambiguous server selection unexpectedly succeeded' >&2; exit 1; fi

write "$root/server.json" '{"id":2,"status":"active","virtualization":"kvm","state":{"measured_boot":null}}'
write "$root/status.json" '{'
if "$script" --root "$root" --server-id 2 >/dev/null 2>&1; then echo 'invalid present status unexpectedly succeeded' >&2; exit 1; fi
echo 'vpsbg production status offline fixture: PASS'
