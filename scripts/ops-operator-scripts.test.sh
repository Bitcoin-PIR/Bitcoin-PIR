#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$script_dir/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/bpir-ops-scripts.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

expect_pass() {
  local label=$1
  shift
  local out
  out=$("$@")
  grep -q 'PASS ' <<<"$out" || {
    echo "$label did not print PASS" >&2
    printf '%s\n' "$out" >&2
    exit 1
  }
}

expect_fail() {
  local label=$1
  shift
  if "$@" >/dev/null 2>"$tmp/err"; then
    echo "$label unexpectedly succeeded" >&2
    exit 1
  fi
}

images_preview=$("$script_dir/vpsbg-measured-boot.sh" images --dry-run)
grep -qx 'PASS action=images dry_run=true' <<<"$images_preview"
grep -q '\.secrets/vpsbg-api-token' <<<"$images_preview"

open_preview=$("$script_dir/vpsbg-data-disk.sh" open --image-id 291 --dry-run)
grep -qx 'server_id=25285' <<<"$open_preview"
grep -qx 'detach_body={"kernel_image_id":null}' <<<"$open_preview"
grep -qx 'PASS action=open dry_run=true' <<<"$open_preview"

close_preview=$("$script_dir/vpsbg-data-disk.sh" close --server-id 25285 --image-id 291 --dry-run)
grep -qx 'PASS action=close dry_run=true' <<<"$close_preview"

printf '%s\n' \
  'schema=bitcoinpir-pir2-sealed-startup-v2' \
  'profile=pir2-snp-sealed-v1' \
  'phase=observe' >"$tmp/observe.startup.env"
put_preview=$("$script_dir/vpsbg-data-disk.sh" put \
  --local "$tmp/observe.startup.env" \
  --remote /home/pir/data/pir2-sealed/startup.env --dry-run)
grep -qx 'PASS action=put dry_run=true' <<<"$put_preview"

expect_fail 'put outside /home/pir/data' \
  "$script_dir/vpsbg-data-disk.sh" put --local "$tmp/observe.startup.env" --remote /tmp/startup.env --dry-run
expect_fail 'put startup.env at wrong sealed path' \
  "$script_dir/vpsbg-data-disk.sh" put --local "$tmp/observe.startup.env" --remote /home/pir/data/startup.env --dry-run
expect_fail 'put provisioner path' \
  "$script_dir/vpsbg-data-disk.sh" put --local "$tmp/observe.startup.env" --remote /home/pir/data/provisioner.env --dry-run
printf 'not-a-ceremony\n' >"$tmp/bad.startup.env"
expect_fail 'put non-ceremony startup.env' \
  "$script_dir/vpsbg-data-disk.sh" put --local "$tmp/bad.startup.env" --remote /home/pir/data/pir2-sealed/startup.env --dry-run
expect_fail 'open without image id' \
  "$script_dir/vpsbg-data-disk.sh" open --dry-run

status_preview=$("$script_dir/production-status.sh" --dry-run)
grep -qx 'PASS production_status dry_run=true' <<<"$status_preview"
grep -qx 'pir1_host=65.21.91.217' <<<"$status_preview"

# Empty-array regressions: a bare quoted-at expansion crashes under `set -u`
# on bash < 4.4 (macOS /bin/bash 3.2), so every status_args expansion must be
# written with the "${status_args[@]+...}" guard idiom. The inner repetition
# inside the idiom is fine; flag only expansions missing the @]+ guard.
if grep '"${status_args\[@\]}"' "$script_dir/production-status.sh" | grep -qv '@\]+'; then
  echo 'production-status.sh uses the unbound bare status_args expansion' >&2
  exit 1
fi
if grep '"${status_args\[@\]}"' "$script_dir/vpsbg-measured-boot.sh" | grep -qv '@\]+'; then
  echo 'vpsbg-measured-boot.sh uses the unbound bare status_args expansion' >&2
  exit 1
fi

printf 'test-token\n' >"$tmp/vpsbg-token"
status_token_preview=$("$script_dir/vpsbg-measured-boot.sh" status --token-file "$tmp/vpsbg-token" --dry-run)
grep -qx 'PASS action=status dry_run=true' <<<"$status_token_preview"
expect_fail 'status still rejects --image-id' \
  "$script_dir/vpsbg-measured-boot.sh" status --image-id 291 --dry-run
check_preview=$("$script_dir/pir2-post-switch-check.sh" --dry-run)
grep -qx "pin_source=$repo/web/src/attest-pin.ts" <<<"$check_preview"
grep -qx 'PASS action=post_switch_check dry_run=true' <<<"$check_preview"

printf 'export const PIR2_TIER3_PIN: ServerAttestPin = {\n};\n' >"$tmp/empty-pin.ts"
expect_fail 'post-switch-check missing pin fields' \
  "$script_dir/pir2-post-switch-check.sh" --pin-file "$tmp/empty-pin.ts" --dry-run

echo 'ops operator scripts offline fixture: PASS'
