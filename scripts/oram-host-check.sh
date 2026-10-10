#!/usr/bin/env bash
# After a measured-boot switch: wait until the Direct ORAM host runs measured,
# then attest it against the pins in web/src (edit them first for a new
# image), test the encrypted channel, and send one padded ORAM query to each
# database. Options are passed to scripts/vpsbg-production-status.sh.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
pins=$(python3 "$root/scripts/production-pins.py")
pin() { awk -F= -v key="$1" '$1 == key { print $2 }' <<<"$pins"; }
server=$(pin oram_url)
[[ "$server" != - ]] || { echo 'ORAM_PROVIDER is null (Direct ORAM paused)'; exit 0; }
if [[ -n "${BPIR_ADMIN:-}" ]]; then
  admin=("$BPIR_ADMIN")
else
  admin=(cargo run --locked -q --manifest-path "$root/Cargo.toml" -p bpir-admin --)
fi

status_field() {
  awk -F= -v key="$1" '$1 == key { print $2; found=1 } END { if (!found) print "unavailable" }'
}

echo '[stage] wait for measured boot'
t0=$(date -u +%s)
while :; do
  snapshot=$("$root/scripts/vpsbg-production-status.sh" "$@")
  boot_mode=$(status_field boot_mode <<<"$snapshot")
  running=$(status_field control_plane_running <<<"$snapshot")
  echo "boot_mode=$boot_mode control_plane_running=$running image_id=$(status_field image_id <<<"$snapshot") elapsed_seconds=$(($(date -u +%s) - t0))"
  [[ "$boot_mode" == measured && "$running" == true ]] && break
  sleep 10
done

echo '[stage] attest, channel, ORAM queries'
"${admin[@]}" attest "$server" \
  --expect-measurement "$(pin oram_measurement)" \
  --expect-binary "$(pin oram_binary)" \
  --expect-ark-fingerprint "$(pin oram_ark)"
"${admin[@]}" channel-test "$server" --expect-ark-fingerprint "$(pin oram_ark)"
for db_id in 0 1; do
  cargo run --locked -q --manifest-path "$root/Cargo.toml" -p pir-sdk-client \
    --example oram_local_smoke -- --server "$server" --db-id "$db_id" \
    --padded-slots 25 4242424242424242424242424242424242424242
done
