#!/usr/bin/env bash
# Hash-checked retrieval of one Observe / Enroll / Probe receipt from the pir2
# sealed recovery root (pain point 9). The guest serves status.json and
# pir2-sealed-receipt.bin on its bounded recovery listener for 600 s after an
# inert phase; the public origin sits behind Cloudflare, which has served a
# cached receipt from an earlier phase (Cache-Control max-age=14400). So:
# cache-bust every request, wait until status.json names the expected phase
# and ordinal, download the receipt, and require its sha256 to equal the
# status declaration; anything else is quarantined, never accepted.
set -euo pipefail

usage() { cat <<'USAGE'
usage: scripts/pir2-sealed-recovery-receipt.sh --phase observe|enroll|probe --ordinal N \
         --out-dir DIR [--label LABEL] [--wait SECONDS] [--poll SECONDS] \
         [--base-url URL] [--dry-run]

Writes DIR/LABEL.status.json, DIR/LABEL.status.headers.txt, DIR/LABEL.receipt.bin,
DIR/LABEL.receipt.headers.txt (LABEL defaults to <phase>-ordinal<N>). Polls until
status.json reports the phase and ordinal (default --wait 900, --poll 15), then
fetches the receipt up to three times until its sha256 equals status.receipt_sha256.
A mismatching download is renamed *.REJECTED-<unix>-<attempt>.bin and the run fails. Ends
with PASS pir2_sealed_recovery_receipt phase=... ordinal=... boot_id_hex=...
receipt_sha256=... and NEXT_STEP. Ready receipts are not on the recovery root:
use scripts/pir2-sealed-ceremony.sh fetch.
USAGE
}

phase= ordinal= out_dir= label= wait_seconds=900 poll_seconds=15 dry_run=0
base_url=${PIR2_RECOVERY_BASE_URL:-https://weikeng2.bitcoinpir.org}
while (($#)); do
  case "$1" in
    --phase) phase=${2:?}; shift 2 ;;
    --ordinal) ordinal=${2:?}; shift 2 ;;
    --out-dir) out_dir=${2:?}; shift 2 ;;
    --label) label=${2:?}; shift 2 ;;
    --wait) wait_seconds=${2:?}; shift 2 ;;
    --poll) poll_seconds=${2:?}; shift 2 ;;
    --base-url) base_url=${2:?}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$phase" =~ ^(observe|enroll|probe)$ ]] || { echo "--phase must be observe, enroll, or probe (Ready receipts come over the WebSocket)" >&2; exit 2; }
[[ "$ordinal" =~ ^[1-9][0-9]*$ ]] || { echo "--ordinal must be a positive integer" >&2; exit 2; }
[[ -n "$out_dir" ]] || { echo "--out-dir is required" >&2; exit 2; }
[[ "$wait_seconds" =~ ^[0-9]+$ && "$poll_seconds" =~ ^[0-9]+$ ]] || { echo "--wait and --poll take seconds" >&2; exit 2; }
[[ -n "$label" ]] || label=$phase-ordinal$ordinal
[[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$ ]] || { echo "--label must be [A-Za-z0-9._-]" >&2; exit 2; }
if command -v sha256sum >/dev/null 2>&1; then hash_one() { sha256sum "$1" | awk '{print $1}'; }; else hash_one() { shasum -a 256 "$1" | awk '{print $1}'; }; fi

echo "[stage] recovery receipt phase=$phase ordinal=$ordinal label=$label"
echo "base_url=$base_url"
if ((dry_run)); then
  echo "planned_status_url=$base_url/status.json?ts=<unix>"
  echo "planned_receipt_url=$base_url/pir2-sealed-receipt.bin?ts=<unix>"
  echo "planned_files=$out_dir/$label.{status.json,status.headers.txt,receipt.bin,receipt.headers.txt}"
  echo "PASS pir2_sealed_recovery_receipt dry_run=true"
  echo "NEXT_STEP=run without --dry-run once the guest has booted the $phase phase"
  exit 0
fi
[[ -d "$out_dir" ]] || { echo "--out-dir is not a directory: $out_dir" >&2; exit 2; }
for f in status.json status.headers.txt receipt.bin receipt.headers.txt; do
  [[ ! -e "$out_dir/$label.$f" ]] || { echo "refusing to overwrite $out_dir/$label.$f" >&2; exit 1; }
done
umask 077
started=$(date +%s); attempts=0
while :; do
  now=$(date +%s)
  (( now - started <= wait_seconds )) || { echo "HARD_STOP no $phase/$ordinal status within ${wait_seconds}s"; exit 1; }
  status=$(curl -sS --max-time 15 "$base_url/status.json?ts=$now" 2>/dev/null || true)
  seen_phase=$(jq -r '.phase // ""' <<<"$status" 2>/dev/null || true)
  seen_ordinal=$(jq -r '.ordinal // ""' <<<"$status" 2>/dev/null || true)
  if [[ "$seen_phase" == "$phase" && "$seen_ordinal" == "$ordinal" ]]; then
    attempts=$((attempts + 1))
    ts=$(date +%s)
    curl -sS --fail --max-time 30 -D "$out_dir/$label.status.headers.txt" -o "$out_dir/$label.status.json" "$base_url/status.json?ts=$ts"
    curl -sS --fail --max-time 30 -D "$out_dir/$label.receipt.headers.txt" -o "$out_dir/$label.receipt.bin" "$base_url/pir2-sealed-receipt.bin?ts=$ts"
    want=$(jq -r '.receipt_sha256 // ""' "$out_dir/$label.status.json")
    boot=$(jq -r '.boot_id // ""' "$out_dir/$label.status.json")
    have=$(hash_one "$out_dir/$label.receipt.bin")
    echo "status_json=$(tr -d '\n' < "$out_dir/$label.status.json")"
    grep -i '^cf-cache-status\|^content-length' "$out_dir/$label.receipt.headers.txt" | tr -d '\r' || true
    if [[ "$want" =~ ^[0-9a-f]{64}$ && "$have" == "$want" && "$boot" =~ ^[0-9a-f]{32}$ ]]; then
      echo "receipt_sha256=$have"
      echo "PASS pir2_sealed_recovery_receipt phase=$phase ordinal=$ordinal boot_id_hex=$boot receipt_sha256=$have"
      case "$phase" in
        observe) echo "NEXT_STEP=run scripts/pir2-sealed-ceremony.sh release with this receipt, its ordinal, nonce, channel key, and boot ID" ;;
        *) echo "NEXT_STEP=accept it with scripts/pir2-sealed-ceremony.sh receipt --expected-phase $phase --expected-ordinal $ordinal --expected-boot-id-hex $boot --expected-receipt-sha256-hex $have" ;;
      esac
      exit 0
    fi
    mv "$out_dir/$label.receipt.bin" "$out_dir/$label.receipt.REJECTED-$ts-$attempts.bin"
    rm -f "$out_dir/$label.status.json" "$out_dir/$label.status.headers.txt" "$out_dir/$label.receipt.headers.txt"
    echo "RECEIPT_HASH_MATCH=false status=$want download=$have (quarantined as $label.receipt.REJECTED-$ts-$attempts.bin)"
    (( attempts < 3 )) || { echo "FETCH_FAILED after 3 attempts; retrieve the persisted receipt through the Flow F data-disk window"; exit 1; }
  else
    echo "waiting elapsed=$((now - started)) phase=${seen_phase:-n/a} ordinal=${seen_ordinal:-n/a}"
  fi
  sleep "$poll_seconds"
done
