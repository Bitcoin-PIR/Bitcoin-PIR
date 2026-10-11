#!/usr/bin/env bash
# Re-sign and publish the whole service directory in one run: per provider a
# fresh operator assertion (when its operator key is local) and the next entry
# or tombstone, then the next 16 shard checkpoints over all of them, published
# unchanged to the relay's publisher lane and read back from the public lane
# (docs/runbooks/directory-relay.md "Publish or update entries"). Entries and
# checkpoints expire after at most 31 days, so run it at least monthly and
# after any provider change.
#
# Usage: scripts/directory-publish.sh DIR [--validate-only]
#
# DIR stays on the publisher's workstation and holds:
#   directory-nostr.key  the publisher key (`bpir-admin directory-artifact keygen`)
#   providers.tsv        one provider per line, tab-separated, `#` comments:
#                        name server_id endpoint role attestation backends source
#                        [assertion_valid_until]
#                        backends: comma-separated NAME=ACCESS, as the live
#                        GET_INFO_JSON `credits.access` says (dpf=best-effort,...)
#                        source: the operator's key file (signed here), the
#                        operator's own assertion file (*.bin, with its
#                        valid_until in the last column: an entry cannot
#                        outlive its assertion), or `retired` (publishes a
#                        tombstone; the provider stays in the checkpoints)
#   ledger.tsv           written after each publish: name provider_id
#                        sequence assertion_epoch, and a `checkpoints` line
#   runs/<unix time>-*/  the artifacts of each run
#
# Environment: BPIR_ADMIN (bpir-admin), PUBLISHER_RELAY (ws://127.0.0.1:8097,
# the pir1 publisher lane through `ssh -N -L 8097:127.0.0.1:8097 <pir1>`),
# PUBLIC_RELAY (wss://directory.bitcoinpir.org), VALID_DAYS (30). The
# readback needs the WASM package (`wasm-pack build crates/sdk/wasm --target
# web --out-dir pkg`).
set -euo pipefail

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }
[[ "${1:-}" == -h || "${1:-}" == --help ]] && { usage; exit 0; }
[[ $# -ge 1 ]] || { usage >&2; exit 2; }
DIR=$1
VALIDATE=()
[[ "${2:-}" == --validate-only ]] && VALIDATE=(--validate-only)

ADMIN=${BPIR_ADMIN:-bpir-admin}
PUBLISHER_RELAY=${PUBLISHER_RELAY:-ws://127.0.0.1:8097}
PUBLIC_RELAY=${PUBLIC_RELAY:-wss://directory.bitcoinpir.org}
VALID_DAYS=${VALID_DAYS:-30}
REPO=$(cd "$(dirname "$0")/.." && pwd)
KEY=$DIR/directory-nostr.key
LEDGER=$DIR/ledger.tsv
NOW=$(date +%s)
UNTIL=$((NOW + VALID_DAYS * 86400))
BUCKET=$((NOW / 300 * 300))
mkdir -p "$DIR/runs"
RUN=$(mktemp -d "$DIR/runs/$NOW-XXXX")
touch "$LEDGER"

# Column $2 of the ledger line named $1, or $3 when there is none (or `-`).
ledger() {
  awk -F'\t' -v n="$1" -v c="$2" -v d="$3" \
    '$1 == n && $c != "-" { v = $c } END { print (v == "" ? d : v) }' "$LEDGER"
}
# Value of `KEY=` in bpir-admin output $2.
field() { awk -v k="$1=" 'index($0, k) == 1 { print substr($0, length(k) + 1); exit }' <<<"$2"; }

# 101 means the endpoint accepted a WebSocket upgrade (scripts/node-monitor.sh).
health() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --http1.1 -m 10 \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "https://${1#wss://}" || true)
  [[ "$code" == 101 ]] && echo available || echo unavailable
}

events=()
new_ledger=()
directory_pubkey=
while IFS=$'\t' read -r name server_id endpoint role attestation backends source assertion_until; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  sequence=$(( $(ledger "$name" 3 0) + 1 ))
  epoch=$(ledger "$name" 4 -)
  if [[ "$source" == retired ]]; then
    provider_id=$(ledger "$name" 2 "")
    [[ -n "$provider_id" ]] || { echo "$name: retired but never published" >&2; exit 1; }
    out=$(
      "$ADMIN" directory-artifact tombstone --provider-id-hex "$provider_id" \
        --directory-signing-key "$KEY" --directory-sequence "$sequence" \
        --directory-valid-until "$UNTIL" --health-class unavailable \
        --health-observed-bucket "$BUCKET" --created-at "$NOW" --now-unix "$NOW" \
        --out "$RUN/$name.tombstone.event.json"
    )
    events+=("$RUN/$name.tombstone.event.json")
  else
    entry_until=$UNTIL
    if [[ "$source" == *.bin ]]; then
      assertion=$source
      [[ -n "$assertion_until" && "$assertion_until" -lt "$UNTIL" ]] && entry_until=$assertion_until
    else
      [[ "$epoch" == - ]] && epoch=0
      epoch=$((epoch + 1))
      assertion=$RUN/$name.assertion.bin
      "$ADMIN" directory-artifact assertion --operator-signing-key "$source" \
        --stable-server-id "$server_id" --assertion-epoch "$epoch" --not-before "$NOW" \
        --valid-until "$UNTIL" --endpoint "$endpoint" --now-unix "$NOW" \
        --out "$assertion" >/dev/null
    fi
    backend_args=()
    IFS=, read -ra list <<<"$backends"
    for backend in "${list[@]}"; do backend_args+=(--backend "$backend"); done
    state=$(health "$endpoint")
    out=$(
      "$ADMIN" directory-artifact entry --assertion "$assertion" \
        --directory-signing-key "$KEY" --directory-sequence "$sequence" \
        --directory-valid-until "$entry_until" --created-at "$NOW" --role "$role" \
        --attestation "$attestation" "${backend_args[@]}" --health-class "$state" \
        --health-observed-bucket "$BUCKET" --now-unix "$NOW" \
        --out "$RUN/$name.entry.event.json"
    )
    provider_id=$(field provider_id "$out")
    events+=("$RUN/$name.entry.event.json")
    echo "$name: provider_id=$provider_id sequence=$sequence health=$state"
  fi
  key_hex=$(field directory_pubkey_xonly "$out")
  [[ -z "$key_hex" ]] || directory_pubkey=$key_hex
  new_ledger+=("$name"$'\t'"$provider_id"$'\t'"$sequence"$'\t'"$epoch")
done <"$DIR/providers.tsv"
[[ ${#events[@]} -gt 0 ]] || { echo "no providers in $DIR/providers.tsv" >&2; exit 1; }

checkpoint_epoch=$(( $(ledger checkpoints 3 0) + 1 ))
entry_args=()
for event in "${events[@]}"; do entry_args+=(--entry-event "$event"); done
"$ADMIN" directory-artifact checkpoints "${entry_args[@]}" --directory-signing-key "$KEY" \
  --checkpoint-epoch "$checkpoint_epoch" --not-before "$NOW" --valid-until "$UNTIL" \
  --created-at "$NOW" --now-unix "$NOW" --out "$RUN/checkpoints.json" >/dev/null
echo "checkpoints: epoch=$checkpoint_epoch valid_until=$UNTIL"

artifact_args=()
for event in "${events[@]}" "$RUN/checkpoints.json"; do artifact_args+=(--artifact "$event"); done
"$ADMIN" directory-artifact publish "${artifact_args[@]}" --relay "$PUBLISHER_RELAY" \
  --loopback-publisher --centralized-single-relay --directory-pubkey-hex "$directory_pubkey" \
  --now-unix "$(date +%s)" ${VALIDATE[@]+"${VALIDATE[@]}"}
[[ ${#VALIDATE[@]} -eq 0 ]] || { echo "validated only; nothing published, ledger unchanged"; exit 0; }

{
  printf '%s\n' "${new_ledger[@]}"
  printf 'checkpoints\t-\t%s\t-\n' "$checkpoint_epoch"
} >"$LEDGER"
node "$REPO/scripts/directory-readback.mjs" --relay "$PUBLIC_RELAY" --centralized-single-relay \
  --directory-pubkey-hex "$directory_pubkey" "${artifact_args[@]}"
