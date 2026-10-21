#!/usr/bin/env bash
# Probe each production node's public WebSocket endpoint and keep one GitHub
# issue per node in step with it: opened (label `node-down`) when the node
# stops accepting a WebSocket upgrade, closed with a comment when it accepts
# one again. Then read the service directory back from its relay and keep one
# issue (label `directory-stale`) open while the catalog is unreadable, short
# of its 16 shards or within DIRECTORY_MIN_DAYS of expiry. An open issue is
# matched by the marker `node-monitor:<name>` in its body, so an issue opened
# by hand can be adopted by adding the marker.
# Run by .github/workflows/node-monitor.yml: hourly for the nodes, once a day
# with the WASM package built so the directory check runs too; needs `gh`
# with GH_TOKEN/GH_REPO (issues: write).
set -euo pipefail

NODES=(
  "pir1|wss://weikeng1.bitcoinpir.org|DPF server 0, OnionPIR, HarmonyPIR hints"
  "server1|wss://bitcoin-pir-weikeng-laptop.chenweikeng.com|DPF server 1 and HarmonyPIR queries (run best-effort)"
  "oram|wss://weikeng2.bitcoinpir.org|Direct ORAM (AMD SEV-SNP)"
)
ATTEMPTS=3
RETRY_SECS=20

# 101 means the endpoint accepted a WebSocket upgrade; curl then waits for
# data until -m expires, so its exit status is ignored.
probe() {
  curl -s -o /dev/null -w '%{http_code}' --http1.1 -m 10 \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
    "https://${1#wss://}" || true
}

gh label create node-down --color B60205 \
  --description 'A production node is unreachable (node-monitor)' 2>/dev/null || true
now=$(date -u +%FT%TZ)

for node in "${NODES[@]}"; do
  IFS='|' read -r name url role <<<"$node"
  code=000
  for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
    code=$(probe "$url")
    [[ "$code" == 101 ]] && break
    ((attempt < ATTEMPTS)) && sleep "$RETRY_SECS"
  done
  issue=$(gh issue list --state open --label node-down --limit 100 --json number,body \
    --jq "[.[] | select(.body | contains(\"node-monitor:$name\"))][0].number // empty")
  if [[ "$code" == 101 ]]; then
    echo "$name: up"
    if [[ -n "$issue" ]]; then
      gh issue close "$issue" --comment "node-monitor: \`$url\` accepts WebSocket upgrades again ($now)."
      echo "$name: closed #$issue"
    fi
  else
    echo "$name: down (HTTP $code after $ATTEMPTS attempts)"
    if [[ -z "$issue" ]]; then
      body="\`$url\` ($role) did not accept a WebSocket upgrade: HTTP $code after $ATTEMPTS attempts at $now.

This issue closes itself when the node answers again (\`scripts/node-monitor.sh\`, run hourly).

<!-- node-monitor:$name -->"
      gh issue create --label node-down --title "$name unreachable: $url" --body "$body"
    fi
  fi
done

# Service directory (docs/runbooks/directory-relay.md): the readback needs the
# WASM package (`wasm-pack build crates/sdk/wasm --target web --out-dir pkg`);
# without it the check is skipped. The publisher key is the web client's pin.
DIRECTORY_RELAY=wss://directory.bitcoinpir.org
DIRECTORY_MIN_DAYS=7
PIN=web/src/production-providers.ts

if [[ ! -f crates/sdk/wasm/pkg/pir_sdk_wasm.js ]]; then
  echo "directory: skipped (crates/sdk/wasm/pkg not built)"
  exit 0
fi
key=$(tr -d ' \n' <"$PIN" | sed -n "s/.*directoryPubkeyHex:['\"]\([0-9a-f]\{64\}\)['\"].*/\1/p")
if [[ -z "$key" ]]; then
  echo "directory: skipped (directoryPubkeyHex is null in $PIN)"
  exit 0
fi
gh label create directory-stale --color B60205 \
  --description 'The service directory catalog is unreadable or about to expire (node-monitor)' 2>/dev/null || true

status=0
for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
  status=0
  out=$(node scripts/directory-readback.mjs --relay "$DIRECTORY_RELAY" --centralized-single-relay \
    --directory-pubkey-hex "$key" 2>&1) || status=$?
  ((status == 0)) && break
  ((attempt < ATTEMPTS)) && sleep "$RETRY_SECS"
done
printf '%s\n' "$out"
shards=$(sed -n 's/^catalog .*shards=\([0-9]*\)\/16 .*/\1/p' <<<"$out")
valid_until=$(sed -n 's/^catalog .*valid_until=\([0-9]*\).*/\1/p' <<<"$out")
days=$(( (${valid_until:-0} - $(date +%s)) / 86400 ))
if ((status != 0)); then reason="readback exit status $status"
elif ((${shards:-0} < 16)); then reason="only ${shards:-0}/16 shards"
elif ((days < DIRECTORY_MIN_DAYS)); then reason="valid_until=$valid_until ($days days left)"
else reason=
fi
issue=$(gh issue list --state open --label directory-stale --limit 100 --json number,body \
  --jq '[.[] | select(.body | contains("node-monitor:directory"))][0].number // empty')
if [[ -z "$reason" ]]; then
  echo "directory: healthy ($shards/16 shards, $days days left)"
  if [[ -n "$issue" ]]; then
    gh issue close "$issue" --comment "node-monitor: \`$DIRECTORY_RELAY\` serves all 16 shards again, valid for another $days days ($now)."
    echo "directory: closed #$issue"
  fi
else
  echo "directory: stale ($reason)"
  if [[ -z "$issue" ]]; then
    body="The service directory at \`$DIRECTORY_RELAY\` is stale: $reason at $now.

Republish it (\`docs/runbooks/directory-relay.md\`, \"Publish or update entries\"); the launchd agent on the Mac Studio normally does so on the 1st and 15th. This issue closes itself when the readback is healthy again (\`scripts/node-monitor.sh\`, run daily).

<details><summary>Readback</summary>

\`\`\`
$out
\`\`\`

</details>

<!-- node-monitor:directory -->"
    gh issue create --label directory-stale --title "service directory stale: $DIRECTORY_RELAY" --body "$body"
  fi
fi
