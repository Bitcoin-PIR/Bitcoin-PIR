#!/usr/bin/env bash
# Probe each production node's public WebSocket endpoint and keep one GitHub
# issue per node in step with it: opened (label `node-down`) when the node
# stops accepting a WebSocket upgrade, closed with a comment when it accepts
# one again. An open issue is matched by the marker `node-monitor:<name>` in
# its body, so an issue opened by hand can be adopted by adding the marker.
# Run hourly by .github/workflows/node-monitor.yml; needs `gh` with
# GH_TOKEN/GH_REPO (issues: write).
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
