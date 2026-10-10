#!/usr/bin/env bash
# Read-only pir1 SSH health, a public attest of the pir2 MacBook node, and the
# Direct ORAM TEE host's VPSBG status plus its pinned SEV-SNP attest.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/production-status.sh [--server-id ID]

Prints pir1 systemd/port/disk health over SSH, then attests the pir2
MacBook node over its public endpoint against PIR2_MACBOOK_PIN. Then it
shows the Direct ORAM TEE host's VPSBG control-plane status
(scripts/vpsbg-production-status.sh, default server 26939) and attests the
host against the pins ORAM_PROVIDER names (MEASUREMENT, binary, AMD ARK).
Endpoints and pins come from web/src (scripts/production-pins.py); while
ORAM_PROVIDER is null the ORAM host is skipped. Never restarts a service.

BPIR_ADMIN=/absolute/path/to/bpir-admin runs a prebuilt binary; otherwise
the attests run through `cargo run --release -p bpir-admin`.
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly HETZNER_HOST=65.21.91.217

server_id=26939
while (($#)); do
  case "$1" in
    --server-id) server_id=${2:?missing server ID}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

pins=$(python3 "$root/scripts/production-pins.py")
pin() { awk -F= -v key="$1" '$1 == key { print $2 }' <<<"$pins"; }
if [[ -n "${BPIR_ADMIN:-}" ]]; then
  admin=("$BPIR_ADMIN")
else
  admin=(cargo run --quiet --release --manifest-path "$root/Cargo.toml" -p bpir-admin --)
fi

echo '[stage] pir1 Hetzner health'
ssh -o BatchMode=yes -o ConnectTimeout=20 \
  -o UserKnownHostsFile="$root/deploy/known_hosts" -o StrictHostKeyChecking=yes \
  "root@$HETZNER_HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
# Capture first: under pipefail, `ss | grep -q` can fail with SIGPIPE (141).
if listeners=$(ss -tln 2>/dev/null) && grep -Eq ':8091\b' <<<"$listeners"; then
  port=listening
else
  port=missing
fi
printf 'pir1_primary=%s\n' "$(systemctl is-active pir-primary 2>/dev/null || true)"
printf 'pir1_cloudflared=%s\n' "$(systemctl is-active cloudflared 2>/dev/null || true)"
printf 'pir1_port_8091=%s\n' "$port"
printf 'pir1_disk_used=%s\n' "$(df -P /home/pir | awk 'NR==2 { print $5 }')"
REMOTE

echo '[stage] pir2 MacBook node attest'
attest_out=$("${admin[@]}" attest "$(pin pir2_url)" 2>&1) || {
  printf '%s\n' "$attest_out"
  echo 'pir2 attest failed' >&2
  exit 1
}
printf '%s\n' "$attest_out"
running=$(awk '$1 == "binary_sha256:" { print tolower($2) }' <<<"$attest_out")
if [[ "$running" == "$(pin pir2_binary)" ]]; then
  echo '✓ binary_sha256 matches PIR2_MACBOOK_PIN'
elif [[ "$running" == "$(pin pir2_transition)" ]]; then
  echo '✓ binary_sha256 matches the transition build of PIR2_MACBOOK_PIN (switch pending)'
else
  echo "✗ pir2 binary_sha256 ${running:-unavailable} matches neither build PIR2_MACBOOK_PIN accepts" >&2
  exit 1
fi

echo '[stage] Direct ORAM TEE host'
if [[ "$(pin oram_url)" == - ]]; then
  echo 'oram=paused (ORAM_PROVIDER is null)'
  exit 0
fi
"$root/scripts/vpsbg-production-status.sh" --server-id "$server_id"
"${admin[@]}" attest "$(pin oram_url)" \
  --expect-measurement "$(pin oram_measurement)" \
  --expect-binary "$(pin oram_binary)" \
  --expect-ark-fingerprint "$(pin oram_ark)"
