#!/usr/bin/env bash
set -euo pipefail

if [[ "${BPIR_PUBLISHER_FIREWALL_TEST:-}" != "I_UNDERSTAND_DISPOSABLE_CONTAINER" ]]; then
  echo "refusing: set BPIR_PUBLISHER_FIREWALL_TEST=I_UNDERSTAND_DISPOSABLE_CONTAINER" >&2
  exit 2
fi
if [[ ! -f /.dockerenv ]]; then
  echo "refusing: publisher firewall e2e may run only inside a disposable container" >&2
  exit 2
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "refusing: publisher firewall e2e requires root inside the container" >&2
  exit 2
fi

for command in /usr/sbin/ufw /usr/sbin/nft /usr/sbin/ip /usr/bin/node; do
  [[ -x "$command" ]] || { echo "missing test dependency: $command" >&2; exit 2; }
done

test_root="$(mktemp -d /tmp/bitcoinpir-publisher-firewall.XXXXXX)"
cleanup() {
  /usr/sbin/ufw --force disable >/dev/null 2>&1 || true
  /usr/sbin/ip link del bpir-pub-h >/dev/null 2>&1 || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

/usr/sbin/ip link add bpir-pub-h type dummy
/usr/sbin/ip addr add 10.203.0.1/30 dev bpir-pub-h
/usr/sbin/ip link set bpir-pub-h up
/usr/sbin/ufw --force reset >/dev/null
/usr/sbin/ufw logging off >/dev/null
/usr/sbin/ufw prepend deny in on bpir-pub-h from any to any >/dev/null
/usr/sbin/ufw prepend allow in on bpir-pub-h from 10.203.0.2 to 10.203.0.1 proto tcp port 443 >/dev/null
/usr/sbin/ufw route prepend deny in on bpir-pub-h from any to any >/dev/null
/usr/sbin/ufw route prepend deny out on bpir-pub-h from any to any >/dev/null
/usr/sbin/ufw --force enable >/dev/null

capture_and_verify() {
  local suffix="$1"
  local output="$test_root/$suffix"
  mkdir -m 0700 "$output"
  /usr/sbin/ufw status numbered >"$output/ufw_status.txt"
  /usr/sbin/ufw show raw >"$output/ufw_raw.txt"
  /usr/sbin/nft list chain ip filter INPUT >"$output/nft_ip_base_input.txt"
  /usr/sbin/nft list chain ip filter FORWARD >"$output/nft_ip_base_forward.txt"
  /usr/sbin/nft list chain ip filter ufw-before-logging-input >"$output/nft_ip_before_logging_input.txt"
  /usr/sbin/nft list chain ip filter ufw-before-logging-forward >"$output/nft_ip_before_logging_forward.txt"
  /usr/sbin/nft list chain ip filter ufw-before-input >"$output/nft_ip_before_input.txt"
  /usr/sbin/nft list chain ip filter ufw-before-forward >"$output/nft_ip_before_forward.txt"
  /usr/sbin/nft list chain ip filter ufw-logging-deny >"$output/nft_ip_logging_deny.txt"
  /usr/sbin/nft list chain ip filter ufw-not-local >"$output/nft_ip_not_local.txt"
  /usr/sbin/nft list chain ip filter ufw-user-input >"$output/nft_ip_input.txt"
  /usr/sbin/nft list chain ip filter ufw-user-forward >"$output/nft_ip_forward.txt"
  /usr/sbin/nft list chain ip6 filter INPUT >"$output/nft_ip6_base_input.txt"
  /usr/sbin/nft list chain ip6 filter FORWARD >"$output/nft_ip6_base_forward.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-before-logging-input >"$output/nft_ip6_before_logging_input.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-before-logging-forward >"$output/nft_ip6_before_logging_forward.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-before-input >"$output/nft_ip6_before_input.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-before-forward >"$output/nft_ip6_before_forward.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-logging-deny >"$output/nft_ip6_logging_deny.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-user-input >"$output/nft_ip6_input.txt"
  /usr/sbin/nft list chain ip6 filter ufw6-user-forward >"$output/nft_ip6_forward.txt"
  /usr/bin/node scripts/payment-v1-publisher-netns-gate.mjs \
    verify-firewall-directory "$output"
}

capture_and_verify before
/usr/sbin/ufw reload >/dev/null
capture_and_verify after

echo "payment-v1 publisher firewall privileged e2e: ok"
