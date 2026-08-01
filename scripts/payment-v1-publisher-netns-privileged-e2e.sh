#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(id -u)" != 0 ]]; then
  echo "publisher-netns privileged test requires disposable Linux with euid 0" >&2
  exit 2
fi
if [[ "${BPIR_PUBLISHER_NETNS_PRIVILEGED_TEST:-}" != "I_UNDERSTAND_DISPOSABLE_HOST" ]]; then
  echo "set BPIR_PUBLISHER_NETNS_PRIVILEGED_TEST=I_UNDERSTAND_DISPOSABLE_HOST" >&2
  exit 2
fi
if [[ ! -f /.dockerenv && "${BPIR_PUBLISHER_NETNS_DISPOSABLE_VM:-}" != "yes" ]]; then
  echo "refusing a non-container host without BPIR_PUBLISHER_NETNS_DISPOSABLE_VM=yes" >&2
  exit 2
fi

for command in gcc ip python3; do
  if ! command -v "$command" >/dev/null; then
    echo "missing required test command: $command" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
test_root="$(mktemp -d /tmp/bitcoinpir-publisher-netns-e2e.XXXXXX)"
helper="$test_root/payment-v1-publisher-netns"
listener_pid=""
owner_pid=""
cleanup_pid=""

terminate_child() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then break; fi
    sleep 0.05
  done
  kill -KILL "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
}

cleanup() {
  terminate_child "$cleanup_pid"
  terminate_child "$owner_pid"
  terminate_child "$listener_pid"
  if [[ -x "$helper" ]]; then
    "$helper" cleanup >/dev/null 2>&1 || true
  fi
  rm -f /tmp/bitcoinpir-publisher-netns-test-pause
  rm -rf -- "$test_root"
}
trap cleanup EXIT

assert_namespace_transaction_clean() {
  test ! -e /run/netns/bpir-pub-test
  test ! -e /tmp/bitcoinpir-publisher-netns-test-state/pending.v1
  if compgen -G '/run/netns/.bpir-pub-*' >/dev/null ||
     compgen -G '/run/netns/.bpir-final-*' >/dev/null; then
    echo "publisher namespace cleanup left a hidden mount placeholder" >&2
    return 1
  fi
}

gcc -DBPIR_PUBLISHER_NETNS_TEST_PROFILE \
  -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
  "$repo_root/scripts/payment-v1-publisher-netns.c" -o "$helper"
"$helper" self-test

start_notify_listener() {
  local socket_path="$1"
  local ready_path="$2"
  local receipt_path="$3"
  rm -f -- "$socket_path" "$ready_path" "$receipt_path"
  python3 - "$socket_path" "$ready_path" "$receipt_path" <<'PY' &
import pathlib
import socket
import sys

socket_path, ready_path, receipt_path = sys.argv[1:]
listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
listener.bind(socket_path)
pathlib.Path(ready_path).write_bytes(b"ready\n")
listener.settimeout(20)
message = listener.recv(4096)
if message != b"READY=1\nSTATUS=publisher namespace sealed and monitored":
    raise SystemExit("unexpected readiness datagram")
pathlib.Path(receipt_path).write_bytes(message)
listener.close()
PY
  listener_pid=$!
  for _ in $(seq 1 80); do
    [[ -f "$ready_path" ]] && return 0
    sleep 0.1
  done
  echo "timed out waiting for readiness listener" >&2
  return 1
}

notify_socket="$test_root/notify.sock"
listener_ready="$test_root/listener.ready"
ready_receipt="$test_root/ready.receipt"
start_notify_listener "$notify_socket" "$listener_ready" "$ready_receipt"
NOTIFY_SOCKET="$notify_socket" "$helper" run &
owner_pid=$!
for _ in $(seq 1 100); do
  [[ -f "$ready_receipt" ]] && break
  if ! kill -0 "$owner_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ ! -f "$ready_receipt" ]]; then
  echo "helper did not notify after monitor initialization" >&2
  exit 1
fi
wait "$listener_pid"
listener_pid=""
kill -TERM "$owner_pid"
wait "$owner_pid"
owner_pid=""
"$helper" cleanup

# A client monitor initialization failure must make the owner fail before any
# READY datagram is emitted.
start_notify_listener "$notify_socket" "$listener_ready" "$ready_receipt"
if NOTIFY_SOCKET="$notify_socket" BPIR_TEST_FAIL_MONITOR_INIT=client "$helper" run; then
  echo "helper succeeded despite injected client monitor initialization failure" >&2
  exit 1
fi
kill "$listener_pid" >/dev/null 2>&1 || true
wait "$listener_pid" >/dev/null 2>&1 || true
listener_pid=""
if [[ -f "$ready_receipt" ]]; then
  echo "helper emitted READY before the client monitor initialized" >&2
  exit 1
fi
"$helper" cleanup

BPIR_TEST_SKIP_NOTIFY=1 "$helper" run &
owner_pid=$!
sleep 2
kill -TERM "$owner_pid"
wait "$owner_pid"
owner_pid=""
"$helper" cleanup
assert_namespace_transaction_clean

wait_for_pause() {
  for _ in $(seq 1 80); do
    if [[ -f /tmp/bitcoinpir-publisher-netns-test-pause ]]; then return 0; fi
    sleep 0.1
  done
  echo "timed out waiting for helper fault-injection pause" >&2
  return 1
}

for crash_stage in \
  after-pre-mutation-journal \
  after-transaction-directory \
  after-placeholder-intent \
  after-transaction-placeholder \
  after-final-placeholder \
  after-prepared-record \
  after-active-record \
  after-namespace-mount \
  after-final-rename \
  after-final-mount \
  after-veth-create \
  after-veth-move
do
  rm -f /tmp/bitcoinpir-publisher-netns-test-pause
  BPIR_TEST_SKIP_NOTIFY=1 BPIR_TEST_PAUSE_AT="$crash_stage" "$helper" run &
  owner_pid=$!
  wait_for_pause
  kill -KILL "$owner_pid"
  wait "$owner_pid" || true
  owner_pid=""
  rm /tmp/bitcoinpir-publisher-netns-test-pause
  "$helper" cleanup
  assert_namespace_transaction_clean
done

for crash_stage in \
  after-veth-delete-cleanup \
  after-final-remove-cleanup \
  after-tx-remove-cleanup
do
  BPIR_TEST_SKIP_NOTIFY=1 "$helper" run &
  owner_pid=$!
  sleep 2
  kill -TERM "$owner_pid"
  wait "$owner_pid"
  owner_pid=""
  rm -f /tmp/bitcoinpir-publisher-netns-test-pause
  BPIR_TEST_PAUSE_AT="$crash_stage" "$helper" cleanup &
  cleanup_pid=$!
  wait_for_pause
  kill -KILL "$cleanup_pid"
  wait "$cleanup_pid" || true
  cleanup_pid=""
  rm /tmp/bitcoinpir-publisher-netns-test-pause
  "$helper" cleanup
  assert_namespace_transaction_clean
done

# A dead main process leaves a journal and kernel objects. PDEATHSIG removes
# the client monitor; exact cleanup then proves the recorded identities.
BPIR_TEST_SKIP_NOTIFY=1 "$helper" run &
owner_pid=$!
sleep 2
kill -KILL "$owner_pid"
wait "$owner_pid" || true
owner_pid=""
sleep 1
"$helper" cleanup
assert_namespace_transaction_clean

# A host endpoint drift must terminate the owner; exact alias/MAC identity is
# still sufficient for the explicit cleanup command to remove the pair.
BPIR_TEST_SKIP_NOTIFY=1 "$helper" run &
owner_pid=$!
sleep 2
ip link set bpirtsth down
for _ in $(seq 1 20); do
  if ! kill -0 "$owner_pid" 2>/dev/null; then break; fi
  sleep 0.25
done
if kill -0 "$owner_pid" 2>/dev/null; then
  echo "namespace owner did not fail closed after link drift" >&2
  exit 1
fi
if wait "$owner_pid"; then
  owner_pid=""
  echo "namespace owner reported success after link drift" >&2
  exit 1
fi
owner_pid=""
"$helper" cleanup

# The namespace-side monitor independently rejects a newly injected default
# route; no publisher process or host-side health probe is trusted for this.
BPIR_TEST_SKIP_NOTIFY=1 "$helper" run &
owner_pid=$!
sleep 2
ip netns exec bpir-pub-test ip route add default via 10.203.254.1
for _ in $(seq 1 20); do
  if ! kill -0 "$owner_pid" 2>/dev/null; then break; fi
  sleep 0.25
done
if kill -0 "$owner_pid" 2>/dev/null; then
  echo "namespace owner did not fail closed after default-route drift" >&2
  exit 1
fi
if wait "$owner_pid"; then
  owner_pid=""
  echo "namespace owner reported success after default-route drift" >&2
  exit 1
fi
owner_pid=""
"$helper" cleanup

# With no active journal, an unrelated fixed-name preimage is never adopted.
touch /run/netns/bpir-pub-test
if BPIR_TEST_SKIP_NOTIFY=1 "$helper" run; then
  echo "namespace owner adopted an unknown fixed-name preimage" >&2
  exit 1
fi
rm /run/netns/bpir-pub-test

echo "payment-v1 publisher netns privileged e2e: ok"
