#!/bin/sh

set -eu

if test "${BITCOINPIR_DISPOSABLE_SYSTEMD_TEST:-}" != "1"; then
  echo "publisher-firewall-guard-systemd=FAIL: requires disposable PID 1" >&2
  exit 1
fi
test -f /.dockerenv
test "$(cat /proc/1/comm)" = "systemd"
test "$(systemctl --version | sed -n '1p')" = "systemd 255 (255.4-1ubuntu8.15)"

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
guard_unit=bitcoinpir-payment-v1-publisher-firewall-guard-owner.service
publisher_unit=bitcoinpir-payment-v1-publisher-firewall-guard-publication.service
guard_unit_path="/etc/systemd/system/$guard_unit"
publisher_unit_path="/etc/systemd/system/$publisher_unit"
guard_probe=/usr/local/libexec/bitcoinpir-publisher-firewall-guard-owner-probe
publisher_probe=/usr/local/libexec/bitcoinpir-publisher-firewall-guard-publication-probe
failure=/run/bitcoinpir-publisher-firewall-guard-fail
started=/run/bitcoinpir-publisher-firewall-publication-started
commit=/run/bitcoinpir-publisher-firewall-publication-committed
allow_commit=/run/bitcoinpir-publisher-firewall-publication-allow-commit

cleanup() {
  systemctl stop "$publisher_unit" "$guard_unit" >/dev/null 2>&1 || true
  systemctl reset-failed "$publisher_unit" "$guard_unit" >/dev/null 2>&1 || true
  rm -f "$failure" "$started" "$commit" "$allow_commit"
  rm -f "$guard_unit_path" "$publisher_unit_path" "$guard_probe" "$publisher_probe"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

wait_for_value() {
  unit=$1
  property=$2
  wanted=$3
  attempt=0
  while test "$(systemctl show "$unit" "--property=$property" --value 2>/dev/null || true)" != "$wanted"; do
    attempt=$((attempt + 1))
    if test "$attempt" -ge 200; then
      echo "publisher-firewall-guard-systemd=FAIL: $unit $property did not become $wanted" >&2
      systemctl show "$unit" >&2 || true
      exit 1
    fi
    sleep 0.05
  done
}

install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0555 \
  "$script_directory/fixtures/payment-v1-publisher-firewall-guard-owner-probe.sh" \
  "$guard_probe"
install -o root -g root -m 0555 \
  "$script_directory/fixtures/payment-v1-publisher-firewall-guard-publication-probe.sh" \
  "$publisher_probe"
install -o root -g root -m 0644 \
  "$script_directory/fixtures/payment-v1-publisher-firewall-guard-owner.service" \
  "$guard_unit_path"
install -o root -g root -m 0644 \
  "$script_directory/fixtures/payment-v1-publisher-firewall-guard-publication.service" \
  "$publisher_unit_path"
systemctl daemon-reload
systemd-analyze verify "$guard_unit_path" "$publisher_unit_path"

# Pre-ready failure: Requires/After must keep publication from starting when
# the guard cannot reach READY.
: >"$failure"
if systemctl start "$publisher_unit"; then
  echo "publisher-firewall-guard-systemd=FAIL: pre-ready guard failure was accepted" >&2
  exit 1
fi
test ! -e "$started"
test ! -e "$commit"
wait_for_value "$guard_unit" ActiveState failed
# The dependency transaction never starts the publisher. systemd may garbage
# collect that never-loaded unit immediately, so only the guard has failed
# state to reset here.
systemctl reset-failed "$guard_unit"
rm -f "$failure"

# In-flight failure: BindsTo must terminate the publisher before its commit
# marker when the continuous guard fails.
systemctl start "$publisher_unit" >/run/bitcoinpir-publisher-firewall-start.log 2>&1 &
start_pid=$!
attempt=0
while test ! -e "$started"; do
  attempt=$((attempt + 1))
  if test "$attempt" -ge 200; then
    echo "publisher-firewall-guard-systemd=FAIL: publication never started" >&2
    exit 1
  fi
  sleep 0.05
done
: >"$failure"
if wait "$start_pid"; then
  echo "publisher-firewall-guard-systemd=FAIL: in-flight guard failure succeeded" >&2
  exit 1
fi
test ! -e "$commit"
wait_for_value "$guard_unit" ActiveState failed
wait_for_value "$publisher_unit" ActiveState failed
systemctl reset-failed "$publisher_unit" "$guard_unit"
rm -f "$failure" "$started"

# Post-success failure: a RemainAfterExit publisher is deauthorized when the
# lifetime-superset guard later fails. The immutable receipt/commit remains for
# explicit reconciliation; it is never silently deleted.
: >"$allow_commit"
systemctl start "$publisher_unit"
test -e "$started"
test -e "$commit"
wait_for_value "$publisher_unit" ActiveState active
: >"$failure"
wait_for_value "$guard_unit" ActiveState failed
wait_for_value "$publisher_unit" ActiveState inactive
test -e "$commit"

echo "publisher-firewall-guard-systemd=PASS pre=blocked in-flight=failed post=deauthorized"
