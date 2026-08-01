#!/bin/sh

set -eu

if test "${BITCOINPIR_DISPOSABLE_SYSTEMD_TEST:-}" != "1"; then
  echo "publisher-oneshot-systemd=FAIL: requires an explicitly disposable systemd container" >&2
  exit 1
fi
test -f /.dockerenv
test "$(cat /proc/1/comm)" = "systemd"
test "$(systemctl --version | sed -n '1p')" = "systemd 255 (255.4-1ubuntu8.15)"

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
unit_fixture="$script_directory/fixtures/payment-v1-directory-publisher-oneshot-runtime.service"
probe_fixture="$script_directory/fixtures/payment-v1-directory-publisher-oneshot-probe.sh"
unit_name="bitcoinpir-payment-v1-directory-publisher.service"
unit_path="/etc/systemd/system/$unit_name"
probe_path="/usr/local/libexec/bitcoinpir-directory-publisher-oneshot-probe"
sentinel="/run/bitcoinpir-publisher-oneshot-runtime-approved"
failure_sentinel="/run/bitcoinpir-publisher-oneshot-fail-after-receipt"
receipt_directory="/var/lib/bitcoinpir-directory-publication"
service_user="bitcoinpir-directory-publisher"
service_id="52903"

cleanup() {
  systemctl stop "$unit_name" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
  systemctl unset-environment NODE_OPTIONS HTTP_PROXY >/dev/null 2>&1 || true
  unlink "$failure_sentinel" >/dev/null 2>&1 || true
  unlink "$sentinel" >/dev/null 2>&1 || true
  unlink "$unit_path" >/dev/null 2>&1 || true
  unlink "$probe_path" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f "$receipt_directory"/*.json >/dev/null 2>&1 || true
  rmdir "$receipt_directory" >/dev/null 2>&1 || true
  userdel "$service_user" >/dev/null 2>&1 || true
  groupdel "$service_user" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

test -f "$unit_fixture"
test -f "$probe_fixture"
test "$(systemctl show "$unit_name" --property=LoadState --value 2>/dev/null || true)" = "not-found"
test ! -e "$unit_path"
test ! -L "$unit_path"
test ! -e "$probe_path"
test ! -L "$probe_path"
test ! -e "$sentinel"
test ! -L "$sentinel"
test ! -e "$failure_sentinel"
test ! -L "$failure_sentinel"
if getent passwd "$service_user" >/dev/null || getent group "$service_user" >/dev/null; then
  echo "publisher-oneshot-systemd=FAIL: disposable identity already exists" >&2
  exit 1
fi

groupadd --gid "$service_id" "$service_user"
useradd \
  --uid "$service_id" \
  --gid "$service_id" \
  --no-create-home \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  "$service_user"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0555 "$probe_fixture" "$probe_path"
install -o root -g root -m 0644 "$unit_fixture" "$unit_path"
touch "$sentinel"
systemctl set-environment \
  NODE_OPTIONS=bitcoinpir-publisher-oneshot-runtime-probe \
  HTTP_PROXY=http://127.0.0.1:1
systemctl daemon-reload
systemd-analyze verify "$unit_path"

# Invocation A models the ambiguity window where the exact relay accepts every
# EVENT and the local immutable receipt is committed, but the process dies
# before systemd can retain a successful oneshot state.
touch "$failure_sentinel"
if systemctl start "$unit_name"; then
  echo "publisher-oneshot-systemd=FAIL: invocation A unexpectedly succeeded" >&2
  exit 1
fi

show() {
  systemctl show "$unit_name" "--property=$1" --value
}

test "$(show ActiveState)" = "failed"
test "$(show SubState)" = "failed"
test "$(show Result)" = "exit-code"
test "$(show ExecMainCode)" = "1"
test "$(show ExecMainStatus)" = "42"
test "$(show MainPID)" = "0"
invocation_a=$(show InvocationID)
case "$invocation_a" in
  ""|00000000000000000000000000000000|*[!0-9a-f]*) exit 1 ;;
esac
test "${#invocation_a}" -eq 32
receipt_a="$receipt_directory/$invocation_a.json"
test -f "$receipt_a"
test ! -L "$receipt_a"
test "$(stat -c '%u:%g:%a:%h' "$receipt_a")" = "$service_id:$service_id:600:1"
test "$(cat "$receipt_a")" = "{\"invocation_id\":\"$invocation_a\"}"

# A distinct invocation B replays the same frozen EVENT set. The relay's
# reviewed exact-duplicate OK true behavior lets B converge without adopting,
# replacing or deleting A's local receipt.
unlink "$failure_sentinel"
systemctl reset-failed "$unit_name"
systemctl start "$unit_name"

test "$(show LoadState)" = "loaded"
test "$(show ActiveState)" = "active"
test "$(show SubState)" = "exited"
test "$(show Type)" = "oneshot"
test "$(show RemainAfterExit)" = "yes"
test "$(show MainPID)" = "0"
test "$(show Result)" = "success"
test "$(show ExecMainCode)" = "1"
test "$(show ExecMainStatus)" = "0"
test "$(show NeedDaemonReload)" = "no"
test "$(show ConditionResult)" = "yes"
test "$(show FragmentPath)" = "$unit_path"
test "$(show ControlGroup)" = ""

active_enter=$(show ActiveEnterTimestampMonotonic)
case "$active_enter" in
  ''|0|*[!0-9]*) exit 1 ;;
esac
invocation_id=$(show InvocationID)
case "$invocation_id" in
  ""|00000000000000000000000000000000|*[!0-9a-f]*) exit 1 ;;
esac
test "${#invocation_id}" -eq 32
test "$invocation_id" != "$invocation_a"
receipt_b="$receipt_directory/$invocation_id.json"
test -f "$receipt_b"
test ! -L "$receipt_b"
test "$(stat -c '%u:%g:%a:%h' "$receipt_b")" = "$service_id:$service_id:600:1"
test "$(cat "$receipt_b")" = "{\"invocation_id\":\"$invocation_id\"}"
test "$(find "$receipt_directory" -mindepth 1 -maxdepth 1 -type f -name '*.json' | wc -l)" -eq 2
test "$(stat -c '%u:%g:%a' "$receipt_directory")" = "$service_id:$service_id:700"

exec_start=$(show ExecStart)
case "$exec_start" in
  *"path=$probe_path"*"argv[]=$probe_path"*"start_time=[n/a]"*) exit 1 ;;
esac
case "$exec_start" in
  *"stop_time=[n/a]"*|*"pid=0"*|*"code=exited"*"status=0"*)
    case "$exec_start" in
      *"stop_time=[n/a]"*|*"pid=0"*) exit 1 ;;
      *"code=exited"*"status=0"*) ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac

expected_unset="ALL_PROXY BASH_ENV ENV GLIBC_TUNABLES HTTPS_PROXY HTTP_PROXY LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_PATH NO_PROXY all_proxy http_proxy https_proxy no_proxy"
actual_unset=$(show UnsetEnvironment | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')
test "$actual_unset" = "$expected_unset"

credential_holders=0
for status in /proc/[0-9]*/task/[0-9]*/status; do
  if awk -v id="$service_id" '
    /^Uid:|^Gid:|^Groups:/ {
      for (field = 2; field <= NF; field += 1) {
        if ($field == id) found = 1
      }
    }
    END { exit found ? 0 : 1 }
  ' "$status"; then
    credential_holders=$((credential_holders + 1))
  else
    awk_status=$?
    test "$awk_status" -eq 1 || exit 1
  fi
done
test "$credential_holders" -eq 0

echo "publisher-oneshot-systemd=PASS failed_invocation=$invocation_a current_invocation=$invocation_id receipts=2 holders=0"
