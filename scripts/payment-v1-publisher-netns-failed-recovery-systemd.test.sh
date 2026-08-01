#!/bin/sh

set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
pre_ready_fixture="$script_directory/fixtures/payment-v1-publisher-netns-failed-recovery.service"
post_ready_fixture="$script_directory/fixtures/payment-v1-publisher-netns-post-ready-failed-recovery.service"
schema="$script_directory/payment-v1-publisher-netns-schema.mjs"
unit_name="bitcoinpir-payment-v1-publisher-netns.service"
unit_path="/run/systemd/system/$unit_name"
installed_unit=0

run_root() {
  if test "$(id -u)" -eq 0; then
    "$@"
  else
    sudo -n "$@"
  fi
}

cleanup() {
  if test "$installed_unit" -eq 1; then
    run_root systemctl stop "$unit_name" >/dev/null 2>&1 || true
    run_root systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
    run_root unlink "$unit_path" >/dev/null 2>&1 || true
    run_root systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

for command in install node systemctl systemd-analyze; do
  command -v "$command" >/dev/null
done
test "${BITCOINPIR_DISPOSABLE_SYSTEMD_TEST:-}" = "1"
test -e /.dockerenv
test -f "$pre_ready_fixture"
test -f "$post_ready_fixture"
test -f "$schema"
run_root true
test "$(cat /proc/1/comm)" = "systemd"
test "$(systemctl is-system-running)" = "running"
test "$(systemctl --version | sed -n '1p')" = "systemd 255 (255.4-1ubuntu8.15)"

if test "$(systemctl show "$unit_name" --property=LoadState --value 2>/dev/null || true)" != "not-found"; then
  echo "publisher-netns-failed-recovery-systemd=FAIL: refusing existing $unit_name" >&2
  exit 1
fi
test ! -e "$unit_path"
test ! -L "$unit_path"

validate_failed_generation() {
  expected_case=$1
  BPIR_FAILED_SCHEMA="$schema" BPIR_FAILED_UNIT="$unit_name" \
    BPIR_FAILED_CASE="$expected_case" node --input-type=module -e '
  import { execFileSync } from "node:child_process";
  import { pathToFileURL } from "node:url";
  const { validatePublisherNetnsFailedUnitV1 } =
    await import(pathToFileURL(process.env.BPIR_FAILED_SCHEMA));
  const properties = [
    "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID",
    "ActiveEnterTimestampMonotonic", "InactiveEnterTimestampMonotonic",
    "StateChangeTimestampMonotonic", "NeedDaemonReload", "Result", "ExecMainCode",
    "ExecMainStatus",
  ];
  const output = execFileSync("systemctl", [
    "show", process.env.BPIR_FAILED_UNIT,
    ...properties.flatMap((property) => ["-p", property]),
  ], { encoding: "utf8" });
  const values = new Map(output.trimEnd().split("\n").map((line) => {
    const equals = line.indexOf("=");
    if (equals < 1) throw new Error("malformed systemctl output");
    return [line.slice(0, equals), line.slice(equals + 1)];
  }));
  if (values.size !== properties.length || properties.some((key) => !values.has(key))) {
    throw new Error("systemctl omitted a failed-unit property");
  }
  validatePublisherNetnsFailedUnitV1({
    active_enter_timestamp_monotonic: values.get("ActiveEnterTimestampMonotonic"),
    active_state: values.get("ActiveState"),
    exec_main_code: values.get("ExecMainCode"),
    exec_main_status: values.get("ExecMainStatus"),
    inactive_enter_timestamp_monotonic: values.get("InactiveEnterTimestampMonotonic"),
    invocation_id: values.get("InvocationID"),
    load_state: values.get("LoadState"),
    main_pid: values.get("MainPID"),
    name: process.env.BPIR_FAILED_UNIT,
    need_daemon_reload: values.get("NeedDaemonReload"),
    result: values.get("Result"),
    state_change_timestamp_monotonic: values.get("StateChangeTimestampMonotonic"),
    sub_state: values.get("SubState"),
  }, "real systemd failed publisher unit");
  const exactByCase = {
    "pre-ready": { active: "0", code: "2", result: "timeout", status: "15" },
    "post-ready": { active: "nonzero", code: "1", result: "exit-code", status: "42" },
  };
  const expected = exactByCase[process.env.BPIR_FAILED_CASE];
  if (!expected) throw new Error("unknown failed-generation case");
  if (
    (expected.active === "0"
      ? values.get("ActiveEnterTimestampMonotonic") !== "0"
      : values.get("ActiveEnterTimestampMonotonic") === "0") ||
    values.get("ExecMainCode") !== expected.code ||
    values.get("ExecMainStatus") !== expected.status ||
    values.get("Result") !== expected.result
  ) throw new Error(`unexpected ${process.env.BPIR_FAILED_CASE} terminal tuple`);
'
}

install_fixture() {
  selected_fixture=$1
  run_root install -o root -g root -m 0644 "$selected_fixture" "$unit_path"
  installed_unit=1
  run_root systemd-analyze verify "$unit_path"
  run_root systemctl daemon-reload
}

reset_and_assert_inactive() {
  test "$(systemctl show "$unit_name" --property=Job --value)" = ""
  run_root systemctl reset-failed "$unit_name"
  test "$(systemctl show "$unit_name" --property=LoadState --value)" = "loaded"
  test "$(systemctl show "$unit_name" --property=ActiveState --value)" = "inactive"
  test "$(systemctl show "$unit_name" --property=SubState --value)" = "dead"
  test "$(systemctl show "$unit_name" --property=MainPID --value)" = "0"
  case "$(systemctl show "$unit_name" --property=InvocationID --value)" in
    ''|00000000000000000000000000000000) ;;
    *) echo "publisher-netns-failed-recovery-systemd=FAIL: InvocationID survived reset" >&2; exit 1 ;;
  esac
  test "$(systemctl show "$unit_name" --property=Job --value)" = ""
}

install_fixture "$pre_ready_fixture"
if run_root systemctl start "$unit_name" >/dev/null 2>&1; then
  echo "publisher-netns-failed-recovery-systemd=FAIL: pre-READY notify timeout unexpectedly succeeded" >&2
  exit 1
fi
validate_failed_generation pre-ready
reset_and_assert_inactive

install_fixture "$post_ready_fixture"
run_root systemctl start "$unit_name"
attempt=0
while test "$(systemctl show "$unit_name" --property=ActiveState --value)" != "failed"; do
  attempt=$((attempt + 1))
  if test "$attempt" -ge 100; then
    echo "publisher-netns-failed-recovery-systemd=FAIL: post-READY process did not fail" >&2
    exit 1
  fi
  sleep 0.05
done
validate_failed_generation post-ready
reset_and_assert_inactive

echo "publisher-netns-failed-recovery-systemd=PASS pre-ready=validated post-ready=validated reset=inactive-dead"
