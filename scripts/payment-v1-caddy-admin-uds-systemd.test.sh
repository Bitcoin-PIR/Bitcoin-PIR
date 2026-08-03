#!/bin/sh

set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
unit_fixture="$script_directory/fixtures/payment-v1-caddy-admin-uds-hardened.service"
config_fixture="$script_directory/fixtures/payment-v1-caddy-admin-uds-process.Caddyfile"
unit_name="bhtm-caddy.service"
unit_path="/run/systemd/system/$unit_name"
config_directory="/etc/caddy"
config_path="$config_directory/Caddyfile"
runtime_directory="/run/bitcoinpir-caddy-admin"
admin_socket="$runtime_directory/admin.sock"
journal_sentinel="bitcoinpir-journal-probe-$$"
created_config_directory=0
installed_config=0
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
    run_root unlink "$unit_path" >/dev/null 2>&1 || true
    run_root systemctl daemon-reload >/dev/null 2>&1 || true
    run_root systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
  fi
  if test "$installed_config" -eq 1; then
    run_root unlink "$config_path" >/dev/null 2>&1 || true
  fi
  if test "$created_config_directory" -eq 1; then
    run_root rmdir "$config_directory" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

for command in awk cmp curl grep install journalctl node sha256sum stat systemctl systemd-analyze; do
  command -v "$command" >/dev/null
done
test -f "$unit_fixture"
test -f "$config_fixture"
test -x /usr/local/bin/caddy
run_root true
test "$(cat /proc/1/comm)" = "systemd"
test "$(systemctl is-system-running)" = "running"

case "$(uname -m)" in
  x86_64)
    expected_caddy_sha256="b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9"
    ;;
  aarch64|arm64)
    expected_caddy_sha256="e1f904038fc11ca897ac5a12fdacfb2a7add02a8720c426d562a37f6fdad2afe"
    ;;
  *)
    echo "caddy-admin-uds-systemd=FAIL: unsupported architecture" >&2
    exit 1
    ;;
esac
test "$(sha256sum /usr/local/bin/caddy | awk '{print $1}')" = "$expected_caddy_sha256"
test "$(/usr/local/bin/caddy version | awk '{print $1}')" = "v2.11.4"
test "$(run_root stat -c '%u:%g:%a:%F' /usr/local/bin/caddy)" = "0:0:555:regular file"

if test "$(systemctl show "$unit_name" --property=LoadState --value 2>/dev/null || true)" != "not-found"; then
  echo "caddy-admin-uds-systemd=FAIL: refusing to replace an existing $unit_name" >&2
  exit 1
fi
for path in "$unit_path" "$config_path" "$runtime_directory"; do
  if test -e "$path" || test -L "$path"; then
    echo "caddy-admin-uds-systemd=FAIL: refusing to replace existing path $path" >&2
    exit 1
  fi
done
if test -e "$config_directory" || test -L "$config_directory"; then
  echo "caddy-admin-uds-systemd=FAIL: isolated test requires absent $config_directory" >&2
  exit 1
fi

run_root install -d -o root -g root -m 0755 "$config_directory"
created_config_directory=1
run_root install -o root -g root -m 0644 "$config_fixture" "$config_path"
installed_config=1
run_root install -o root -g root -m 0644 "$unit_fixture" "$unit_path"
installed_unit=1
run_root cmp "$config_fixture" "$config_path"
run_root cmp "$unit_fixture" "$unit_path"
run_root systemd-analyze verify "$unit_path"
run_root systemctl daemon-reload

wait_live() {
  attempt=0
  while ! systemctl is-active --quiet "$unit_name" || ! run_root test -S "$admin_socket"; do
    attempt=$((attempt + 1))
    if test "$attempt" -ge 100; then
      run_root systemctl status "$unit_name" --no-pager >&2 || true
      run_root journalctl -u "$unit_name" --no-pager -n 100 >&2 || true
      echo "caddy-admin-uds-systemd=FAIL: service did not become live" >&2
      exit 1
    fi
    sleep 0.1
  done
}

verify_live() {
  test "$(run_root stat -c '%u:%g:%a:%F' "$runtime_directory")" = "0:0:700:directory"
  test "$(run_root stat -c '%u:%g:%a:%F' "$admin_socket")" = "0:0:200:socket"
  test "$(systemctl show "$unit_name" --property=LimitCORE --value)" = "0"
  test "$(systemctl show "$unit_name" --property=MemorySwapMax --value)" = "0"
  test "$(systemctl show "$unit_name" --property=StandardOutput --value)" = "null"
  test "$(systemctl show "$unit_name" --property=StandardError --value)" = "null"
  main_pid=$(systemctl show "$unit_name" --property=MainPID --value)
  case "$main_pid" in
    ''|*[!0-9]*|0) exit 1 ;;
  esac
  test "$(run_root sh -c "tr '\000' ' ' </proc/$main_pid/cmdline")" = \
    "/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile "
  if run_root sh -c "tr '\000' '\n' </proc/$main_pid/environ | grep -q '^CADDY_ADMIN='"; then
    echo "caddy-admin-uds-systemd=FAIL: CADDY_ADMIN reached the service environment" >&2
    exit 1
  fi
  test "$(curl --fail --silent --show-error --max-time 3 http://127.0.0.1:18080/)" = \
    "bitcoinpir-caddy-admin-uds-ok"
  test "$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 \
    "http://127.0.0.1:18080/$journal_sentinel")" = "502"
  if run_root journalctl -u "$unit_name" --no-pager --output=cat | grep -F "$journal_sentinel"; then
    echo "caddy-admin-uds-systemd=FAIL: request metadata reached journald" >&2
    exit 1
  fi
  test "$(run_root curl --fail --silent --show-error --max-time 3 \
    --unix-socket "$admin_socket" http://localhost/config/ \
    | node -e 'const chunks=[]; process.stdin.on("data", chunk => chunks.push(chunk)); process.stdin.on("end", () => { const value=JSON.parse(Buffer.concat(chunks)); process.stdout.write(value?.admin?.listen ?? ""); });')" = \
    "unix//run/bitcoinpir-caddy-admin/admin.sock|0200"
  test "$(awk '$2 ~ /:07E3$/ && $4 == "0A" {count++} END {print count+0}' /proc/net/tcp /proc/net/tcp6)" = "0"
}

run_root systemctl start "$unit_name"
wait_live
verify_live
first_invocation=$(systemctl show "$unit_name" --property=InvocationID --value)
first_pid=$(systemctl show "$unit_name" --property=MainPID --value)
BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
  node --input-type=module -e '
    import { pathToFileURL } from "node:url";
    const { validateSystemdInvocationId } = await import(pathToFileURL(process.env.BPIR_GATE));
    validateSystemdInvocationId(process.argv[1], "real systemd InvocationID");
  ' "$first_invocation"
run_root systemctl reload "$unit_name"
test "$(systemctl show "$unit_name" --property=MainPID --value)" = "$first_pid"
verify_live

run_root systemctl stop "$unit_name"
test "$(systemctl is-active "$unit_name" 2>/dev/null || true)" = "inactive"
stopped_invocation=$(systemctl show "$unit_name" --property=InvocationID --value)
BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
  node --input-type=module -e '
    import { pathToFileURL } from "node:url";
    const { normalizeSystemdInvocationId } = await import(pathToFileURL(process.env.BPIR_GATE));
    if (normalizeSystemdInvocationId(process.argv[1], { active: false }) !== "") process.exit(1);
  ' "$stopped_invocation"
test ! -e "$runtime_directory"
test ! -L "$runtime_directory"

run_root systemctl start "$unit_name"
wait_live
verify_live
second_invocation=$(systemctl show "$unit_name" --property=InvocationID --value)
BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
  node --input-type=module -e '
    import { pathToFileURL } from "node:url";
    const { validateSystemdInvocationId } = await import(pathToFileURL(process.env.BPIR_GATE));
    validateSystemdInvocationId(process.argv[1], "real systemd InvocationID");
  ' "$second_invocation"
test "$second_invocation" != "$first_invocation"
run_root systemctl stop "$unit_name"
test "$(systemctl is-active "$unit_name" 2>/dev/null || true)" = "inactive"
test ! -e "$runtime_directory"
test ! -L "$runtime_directory"

echo "caddy-admin-uds-systemd=PASS generations=2 runtime-directory=remove-and-recreate reload=uds"
