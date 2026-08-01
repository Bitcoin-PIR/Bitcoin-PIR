#!/bin/sh

set -eu

if test "${BITCOINPIR_DISPOSABLE_SYSTEMD_TEST:-}" != 1; then
  echo "systemd-255-unit-lookup=SKIP disposable PID1 container gate is absent" >&2
  exit 77
fi

test "$(cat /proc/1/comm)" = systemd
test "$(systemctl --version | sed -n '1p')" = "systemd 255 (255.4-1ubuntu8.15)"

scanner_root="/run/bitcoinpir-systemd-scanner-$$"
mkdir -m 0700 "$scanner_root"

scanner_accepts() {
  SCAN_ROOT="$1" node --input-type=module -e '
    import { scanApportEnablement } from
      "/work/scripts/payment-v1-core-pattern-ceremony.mjs";
    scanApportEnablement([process.env.SCAN_ROOT]);
  '
}

trusted_generation_root="$scanner_root/trusted-generation/root"
mkdir -p "$trusted_generation_root"
SCAN_ROOT="$trusted_generation_root" node --input-type=module -e '
  import { scanManagerUnitPathGenerationForTest } from
    "/work/scripts/payment-v1-core-pattern-ceremony.mjs";
  const generation = scanManagerUnitPathGenerationForTest(
    [process.env.SCAN_ROOT], {}, true,
  );
  if (generation.ancestors[0]?.path !== "/" ||
      generation.directories[0]?.path !== process.env.SCAN_ROOT ||
      generation.ancestors.some((entry) => entry.state !== "present")) {
    throw new Error("trusted UnitPath ancestor generation was incomplete");
  }
'
chmod 0777 "$scanner_root/trusted-generation"
if SCAN_ROOT="$trusted_generation_root" node --input-type=module -e '
  import { scanManagerUnitPathGenerationForTest } from
    "/work/scripts/payment-v1-core-pattern-ceremony.mjs";
  scanManagerUnitPathGenerationForTest([process.env.SCAN_ROOT], {}, true);
' 2>/dev/null; then
  echo 'systemd-255-unit-lookup=FAIL writable UnitPath ancestor accepted' >&2
  exit 1
fi
chmod 0755 "$scanner_root/trusted-generation"

# The exact Noble vendor generation is a required benign baseline.  Any stock
# false positive must be admitted only by a source-pinned exception in the
# scanner; this whole-root check prevents fixture-only parser coverage.
scanner_accepts /usr/lib/systemd/system

assert_scanner_rejects() {
  if scanner_accepts "$1" 2>/dev/null; then
    echo "systemd-255-unit-lookup=FAIL scanner accepted $1" >&2
    exit 1
  fi
}

template=bitcoinpir-dropin-alpha-beta@.service
instance=bitcoinpir-dropin-alpha-beta@probe.service
printf '[Service]\nType=oneshot\nExecStart=/bin/true\n' > "/etc/systemd/system/$template"

expected_directories=$(
  node --input-type=module -e '
    import { systemdDropinDirectoryNamesForTest } from
      "/work/scripts/payment-v1-core-pattern-ceremony.mjs";
    process.stdout.write(Array.from(systemdDropinDirectoryNamesForTest(
      "bitcoinpir-dropin-alpha-beta@probe.service",
    )).sort().join("\n") + "\n");
  '
)
index=0
for directory in $expected_directories; do
  index=$((index + 1))
  mkdir -p "/etc/systemd/system/$directory"
  printf '[Service]\nEnvironment=BITCOINPIR_DROPIN_%s=1\n' "$index" \
    > "/etc/systemd/system/$directory/$index.conf"
done

systemctl daemon-reload
actual_directories=$(
  systemctl show --property=DropInPaths --value "$instance" |
    tr ' ' '\n' |
    while IFS= read -r path; do
      test -n "$path" && basename "$(dirname "$path")"
    done |
    sort
)
test "$actual_directories" = "$expected_directories"

continuation_scan="$scanner_root/continuation"
mkdir "$continuation_scan"
printf '%s\n' \
  '[Unit]' \
  'Wants=unrelated.service \' \
  '# a physical comment does not terminate continuation' \
  > "$continuation_scan/foreign.service"
printf '\357\273\277  systemd-coredump.socket\n' \
  >> "$continuation_scan/foreign.service"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/bin/true' >> "$continuation_scan/foreign.service"
assert_scanner_rejects "$continuation_scan"
cp "$continuation_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-continuation.service
systemctl daemon-reload
case " $(systemctl show --property=Wants --value bitcoinpir-continuation.service) " in
  *' systemd-coredump.socket '*) ;;
  *) echo 'systemd-255-unit-lookup=FAIL continuation comment changed Wants' >&2; exit 1 ;;
esac

dynamic_scan="$scanner_root/dynamic-exec"
mkdir "$dynamic_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  'ExecStart=/usr/bin/systemctl start $TARGET' \
  > "$dynamic_scan/foreign.service"
assert_scanner_rejects "$dynamic_scan"
printf '%s\n' \
  '[Unit]' \
  'Description=BitcoinPIR protected-family marker' \
  '[Service]' \
  'Type=oneshot' \
  "ExecStart=/bin/sh -c 'printf reached > /run/bitcoinpir-protected-reached'" \
  > /etc/systemd/system/apport-coredump-hook@.service
cp "$dynamic_scan/foreign.service" /etc/systemd/system/bitcoinpir-dynamic-exec.service
systemctl daemon-reload
rm -f /run/bitcoinpir-protected-reached
systemctl start bitcoinpir-dynamic-exec.service
test "$(cat /run/bitcoinpir-protected-reached)" = reached

semicolon_scan="$scanner_root/semicolon-exec"
mkdir "$semicolon_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  'ExecStart=/bin/true ; /usr/bin/systemctl start $TARGET' \
  > "$semicolon_scan/foreign.service"
assert_scanner_rejects "$semicolon_scan"
cp "$semicolon_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-semicolon-exec.service
systemctl daemon-reload
rm -f /run/bitcoinpir-protected-reached
systemctl start bitcoinpir-semicolon-exec.service
test "$(cat /run/bitcoinpir-protected-reached)" = reached

wrapper_scan="$scanner_root/wrapped-interpreter"
mkdir "$wrapper_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  "ExecStart=/usr/bin/nice /bin/sh -c 'systemctl start \$TARGET'" \
  > "$wrapper_scan/foreign.service"
assert_scanner_rejects "$wrapper_scan"
cp "$wrapper_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-wrapped-interpreter.service
systemctl daemon-reload
rm -f /run/bitcoinpir-protected-reached
systemctl start bitcoinpir-wrapped-interpreter.service
test "$(cat /run/bitcoinpir-protected-reached)" = reached

mkdir -p /usr/share/apport /usr/lib/systemd
test ! -e /usr/share/apport/apport
test ! -e /usr/lib/systemd/systemd-coredump
printf '%s\n' '#!/bin/sh' \
  'printf reached > /run/bitcoinpir-apport-handler-reached' \
  > /usr/share/apport/apport
printf '%s\n' '#!/bin/sh' \
  'printf reached > /run/bitcoinpir-systemd-coredump-reached' \
  > /usr/lib/systemd/systemd-coredump
chmod 0755 /usr/share/apport/apport /usr/lib/systemd/systemd-coredump

specifier_scan="$scanner_root/executable-specifier"
mkdir "$specifier_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/lib/systemd/systemd-core%i' \
  > "$specifier_scan/foreign@.service"
assert_scanner_rejects "$specifier_scan"
cp "$specifier_scan/foreign@.service" \
  /etc/systemd/system/bitcoinpir-executable-specifier@.service
systemctl daemon-reload
rm -f /run/bitcoinpir-systemd-coredump-reached
systemctl start bitcoinpir-executable-specifier@dump.service
test "$(cat /run/bitcoinpir-systemd-coredump-reached)" = reached

specifier_search_scan="$scanner_root/executable-specifier-search"
mkdir "$specifier_search_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecSearchPath=/usr/lib/systemd' \
  'ExecStart=systemd-core%i' \
  > "$specifier_search_scan/foreign@probe.service"
assert_scanner_rejects "$specifier_search_scan"
cp "$specifier_search_scan/foreign@probe.service" \
  /etc/systemd/system/bitcoinpir-executable-specifier-search@dump.service
systemctl daemon-reload
rm -f /run/bitcoinpir-systemd-coredump-reached
systemctl start bitcoinpir-executable-specifier-search@dump.service
test "$(cat /run/bitcoinpir-systemd-coredump-reached)" = reached

handler_path_scan="$scanner_root/child-path"
mkdir "$handler_path_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=PATH=/usr/share/apport:/usr/bin' \
  'ExecStart=/usr/bin/nice apport --start' \
  > "$handler_path_scan/nice.service"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=PATH=/usr/share/apport:/usr/bin' \
  'ExecStart=/usr/bin/env apport --start' \
  > "$handler_path_scan/env.service"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=PATH=/usr/share/apport:/usr/bin' \
  "ExecStart=/bin/sh -c 'exec apport --start'" \
  > "$handler_path_scan/shell.service"
assert_scanner_rejects "$handler_path_scan"
cp "$handler_path_scan/nice.service" \
  /etc/systemd/system/bitcoinpir-child-path-nice.service
cp "$handler_path_scan/env.service" \
  /etc/systemd/system/bitcoinpir-child-path-env.service
cp "$handler_path_scan/shell.service" \
  /etc/systemd/system/bitcoinpir-child-path-shell.service
systemctl daemon-reload
for unit in \
  bitcoinpir-child-path-nice.service \
  bitcoinpir-child-path-env.service \
  bitcoinpir-child-path-shell.service
do
  rm -f /run/bitcoinpir-apport-handler-reached
  systemctl start "$unit"
  test "$(cat /run/bitcoinpir-apport-handler-reached)" = reached
done

default_path_scan="$scanner_root/default-child-path"
mkdir "$default_path_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/bin/nice apport --start' \
  > "$default_path_scan/benign.service"
scanner_accepts "$default_path_scan"
cp "$default_path_scan/benign.service" \
  /etc/systemd/system/bitcoinpir-default-child-path.service
systemctl daemon-reload
rm -f /run/bitcoinpir-apport-handler-reached
if systemctl start bitcoinpir-default-child-path.service 2>/dev/null; then
  echo 'systemd-255-unit-lookup=FAIL default PATH found /usr/share/apport/apport' >&2
  exit 1
fi
test ! -e /run/bitcoinpir-apport-handler-reached
systemctl reset-failed bitcoinpir-default-child-path.service

first_exec_scan="$scanner_root/first-executable-path"
mkdir "$first_exec_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=PATH=/usr/share/apport:/usr/bin' \
  'ExecStart=apport --start' \
  > "$first_exec_scan/benign.service"
scanner_accepts "$first_exec_scan"
cp "$first_exec_scan/benign.service" \
  /etc/systemd/system/bitcoinpir-first-executable-path.service
systemctl daemon-reload
rm -f /run/bitcoinpir-apport-handler-reached
if systemctl start bitcoinpir-first-executable-path.service 2>/dev/null; then
  echo 'systemd-255-unit-lookup=FAIL Environment PATH selected first executable' >&2
  exit 1
fi
test ! -e /run/bitcoinpir-apport-handler-reached
systemctl reset-failed bitcoinpir-first-executable-path.service

late_environment_scan="$scanner_root/late-environment-file"
mkdir "$late_environment_scan"
rm -f /run/bitcoinpir-late-environment
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'EnvironmentFile=-/run/bitcoinpir-late-environment' \
  'ExecStart=/usr/bin/nice apport --start' \
  > "$late_environment_scan/foreign.service"
assert_scanner_rejects "$late_environment_scan"
cp "$late_environment_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-late-environment-file.service
systemctl daemon-reload
printf '%s\n' 'PATH=/usr/share/apport:/usr/bin' \
  > /run/bitcoinpir-late-environment
rm -f /run/bitcoinpir-apport-handler-reached
systemctl start bitcoinpir-late-environment-file.service
test "$(cat /run/bitcoinpir-apport-handler-reached)" = reached

mkdir -p /opt
ln /usr/bin/nice /opt/bitcoinpir-nice-hardlink
hardlink_wrapper_scan="$scanner_root/hardlink-wrapper-unknown-path"
mkdir "$hardlink_wrapper_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'EnvironmentFile=-/run/bitcoinpir-absent-wrapper-path' \
  'ExecStart=/usr/bin/env /opt/bitcoinpir-nice-hardlink apport --start' \
  > "$hardlink_wrapper_scan/foreign.service"
assert_scanner_rejects "$hardlink_wrapper_scan"

shell_escape_scan="$scanner_root/shell-escape"
mkdir "$shell_escape_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  "ExecStart=/bin/sh -c 'exec syst\\\\emctl start systemd-\\\\coredump.socket'" \
  > "$shell_escape_scan/foreign.service"
assert_scanner_rejects "$shell_escape_scan"
cp "$shell_escape_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-shell-escape.service
printf '%s\n' \
  '[Socket]' \
  'ListenStream=/run/bitcoinpir-systemd-coredump.sock' \
  'Accept=yes' \
  > /etc/systemd/system/systemd-coredump.socket
printf '%s\n' \
  '[Service]' \
  'StandardInput=socket' \
  'ExecStart=/bin/true' \
  > /etc/systemd/system/systemd-coredump@.service
systemctl daemon-reload
rm -f /run/bitcoinpir-systemd-coredump.sock
if ! systemctl start bitcoinpir-shell-escape.service; then
  systemctl status --no-pager bitcoinpir-shell-escape.service >&2 || true
  sed -n '1,20p' /etc/systemd/system/bitcoinpir-shell-escape.service >&2
  exit 1
fi
test "$(systemctl show --property=ActiveState --value systemd-coredump.socket)" = active
systemctl stop systemd-coredump.socket

ln -s /usr/share/apport/apport /usr/local/bin/bitcoinpir-apport-symlink
ln /usr/share/apport/apport /usr/local/bin/bitcoinpir-apport-hardlink
handler_alias_scan="$scanner_root/handler-aliases"
mkdir "$handler_alias_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/local/bin/bitcoinpir-apport-symlink --start' \
  > "$handler_alias_scan/symlink.service"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/bin/nice /usr/local/bin/bitcoinpir-apport-hardlink --start' \
  > "$handler_alias_scan/hardlink.service"
assert_scanner_rejects "$handler_alias_scan"
cp "$handler_alias_scan/symlink.service" \
  /etc/systemd/system/bitcoinpir-handler-symlink.service
cp "$handler_alias_scan/hardlink.service" \
  /etc/systemd/system/bitcoinpir-handler-hardlink.service
systemctl daemon-reload
for unit in bitcoinpir-handler-symlink.service bitcoinpir-handler-hardlink.service
do
  rm -f /run/bitcoinpir-apport-handler-reached
  systemctl start "$unit"
  test "$(cat /run/bitcoinpir-apport-handler-reached)" = reached
done

bind_manager_scan="$scanner_root/bind-manager"
mkdir "$bind_manager_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  'BindReadOnlyPaths=/usr/bin/systemctl:/opt/manager' \
  'ExecStart=/opt/manager start $TARGET' \
  > "$bind_manager_scan/foreign.service"
assert_scanner_rejects "$bind_manager_scan"
cp "$bind_manager_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-bind-manager.service
systemctl daemon-reload
rm -f /run/bitcoinpir-protected-reached
systemctl start bitcoinpir-bind-manager.service
test "$(cat /run/bitcoinpir-protected-reached)" = reached

optional_bind_scan="$scanner_root/optional-bind-manager"
mkdir "$optional_bind_scan"
rm -f /usr/local/bin/bitcoinpir-late-manager
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  'BindReadOnlyPaths=-/usr/local/bin/bitcoinpir-late-manager:/opt/manager-late' \
  'ExecStart=/opt/manager-late start $TARGET' \
  > "$optional_bind_scan/foreign.service"
assert_scanner_rejects "$optional_bind_scan"
cp "$optional_bind_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-optional-bind-manager.service
systemctl daemon-reload
cp /usr/bin/systemctl /usr/local/bin/bitcoinpir-late-manager
rm -f /run/bitcoinpir-protected-reached
if ! systemctl start bitcoinpir-optional-bind-manager.service; then
  systemctl status --no-pager bitcoinpir-optional-bind-manager.service >&2 || true
  journalctl --no-pager -u bitcoinpir-optional-bind-manager.service >&2 || true
  exit 1
fi
test "$(cat /run/bitcoinpir-protected-reached)" = reached

pass_environment_scan="$scanner_root/pass-environment-path"
mkdir "$pass_environment_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'PassEnvironment=PATH' \
  'ExecStart=/usr/bin/nice apport --start' \
  > "$pass_environment_scan/foreign.service"
assert_scanner_rejects "$pass_environment_scan"
cp "$pass_environment_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-pass-environment-path.service
systemctl daemon-reload
test "$(systemctl show --property=PassEnvironment --value \
  bitcoinpir-pass-environment-path.service)" = PATH

exec_search_path_scan="$scanner_root/exec-search-child-path"
mkdir "$exec_search_path_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecSearchPath=/usr/share/apport:/usr/bin' \
  'ExecStart=nice apport --start' \
  > "$exec_search_path_scan/foreign.service"
assert_scanner_rejects "$exec_search_path_scan"
cp "$exec_search_path_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-exec-search-child-path.service
systemctl daemon-reload
rm -f /run/bitcoinpir-apport-handler-reached
systemctl start bitcoinpir-exec-search-child-path.service
test "$(cat /run/bitcoinpir-apport-handler-reached)" = reached

effective_scan="$scanner_root/effective-fragment-dropin"
mkdir -p "$effective_scan/foreign.service.d"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/usr/bin/nice apport --start' \
  > "$effective_scan/foreign.service"
printf '%s\n' \
  '[Service]' \
  'Environment=PATH=/usr/share/apport:/usr/bin' \
  > "$effective_scan/foreign.service.d/10-path.conf"
assert_scanner_rejects "$effective_scan"
cp "$effective_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-effective-fragment-dropin.service
mkdir -p /etc/systemd/system/bitcoinpir-effective-fragment-dropin.service.d
cp "$effective_scan/foreign.service.d/10-path.conf" \
  /etc/systemd/system/bitcoinpir-effective-fragment-dropin.service.d/10-path.conf
systemctl daemon-reload
rm -f /run/bitcoinpir-apport-handler-reached
systemctl start bitcoinpir-effective-fragment-dropin.service
test "$(cat /run/bitcoinpir-apport-handler-reached)" = reached

hardlink_scan="$scanner_root/hardlink-manager"
mkdir "$hardlink_scan"
ln /usr/bin/systemctl /usr/local/bin/bitcoinpir-systemctl-hardlink
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=TARGET=apport-coredump-hook@probe.service' \
  'ExecStart=/usr/local/bin/bitcoinpir-systemctl-hardlink start $TARGET' \
  > "$hardlink_scan/foreign.service"
assert_scanner_rejects "$hardlink_scan"
cp "$hardlink_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-hardlink-manager.service
systemctl daemon-reload
rm -f /run/bitcoinpir-protected-reached
systemctl start bitcoinpir-hardlink-manager.service
test "$(cat /run/bitcoinpir-protected-reached)" = reached

benign_scan="$scanner_root/benign-environment"
mkdir "$benign_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Environment=LABEL=systemd-coredump' \
  'ExecStart=/bin/true' > "$benign_scan/benign.service"
scanner_accepts "$benign_scan"

unsafe_generation_scan="$scanner_root/unsafe-exec-generation"
unsafe_generation_source=/run/bitcoinpir-unsafe-exec-generation
mkdir "$unsafe_generation_scan" "$unsafe_generation_source"
chmod 0777 "$unsafe_generation_source"
printf '%s\n' '#!/bin/sh' 'exit 0' \
  > "$unsafe_generation_source/manager"
chmod 0755 "$unsafe_generation_source/manager"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  "Environment=PATH=$unsafe_generation_source:/usr/bin" \
  'ExecStart=/usr/bin/nice true' \
  > "$unsafe_generation_scan/foreign.service"
assert_scanner_rejects "$unsafe_generation_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  "BindReadOnlyPaths=$unsafe_generation_source/manager:/opt/manager-unsafe" \
  'ExecStart=/bin/true' \
  > "$unsafe_generation_scan/foreign.service"
assert_scanner_rejects "$unsafe_generation_scan"

mount_scan="$scanner_root/requires-mounts-for"
mkdir "$mount_scan"
printf '%s\n' \
  '[Unit]' \
  'RequiresMountsFor=/systemd/coredump' \
  '[Service]' \
  'Type=oneshot' \
  'ExecStart=/bin/true' > "$mount_scan/foreign.service"
assert_scanner_rejects "$mount_scan"
mkdir -p /systemd/coredump
printf '%s\n' \
  '[Unit]' \
  'Description=BitcoinPIR protected-family mount marker' \
  '[Mount]' \
  'What=tmpfs' \
  'Where=/systemd/coredump' \
  'Type=tmpfs' > /etc/systemd/system/systemd-coredump.mount
cp "$mount_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-requires-mounts-for.service
systemctl daemon-reload
case " $(systemctl show --property=Requires --value bitcoinpir-requires-mounts-for.service) " in
  *' systemd-coredump.mount '*) ;;
  *) echo 'systemd-255-unit-lookup=FAIL RequiresMountsFor= edge absent' >&2; exit 1 ;;
esac

slice_scan="$scanner_root/slice-hierarchy"
mkdir "$slice_scan"
printf '%s\n' '[Slice]' 'CPUWeight=100' \
  > "$slice_scan/systemd-coredump-child.slice"
assert_scanner_rejects "$slice_scan"
cp "$slice_scan/systemd-coredump-child.slice" \
  /etc/systemd/system/systemd-coredump-child.slice
systemctl daemon-reload
systemctl start systemd-coredump-child.slice
case " $(systemctl show --property=Requires --value systemd-coredump-child.slice) " in
  *' systemd-coredump.slice '*) ;;
  *) echo 'systemd-255-unit-lookup=FAIL slice parent Requires edge absent' >&2; exit 1 ;;
esac
test "$(systemctl show --property=ActiveState --value systemd-coredump.slice)" = active

implicit_scan="$scanner_root/implicit-directives"
mkdir "$implicit_scan"
printf '%s\n' \
  '[Service]' \
  'Type=oneshot' \
  'Slice=systemd-coredump.slice' \
  'Sockets=systemd-coredump.socket' \
  'ExecStart=/bin/true' > "$implicit_scan/foreign.service"
assert_scanner_rejects "$implicit_scan"
cp "$implicit_scan/foreign.service" \
  /etc/systemd/system/bitcoinpir-implicit-directives.service
systemctl daemon-reload
case " $(systemctl show --property=Requires --value bitcoinpir-implicit-directives.service) " in
  *' systemd-coredump.slice '*) ;;
  *) echo 'systemd-255-unit-lookup=FAIL Slice= Requires edge absent' >&2; exit 1 ;;
esac
case " $(systemctl show --property=Wants --value bitcoinpir-implicit-directives.service) " in
  *' systemd-coredump.socket '*) ;;
  *) echo 'systemd-255-unit-lookup=FAIL Sockets= Wants edge absent' >&2; exit 1 ;;
esac

printf '%s\n' \
  '[Socket]' \
  'ListenStream=127.0.0.1:32123' \
  'Accept=yes' > /etc/systemd/system/bitcoinpir-accept.socket
printf '%s\n' \
  '[Service]' \
  'StandardInput=socket' \
  "ExecStart=/bin/sh -c 'printf \"%%s\\n\" \"%i\" > /run/bitcoinpir-accept-instance'" \
  > /etc/systemd/system/bitcoinpir-accept@.service
systemctl daemon-reload
test "$(systemctl show --property=Accept --value bitcoinpir-accept.socket)" = yes
systemctl start bitcoinpir-accept.socket
/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/32123; printf x >&3; exec 3>&-'
attempt=0
while test ! -s /run/bitcoinpir-accept-instance; do
  attempt=$((attempt + 1))
  test "$attempt" -lt 100
  sleep 0.02
done
systemctl stop bitcoinpir-accept.socket

echo "systemd-255-unit-lookup=PASS recursive-dropins=$index accept-template=activated parser-counterexamples=closed"
