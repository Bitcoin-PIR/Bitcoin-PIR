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
