#!/bin/sh

set -eu

if test "${BITCOINPIR_DISPOSABLE_SYSTEMD_TEST:-}" != 1; then
  echo "systemd-255-unit-lookup=SKIP disposable PID1 container gate is absent" >&2
  exit 77
fi

test "$(cat /proc/1/comm)" = systemd
test "$(systemctl --version | sed -n '1p')" = "systemd 255 (255.4-1ubuntu8.15)"

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

echo "systemd-255-unit-lookup=PASS recursive-dropins=$index accept-template=activated"
