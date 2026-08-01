#!/bin/sh

set -eu

failure=/run/bitcoinpir-publisher-firewall-guard-fail

if test -e "$failure"; then
  exit 42
fi

systemd-notify --ready --status="publisher firewall generation guard ready"
trap 'exit 0' TERM INT
while test ! -e "$failure"; do
  sleep 0.05
done
exit 42
