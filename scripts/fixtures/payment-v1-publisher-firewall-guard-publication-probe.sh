#!/bin/sh

set -eu

started=/run/bitcoinpir-publisher-firewall-publication-started
commit=/run/bitcoinpir-publisher-firewall-publication-committed
allow_commit=/run/bitcoinpir-publisher-firewall-publication-allow-commit

trap 'exit 43' TERM INT
: >"$started"
while test ! -e "$allow_commit"; do
  sleep 0.05
done
: >"$commit"
