#!/bin/sh
set -eu

state=/var/lib/bitcoinpir-apport-fixture
mkdir -p "$state"
case "$1" in
  --start)
    printf '%s\n' start:kernel.core_pattern start:fs.suid_dumpable start:kernel.core_pipe_limit >>"$state/calls"
    printf '%s\n' '|/usr/share/apport/apport ...' >"$state/kernel.core_pattern"
    printf '%s\n' 2 >"$state/fs.suid_dumpable"
    printf '%s\n' 10 >"$state/kernel.core_pipe_limit"
    ;;
  --stop)
    printf '%s\n' stop:kernel.core_pipe_limit stop:fs.suid_dumpable stop:kernel.core_pattern >>"$state/calls"
    printf '%s\n' 0 >"$state/kernel.core_pipe_limit"
    printf '%s\n' 0 >"$state/fs.suid_dumpable"
    printf '%s\n' core >"$state/kernel.core_pattern"
    ;;
  *)
    exit 64
    ;;
esac
