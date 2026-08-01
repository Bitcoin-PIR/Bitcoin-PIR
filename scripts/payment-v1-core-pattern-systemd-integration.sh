#!/bin/sh
set -eu

cat >&2 <<'EOF'
RETIRED: the former privileged-container PID 1 test shared the Linux host
kernel and was not valid core-pattern isolation evidence. It is deliberately
disabled and must not be restored or invoked. Provision a disposable VM with
an independent kernel, pass the independent-kernel guest gate, and run a
separately reviewed canonical production matrix there.
EOF
exit 78
