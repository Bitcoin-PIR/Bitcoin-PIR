#!/bin/sh
# Print one strictly validated Cloudflare tunnel token. The input is data, not
# shell syntax; no assignment, command substitution, or additional variable is
# ever evaluated.

# shellcheck shell=sh

[ "$#" -eq 1 ] || exit 2
BB=${BPIR_BUSYBOX:-/usr/bin/busybox}

$BB awk '
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*#/ { next }
    /^TUNNEL_TOKEN=[A-Za-z0-9._~+\/=:-]+$/ {
        if (seen) { bad = 1; next }
        seen = 1
        token = substr($0, 14)
        next
    }
    { bad = 1 }
    END {
        if (!seen || bad) exit 1
        print token
    }
' "$1"
