#!/bin/sh
# Minimal udhcpc hook for the attested-builder progress API.

set -u

BB=/usr/bin/busybox

mask_to_prefix() {
    case "${1:-}" in
        255.255.255.255) printf 32 ;;
        255.255.255.254) printf 31 ;;
        255.255.255.252) printf 30 ;;
        255.255.255.248) printf 29 ;;
        255.255.255.240) printf 28 ;;
        255.255.255.224) printf 27 ;;
        255.255.255.192) printf 26 ;;
        255.255.255.128) printf 25 ;;
        255.255.255.0) printf 24 ;;
        255.255.254.0) printf 23 ;;
        255.255.252.0) printf 22 ;;
        255.255.248.0) printf 21 ;;
        255.255.240.0) printf 20 ;;
        255.255.224.0) printf 19 ;;
        255.255.192.0) printf 18 ;;
        255.255.128.0) printf 17 ;;
        255.255.0.0) printf 16 ;;
        *) printf 24 ;;
    esac
}

case "${1:-}" in
    bound|renew)
        [ -n "${interface:-}" ] || exit 0
        prefix=$(mask_to_prefix "${subnet:-255.255.255.0}")
        "$BB" ip link set "$interface" up 2>/dev/null || true
        "$BB" ip addr flush dev "$interface" 2>/dev/null || true
        "$BB" ip addr add "${ip}/${prefix}" dev "$interface" 2>/dev/null || true

        if [ -n "${router:-}" ]; then
            for r in $router; do
                "$BB" ip route add default via "$r" dev "$interface" 2>/dev/null || true
                break
            done
        fi

        if [ -n "${dns:-}" ]; then
            : > /etc/resolv.conf
            for d in $dns; do
                printf 'nameserver %s\n' "$d" >> /etc/resolv.conf
            done
        fi
        ;;
    deconfig)
        [ -n "${interface:-}" ] || exit 0
        "$BB" ip addr flush dev "$interface" 2>/dev/null || true
        ;;
esac
