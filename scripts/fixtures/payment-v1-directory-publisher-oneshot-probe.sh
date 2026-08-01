#!/bin/sh

set -eu

for name in NODE_OPTIONS HTTP_PROXY; do
  if /usr/bin/printenv "$name" >/dev/null 2>&1; then
    exit 1
  fi
done

case "${INVOCATION_ID:-}" in
  ""|00000000000000000000000000000000|*[!0-9a-f]*) exit 1 ;;
esac
test "${#INVOCATION_ID}" -eq 32

receipt_directory=/var/lib/bitcoinpir-directory-publication
receipt="$receipt_directory/$INVOCATION_ID.json"
test -d "$receipt_directory"
test ! -e "$receipt"
test ! -L "$receipt"
umask 077
(
  set -C
  printf '{"invocation_id":"%s"}\n' "$INVOCATION_ID" >"$receipt"
)
/usr/bin/chmod 0600 "$receipt"

if test -e /run/bitcoinpir-publisher-oneshot-fail-after-receipt; then
  exit 42
fi

exit 0
