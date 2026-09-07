#!/usr/bin/env bash
# Fake `curl` for scripts/pir2-sealed-recovery-receipt.test.mjs. State dir FAKE_RECOVERY_STATE:
#   status.json     body served for /status.json (rewritten by the "script" events)
#   receipt.bin     body served for /pir2-sealed-receipt.bin
#   script          newline-separated events consumed one per status GET:
#                   "status-ready" (copy status.ready.json over status.json),
#                   "receipt-ready" (copy receipt.ready.bin over receipt.bin), "noop"
#   log             appended URLs
S=$FAKE_RECOVERY_STATE
out=; dump=; url=
while (($#)); do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -D) dump=$2; shift 2 ;;
    -sS|--fail|-s) shift ;;
    --max-time) shift 2 ;;
    *) url=$1; shift ;;
  esac
done
echo "$url" >> "$S/log"
case "$url" in
  */status.json*)
    if [[ -s "$S/script" ]]; then
      ev=$(head -1 "$S/script"); tail -n +2 "$S/script" > "$S/script.tmp"; mv "$S/script.tmp" "$S/script"
      case "$ev" in
        status-ready) cp "$S/status.ready.json" "$S/status.json" ;;
        receipt-ready) cp "$S/receipt.ready.bin" "$S/receipt.bin" ;;
      esac
    fi
    body=$S/status.json ;;
  */pir2-sealed-receipt.bin*) body=$S/receipt.bin ;;
  *) exit 22 ;;
esac
[[ -f "$body" ]] || exit 22
[[ -n "$dump" ]] && printf 'HTTP/2 200\r\ncontent-length: %s\r\ncf-cache-status: MISS\r\n\r\n' "$(wc -c < "$body" | tr -d ' ')" > "$dump"
if [[ -n "$out" ]]; then cat "$body" > "$out"; else cat "$body"; fi
