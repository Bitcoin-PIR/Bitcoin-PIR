#!/usr/bin/env bash
# Offline release builder and explicit hand-off for the measured pir2 phases.
set -euo pipefail
usage() { cat <<'EOF'
usage: scripts/pir2-sealed-ceremony.sh release [bpir-admin pir2-sealed-release options] [--dry-run]
       scripts/pir2-sealed-ceremony.sh receipt [bpir-admin pir2-sealed-receipt-verify options] [--dry-run]
       scripts/pir2-sealed-ceremony.sh phase \
         --phase observe|enroll|probe|ready --out PATH --ordinal NON_ZERO \
         --verifier-nonce-hex HEX64 [--dry-run]

`release` forwards its options exactly to `bpir-admin pir2-sealed-release`.
`receipt` forwards its options exactly to `bpir-admin pir2-sealed-receipt-verify`,
the offline acceptance of an Enroll, Probe, or Ready receipt.
`phase` writes the public, canonical-v3 startup.env consumed by the measured
UKI. --dry-run never reads a signing key, release input, or host state.
EOF
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
action=${1:-}; [[ "$action" != --help && "$action" != -h ]] || { usage; exit 0; }
[[ "$action" =~ ^(release|phase|receipt)$ ]] || { usage >&2; exit 2; }; shift || true
if [[ "$action" == phase ]]; then
  dry_run=0
  phase= out= ordinal= verifier_nonce_hex=
  require_value() {
    [[ $# -ge 2 && -n "$2" ]] || { echo "$1 requires a value" >&2; exit 2; }
  }
  while (($#)); do
    case "$1" in
      --dry-run) dry_run=1; shift ;;
      --phase) require_value "$1" "${2:-}"; phase=$2; shift 2 ;;
      --out) require_value "$1" "${2:-}"; out=$2; shift 2 ;;
      --ordinal) require_value "$1" "${2:-}"; ordinal=$2; shift 2 ;;
      --verifier-nonce-hex) require_value "$1" "${2:-}"; verifier_nonce_hex=$2; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "unknown phase option: $1" >&2; usage >&2; exit 2 ;;
    esac
  done
  [[ "$phase" =~ ^(observe|enroll|probe|ready)$ ]] || { echo 'phase requires observe, enroll, probe, or ready' >&2; exit 2; }
  [[ -n "$out" ]] || { echo 'phase requires --out PATH' >&2; exit 2; }
  [[ "$ordinal" =~ ^[0-9]+$ && "$ordinal" != 0 ]] || { echo 'ordinal must be a non-zero decimal integer' >&2; exit 2; }
  validate_hex64() {
    local value=$1 label=$2
    [[ "$value" =~ ^[0-9a-f]{64}$ && "$value" =~ [1-9a-f] ]] || {
      echo "$label must be 64 lowercase, non-zero hexadecimal characters" >&2
      exit 2
    }
  }
  validate_hex64 "$verifier_nonce_hex" 'verifier nonce'
  if ((dry_run)); then
    echo '[stage] sealed phase config preview'
    echo "planned_startup_env=$out"
    echo "PASS sealed_phase_config=$phase"
    echo 'NEXT_STEP=run without --dry-run to write this exact startup.env'
    exit 0
  fi
  [[ ! -e "$out" && ! -L "$out" ]] || { echo "startup.env target already exists: $out" >&2; exit 2; }
  out_dir=$(dirname "$out")
  out_base=$(basename "$out")
  [[ -d "$out_dir" ]] || { echo "startup.env parent directory does not exist: $out_dir" >&2; exit 2; }
  echo "[stage] write sealed $phase startup config"
  umask 077
  tmp=$(mktemp "$out_dir/.${out_base}.tmp.XXXXXX")
  cleanup_phase_tmp() { rm -f "$tmp"; }
  trap cleanup_phase_tmp EXIT HUP INT TERM
  printf '%s\n' \
    'schema=bitcoinpir-pir2-sealed-startup-v3' \
    'profile=pir2-snp-sealed-v1' \
    "phase=$phase" \
    "ordinal=$ordinal" \
    "verifier_nonce_hex=$verifier_nonce_hex" >"$tmp"
  chmod 600 "$tmp"
  ln "$tmp" "$out" || { echo "startup.env target already exists or cannot be created: $out" >&2; exit 2; }
  rm -f "$tmp"
  trap - EXIT HUP INT TERM
  echo "startup_env=$out"
  echo "PASS sealed_phase_config=$phase"
  echo 'NEXT_STEP=place this exact startup.env with scripts/vpsbg-data-disk.sh put, then boot the measured UKI'
  exit 0
fi
dry_run=0; args=()
while (($#)); do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) args+=("$1"); shift ;;
  esac
done
if [[ "$action" == receipt ]]; then
  subcommand=pir2-sealed-receipt-verify
else
  subcommand=pir2-sealed-release
fi
if ((${#args[@]})) && [[ "${args[0]}" == --help || "${args[0]}" == -h ]]; then
  (cd "$root" && exec cargo run --locked --offline -p bpir-admin -- "$subcommand" --help)
  exit $?
fi
cmd=(cargo run --locked --offline -p bpir-admin -- "$subcommand" "${args[@]}")
if [[ "$action" == receipt ]]; then
  if ((dry_run)); then
    echo '[stage] sealed receipt acceptance command preview'; printf 'COMMAND='; printf '%q ' "${cmd[@]}"; echo
    echo 'PASS sealed_receipt_verify dry_run=true'
    echo 'NEXT_STEP=run without --dry-run once the receipt, its status hash, and boot ID are downloaded'
    exit 0
  fi
  echo '[stage] accept sealed phase receipt against the operator-signed release'
  (cd "$root" && "${cmd[@]}")
  exit 0
fi
if ((dry_run)); then
  echo '[stage] sealed release command preview'; printf 'COMMAND='; printf '%q ' "${cmd[@]}"; echo
  echo 'PASS sealed_release dry_run=true'
  echo 'NEXT_STEP=run without --dry-run after the Observe receipt and exact UKI/OVMF inputs are available'
  exit 0
fi
echo '[stage] verify observation and write sealed release'
(cd "$root" && "${cmd[@]}")
echo 'PASS sealed_release'
echo 'NEXT_STEP=run phase enroll for the exact measured UKI, then probe and ready in order'
