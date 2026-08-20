#!/usr/bin/env bash
# One offline entry point for bpir-admin Payment V1 artifact builders.
set -euo pipefail
usage() { cat <<'EOF'
usage: scripts/payment-v1-artifacts.sh <kind> [builder options] [--dry-run]

kind:
  quote-delegation | credential-binding | cashu-manifest
  clearing-authorization | clearing-approval
  bat-v2-class | bat-v2-accounting-authorization
  bat-v2-accounting-approval

This forwards the exact documented options to `bpir-admin payment-artifact`.
Required inputs depend on the selected builder; run this script's command with
--help for Clap's authoritative argument list.  --dry-run prints the command
without reading keys, configs, or output paths.  Successful execution prints
the builder output followed by PASS and NEXT_STEP.
EOF
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
kind=${1:-}; [[ -n "$kind" ]] || { usage >&2; exit 2; }; shift || true
[[ "$kind" != --help && "$kind" != -h ]] || { usage; exit 0; }
[[ "$kind" =~ ^(quote-delegation|credential-binding|cashu-manifest|clearing-authorization|clearing-approval|bat-v2-class|bat-v2-accounting-authorization|bat-v2-accounting-approval)$ ]] || { usage >&2; exit 2; }
dry_run=0; args=()
for arg in "$@"; do [[ "$arg" == --dry-run ]] && { dry_run=1; continue; }; args+=("$arg"); done
if ((${#args[@]})) && [[ "${args[0]}" == --help || "${args[0]}" == -h ]]; then
  (cd "$root" && exec cargo run --locked --offline -p bpir-admin -- payment-artifact "$kind" --help)
  exit $?
fi
cmd=(cargo run --locked --offline -p bpir-admin -- payment-artifact "$kind" "${args[@]}")
if ((dry_run)); then
  echo '[stage] artifact command preview'; printf 'COMMAND='; printf '%q ' "${cmd[@]}"; echo
  echo "PASS artifact=$kind dry_run=true"
  echo 'NEXT_STEP=run the same command without --dry-run in the offline owner environment'
  exit 0
fi
echo "[stage] build $kind artifact"
(cd "$root" && "${cmd[@]}")
echo "PASS artifact=$kind"
echo 'NEXT_STEP=record the printed digest and use the artifact in the next sealed or issuer-state step'
