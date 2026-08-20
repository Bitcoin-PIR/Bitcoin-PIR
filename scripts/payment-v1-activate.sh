#!/usr/bin/env bash
# One entry point for the private publisher start and production source check.
set -euo pipefail
usage() { cat <<'EOF'
usage: scripts/payment-v1-activate.sh <private|production> [options]

  private --plan ABSOLUTE_PLAN --approved-plan-sha256 HEX \
    --approved-source-sha256 HEX --approved-launcher-sha256 HEX \
    --approved-manifest-sha256 HEX --approval ABSOLUTE_APPROVAL \
    --approved-approval-sha256 HEX (--dry-run | --apply)
  production [--dry-run]

private starts the publisher network namespace through the installed,
content-addressed launcher. production runs the existing source-readiness
check; it does not install, start, fund, or enable a production service.
--dry-run validates and prints the selected work without reading files,
contacting a service, or changing state.
EOF
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
action=${1:-}; [[ "$action" != --help && "$action" != -h ]] || { usage; exit 0; }
[[ "$action" =~ ^(private|production)$ ]] || { usage >&2; exit 2; }; shift || true
dry_run=0; apply=0; plan= approval=
approved_plan_sha256= approved_source_sha256= approved_launcher_sha256=
approved_manifest_sha256= approved_approval_sha256=
while (($#)); do
  case "$1" in
    --plan) plan=${2:?missing plan}; shift 2 ;;
    --approval) approval=${2:?missing approval}; shift 2 ;;
    --approved-plan-sha256) approved_plan_sha256=${2:?missing approved plan SHA-256}; shift 2 ;;
    --approved-source-sha256) approved_source_sha256=${2:?missing approved source SHA-256}; shift 2 ;;
    --approved-launcher-sha256) approved_launcher_sha256=${2:?missing approved launcher SHA-256}; shift 2 ;;
    --approved-manifest-sha256) approved_manifest_sha256=${2:?missing approved manifest SHA-256}; shift 2 ;;
    --approved-approval-sha256) approved_approval_sha256=${2:?missing approved approval SHA-256}; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --apply) apply=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [[ "$action" == private ]]; then
  (( dry_run + apply == 1 )) || {
    echo 'private requires exactly one of --dry-run or --apply' >&2; exit 2;
  }
  [[ -n "$plan" && -n "$approval" && -n "$approved_plan_sha256" \
    && -n "$approved_source_sha256" && -n "$approved_launcher_sha256" \
    && -n "$approved_manifest_sha256" && -n "$approved_approval_sha256" ]] || {
    echo 'private requires the plan, approval, launcher, manifest, source, and approval digests shown in --help' >&2; exit 2;
  }
  [[ "$plan" == /* && "$approval" == /* ]] || {
    echo 'plan and approval paths must be absolute' >&2; exit 2;
  }
  for digest in "$approved_plan_sha256" "$approved_source_sha256" \
    "$approved_launcher_sha256" "$approved_manifest_sha256" \
    "$approved_approval_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
      echo 'approved SHA-256 values must be lowercase 64-character hex' >&2; exit 2;
    }
  done
else
  (( ! apply )) || { echo 'production accepts --dry-run, not --apply' >&2; exit 2; }
  [[ -z "$plan" && -z "$approval" && -z "$approved_plan_sha256" \
    && -z "$approved_source_sha256" && -z "$approved_launcher_sha256" \
    && -z "$approved_manifest_sha256" && -z "$approved_approval_sha256" ]] || {
    echo 'production accepts no private-start arguments' >&2; exit 2;
  }
fi
if [[ "$action" == private ]]; then
  launcher="/opt/bitcoinpir/publisher-netns-launcher/$approved_launcher_sha256/payment-v1-publisher-netns-launcher"
  cmd=(sudo "$launcher"
    --approved-launcher-sha256 "$approved_launcher_sha256"
    --approved-manifest-sha256 "$approved_manifest_sha256" -- apply
    --plan "$plan"
    --approved-plan-sha256 "$approved_plan_sha256"
    --approved-source-sha256 "$approved_source_sha256"
    --approval "$approval"
    --approved-approval-sha256 "$approved_approval_sha256")
  if ((dry_run)); then
    echo '[stage] private publisher start preview'
    printf 'COMMAND='; printf '%q ' "${cmd[@]}"; echo
    echo 'PASS private_start dry_run=true'
    echo 'NEXT_STEP=review the complete launcher command, then rerun with --apply'
    exit 0
  fi
  command -v sudo >/dev/null 2>&1 || { echo 'sudo is required for private --apply' >&2; exit 2; }
  echo '[stage] start private publisher namespace'
  "${cmd[@]}"
  echo 'PASS private_start'
  echo 'NEXT_STEP=record the committed receipt and collect fresh private runtime evidence'
  exit 0
fi
if ((dry_run)); then
  echo '[stage] production source-readiness preview'
  echo "COMMAND=$root/scripts/payment-v1-mainnet-lightning-v1-check.sh"
  echo 'PASS production_source_readiness dry_run=true'
  echo 'NEXT_STEP=run without --dry-run to execute the source-readiness check'
  exit 0
fi
echo '[stage] production source-readiness check'
"$root/scripts/payment-v1-mainnet-lightning-v1-check.sh"
echo 'PASS production_source_readiness'
echo 'NEXT_STEP=record the result, then prepare the reviewed rendered installation and activation transaction'
