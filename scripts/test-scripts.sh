#!/usr/bin/env bash
# The one place that lists the offline script suites, run as a single
# `node --test` invocation (pain point 8: chaining `node --test a | grep … &&
# node --test b` masked the first failure and starved the second). CI's
# supply-chain gate runs exactly this script; docs/TESTING.md points here.
#
#   scripts/test-scripts.sh            run the node suites
#   scripts/test-scripts.sh --list     print the suite paths
#   scripts/test-scripts.sh --with-bash  also run the bash suites (dry-run
#                                       previews of the operator scripts)
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
NODE_SUITES=(
  scripts/tier3-uki-policy-contract.test.mjs
  scripts/vpsbg-data-disk.test.mjs
  scripts/pir2-sealed-ceremony.test.mjs
  scripts/pir2-sealed-rollback-set.test.mjs
  scripts/generate-release-record.test.mjs
  scripts/pir2-sealed-recovery-receipt.test.mjs
  scripts/pir2-sealed-campaign.test.mjs
)
BASH_SUITES=(
  scripts/vpsbg-production-status.test.sh
  scripts/ops-operator-scripts.test.sh
)
with_bash=0
case "${1:-}" in
  '') ;;
  --list) printf '%s\n' "${NODE_SUITES[@]}"; exit 0 ;;
  --with-bash) with_bash=1 ;;
  -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac
cd "$root"
for suite in "${NODE_SUITES[@]}"; do [[ -f "$suite" ]] || { echo "missing suite: $suite" >&2; exit 2; }; done
node --test "${NODE_SUITES[@]}"
if ((with_bash)); then
  for suite in "${BASH_SUITES[@]}"; do echo "== $suite"; bash "$suite"; done
fi
echo "PASS script_suites node=${#NODE_SUITES[@]}$( ((with_bash)) && echo " bash=${#BASH_SUITES[@]}")"
