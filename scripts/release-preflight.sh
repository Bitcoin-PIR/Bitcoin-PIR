#!/usr/bin/env bash
# Read-only release preflight (docs/RELEASE.md). Reports; never blocks.
set -uo pipefail

usage() {
  cat <<'EOF'
usage: scripts/release-preflight.sh [--live] [COMMIT]

Reports, one line each, for COMMIT (default origin/main):
  main        on GitHub's main, and how far behind its tip
  web-build   its web-build.yml run (path-filtered: else the newest on an ancestor)
  rust-ci     its rust-ci.yml run (likewise)
  transition  pins in its web/src/attest-pin.ts with a transitionBinarySha256Hex
  pages       the commit GitHub Pages serves; web/wasm files that differ
  playground  the commit $PLAYGROUND_REPO (Bitcoin-PIR/playground) vendors, per
              its vendor/SOURCE_COMMIT.txt; vendored files that differ
  live        --live runs scripts/production-status.sh on this checkout's pins
              (BPIR_ADMIN=/path/to/bpir-admin skips its cargo build)

Needs git and an authenticated gh. Changes nothing; exits 0 unless invoked
wrongly (2).
EOF
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$root" || exit 2

live=0
ref=
while (($#)); do
  case "$1" in
    --live) live=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) [[ -z "$ref" ]] || { usage >&2; exit 2; }; ref=$1; shift ;;
  esac
done
ref=${ref:-origin/main}
sha=$(git rev-parse --verify --quiet "$ref^{commit}") ||
  { echo "not a commit in this clone: $ref (git fetch origin?)" >&2; exit 2; }
short=${sha:0:12}
repo=$(git remote get-url origin 2>/dev/null |
  sed -E 's#^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)##; s#\.git$##')
playground=${PLAYGROUND_REPO:-Bitcoin-PIR/playground}
# What the wasm package is built from (web-build.yml's path filter, minus web/).
wasm_inputs=(crates vendor .cargo Cargo.toml Cargo.lock rust-toolchain.toml)

say() { printf '%-11s %s\n' "$1:" "$2"; }
# The useful part of a failed gh call: its last line, minus "gh: ".
why() { local line; line=$(tail -n 1 <<<"$1"); printf '%s' "${line##*gh: }"; }
# How many files under the given paths differ between commit $1 and $sha.
changed() {
  local base=$1; shift
  if git cat-file -e "$base^{commit}" 2>/dev/null; then
    git diff --name-only "$base" "$sha" -- "$@" | wc -l | tr -d ' '
  else
    printf '? (%s is not in this clone)' "${base:0:12}"
  fi
}
# A workflow's run for $sha; without one (path filters), the newest main push
# run on an ancestor, which is the run that covers $sha.
ci() {
  local fmt runs result head url
  fmt='.[] | "\(if .status == "completed" then .conclusion else .status end) \(.headSha) \(.url)"'
  runs=$(gh run list -R "$repo" -w "$1" -c "$sha" -L 1 --json status,conclusion,headSha,url --jq "$fmt" 2>&1) ||
    { echo "unavailable ($(why "$runs"))"; return; }
  if [[ -n "$runs" ]]; then read -r result head url <<<"$runs"; echo "$result $url"; return; fi
  runs=$(gh run list -R "$repo" -w "$1" -b main -e push -L 20 --json status,conclusion,headSha,url --jq "$fmt" 2>&1) ||
    { echo "no run for $short; unavailable ($(why "$runs"))"; return; }
  while read -r result head url; do
    git merge-base --is-ancestor "$head" "$sha" 2>/dev/null || continue
    echo "no run for $short (path-filtered); newest on an ancestor: $result at ${head:0:12} $url"
    return
  done <<<"$runs"
  echo "no run for $short or an ancestor among the last 20 main push runs"
}

echo "release preflight for $short ($ref)"

# (a) On main?
if cmp=$(gh api "repos/$repo/compare/main...$sha" --jq '"\(.status) \(.ahead_by) \(.behind_by)"' 2>&1); then
  read -r status ahead behind <<<"$cmp"
  case "$status" in
    identical) say main "on main, the tip" ;;
    behind) say main "on main, $behind commit(s) behind the tip" ;;
    *) say main "NOT on main ($status: $ahead ahead, $behind behind)" ;;
  esac
else
  say main "unavailable ($(why "$cmp"))"
fi

# (b) CI.
say web-build "$(ci web-build.yml)"
say rust-ci "$(ci rust-ci.yml)"

# (c) A leftover transition: a hex literal for transitionBinarySha256Hex on
# its line or the next, reported by the pin it belongs to.
if pins=$(git show "$sha:web/src/attest-pin.ts" 2>/dev/null); then
  open=$(awk '
    /^export const / { name = $3; sub(/[^A-Za-z0-9_].*/, "", name) }
    /transitionBinarySha256Hex:/ { left = /transitionBinarySha256Hex:[ \t]*$/ ? 2 : 1 }
    left && /\047[0-9a-fA-F]+\047/ { print name; left = 0 }
    left { left-- }' <<<"$pins" | tr '\n' ' ')
  if [[ -n "$open" ]]; then
    say transition "open in ${open% } (drop it once that host runs the new build)"
  else
    say transition "none in web/src/attest-pin.ts"
  fi
else
  say transition "web/src/attest-pin.ts not found at $short"
fi

# What GitHub Pages serves: the latest github-pages deployment.
if ! dep=$(gh api "repos/$repo/deployments?environment=github-pages&per_page=1" \
  --jq '.[0] // empty | "\(.id) \(.sha) \(.created_at)"' 2>&1); then
  say pages "unavailable ($(why "$dep"))"
elif [[ -z "$dep" ]]; then
  say pages "no github-pages deployment found"
else
  read -r dep_id dep_sha dep_at <<<"$dep"
  state=$(gh api "repos/$repo/deployments/$dep_id/statuses?per_page=1" --jq '.[0].state // "no status"' 2>/dev/null) ||
    state=unknown
  if [[ "$dep_sha" == "$sha" ]]; then
    say pages "serves $short ($state, $dep_at)"
  else
    say pages "serves ${dep_sha:0:12} ($state, $dep_at); $(changed "$dep_sha" web "${wasm_inputs[@]}") web/wasm input file(s) differ"
  fi
fi

# (e) The playground's vendored copy (its sync-vendor writes SOURCE_COMMIT.txt).
if ! src=$(gh api -H 'Accept: application/vnd.github.raw' "repos/$playground/contents/vendor/SOURCE_COMMIT.txt" 2>&1); then
  say playground "no vendor/SOURCE_COMMIT.txt in $playground ($(why "$src"))"
else
  vendored=$(sed -nE 's/^BitcoinPIR @ ([0-9a-f]{40}).*/\1/p' <<<"$src")
  dirty=
  [[ "$src" != *"(dirty)"* ]] || dirty=" (dirty)"
  if [[ -z "$vendored" ]]; then
    say playground "records no commit (vendor/SOURCE_COMMIT.txt: $(head -n 1 <<<"$src"))"
  elif [[ "$vendored" == "$sha" ]]; then
    say playground "vendors $short$dirty"
  else
    say playground "vendors ${vendored:0:12}$dirty; $(changed "$vendored" ':(glob)web/src/*.ts' "${wasm_inputs[@]}") vendored input file(s) differ"
  fi
fi

# (d) The live hosts.
if ((live)); then
  out=$("$root/scripts/production-status.sh" 2>&1)
  rc=$?
  while IFS= read -r line; do printf '  | %s\n' "$line"; done <<<"$out"
  note=
  git diff --quiet "$sha" -- web/src/attest-pin.ts web/src/production-providers.ts 2>/dev/null ||
    note="; they differ from $short's"
  say live "production-status.sh exit $rc (pins from this checkout$note)"
else
  say live "not queried; pass --live, or run scripts/production-status.sh"
fi
exit 0
