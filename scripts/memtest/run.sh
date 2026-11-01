#!/usr/bin/env bash
# Memory and speed test of PRs #466 (OnionPIR single pass) and #467 (DPF
# shared scan) against main, on real data. See README.md.
#
#   DATA=~/bpir-data/948454 bash scripts/memtest/run.sh
#
# Environment (all optional):
#   REPO   a clone of github.com/Bitcoin-PIR/Bitcoin-PIR (only read; work
#          happens in worktrees under WORK); default: the repo holding this file
#   DATA   where generation 948454 is or goes      (default ~/bpir-data/948454)
#   WORK   worktrees, builds and reports           (default ~/bpir-memtest)
#   ONLY   dpf or onion, to run one backend only
#   FETCH  1 to (re)run the resumable download even if DATA has databases.toml
#   PRS    branches merged into main for the "pr" build (default: #466 and
#          #467); empty (PRS=) builds main only
#   CLIENT_REF  branch the bench client is built from (default main)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${REPO:-$(git -C "$HERE" rev-parse --show-toplevel)}
DATA=${DATA:-$HOME/bpir-data/948454}
WORK=${WORK:-$HOME/bpir-memtest}
URL=https://data.bitcoinpir.org/948454
PRS=${PRS-codex/onionpir-chunk-single-pass codex/dpf-shared-scan}
CLIENT_REF=${CLIENT_REF:-main}

say() { printf '\n== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
free_gb() { df -Pk "$1" | awk 'NR==2 {print int($4 / 1048576)}'; }

say "checks"
for tool in git cargo cmake python3 curl; do
  command -v "$tool" >/dev/null || die "$tool not found (macOS: xcode-select --install; brew install cmake; rustup)"
done
[[ $(uname) == Darwin ]] || echo "note: written for macOS; on Linux footprint falls back to RSS"
for port in 18091 18092 18093; do
  if lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then die "port $port is in use"; fi
done
mkdir -p "$DATA" "$WORK"
if [[ ! -f $DATA/databases.toml || ${FETCH:-0} == 1 ]]; then
  need=60
  [[ $(free_gb "$DATA") -ge $need ]] || die "need about $need GB free at $DATA for the data"
fi
[[ $(free_gb "$WORK") -ge 15 ]] || die "need about 15 GB free at $WORK for two release builds"
if sudo -n /usr/sbin/purge 2>/dev/null; then
  echo "purge: ok (cold-cache runs enabled)"
else
  echo "purge: needs a password, so cold-cache runs will be skipped (README: enabling purge)"
fi

if [[ ! -f $DATA/databases.toml || ${FETCH:-0} == 1 ]]; then
  say "download generation 948454 without the Direct ORAM inputs (53 GB, resumable)"
  "$REPO/scripts/data-bundle.sh" fetch "$URL" "$DATA" oram-direct-inputs
fi

say "sources: main${PRS:+, main + $PRS}; client from $CLIENT_REF"
refs=""
for b in main $PRS $CLIENT_REF; do refs+="+refs/heads/$b:refs/remotes/origin/$b "; done
# shellcheck disable=SC2086
git -C "$REPO" fetch origin $refs
git -C "$REPO" worktree prune
worktree() {  # worktree NAME REF: a clean detached checkout of REF
  if [[ -d $WORK/src-$1 ]]; then
    git -C "$WORK/src-$1" checkout -q --detach "$2"
    git -C "$WORK/src-$1" reset -q --hard "$2"
    git -C "$WORK/src-$1" clean -qfd
  else
    git -C "$REPO" worktree add -q --detach "$WORK/src-$1" "$2"
  fi
}
worktree main origin/main
worktree client "origin/$CLIENT_REF"
BUILDS=(main)
REV_MAIN=$(git -C "$WORK/src-main" rev-parse --short HEAD)
REVS=(--rev "main=$REV_MAIN")
if [[ -n $PRS ]]; then
  worktree pr origin/main
  REV_PR=$REV_MAIN
  for b in $PRS; do
    # -X ours: PRs that only overlap in docs keep the first one's lines.
    git -C "$WORK/src-pr" -c user.name=memtest -c user.email=memtest@localhost \
      merge -q --no-edit -X ours "origin/$b"
    REV_PR+=" + $b@$(git -C "$REPO" rev-parse --short "origin/$b")"
  done
  BUILDS+=(pr)
  REVS+=(--rev "pr=$REV_PR")
fi

BUILD_ARGS=()
for wt in "${BUILDS[@]}"; do
  say "build unified_server ($wt)"
  (cd "$WORK/src-$wt" && CARGO_TARGET_DIR=$WORK/target-$wt \
    cargo build --locked --offline --release -p runtime --bin unified_server)
  BUILD_ARGS+=(--build "$wt=$WORK/target-$wt/release/unified_server")
done
say "build bench_client (from $CLIENT_REF)"
cp "$HERE/bench_client.rs" "$WORK/src-client/crates/sdk/client/examples/bench_client.rs"
(cd "$WORK/src-client" && CARGO_TARGET_DIR=$WORK/target-client \
  cargo build --locked --offline --release -p pir-sdk-client --features onion --example bench_client)

OUT=$WORK/report-$(date +%Y%m%d-%H%M%S)
say "measure (writes $OUT)"
python3 "$HERE/bench.py" \
  --config "$DATA/databases.toml" \
  --client "$WORK/target-client/release/examples/bench_client" \
  "${BUILD_ARGS[@]}" "${REVS[@]}" --rev "client=$CLIENT_REF@$(git -C "$WORK/src-client" rev-parse --short HEAD)" \
  ${ONLY:+--only "$ONLY"} \
  --out "$OUT"
say "report: $OUT/report.md"
