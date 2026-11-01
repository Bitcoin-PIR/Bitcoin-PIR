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
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${REPO:-$(git -C "$HERE" rev-parse --show-toplevel)}
DATA=${DATA:-$HOME/bpir-data/948454}
WORK=${WORK:-$HOME/bpir-memtest}
URL=https://data.bitcoinpir.org/948454
PR466=codex/onionpir-chunk-single-pass
PR467=codex/dpf-shared-scan

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

say "sources: main, and main + #466 + #467"
git -C "$REPO" fetch origin $(for b in main "$PR466" "$PR467"; do printf "+refs/heads/%s:refs/remotes/origin/%s " "$b" "$b"; done)
git -C "$REPO" worktree prune
for wt in main pr; do
  if [[ -d $WORK/src-$wt ]]; then
    git -C "$WORK/src-$wt" checkout -q --detach origin/main
    git -C "$WORK/src-$wt" reset -q --hard origin/main
    git -C "$WORK/src-$wt" clean -qfd
  else
    git -C "$REPO" worktree add -q --detach "$WORK/src-$wt" origin/main
  fi
done
# The two PRs only overlap in one table of docs/OPERATOR_GUIDE.md; -X ours
# keeps #466's line there. Code is unaffected.
git -C "$WORK/src-pr" -c user.name=memtest -c user.email=memtest@localhost \
  merge -q --no-edit "origin/$PR466"
git -C "$WORK/src-pr" -c user.name=memtest -c user.email=memtest@localhost \
  merge -q --no-edit -X ours "origin/$PR467"
REV_MAIN=$(git -C "$WORK/src-main" rev-parse --short HEAD)
REV_PR="$REV_MAIN + $(git -C "$REPO" rev-parse --short "origin/$PR466") (#466) + $(git -C "$REPO" rev-parse --short "origin/$PR467") (#467)"

for wt in main pr; do
  say "build unified_server ($wt)"
  (cd "$WORK/src-$wt" && CARGO_TARGET_DIR=$WORK/target-$wt \
    cargo build --locked --offline --release -p runtime --bin unified_server)
done
say "build bench_client (from main; the client is the same in both)"
cp "$HERE/bench_client.rs" "$WORK/src-main/crates/sdk/client/examples/bench_client.rs"
(cd "$WORK/src-main" && CARGO_TARGET_DIR=$WORK/target-main \
  cargo build --locked --offline --release -p pir-sdk-client --features onion --example bench_client)

OUT=$WORK/report-$(date +%Y%m%d-%H%M%S)
say "measure (writes $OUT)"
python3 "$HERE/bench.py" \
  --config "$DATA/databases.toml" \
  --client "$WORK/target-main/release/examples/bench_client" \
  --build "main=$WORK/target-main/release/unified_server" \
  --build "pr=$WORK/target-pr/release/unified_server" \
  --rev "main=$REV_MAIN" --rev "pr=$REV_PR" \
  ${ONLY:+--only "$ONLY"} \
  --out "$OUT"
say "report: $OUT/report.md"
