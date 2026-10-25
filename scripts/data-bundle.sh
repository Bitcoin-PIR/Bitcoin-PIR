#!/usr/bin/env bash
# The public data bundle of a database generation: the directories the
# reference catalog (databases.toml) names, served read-only from object
# storage (Cloudflare R2 behind https://data.bitcoinpir.org) together with a
# hash list. Publishing side: docs/runbooks/data-bundle.md. Operator side:
# docs/OPERATOR_GUIDE.md section 3.
#
# Usage:
#   scripts/data-bundle.sh hash   DATA_ROOT CATALOG           > SHA256SUMS
#   scripts/data-bundle.sh upload DATA_ROOT BUNDLE_DIR REMOTE
#   scripts/data-bundle.sh verify BUNDLE_DIR URL
#   scripts/data-bundle.sh fetch  URL DEST [SKIP_REGEX]
#
# hash    prints `<sha256>  <relative path>` for every file under the
#         catalog's `path`, `proof_dir` and `proof_v2_dir` directories, paths
#         relative to DATA_ROOT, sorted. Files are read with O_DIRECT where the
#         filesystem allows it, so a serving node's page cache is left alone.
# upload  copies those directories and BUNDLE_DIR/{SHA256SUMS,databases.toml}
#         to REMOTE, an rclone path such as r2:bitcoinpir-data/948454.
#         BUNDLE_DIR is deploy/data-bundles/<generation>, whose databases.toml
#         is the catalog with relative paths. BPIR_BUNDLE_BWLIMIT (rclone
#         --bwlimit, default off) and BPIR_BUNDLE_TRANSFERS (2) apply.
# verify  streams every file of BUNDLE_DIR/SHA256SUMS from URL, the public
#         base of the generation (https://data.bitcoinpir.org/948454), through
#         sha256 and compares; SHA256SUMS and databases.toml are compared too.
#         Nothing is written to disk.
# fetch   downloads SHA256SUMS, databases.toml and every listed file from URL
#         into DEST, resumable (files already matching the list are skipped),
#         then checks the list. SKIP_REGEX leaves out matching paths, for
#         example `oram-direct-inputs` on a node without Direct ORAM.
set -euo pipefail

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }

if command -v sha256sum >/dev/null 2>&1; then SHA=(sha256sum); else SHA=(shasum -a 256); fi

# catalog_dirs CATALOG DATA_ROOT: the catalog's directories relative to DATA_ROOT.
catalog_dirs() {
  local root=${2%/}
  grep -oE '^(path|proof_dir|proof_v2_dir)[[:space:]]*=[[:space:]]*"[^"]+"' "$1" |
    sed -E 's/^[a-z_2]+[[:space:]]*=[[:space:]]*"([^"]+)"/\1/' |
    sed -E "s#^${root}/##" | sort -u
}

# hash_file FILE: sha256 of FILE, read with O_DIRECT when dd supports it here.
hash_file() {
  local h
  h=$(set -o pipefail; dd if="$1" bs=16M iflag=direct status=none 2>/dev/null | "${SHA[@]}" | cut -d' ' -f1) ||
    h=$("${SHA[@]}" "$1" | cut -d' ' -f1)
  printf '%s' "$h"
}

cmd_hash() {
  local root=${1%/} catalog=$2 d f
  catalog=$(cd "$(dirname "$catalog")" && pwd)/$(basename "$catalog")
  cd "$root"
  catalog_dirs "$catalog" "$root" | while read -r d; do
    find "$d" -type f -print0 | sort -z | while IFS= read -r -d '' f; do
      printf '%s  %s\n' "$(hash_file "$f")" "$f"
    done
  done
}

cmd_upload() {
  local root=${1%/} bundle=$2 remote=${3%/} d
  local opts=(--s3-chunk-size 128M --s3-upload-cutoff 128M
    --transfers "${BPIR_BUNDLE_TRANSFERS:-2}" --checkers 4
    --bwlimit "${BPIR_BUNDLE_BWLIMIT:-off}" --stats 60s --stats-one-line)
  catalog_dirs "$bundle/databases.toml" "$root" | while read -r d; do
    echo "== $d"
    rclone copy "${opts[@]}" "$root/$d" "$remote/$d"
  done
  rclone copyto "${opts[@]}" "$bundle/SHA256SUMS" "$remote/SHA256SUMS"
  rclone copyto "${opts[@]}" "$bundle/databases.toml" "$remote/databases.toml"
}

cmd_verify() {
  local bundle=$1 url=${2%/} fail=0 want path got f
  while read -r want path; do
    got=$(set -o pipefail; curl -fsSL "$url/$path" | "${SHA[@]}" | cut -d' ' -f1) || got=download-failed
    if [[ $got == "$want" ]]; then echo "ok    $path"; else echo "FAIL  $path  $got"; fail=$((fail + 1)); fi
  done < "$bundle/SHA256SUMS"
  for f in SHA256SUMS databases.toml; do
    if cmp -s <(curl -fsSL "$url/$f") "$bundle/$f"; then echo "ok    $f"; else echo "FAIL  $f"; fail=$((fail + 1)); fi
  done
  echo "$fail failure(s)"
  [[ $fail -eq 0 ]]
}

cmd_fetch() {
  local url=${1%/} dest=$2 skip=${3:-} want path
  mkdir -p "$dest"
  cd "$dest"
  curl -fsSL -o SHA256SUMS "$url/SHA256SUMS"
  curl -fsSL -o databases.toml "$url/databases.toml"
  while read -r want path; do
    [[ -n $skip && $path =~ $skip ]] && continue
    if [[ -f $path ]] && [[ $("${SHA[@]}" "$path" | cut -d' ' -f1) == "$want" ]]; then echo "have  $path"; continue; fi
    echo "get   $path"
    curl -fL -C - --create-dirs --progress-bar -o "$path" "$url/$path"
  done < SHA256SUMS
  if [[ -n $skip ]]; then "${SHA[@]}" -c <(grep -Ev "$skip" SHA256SUMS); else "${SHA[@]}" -c SHA256SUMS; fi
}

case "${1:-}" in
  hash)   [[ $# -eq 3 ]] || { usage >&2; exit 2; }; cmd_hash "$2" "$3" ;;
  upload) [[ $# -eq 4 ]] || { usage >&2; exit 2; }; cmd_upload "$2" "$3" "$4" ;;
  verify) [[ $# -eq 3 ]] || { usage >&2; exit 2; }; cmd_verify "$2" "$3" ;;
  fetch)  [[ $# -eq 3 || $# -eq 4 ]] || { usage >&2; exit 2; }; cmd_fetch "$2" "$3" "${4:-}" ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
