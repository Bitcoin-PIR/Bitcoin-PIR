#!/usr/bin/env bash
# prepare-wasm-publish.sh
#
# Post-processes the wasm-pack-generated `pir-sdk-wasm/pkg/package.json`
# so it has the same provenance metadata (repository, homepage,
# keywords, bugs, description, author) as the crates.io side.
#
# wasm-pack only copies `name` / `version` / `description` / `license`
# from Cargo.toml. Everything else has to be added manually before
# `npm publish`, or the published package shows up on npmjs.com with no
# repo link and no search keywords. This script is the canonical way
# to add them; run it after `wasm-pack build` and before
# `npm publish`.
#
# Usage:
#   cd /path/to/BitcoinPIR
#   wasm-pack build --target web --out-dir pkg --release -- \
#     --manifest-path pir-sdk-wasm/Cargo.toml
#   ./scripts/prepare-wasm-publish.sh
#
# Dependencies: jq (https://jqlang.github.io/jq/).
#
# Exit codes:
#   0 — success
#   1 — pkg/package.json missing (run wasm-pack build first)
#   2 — version in pkg/package.json doesn't match Cargo.toml
#   3 — jq not on PATH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE_DIR="$WORKSPACE_ROOT/pir-sdk-wasm"
PKG_DIR="$CRATE_DIR/pkg"
PKG_JSON="$PKG_DIR/package.json"
CARGO_TOML="$CRATE_DIR/Cargo.toml"

REPOSITORY_URL="https://github.com/Bitcoin-PIR/Bitcoin-PIR"
HOMEPAGE_URL="https://github.com/Bitcoin-PIR/Bitcoin-PIR"
BUGS_URL="https://github.com/Bitcoin-PIR/Bitcoin-PIR/issues"
AUTHOR="Bitcoin PIR contributors"
KEYWORDS_JSON='["pir","privacy","bitcoin","wasm","webassembly","cryptography"]'
DESCRIPTION="WASM bindings for the PIR SDK: async DPF + HarmonyPIR clients, sync planning, delta merging, per-bucket Merkle verification, and lock-free metrics counters."

# --- Preflight ---------------------------------------------------------

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq not found on PATH" >&2
  echo "       install with: brew install jq   (macOS)" >&2
  echo "                 or: apt install jq    (Debian/Ubuntu)" >&2
  exit 3
fi

if [[ ! -f "$PKG_JSON" ]]; then
  echo "ERROR: $PKG_JSON not found" >&2
  echo "       run 'wasm-pack build --target web --out-dir pkg' first" >&2
  exit 1
fi

# --- Version cross-check ----------------------------------------------

CARGO_VERSION=$(
  awk -F'"' '/^version *=/{print $2; exit}' "$CARGO_TOML"
)
PKG_VERSION=$(
  jq -r '.version' "$PKG_JSON"
)

if [[ "$CARGO_VERSION" != "$PKG_VERSION" ]]; then
  echo "ERROR: version mismatch" >&2
  echo "       Cargo.toml   = $CARGO_VERSION" >&2
  echo "       package.json = $PKG_VERSION" >&2
  echo "       re-run wasm-pack build after updating Cargo.toml" >&2
  exit 2
fi

echo "==> pir-sdk-wasm @ $CARGO_VERSION"

# --- Patch pkg/package.json -------------------------------------------

TMP_JSON=$(mktemp -t pir-sdk-wasm-pkg-XXXXXX.json)
trap 'rm -f "$TMP_JSON"' EXIT

# shellcheck disable=SC2016  # jq program uses $KW etc as jq vars, not shell.
# npm auto-includes package.json / README / `LICENSE` / `LICENCE` (case
# insensitive) regardless of the `files` array. It does NOT auto-include
# hyphenated variants like `LICENSE-MIT` or `LICENSE-APACHE`, and it does
# NOT auto-include `CHANGELOG.md`. We explicitly list all four.
#
# We deliberately keep the wasm-bindgen-generated
# `pir_sdk_wasm_bg.wasm.d.ts` out of `files`: downstream TS consumers
# pull types through `pir_sdk_wasm.d.ts`, which re-exports what they
# need. Matches wasm-pack's default publish shape.
jq \
  --arg repo "$REPOSITORY_URL" \
  --arg home "$HOMEPAGE_URL" \
  --arg bugs "$BUGS_URL" \
  --arg author "$AUTHOR" \
  --arg desc "$DESCRIPTION" \
  --argjson kw "$KEYWORDS_JSON" \
  '. + {
    description: $desc,
    author: $author,
    homepage: $home,
    repository: { type: "git", url: ("git+" + $repo + ".git") },
    bugs: { url: $bugs },
    keywords: $kw,
    files: ((.files // []) + [
      "CHANGELOG.md",
      "LICENSE-MIT",
      "LICENSE-APACHE"
    ] | unique)
  }' "$PKG_JSON" > "$TMP_JSON"

mv "$TMP_JSON" "$PKG_JSON"
trap - EXIT

# --- Copy LICENSE-MIT / LICENSE-APACHE + README + CHANGELOG -----------

# Symlinks in the crate dir aren't followed by npm pack, so we copy.
for f in LICENSE-MIT LICENSE-APACHE; do
  if [[ -f "$WORKSPACE_ROOT/$f" ]]; then
    cp "$WORKSPACE_ROOT/$f" "$PKG_DIR/$f"
  fi
done

if [[ -f "$CRATE_DIR/README.md" ]]; then
  cp "$CRATE_DIR/README.md" "$PKG_DIR/README.md"
fi
if [[ -f "$CRATE_DIR/CHANGELOG.md" ]]; then
  cp "$CRATE_DIR/CHANGELOG.md" "$PKG_DIR/CHANGELOG.md"
fi

# --- Summary -----------------------------------------------------------

echo
echo "==> pkg/package.json patched. Now contains:"
jq '{name, version, description, author, repository, homepage, bugs, keywords, license}' "$PKG_JSON"
echo
echo "==> Ready for publish dry-run:"
echo "    (cd $PKG_DIR && npm publish --dry-run)"
echo
echo "==> Actual publish:"
echo "    (cd $PKG_DIR && npm publish --access public)"
