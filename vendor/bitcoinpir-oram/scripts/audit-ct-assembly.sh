#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/audit-ct-assembly.sh [--target TRIPLE]

Build the library with release assembly output and print the ORAM
constant-time hot-loop symbols that need manual inspection. Set CT_TARGET or
pass --target to audit a non-host target, for example:

  CT_TARGET=x86_64-unknown-linux-gnu scripts/audit-ct-assembly.sh
EOF
}

target="${CT_TARGET:-}"
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "${1:-}" == "--target" ]]; then
  if [[ -z "${2:-}" ]]; then
    usage >&2
    exit 2
  fi
  target="$2"
  shift 2
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

cargo_args=(rustc --release --lib)
bin_args=(rustc --release --bin oramctl)
deps_dir="target/release/deps"
if [[ -n "$target" ]]; then
  cargo_args+=(--target "$target")
  bin_args+=(--target "$target")
  deps_dir="target/$target/release/deps"
fi

cargo "${cargo_args[@]}" -- --emit=asm
cargo "${bin_args[@]}" -- --emit=asm

lib_asm_file="$(find "$deps_dir" -maxdepth 1 -name 'bitcoinpir_oram-*.s' -print | sort | tail -n 1)"
bin_asm_file="$(find "$deps_dir" -maxdepth 1 -name 'oramctl-*.s' -print | sort | tail -n 1)"
if [[ -z "$lib_asm_file" || -z "$bin_asm_file" ]]; then
  echo "no bitcoinpir_oram assembly file found under $deps_dir" >&2
  exit 1
fi
asm_files=("$lib_asm_file" "$bin_asm_file")

echo "ct_asm_files:"
printf '  %s\n' "${asm_files[@]}"
echo
echo "ct_hot_symbols:"
missing=0
for symbol in \
  scan_pos_map_lookup \
  scan_pos_map_update \
  scan_pos_map_lookup_batch \
  scan_pos_map_update_batch \
  batch_access_leaves \
  plan_eviction_placements \
  apply_eviction_plan_to_overlays \
  load_eviction_payloads_from_overlay \
  ensure_eviction_stash_capacity \
  insert_candidate_into_stash \
  select_and_remove_target_slots \
  clear_payload_volatile_if \
  clear_payload_if \
  select_index_record_from_bin
do
  if ! grep -Hn "$symbol" "${asm_files[@]}"; then
    echo "missing_symbol=$symbol"
    missing=1
  fi
done
if [[ "$missing" -ne 0 ]]; then
  echo "one or more audited symbols were missing from release assembly" >&2
  exit 1
fi

echo
for clear_symbol in clear_payload_volatile_if clear_payload_if; do
  echo "${clear_symbol}_window:"
  clear_match="$(grep -Hn "$clear_symbol" "${asm_files[@]}" | head -n 1 || true)"
  if [[ -z "$clear_match" ]]; then
    echo "missing $clear_symbol; cannot inspect conditional payload clear" >&2
    exit 1
  fi
  clear_file="${clear_match%%:*}"
  clear_rest="${clear_match#*:}"
  clear_line="${clear_rest%%:*}"
  sed -n "${clear_line},$((clear_line + 90))p" "$clear_file"

  if sed -n "${clear_line},$((clear_line + 90))p" "$clear_file" | grep -Eq '_?bzero|_?memset'; then
    echo "$clear_symbol contains bzero/memset in the inspected window" >&2
    exit 1
  fi
  echo
done

echo
echo "global_memset_bzero_refs_non_fatal:"
grep -HnE '_?bzero|_?memset' "${asm_files[@]}" || true

echo
echo "variable_shift_refs_review_non_fatal:"
if grep -HnE $'\\b(shl|shr|sar|sal)[a-z]*[[:space:]]+%cl|\\b(lsl|lsr|asr)[[:space:]]+[wx][0-9]+,[[:space:]]*[wx][0-9]+,[[:space:]]*[wx][0-9]+' "${asm_files[@]}"; then
  echo "review_note=variable shifts above need target CPU latency review when they are in audited hot symbols"
else
  echo "none"
fi
