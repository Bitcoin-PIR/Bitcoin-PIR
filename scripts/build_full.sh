#!/bin/bash
# Build a full UTXO PIR database (all three backends + Merkle) from a
# Bitcoin Core dumptxoutset snapshot.
#
# Pipeline (single orchestrator, mirrors scripts/build_delta.sh + build_delta_onion.sh):
#   1. gen_0_extract_utxo_set      — read dumptxoutset, write 68B flat UTXOs
#   2. gen_1_build_utxo_chunks     — pack into 80B chunks + 25B index (no dust)
#   3. build_cuckoo_generic index  — build INDEX cuckoo (DPF/HarmonyPIR)
#   4. build_cuckoo_generic chunk  — build CHUNK cuckoo (DPF/HarmonyPIR)
#   5. gen_4_build_merkle_bucket   — per-bucket bin Merkle for INDEX + CHUNK
#   6. gen_1_onion                 — pack UTXOs into 3840B OnionPIR entries
#   7. (move onion_packed_entries.bin + onion_index.bin into checkpoint dir)
#   8. gen_2_onion --data-dir      — NTT store + chunk cuckoo + DATA bin hashes
#   9. gen_3_onion --data-dir      — per-group INDEX PIR DBs, consolidated to onion_index_all.bin
#  10. gen_4_build_merkle_onion    — per-bin Merkle for OnionPIR (INDEX + DATA)
#
# Usage:
#   ./scripts/build_full.sh <dumptxoutset_file> <height>
#
# Example:
#   ./scripts/build_full.sh /Volumes/Bitcoin/snapshots/utxo_948454.dat 948454
#
# Layout:
#   /Volumes/Bitcoin/data/intermediate/full_<H>/   — raw UTXO + chunks + index (large; safe to delete after build)
#   /Volumes/Bitcoin/data/checkpoints/<H>/         — final artifacts the server consumes (~40 GB)
#
# Optional ORAM direct-input preservation:
#   KEEP_ORAM_DIRECT_INPUTS=1 copies the direct INDEX+CHUNK source tables into
#   /Volumes/Bitcoin/data/oram-inputs/checkpoints/<H>/ by default. Keep these
#   outside the checkpoint dir so MANIFEST.toml and server startup do not hash
#   or verify multi-GB intermediate files that are only needed for ORAM image
#   construction.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <dumptxoutset_file> <height>" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 /Volumes/Bitcoin/snapshots/utxo_948454.dat 948454" >&2
    exit 1
fi

SNAPSHOT="$1"
HEIGHT="$2"

if [[ ! -f "$SNAPSHOT" ]]; then
    echo "ERROR: snapshot file not found: $SNAPSHOT" >&2
    exit 1
fi

DATA_DIR="/Volumes/Bitcoin/data"
INTERMEDIATE_DIR="$DATA_DIR/intermediate/full_${HEIGHT}"
CHECKPOINT_DIR="$DATA_DIR/checkpoints/${HEIGHT}"
ORAM_DIRECT_INPUT_DIR="${ORAM_DIRECT_INPUT_DIR:-$DATA_DIR/oram-inputs/checkpoints/${HEIGHT}}"

INDEX_INPUT="$INTERMEDIATE_DIR/utxo_chunks_index_nodust.bin"
CHUNKS_INPUT="$INTERMEDIATE_DIR/utxo_chunks_nodust.bin"

INDEX_CUCKOO_OUT="$CHECKPOINT_DIR/batch_pir_cuckoo.bin"
CHUNK_CUCKOO_OUT="$CHECKPOINT_DIR/chunk_pir_cuckoo.bin"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

mkdir -p "$INTERMEDIATE_DIR"
mkdir -p "$CHECKPOINT_DIR"

echo "========================================"
echo "Bitcoin PIR — Full Snapshot Build Pipeline"
echo "========================================"
echo "Snapshot:       $SNAPSHOT"
echo "Height:         $HEIGHT"
echo "Intermediate:   $INTERMEDIATE_DIR"
echo "Checkpoint:     $CHECKPOINT_DIR"
echo ""

# Build all binaries we need up front so per-stage timing isn't dominated by compilation.
echo "[build] Compiling full-snapshot build binaries..."
cargo build --release -p build \
    --bin gen_0_extract_utxo_set \
    --bin gen_1_build_utxo_chunks \
    --bin build_cuckoo_generic \
    --bin gen_4_build_merkle_bucket \
    --bin gen_1_onion \
    --bin gen_2_onion \
    --bin gen_3_onion \
    --bin gen_4_build_merkle_onion
echo ""

# ── Step 1: extract flat UTXO set ───────────────────────────────────────────
echo "[1/10] gen_0_extract_utxo_set — reading dumptxoutset..."
./target/release/gen_0_extract_utxo_set "$SNAPSHOT" \
    --data-dir "$INTERMEDIATE_DIR" \
    --anchor-height "$HEIGHT"
# Stage chain_anchor.bin into the checkpoint dir so gen_2_onion / gen_3_onion
# (--data-dir $CHECKPOINT_DIR) auto-detect it. build_cuckoo_generic below
# reads it from $INTERMEDIATE_DIR explicitly.
cp -f "$INTERMEDIATE_DIR/chain_anchor.bin" "$CHECKPOINT_DIR/chain_anchor.bin"
echo ""

# ── Step 2: pack into 80B chunks + 25B index ────────────────────────────────
echo "[2/10] gen_1_build_utxo_chunks — packing into chunks + index..."
./target/release/gen_1_build_utxo_chunks --data-dir "$INTERMEDIATE_DIR"
if [[ "${KEEP_ORAM_DIRECT_INPUTS:-0}" == "1" ]]; then
    echo "[2/10] Preserving direct ORAM inputs..."
    mkdir -p "$ORAM_DIRECT_INPUT_DIR"
    cp -f "$INDEX_INPUT" "$ORAM_DIRECT_INPUT_DIR/utxo_chunks_index_nodust.bin"
    cp -f "$CHUNKS_INPUT" "$ORAM_DIRECT_INPUT_DIR/utxo_chunks_nodust.bin"
    du -sh "$ORAM_DIRECT_INPUT_DIR"
fi
echo ""

# ── Step 3: INDEX cuckoo (DPF/HarmonyPIR) ───────────────────────────────────
echo "[3/10] build_cuckoo_generic index — building INDEX cuckoo..."
./target/release/build_cuckoo_generic index "$INDEX_INPUT" "$INDEX_CUCKOO_OUT" \
    --anchor "$INTERMEDIATE_DIR/chain_anchor.bin"
echo ""

# ── Step 4: CHUNK cuckoo (DPF/HarmonyPIR) ───────────────────────────────────
echo "[4/10] build_cuckoo_generic chunk — building CHUNK cuckoo..."
./target/release/build_cuckoo_generic chunk "$CHUNKS_INPUT" "$INDEX_INPUT" "$CHUNK_CUCKOO_OUT" \
    --anchor "$INTERMEDIATE_DIR/chain_anchor.bin"
echo ""

# ── Step 5: per-bucket bin Merkle for DPF/Harmony ──────────────────────────
echo "[5/10] gen_4_build_merkle_bucket — per-bucket bin Merkle..."
./target/release/gen_4_build_merkle_bucket --data-dir "$CHECKPOINT_DIR"
echo ""

# ── Step 6: pack UTXOs into 3840B OnionPIR entries ─────────────────────────
echo "[6/10] gen_1_onion — packing into OnionPIR 3840B entries..."
./target/release/gen_1_onion --data-dir "$INTERMEDIATE_DIR"
echo ""

# ── Step 7: stage onion_packed_entries.bin + onion_index.bin into checkpoint dir ──
echo "[7/10] Staging OnionPIR inputs into checkpoint dir..."
mv -f "$INTERMEDIATE_DIR/onion_packed_entries.bin" "$CHECKPOINT_DIR/onion_packed_entries.bin"
mv -f "$INTERMEDIATE_DIR/onion_index.bin"          "$CHECKPOINT_DIR/onion_index.bin"
echo ""

# ── Step 8: NTT store + chunk cuckoo + DATA bin hashes ─────────────────────
echo "[8/10] gen_2_onion — NTT store + chunk cuckoo..."
./target/release/gen_2_onion --data-dir "$CHECKPOINT_DIR"
echo ""

# ── Step 9: per-group index PIR databases + INDEX bin hashes ───────────────
echo "[9/10] gen_3_onion — per-group index PIR databases..."
./target/release/gen_3_onion --data-dir "$CHECKPOINT_DIR"
echo ""

# ── Step 10: per-bin Merkle for OnionPIR (INDEX + DATA sub-trees) ──────────
echo "[10/10] gen_4_build_merkle_onion — per-bin Merkle..."
./target/release/gen_4_build_merkle_onion --data-dir "$CHECKPOINT_DIR"
echo ""

# Onion no longer needs the raw packed-entries / 27B index file in the
# checkpoint dir at runtime — gen_2_onion + gen_3_onion have consumed
# them. Remove so the checkpoint dir matches the canonical layout
# (compare scripts/build_db_manifest.sh + production checkpoints/).
rm -f "$CHECKPOINT_DIR/onion_packed_entries.bin" \
      "$CHECKPOINT_DIR/onion_index.bin"

echo "========================================"
echo "Full snapshot build complete: $CHECKPOINT_DIR"
echo "========================================"
ls -lh "$CHECKPOINT_DIR"
echo ""
echo "Total checkpoint size:"
du -sh "$CHECKPOINT_DIR"
echo ""
echo "Intermediate files (safe to delete after build):"
du -sh "$INTERMEDIATE_DIR"
echo "  ($INTERMEDIATE_DIR)"
