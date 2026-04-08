#!/bin/bash
# Build a delta UTXO database between two Bitcoin block heights.
#
# A delta database contains only the UTXOs that changed (newly created or
# spent) between heights A and B. The unified server can load it alongside
# the main UTXO database (the "main" snapshot at height A) so clients can
# query the latest state by combining a main lookup with a delta lookup.
#
# Pipeline:
#   1. delta_gen_0            — diff dumptxoutset@A vs replayed blocks A+1..=B
#   2. delta_gen_1            — pack the diff into 40B chunks + index
#   3. build_cuckoo_generic   — build INDEX cuckoo (on delta_index_<A>_<B>.bin)
#   4. build_cuckoo_generic   — build CHUNK cuckoo (on delta_chunks_<A>_<B>.bin)
#   5. gen_4_build_merkle_bucket  — build per-bucket bin Merkle for the delta dir
#
# Usage:
#   ./scripts/build_delta.sh <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>
#
# Example:
#   ./scripts/build_delta.sh /Volumes/Bitcoin/snapshots/utxo_940611.dat \
#                            /Volumes/Bitcoin/bitcoin \
#                            940611 944000
#
# Output files (with start=940611, end=944000):
#   /Volumes/Bitcoin/data/intermediate/delta_grouped_940611_944000.bin
#   /Volumes/Bitcoin/data/intermediate/delta_chunks_940611_944000.bin
#   /Volumes/Bitcoin/data/intermediate/delta_index_940611_944000.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/batch_pir_cuckoo.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/chunk_pir_cuckoo.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/merkle_bucket_index_sib_L*.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/merkle_bucket_chunk_sib_L*.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/merkle_bucket_tree_tops.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/merkle_bucket_roots.bin
#   /Volumes/Bitcoin/data/deltas/940611_944000/merkle_bucket_root.bin

set -euo pipefail

if [[ $# -ne 4 ]]; then
    echo "Usage: $0 <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 /Volumes/Bitcoin/snapshots/utxo_940611.dat /Volumes/Bitcoin/bitcoin 940611 944000" >&2
    exit 1
fi

SNAPSHOT="$1"
BITCOIN_DIR="$2"
START_HEIGHT="$3"
END_HEIGHT="$4"

# Default data directory layout (matches delta_gen_0/delta_gen_1 hardcoded paths)
DATA_DIR="/Volumes/Bitcoin/data"
INTERMEDIATE_DIR="$DATA_DIR/intermediate"
DELTA_OUT_DIR="$DATA_DIR/deltas/${START_HEIGHT}_${END_HEIGHT}"

DELTA_INDEX_FILE="$INTERMEDIATE_DIR/delta_index_${START_HEIGHT}_${END_HEIGHT}.bin"
DELTA_CHUNKS_FILE="$INTERMEDIATE_DIR/delta_chunks_${START_HEIGHT}_${END_HEIGHT}.bin"

INDEX_CUCKOO_OUT="$DELTA_OUT_DIR/batch_pir_cuckoo.bin"
CHUNK_CUCKOO_OUT="$DELTA_OUT_DIR/chunk_pir_cuckoo.bin"

# Get the project root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

mkdir -p "$INTERMEDIATE_DIR"
mkdir -p "$DELTA_OUT_DIR"

echo "========================================"
echo "Bitcoin PIR — Delta DB Build Pipeline"
echo "========================================"
echo "Snapshot:    $SNAPSHOT"
echo "Bitcoin dir: $BITCOIN_DIR"
echo "Range:       $START_HEIGHT -> $END_HEIGHT"
echo "Output dir:  $DELTA_OUT_DIR"
echo ""

# Build all binaries we need up front so the timing of each stage isn't
# dominated by compilation.
echo "[build] Compiling delta build binaries..."
cargo build --release -p build \
    --bin delta_gen_0 \
    --bin delta_gen_1 \
    --bin build_cuckoo_generic \
    --bin gen_4_build_merkle_bucket
echo ""

# ── Step 1: compute the grouped delta ───────────────────────────────────────
echo "[1/5] delta_gen_0 — computing grouped delta..."
./target/release/delta_gen_0 "$SNAPSHOT" "$BITCOIN_DIR" "$START_HEIGHT" "$END_HEIGHT"
echo ""

# ── Step 2: pack into chunks + index ────────────────────────────────────────
echo "[2/5] delta_gen_1 — packing into chunks + index..."
./target/release/delta_gen_1 "$START_HEIGHT" "$END_HEIGHT"
echo ""

# ── Step 3: build INDEX cuckoo for the delta ────────────────────────────────
echo "[3/5] build_cuckoo_generic index — building delta INDEX cuckoo..."
./target/release/build_cuckoo_generic index "$DELTA_INDEX_FILE" "$INDEX_CUCKOO_OUT"
echo ""

# ── Step 4: build CHUNK cuckoo for the delta ────────────────────────────────
echo "[4/5] build_cuckoo_generic chunk — building delta CHUNK cuckoo..."
./target/release/build_cuckoo_generic chunk "$DELTA_CHUNKS_FILE" "$DELTA_INDEX_FILE" "$CHUNK_CUCKOO_OUT"
echo ""

# ── Step 5: build per-bucket bin Merkle for the delta dir ───────────────────
echo "[5/5] gen_4_build_merkle_bucket — building per-bucket bin Merkle..."
./target/release/gen_4_build_merkle_bucket --data-dir "$DELTA_OUT_DIR"
echo ""

echo "========================================"
echo "Delta build complete."
echo "========================================"
echo "Files in $DELTA_OUT_DIR:"
ls -lh "$DELTA_OUT_DIR"
