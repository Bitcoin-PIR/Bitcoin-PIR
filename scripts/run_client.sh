#!/bin/bash
# Run DPF-PIR client query
#
# Configuration:
# - Bucket size: 4 entries
# - Number of buckets: 14008287
# - Entry size: 24 bytes
# - Bucket bytes: 24 * 4 = 96 bytes
#
# Usage: ./run_client.sh [SCRIPT_HASH]
# If no SCRIPT_HASH provided, uses the default below

set -e

# Configuration
BUCKETS=14008287
SERVER1_ADDR="127.0.0.1:8081"
SERVER2_ADDR="127.0.0.1:8082"

# ========================================
# SET YOUR SCRIPT HASH HERE (40 hex characters = 20 bytes)
# This is a sample from the data file - replace with actual script hash to query
# ========================================
DEFAULT_SCRIPT_HASH="09301f6ca4ea2ed028935e427616f04c93f2090b"

# Use command line argument or default
SCRIPT_HASH="${1:-$DEFAULT_SCRIPT_HASH}"

# Validate script hash length
if [ ${#SCRIPT_HASH} -ne 40 ]; then
    echo "Error: Script hash must be 40 hex characters (20 bytes)"
    echo "Got: '$SCRIPT_HASH' (${#SCRIPT_HASH} characters)"
    exit 1
fi

# Build the client first
echo "Building client..."
cd "$(dirname "$0")/.."
cargo build --release --bin client

echo ""
echo "========================================"
echo "Querying for script hash: $SCRIPT_HASH"
echo "Server 1: $SERVER1_ADDR"
echo "Server 2: $SERVER2_ADDR"
echo "Number of buckets: $BUCKETS"
echo "========================================"
echo ""

# Run the client
RUST_LOG=info ./target/release/client \
    --server1 "$SERVER1_ADDR" \
    --server2 "$SERVER2_ADDR" \
    --buckets $BUCKETS \
    "$SCRIPT_HASH"

echo ""
echo "Query complete."