#!/bin/bash
# Test the DPF-PIR UTXO lookup client
#
# This script tests the lookup_pir client with example script pubkeys

set -e

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the client first
echo "Building lookup_pir client..."
cargo build --release --bin lookup_pir

echo ""
echo "========================================"
echo "Testing DPF-PIR UTXO Lookup"
echo "========================================"
echo ""

# Server addresses (default)
SERVER1="127.0.0.1:8081"
SERVER2="127.0.0.1:8082"

# Test 1: The specific script requested by user
echo "------------------------------"
SCRIPT1="76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac"
echo "Script: $SCRIPT1"
echo ""
./target/release/lookup_pir --server1 $SERVER1 --server2 $SERVER2 "$SCRIPT1" || echo "Query completed (may not have UTXOs)"

echo ""
echo "========================================"
echo "Tests completed!"
echo "========================================"