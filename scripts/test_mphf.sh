#!/bin/bash

# Test script for MPHF builder
# This script demonstrates how to build and test the MPHF

set -e

echo "=== MPHF Builder Test Script ==="
echo ""

# Check if txid.bin exists
if [ ! -f "/Volumes/Bitcoin/data/txid.bin" ]; then
    echo "✗ Error: /Volumes/Bitcoin/data/txid.bin not found!"
    echo "  Please run generate_txid_file first."
    exit 1
fi

# Show file size
FILE_SIZE=$(stat -f%z "/Volumes/Bitcoin/data/txid.bin" 2>/dev/null || stat -c%s "/Volumes/Bitcoin/data/txid.bin" 2>/dev/null)
echo "✓ txid.bin exists (${FILE_SIZE} bytes)"
echo ""

# Build the MPHF
echo "Building MPHF..."
cd /Users/cusgadmin/BitcoinPIR/pir
cargo run --bin build_mphf

echo ""
echo "=== Test Complete ==="

# Check if MPHF file was created
if [ -f "/Volumes/Bitcoin/data/txid_mphf.bin" ]; then
    MPHF_SIZE=$(stat -f%z "/Volumes/Bitcoin/data/txid_mphf.bin" 2>/dev/null || stat -c%s "/Volumes/Bitcoin/data/txid_mphf.bin" 2>/dev/null)
    echo "✓ MPHF file created successfully (${MPHF_SIZE} bytes)"
else
    echo "✗ MPHF file was not created!"
    exit 1
fi