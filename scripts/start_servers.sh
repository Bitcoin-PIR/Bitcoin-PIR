#!/bin/bash
# Start two DPF-PIR servers for PIR queries
#
# Configuration:
# - Bucket size: 4 entries
# - Number of buckets: 14008287
# - Entry size: 24 bytes
# - Bucket bytes: 24 * 4 = 96 bytes
# - Data file: /Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin

set -e

# Configuration
DATA_FILE="/Volumes/Bitcoin/pir/utxo_chunks_cuckoo.bin"
BUCKETS=14008287
ENTRY_SIZE=24
BUCKET_SIZE=4
SERVER1_PORT=8081
SERVER2_PORT=8082

# Optional: load data into memory for faster queries
# Uncomment the -m flag below if you have enough RAM
LOAD_MEMORY_FLAG=""
# LOAD_MEMORY_FLAG="-m"

# Build the server first
echo "Building server..."
cd "$(dirname "$0")/.."
cargo build --release --bin server

# Start Server 1 in background
echo "Starting Server 1 on port $SERVER1_PORT..."
RUST_LOG=info ./target/release/server \
    --port $SERVER1_PORT \
    --data "$DATA_FILE" \
    --buckets $BUCKETS \
    --entry-size $ENTRY_SIZE \
    --bucket-size $BUCKET_SIZE \
    $LOAD_MEMORY_FLAG &
SERVER1_PID=$!
echo "Server 1 PID: $SERVER1_PID"

# Small delay to let server 1 start
sleep 1

# Start Server 2 in background
echo "Starting Server 2 on port $SERVER2_PORT..."
RUST_LOG=info ./target/release/server \
    --port $SERVER2_PORT \
    --data "$DATA_FILE" \
    --buckets $BUCKETS \
    --entry-size $ENTRY_SIZE \
    --bucket-size $BUCKET_SIZE \
    $LOAD_MEMORY_FLAG &
SERVER2_PID=$!
echo "Server 2 PID: $SERVER2_PID"

echo ""
echo "========================================"
echo "Both servers started!"
echo "Server 1: localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo "Server 2: localhost:$SERVER2_PORT (PID: $SERVER2_PID)"
echo "========================================"
echo ""
echo "Press Ctrl+C to stop both servers..."

# Trap Ctrl+C to kill both servers
trap "echo 'Stopping servers...'; kill $SERVER1_PID $SERVER2_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait