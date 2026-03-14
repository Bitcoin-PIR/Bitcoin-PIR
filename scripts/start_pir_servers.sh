#!/bin/bash
# Start two DPF-PIR servers for UTXO lookups
#
# This script starts both Server 1 (port 8081) and Server 2 (port 8082)
# with the databases configured in dpf_pir/src/server_config.rs

set -e

# Ports for the two servers
SERVER1_PORT=8081
SERVER2_PORT=8082

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the server first
echo "Building server..."
cargo build --release --bin server

echo ""
echo "========================================"
echo "DPF-PIR Server Startup"
echo "========================================"
echo ""
echo "Databases configured in dpf_pir/src/server_config.rs:"
echo "  - utxo_cuckoo_index (cuckoo hash)"
echo "  - utxo_chunks_data (direct index)"
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "server --port $SERVER1_PORT" 2>/dev/null || true
pkill -f "server --port $SERVER2_PORT" 2>/dev/null || true
sleep 1

# Start Server 1 in background
echo "Starting Server 1 on port $SERVER1_PORT..."
RUST_LOG=info ./target/release/server --port $SERVER1_PORT > /tmp/pir_server1.log 2>&1 &
SERVER1_PID=$!
echo "Server 1 PID: $SERVER1_PID"

# Small delay to let server 1 start
sleep 2

# Start Server 2 in background
echo "Starting Server 2 on port $SERVER2_PORT..."
RUST_LOG=info ./target/release/server --port $SERVER2_PORT > /tmp/pir_server2.log 2>&1 &
SERVER2_PID=$!
echo "Server 2 PID: $SERVER2_PID"

# Wait for servers to initialize
sleep 2

echo ""
echo "========================================"
echo "Both servers started!"
echo "========================================"
echo "Server 1: localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo "Server 2: localhost:$SERVER2_PORT (PID: $SERVER2_PID)"
echo ""
echo "Logs:"
echo "  Server 1: /tmp/pir_server1.log"
echo "  Server 2: /tmp/pir_server2.log"
echo ""
echo "To test, run:"
echo "  ./scripts/test_lookup_pir.sh"
echo ""
echo "Press Ctrl+C to stop both servers..."

# Trap Ctrl+C to kill both servers
trap "echo ''; echo 'Stopping servers...'; kill $SERVER1_PID $SERVER2_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait