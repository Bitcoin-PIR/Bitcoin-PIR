#!/bin/bash
# Start DPF-PIR WebSocket servers for UTXO lookups
#
# This script starts two WebSocket servers:
#   - Server 1 on port 8091
#   - Server 2 on port 8092
#
# Browser clients can connect directly via WebSocket.

set -e

# WebSocket Ports
SERVER1_PORT=8091
SERVER2_PORT=8092

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the servers first
echo "Building WebSocket servers..."
cargo build --release --bin server

echo ""
echo "========================================"
echo "DPF-PIR WebSocket Server Startup"
echo "========================================"
echo ""
echo "Databases configured in dpf_pir/src/server_config.rs:"
echo "  - utxo_cuckoo_index (cuckoo hash)"
echo "  - utxo_chunks_data (direct index)"
echo "  - utxo_4b_to_32b (TXID mapping)"
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "server --port $SERVER1_PORT" 2>/dev/null || true
pkill -f "server --port $SERVER2_PORT" 2>/dev/null || true
sleep 1

# Start Server 1 in background
echo "Starting WebSocket Server 1 on port $SERVER1_PORT..."
RUST_LOG=info ./target/release/server --port $SERVER1_PORT > /tmp/pir_server1.log 2>&1 &
SERVER1_PID=$!
echo "Server 1 PID: $SERVER1_PID"

# Start Server 2 in background
echo "Starting WebSocket Server 2 on port $SERVER2_PORT..."
RUST_LOG=info ./target/release/server --port $SERVER2_PORT > /tmp/pir_server2.log 2>&1 &
SERVER2_PID=$!
echo "Server 2 PID: $SERVER2_PID"

# Wait for servers to initialize
sleep 2

echo ""
echo "========================================"
echo "All servers started!"
echo "========================================"
echo ""
echo "WebSocket Servers:"
echo "  Server 1: ws://localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo "  Server 2: ws://localhost:$SERVER2_PORT (PID: $SERVER2_PID)"
echo ""
echo "Logs:"
echo "  Server 1: /tmp/pir_server1.log"
echo "  Server 2: /tmp/pir_server2.log"
echo ""
echo "To test, run:"
echo "  ./scripts/test_lookup_pir.sh"
echo ""
echo "Press Ctrl+C to stop all servers..."

# Trap Ctrl+C to kill all servers
trap "echo ''; echo 'Stopping servers...'; kill $SERVER1_PID $SERVER2_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait