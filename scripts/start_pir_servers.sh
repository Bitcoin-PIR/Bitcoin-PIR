#!/bin/bash
# Start PIR WebSocket servers for UTXO lookups
#
# This script starts three WebSocket servers:
#   - DPF Server 1 on port 8091
#   - DPF Server 2 on port 8092
#   - OnionPIR Server on port 8093
#
# Usage:
#   ./scripts/start_pir_servers.sh

set -e

# WebSocket Ports
DPF_SERVER1_PORT=8091
DPF_SERVER2_PORT=8092
ONIONPIR_PORT=8093

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Build the servers first
echo "Building PIR WebSocket servers..."
cargo build --release -p runtime --bin server --bin onionpir2_server

echo ""
echo "========================================"
echo "PIR WebSocket Server Startup"
echo "========================================"
echo ""

# Kill any existing servers on these ports
echo "Checking for existing servers..."
pkill -f "server --port $DPF_SERVER1_PORT" 2>/dev/null || true
pkill -f "server --port $DPF_SERVER2_PORT" 2>/dev/null || true
pkill -f "onionpir2_server --port $ONIONPIR_PORT" 2>/dev/null || true
sleep 1

# Start DPF Server 1 in background
echo "Starting DPF Server 1 on port $DPF_SERVER1_PORT..."
./target/release/server --port $DPF_SERVER1_PORT > /tmp/pir_server1.log 2>&1 &
DPF1_PID=$!
echo "DPF Server 1 PID: $DPF1_PID"

# Start DPF Server 2 in background
echo "Starting DPF Server 2 on port $DPF_SERVER2_PORT..."
./target/release/server --port $DPF_SERVER2_PORT > /tmp/pir_server2.log 2>&1 &
DPF2_PID=$!
echo "DPF Server 2 PID: $DPF2_PID"

# Start OnionPIR Server in background
echo "Starting OnionPIR Server on port $ONIONPIR_PORT..."
./target/release/onionpir2_server --port $ONIONPIR_PORT > /tmp/pir_onionpir.log 2>&1 &
ONION_PID=$!
echo "OnionPIR Server PID: $ONION_PID"

# Wait for servers to initialize
sleep 2

echo ""
echo "========================================"
echo "All servers started!"
echo "========================================"
echo ""
echo "DPF Servers (2-server PIR):"
echo "  Server 1: ws://localhost:$DPF_SERVER1_PORT (PID: $DPF1_PID)"
echo "  Server 2: ws://localhost:$DPF_SERVER2_PORT (PID: $DPF2_PID)"
echo ""
echo "OnionPIR Server (1-server PIR):"
echo "  Server:   ws://localhost:$ONIONPIR_PORT (PID: $ONION_PID)"
echo ""
echo "Logs:"
echo "  DPF Server 1:  /tmp/pir_server1.log"
echo "  DPF Server 2:  /tmp/pir_server2.log"
echo "  OnionPIR:      /tmp/pir_onionpir.log"
echo ""
echo "To test with CLI client:"
echo "  DPF:      ./target/release/client --hash <script_hash_hex>"
echo "  OnionPIR: ./target/release/onionpir2_client --hash <hex> --server ws://localhost:$ONIONPIR_PORT"
echo ""
echo "Press Ctrl+C to stop all servers..."

# Trap Ctrl+C to kill all servers
trap "echo ''; echo 'Stopping servers...'; kill $DPF1_PID $DPF2_PID $ONION_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait
