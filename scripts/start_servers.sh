#!/bin/bash
# Start two DPF-PIR servers for PIR queries
#
# Database Configuration:
# Databases are now registered in dpf_pir/src/server_config.rs
# Edit that file to add/modify databases, then rebuild.
#
# No command-line arguments needed - the server automatically
# loads all registered databases from the configuration.

set -e

# Ports for the two servers (must match what client expects)
SERVER1_PORT=8081
SERVER2_PORT=8082

# Build the server first
echo "Building server..."
cd "$(dirname "$0")/.."
cargo build --release --bin server

echo ""
echo "========================================"
echo "DPF-PIR Server Startup"
echo "========================================"
echo ""
echo "Note: Databases are configured in dpf_pir/src/server_config.rs"
echo "Edit that file to add/modify databases, then rebuild."
echo ""

# Start Server 1 in background
echo "Starting Server 1 on port $SERVER1_PORT..."
RUST_LOG=info ./target/release/server &
SERVER1_PID=$!
echo "Server 1 PID: $SERVER1_PID"

# Small delay to let server 1 start
sleep 1

# Start Server 2 in background
echo "Starting Server 2 on port $SERVER2_PORT..."
RUST_LOG=info ./target/release/server &
SERVER2_PID=$!
echo "Server 2 PID: $SERVER2_PID"

echo ""
echo "========================================"
echo "Both servers started!"
echo "Server 1: localhost:$SERVER1_PORT (PID: $SERVER1_PID)"
echo "Server 2: localhost:$SERVER2_PORT (PID: $SERVER2_PID)"
echo "========================================"
echo ""
echo "Use './scripts/run_client.sh --list-databases' to see available databases"
echo "Press Ctrl+C to stop both servers..."

# Trap Ctrl+C to kill both servers
trap "echo 'Stopping servers...'; kill $SERVER1_PID $SERVER2_PID 2>/dev/null; exit 0" SIGINT SIGTERM

# Wait for servers
wait