#!/bin/bash
# Run DPF-PIR client query
#
# Usage:
#   ./run_client.sh                     # Query with default script
#   ./run_client.sh <SCRIPT_HEX>        # Query with specific script
#   ./run_client.sh --list-databases    # List available databases
#   ./run_client.sh --db-info <ID>      # Get database info
#   ./run_client.sh --db <ID> <SCRIPT>  # Query specific database
#
# The client computes RIPEMD160(script) to get the 20-byte script hash
# for querying the PIR servers.

set -e

# Server addresses
SERVER1_ADDR="127.0.0.1:8081"
SERVER2_ADDR="127.0.0.1:8082"

# Default script hex (example P2PKH script)
DEFAULT_SCRIPT_HEX="76a9148d87ce8f7d12f2565f029809fa4c4001bf0eb64d88ac"

# Build the client first
echo "Building client..."
cd "$(dirname "$0")/.."
cargo build --release --bin client

echo ""

# Run the client with all arguments
# The client binary handles argument parsing
RUST_LOG=info ./target/release/client \
    --server1 "$SERVER1_ADDR" \
    --server2 "$SERVER2_ADDR" \
    "$@"

echo ""
echo "Query complete."