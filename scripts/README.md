# Bitcoin PIR Scripts

This directory contains scripts for data acquisition, indexing, and querying.

## Index Scripts (Phase 1.5)

### index_blocks.py
Creates global indices for transactions and ScriptPubKeys from a local Bitcoin node.

**Usage**:
```bash
python3 scripts/index_blocks.py --rpc-user <user> --rpc-password <pass> --count 100 --from-tip
```

**Features**:
- Fetches blocks via Bitcoin Core JSON-RPC
- Assigns sequential 4-byte global TXIDs (independent of block boundaries)
- Assigns sequential 2-byte global ScriptPubKey IDs
- Creates binary index files:
  - `tx_global_index.bin` (18 bytes per transaction)
  - `spk_global_index.bin` (variable length per SPK)
  - `spk_global_lookup.bin` (34 bytes per unique SPK)
  - `index_meta.json` (metadata and statistics)

**Requirements**:
- Bitcoin Core node running with RPC enabled
- Node synced to blockchain
- RPC credentials (username and password)

### query_index.py
Queries the generated indices to verify correctness and test lookups.

**Usage**:
```bash
# Show index summary
python3 scripts/query_index.py --summary

# Get transaction by global ID
python3 scripts/query_index.py --get-tx 42

# List transactions
python3 scripts/query_index.py --get-all-tx

# Get ScriptPubKey by ID
python3 scripts/query_index.py --get-spk 10

# Get ScriptPubKey ID by hex
python3 scripts/query_index.py --get-spk-by-hex <spk_hex>
```

## Deprecated Scripts (Phase 1 - API-based)

### fetch_blocks.py.broken
Original blockchain.info API fetcher. Broken due to API rate limiting.

### fetch_blocks_v2.py
BlockCypher API fetcher. Partially successful (91 blocks), then rate limited. Deprecated in favor of local node approach.

### continue_fetch.py
Attempted to continue fetching from BlockCypher after rate limit. Unsuccessful.

## PIR Scripts (Phases 2-4, To Be Created)

### pir_client.py
Client for querying PIR server (to be created in Phase 2/3)

### pir_server.py
PIR server implementation (to be created in Phase 2/3)
