# Bitcoin PIR - Private Information Retrieval for Bitcoin UTXOs

A privacy-preserving system for querying Bitcoin UTXO (Unspent Transaction Output) data using Distributed Point Function (DPF) based Private Information Retrieval (PIR).

## Overview

This project enables querying the Bitcoin UTXO set without revealing which addresses you're interested in. Using a two-server PIR architecture with DPF, the servers learn nothing about your queries as long as they don't collude.

### Key Features

- 🔒 **Privacy-Preserving**: Servers cannot determine which addresses are being queried
- ⚡ **DPF-Based**: Uses Distributed Point Functions for efficient PIR
- 🌐 **Web Compatible**: Browser and Node.js clients via WebSocket
- 🔐 **TLS Support**: Secure WebSocket (wss://) for production deployments
- 📦 **High Performance**: Memory-mapped databases for fast queries

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENT                                    │
│  ┌────────────────────┐    ┌────────────────────┐               │
│  │   Web Browser      │    │   Rust CLI         │               │
│  │   (TypeScript)     │    │   (lookup_pir)     │               │
│  └─────────┬──────────┘    └─────────┬──────────┘               │
│            │                         │                           │
│            └───────────┬─────────────┘                           │
│                        │                                         │
│              WebSocket Connections                                │
│           (ws:// or wss://)                                       │
└────────────────────────┼─────────────────────────────────────────┘
                         │
           ┌─────────────┴─────────────┐
           ▼                           ▼
┌──────────────────────┐    ┌──────────────────────┐
│      SERVER 1        │    │      SERVER 2        │
│   (port 8091)        │    │   (port 8092)        │
│                      │    │                      │
│  ┌────────────────┐  │    │  ┌────────────────┐  │
│  │  Databases     │  │    │  │  Databases     │  │
│  │  (identical)   │  │    │  │  (identical)   │  │
│  └────────────────┘  │    │  └────────────────┘  │
└──────────────────────┘    └──────────────────────┘

PIR Security Model: Privacy guaranteed if at least one server doesn't learn queries.
```

## Project Structure

```
BitcoinPIR/
├── dpf_pir/                    # PIR server implementation (Rust)
│   ├── src/
│   │   ├── lib.rs              # Library exports
│   │   ├── database.rs         # Database trait & implementations
│   │   ├── protocol.rs         # Request/Response types
│   │   ├── pir_protocol.rs     # Simple Binary Protocol
│   │   ├── hash.rs             # Cuckoo hash functions
│   │   ├── websocket.rs        # WebSocket handler
│   │   ├── server_config.rs    # Database configuration
│   │   └── bin/
│   │       ├── server.rs       # WebSocket server binary
│   │       ├── servers.rs      # Multi-server manager
│   │       ├── lookup_pir.rs   # CLI client
│   │       └── lookup_script.rs # Script lookup tool
│   └── Cargo.toml
│
├── build_db/                   # Database generation tools (Rust)
│   └── src/bin/
│       ├── gen_1_txid_file.rs           # Extract TXIDs from blk*.dat
│       ├── gen_2_mphf.rs                # Build minimal perfect hash
│       ├── gen_3_location_index.rs      # Build location index
│       ├── gen_4_utxo_remapped.rs       # Extract UTXOs with 4B TXIDs
│       ├── gen_5_utxo_chunks_from_remapped.rs  # Generate UTXO chunks
│       ├── gen_6_utxo_4b_to_32b.rs      # Build TXID mapping
│       ├── gen_7_cuckoo_chunks.rs       # Build cuckoo index
│       ├── gen_8_cuckoo_txid.rs         # Build cuckoo TXID index
│       └── README.md                    # Detailed pipeline docs
│
├── web_client/                 # Browser/Node.js client (TypeScript)
│   ├── src/
│   │   ├── index.ts            # Main entry point
│   │   ├── client.ts           # WebSocket client
│   │   ├── dpf.ts              # DPF wrapper
│   │   ├── hash.ts             # Hash functions
│   │   ├── bincode.ts          # Binary serialization
│   │   └── constants.ts        # System constants
│   ├── package.json
│   └── README.md
│
├── scripts/                    # Helper scripts
│   ├── start_pir_servers.sh    # Start both PIR servers
│   ├── test_lookup_pir.sh      # Test PIR lookup
│   └── run_client.sh           # Run client script
│
└── doc/                        # Documentation
    ├── DEPLOYMENT.md           # Production deployment guide
    └── WEB.md                  # Web client implementation
```

## Quick Start

### 1. Build the Project

```bash
# Clone the repository
git clone https://github.com/weikengchen/Bitcoin-PIR.git
cd Bitcoin-PIR

# Build all components
cargo build --release
```

### 2. Generate Database Files

The database pipeline transforms Bitcoin blockchain data into PIR-queryable format:

```bash
# Step 1: Extract TXIDs from Bitcoin blk*.dat files
cargo run --release --bin gen_1_txid_file -- /path/to/bitcoin

# Step 2: Build minimal perfect hash function
cargo run --release --bin gen_2_mphf

# Step 3: Build location index
cargo run --release --bin gen_3_location_index

# Step 4: Extract UTXOs (requires stopped bitcoind)
cargo run --release --bin gen_4_utxo_remapped -- /path/to/bitcoin

# Step 5: Generate UTXO chunks
cargo run --release --bin gen_5_utxo_chunks_from_remapped

# Step 6: Build TXID mapping
cargo run --release --bin gen_6_utxo_4b_to_32b

# Step 7: Build cuckoo hash index
cargo run --release --bin gen_7_cuckoo_chunks

# Step 8: Build cuckoo TXID index
cargo run --release --bin gen_8_cuckoo_txid
```

See [`build_db/src/bin/README.md`](build_db/src/bin/README.md) for detailed documentation.

### 3. Configure Server

Edit `dpf_pir/src/server_config.rs` to set your database paths:

```rust
// Update paths to match your data location
let cuckoo_config = DatabaseConfig::new(
    "utxo_cuckoo_index",
    "/data/pir/utxo_chunks_cuckoo.bin",  // Your path here
    24,    // entry_size
    1,     // bucket_size
    15_385_139,  // num_buckets
    2,     // num_locations (cuckoo)
);
```

Rebuild after configuration changes:
```bash
cargo build --release --bin server
```

### 4. Start PIR Servers

```bash
# Start both servers (ports 8091 and 8092)
./scripts/start_pir_servers.sh
```

Or manually:
```bash
# Server 1
RUST_LOG=info ./target/release/server --port 8091

# Server 2 (in another terminal)
RUST_LOG=info ./target/release/server --port 8092
```

### 5. Query UTXOs

**Using CLI:**
```bash
# Build the client
cargo build --release --bin lookup_pir

# Query by script pubkey hash
./target/release/lookup_pir --server1 ws://127.0.0.1:8091 --server2 ws://127.0.0.1:8092 "76a914b64513c1f1b889a556463243cca9c26ee626b9a088ac"
```

**Using Web Client:**
```bash
cd web_client
npm install
npm run build

# Open example.html in browser, or serve it:
python -m http.server 8000
# Navigate to http://localhost:8000/example.html
```

## Databases

The system uses three databases for PIR queries:

### 1. UTXO Cuckoo Index (`utxo_cuckoo_index`)
- **Purpose**: Maps script hashes to UTXO chunk indices
- **Hash**: Cuckoo hashing with 2 locations
- **Entry size**: 24 bytes
- **Buckets**: ~15.4 million

### 2. UTXO Chunks Data (`utxo_chunks_data`)
- **Purpose**: Contains actual UTXO data in chunks
- **Format**: Direct index lookup (no hashing)
- **Entry size**: 1024 bytes
- **Entries**: ~1.2 million

### 3. TXID Mapping (`utxo_4b_to_32b`)
- **Purpose**: Maps 4-byte TXID prefixes to full 32-byte TXIDs
- **Hash**: Cuckoo hashing with 4 entries per bucket
- **Entry size**: 36 bytes (4-byte key + 32-byte TXID)
- **Buckets**: ~30 million

## Query Flow

1. **Compute script hash**: RIPEMD160 of scriptPubkey
2. **Calculate cuckoo locations**: Two hash locations for the script hash
3. **Query cuckoo index**: PIR query to get chunk indices
4. **Query chunks**: PIR query to retrieve UTXO data
5. **Combine results**: XOR responses from both servers
6. **Resolve TXIDs**: Query TXID mapping for full TXIDs

## WebSocket Protocol

The server uses a Simple Binary Protocol over WebSocket:

| Message Type | Format |
|--------------|--------|
| Ping | `[0x01]` |
| Pong | `[0x02]` |
| List Databases | `[0x03]` |
| Database List | `[0x04][count:u32][entries...]` |
| Get Database Info | `[0x05][db_id_len:u16][db_id:bytes]` |
| Database Info | `[0x06][info_data...]` |
| Query | `[0x07][query_data...]` |
| Query Response | `[0x08][response_data...]` |
| Error | `[0xFF][error_message]` |

## TLS/SSL Support

For production deployments, use secure WebSocket (wss://):

```bash
# Generate self-signed certificate (testing)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run server with TLS
./target/release/server --port 8091 \
    --tls-cert /path/to/cert.pem \
    --tls-key /path/to/key.pem
```

For production, use Let's Encrypt certificates. See [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) for complete deployment instructions.

## API Reference

### Rust Library

```rust
use dpf_pir::{
    Database, DatabaseConfig, DatabaseRegistry,
    CuckooDatabase, UtxoChunkDatabase, TxidMappingDatabase,
    cuckoo_locations_default, txid_mapping_locations,
};

// Create a cuckoo database
let config = DatabaseConfig::new(
    "my_db",
    "/path/to/data.bin",
    24,     // entry_size
    1,      // bucket_size
    1000000, // num_buckets
    2,      // num_locations
);
let db = CuckooDatabase::with_mmap(config)?;

// Compute hash locations
let key = hex::decode("76a914...88ac")?;
let (loc1, loc2) = cuckoo_locations_default(&key, db.num_buckets());

// Read bucket entries
let entries = db.read_bucket(loc1)?;
```

### TypeScript Client

```typescript
import { createPirClient, hexToBytes, cuckooHash1, cuckooHash2 } from 'bitcoin-pir';

// Create client
const client = createPirClient(
  'wss://server1.example.com',
  'wss://server2.example.com'
);

// Connect
await client.connect();

// Query database
const result = await client.queryDatabase(
  'utxo_cuckoo_index',
  location1,
  location2,
  24  // DPF parameter
);

// Disconnect
client.disconnect();
```

## Development

```bash
# Build all components
cargo build --release

# Run tests
cargo test

# Build web client
cd web_client && npm run build

# Run web client tests
cd web_client && npm test
```

## Dependencies

### Rust
- `tokio` - Async runtime
- `tokio-tungstenite` - WebSocket support
- `tokio-rustls` - TLS support
- `serde` / `bincode` - Serialization
- `memmap2` - Memory-mapped files
- `libdpf` - DPF implementation
- `sha2`, `ripemd` - Hash functions

### Web Client
- TypeScript 5+
- Node.js 18+ or modern browser
- WebSocket API

## Security Model

### Privacy Guarantees
- **Two-server model**: Privacy is guaranteed if at least one server is honest
- **DPF-based queries**: Each server receives a different DPF key
- **No query logging**: The library does not log query details

### Requirements
- Servers MUST NOT collude
- Use different hosting providers for each server
- Enable TLS in production
- Keep database files synchronized between servers

## Performance

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cuckoo Index Query | ~10-50ms | Memory-mapped access |
| Chunk Query | ~10-50ms | Direct index lookup |
| TXID Mapping Query | ~10-50ms | Cuckoo with 4 entries/bucket |
| Full UTXO Lookup | ~100-200ms | All three queries combined |

## Documentation

- [`build_db/src/bin/README.md`](build_db/src/bin/README.md) - Database generation pipeline
- [`doc/DEPLOYMENT.md`](doc/DEPLOYMENT.md) - Production deployment guide
- [`doc/WEB.md`](doc/WEB.md) - Web client implementation
- [`web_client/README.md`](web_client/README.md) - Web client API reference

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- [Private Information Retrieval](https://en.wikipedia.org/wiki/Private_information_retrieval)
- [Distributed Point Functions](https://eprint.iacr.org/2013/679.pdf)
- [Bitcoin UTXO Model](https://developer.bitcoin.org/devguide/transactions.html)
- [Cuckoo Hashing](https://en.wikipedia.org/wiki/Cuckoo_hashing)
<task_progress>- [x] Explore current README and project structure
- [x] Understand the main components (build_db, dpf_pir, web_client)
- [x] Review documentation in subdirectories
- [x] Write comprehensive README update
- [ ] Verify completeness</task_progress>
</write_to_file>