# Web Client & WebSocket Protocol

## Overview

The PIR system uses WebSocket for all client-server communication. This enables direct browser connections without any intermediary.

Current browser flows use the Rust SDK through `pir-sdk-wasm` for DPF and
HarmonyPIR. The TypeScript adapters are responsible for UI state, IndexedDB hint
storage, address parsing, and status badges; padding, Merkle verification,
runtime attestation, encrypted-channel setup, and database-build proof
verification live below the WASM boundary.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        PIR Server                               │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              WebSocket Listener (Port 8091/8092)         │   │
│  │                                                          │   │
│  │  For Browser/JS Clients and Rust Clients                │   │
│  │  - Persistent connection                                │   │
│  │  - Multiple queries per conn                            │   │
│  │  - Simple Binary Protocol                               │   │
│  └───────────────────────────┬─────────────────────────────┘   │
│                              │                                  │
│                              ▼                                  │
│           ┌─────────────────────────────────┐                  │
│           │      Query Handler              │                  │
│           │  - Parse Request                │                  │
│           │  - Evaluate DPF                 │                  │
│           │  - XOR buckets                  │                  │
│           │  - Return Response              │                  │
│           └─────────────────────────────────┘                  │
│                              │                                  │
│                              ▼                                  │
│           ┌─────────────────────────────────┐                  │
│           │      Database Registry          │                  │
│           │  - utxo_cuckoo_index            │                  │
│           │  - utxo_chunks_data             │                  │
│           └─────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

## File Structure

```
runtime/src/
├── bin/
│   ├── server.rs          # WebSocket server
│   └── client.rs          # WebSocket CLI client
├── eval.rs                # DPF evaluation engine
├── protocol.rs            # Binary protocol codec
└── lib.rs                 # Module exports

web/src/
├── dpf-adapter.ts         # DPF UI adapter over WasmDpfClient
├── harmonypir-adapter.ts  # HarmonyPIR UI adapter over WasmHarmonyClient
├── db-proof.ts            # Browser-side DB proof status/pin helpers
├── attest-pin.ts          # Runtime + DB proof production pins
├── sdk-bridge.ts          # pir-sdk-wasm loader/type bridge
├── hash.ts                # Address/script hashing helpers
├── server-info.ts         # Catalog, server-info, residency helpers
└── index.ts               # Public web exports
```

## Runtime and Database Attestation

The browser renders two distinct badges:

- Runtime attestation: DPF and HarmonyPIR call the WASM attestation API against
  pir1 and pir2. pir2 is checked against the SEV-SNP Tier 3 measurement,
  binary hash, AMD ARK/VCEK chain, encrypted-channel binding, and operator
  identity pins in `web/src/attest-pin.ts`.
- Database build attestation: DPF and HarmonyPIR fetch `REQ_GET_DB_PROOF`
  (`0x0a`) for each configured `PRODUCTION_DB_PROOF_PINS` entry, verify the
  attested-builder evidence in WASM, and compare the result to the pinned block
  range, Bitcoin Core MuHash, bucket Merkle root, onion Merkle root, builder
  binary hash, builder commit, network magic, and params hash.

The current production DB proof is `delta_940611_948454` (`db_id = 1`) with
MuHash `cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee`
at block `948454`
(`00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4`).
This is advisory in the UI today; the remaining strict-mode work is to make
query-path Merkle verification consume the verified roots directly and to add
the same proof path to standalone OnionPIR.

## Running the System

### Start Servers

```bash
./scripts/start_pir_servers.sh
```

This starts two WebSocket servers:
- Server 1: `ws://localhost:8091`
- Server 2: `ws://localhost:8092`

### Web Client (Development)

```bash
cd web
npm install
npx vite --port 8080
```

### Web Client (Production Build)

```bash
cd web
npm run build-web
# Output in dist-web/, deploy to static hosting
```

## WebSocket Protocol

### Message Format

All messages use the Simple Binary Protocol (SBP) — a compact binary format:

**Request Types:**
- `Ping` — `[0x01]`
- `ListDatabases` — `[0x03]`
- `GetDatabaseInfo` — `[0x05][db_id_len:u16][db_id:bytes]`
- `QueryDatabaseSingle` — `[0x07][query_data...]`
- `QueryDatabase` — `[0x07][query_data...]` (two DPF keys)

**Response Types:**
- `Pong` — `[0x02]`
- `DatabaseList` — `[0x04][count:u32][entries...]`
- `DatabaseInfo` — `[0x06][info_data...]`
- `QueryResult` — `[0x08][response_data...]`
- `Error` — `[0xFF][error_message]`

### Connection Lifecycle

```
Client                          Server
  │                               │
  │──── WebSocket Handshake ────▶│
  │                               │
  │──── Ping ────────────────────▶│
  │◀─── Pong ─────────────────────│
  │                               │
  │──── Query (DPF key) ────────▶│
  │◀─── QueryResult ──────────────│
  │         ...                   │
  │                               │
  │──── Close Frame ─────────────▶│
  │◀─── Close Frame ──────────────│
```

### Heartbeat

The web client sends periodic Ping messages to keep connections alive. Pong responses are handled by a central message dispatcher that routes them separately from query responses, preventing race conditions.

## Two-Phase PIR Query

### Phase 1: Cuckoo Index Lookup

1. Client computes HASH160 = RIPEMD160(SHA256(scriptPubKey))
2. Client computes two cuckoo bucket locations from the HASH160
3. Client generates DPF keys targeting both locations
4. Each server evaluates its DPF key across all buckets and XORs matching entries
5. Client XORs both server responses to recover the bucket contents
6. Client searches the bucket for the matching 20-byte HASH160 key
7. The associated 4-byte value is the chunk offset (stored as byte_offset / 2)

### Phase 2: Chunk Data Retrieval

1. Client computes chunk_index = (offset * 2) / 32768
2. Client generates DPF keys for the chunk index
3. Servers evaluate and return XOR'd chunk data
4. Client XORs responses to recover the 32KB chunk
5. Client seeks to local_offset = (offset * 2) % 32768 within the chunk
6. Client reads varint-encoded UTXO entries: [count][32B TXID + varint vout + varint amount] × count

### Whale Address Detection

Addresses with more than 100 UTXOs are excluded from the PIR database during
generation (`gen_1`). Instead of being omitted entirely, a sentinel index entry
is written with `num_chunks = 0` and `flags = 0x40` (bit 6 = `FLAG_WHALE`).

After the index PIR lookup, the client checks for this sentinel:
- `numChunks == 0` **and** `(flags & 0x40) != 0` → whale address, excluded
- Entry not found at all → address not in database (no UTXOs / unknown)

The client displays a notification explaining that the address was excluded due
to having too many UTXOs, rather than a generic "Not Found" message.

## Key Constants

```typescript
// Database IDs
CUCKOO_DB_ID = "utxo_cuckoo_index"
CHUNKS_DB_ID = "utxo_chunks_data"

// Database parameters
CUCKOO_NUM_BUCKETS = 15_385_139
CUCKOO_ENTRY_SIZE = 24        // 20B key + 4B offset
CUCKOO_SLOTS_PER_BIN = 4
CHUNK_SIZE = 32_768            // 32KB
CHUNKS_NUM_ENTRIES = 181_833   // normal (65_294 for small)
```

## Implementation Checklist

- [x] WebSocket server (`server.rs`)
- [x] WebSocket CLI client (`lookup_pir.rs`)
- [x] WebSocket protocol handler (`websocket.rs`)
- [x] Server startup script (`start_pir_servers.sh`)
- [x] Test script (`test_lookup_pir.sh`)
- [x] TypeScript web client library
- [x] Browser demo page with Vite bundling
- [x] GitHub Pages deployment via GitHub Actions
- [x] TLS support (native + Cloudflare Tunnel)
- [x] Heartbeat with race-condition-safe message dispatch
