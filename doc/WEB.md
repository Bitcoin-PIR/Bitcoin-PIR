# Web Frontend Implementation Plan for Bitcoin PIR

## Executive Summary

**Status: ✅ WEBSOCKET IMPLEMENTATION COMPLETE**

The PIR system now uses **WebSocket only** for both server and client communication. This enables direct browser client connections.

---

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
│  │  - Binary bincode protocol                              │   │
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
│           │  - utxo_4b_to_32b               │                  │
│           └─────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Current Implementation

### File Structure

```
dpf_pir/src/
├── bin/
│   ├── server.rs          # WebSocket server
│   └── lookup_pir.rs      # WebSocket client
├── websocket.rs           # WebSocket protocol handler
├── protocol.rs            # Request/Response types
└── ...
```

### Dependencies

```toml
# dpf_pir/Cargo.toml
[dependencies]
tokio-tungstenite = "0.21"
futures-util = "0.3"
```

---

## Running the System

### Start Servers

```bash
./scripts/start_pir_servers.sh
```

This starts two WebSocket servers:
- Server 1: `ws://localhost:8091`
- Server 2: `ws://localhost:8092`

### Test Client

```bash
./scripts/test_lookup_pir.sh
```

---

## WebSocket Protocol

### Message Format

All messages are **binary** using bincode serialization:

**Request:**
- `QueryDatabase { database_id, dpf_key1, dpf_key2 }`
- `QueryDatabaseSingle { database_id, dpf_key }`
- `ListDatabases`
- `GetDatabaseInfo { database_id }`
- `Ping`

**Response:**
- `QueryResult { data: Vec<u8> }`
- `QueryTwoResults { data1, data2 }`
- `DatabaseList { databases }`
- `DatabaseInfo { info }`
- `Error { message }`
- `Pong`

### Connection Lifecycle

```
Client                          Server
  │                               │
  │──── WebSocket Handshake ────▶│
  │                               │
  │──── Binary Request ─────────▶│
  │◀─── Binary Response ─────────│
  │         ...                   │
  │                               │
  │──── Close Frame ────────────▶│
  │◀─── Close Frame ─────────────│
```

---

## JavaScript Client Implementation

### Components Needed

| Component | Status | Notes |
|-----------|--------|-------|
| **DPF** | ✅ Available | `libdpf-ts` exists |
| **Cuckoo Hash** | ✅ Implementable | Simple arithmetic |
| **RIPEMD160** | ✅ Available | Web Crypto or `hash.js` |
| **Bincode** | ⚠️ Needed | Implement subset |
| **WebSocket** | ✅ Native | Browser built-in |

### Key Constants

```typescript
const CUCKOO_DB_ID = "utxo_cuckoo_index";
const CHUNKS_DB_ID = "utxo_chunks_data";
const TXID_MAPPING_DB_ID = "utxo_4b_to_32b";

const CUCKOO_NUM_BUCKETS = 15_385_139;
const CHUNKS_NUM_ENTRIES = 33_038;
const CHUNK_SIZE = 32 * 1024;
const TXID_MAPPING_NUM_BUCKETS = 30_097_234;
```

### Example Browser Client

```javascript
const ws = new WebSocket('ws://localhost:8091');
ws.binaryType = 'arraybuffer';

ws.onopen = () => {
    // Send bincode-serialized request
    const request = encodeRequest({ Ping: {} });
    ws.send(request);
};

ws.onmessage = (event) => {
    const response = decodeResponse(event.data);
    console.log('Response:', response);
};
```

---

## Implementation Checklist

- [x] WebSocket server (`server.rs`)
- [x] WebSocket client (`lookup_pir.rs`)
- [x] WebSocket protocol handler (`websocket.rs`)
- [x] Server startup script (`start_pir_servers.sh`)
- [x] Test script (`test_lookup_pir.sh`)
- [x] JavaScript/TypeScript web client library
- [x] Browser demo HTML page
