# PIR SDK WASM

WASM bindings for the PIR SDK, enabling Rust-backed PIR functionality in JavaScript/TypeScript.

## Features

- **Sync Planning**: Compute optimal sync paths using BFS delta chaining
- **Delta Merging**: Apply delta data to snapshot results
- **Hash Functions**: WASM-accelerated hashing (splitmix64, cuckoo hash, etc.)
- **PBC Utilities**: Cuckoo placement and multi-round planning
- **Codec**: Varint reading and UTXO data decoding

## Installation

### From npm (when published)

```bash
npm install pir-sdk-wasm
```

### Local development

```bash
# Build the WASM package
cd pir-sdk-wasm
wasm-pack build --target web --out-dir pkg

# Link to web project
cd ../web
npm link ../pir-sdk-wasm/pkg
```

## Usage

### Basic Usage

```typescript
import init, {
  WasmDatabaseCatalog,
  computeSyncPlan,
} from 'pir-sdk-wasm';

// Initialize WASM module
await init();

// Create catalog from server response
const catalog = WasmDatabaseCatalog.fromJson({
  databases: [
    {
      dbId: 0,
      dbType: 0, // 0 = full, 1 = delta
      name: 'snapshot_900000',
      baseHeight: 0,
      height: 900000,
      indexBins: 750000,
      chunkBins: 1500000,
      indexK: 75,
      chunkK: 80,
    },
  ],
});

// Compute sync plan
const plan = computeSyncPlan(catalog, undefined); // fresh sync
console.log(`Steps: ${plan.stepsCount}`);
console.log(`Target height: ${plan.targetHeight}`);
console.log(`Fresh sync: ${plan.isFreshSync}`);

// Iterate steps
for (let i = 0; i < plan.stepsCount; i++) {
  const step = plan.getStep(i);
  console.log(`Step ${i}: ${step.name} (${step.dbType})`);
}

// Free WASM memory when done
plan.free();
catalog.free();
```

### Using with Existing Web Client

The `sdk-bridge.ts` module provides a migration path:

```typescript
import {
  initSdkWasm,
  isSdkWasmReady,
  computeSyncPlanSdk,
} from './sdk-bridge.js';

// Try to load SDK WASM
await initSdkWasm();

// Use SDK-backed function (falls back to TS if WASM unavailable)
const plan = computeSyncPlanSdk(catalog, lastHeight);
```

### Hash Functions

```typescript
import {
  splitmix64,
  computeTag,
  deriveGroups,
  deriveCuckooKey,
  cuckooHash,
} from 'pir-sdk-wasm';

// Hash functions use (hi, lo) u32 pairs for u64 values
const result = splitmix64(0, 12345); // Returns Uint8Array(8)

// Derive groups for a script hash
const groups = deriveGroups(scriptHash, 75); // Returns Uint32Array(3)

// Cuckoo hash
const bin = cuckooHash(scriptHash, keyHi, keyLo, numBins);
```

### Delta Merging

```typescript
import {
  WasmQueryResult,
  mergeDelta,
  decodeDeltaData,
} from 'pir-sdk-wasm';

// Decode delta data
const delta = decodeDeltaData(rawDeltaBytes);
console.log(`Spent: ${delta.spent.length}`);
console.log(`New UTXOs: ${delta.newUtxos.length}`);

// Merge delta into snapshot
const snapshot = WasmQueryResult.fromJson({
  entries: [
    { txid: '...', vout: 0, amountSats: 1000 },
  ],
  isWhale: false,
});

const merged = mergeDelta(snapshot, rawDeltaBytes);
console.log(`New balance: ${merged.totalBalance}`);

// Free WASM memory
merged.free();
snapshot.free();
```

## API Reference

### Classes

- `WasmDatabaseCatalog` - Database catalog wrapper
- `WasmSyncPlan` - Sync plan with steps
- `WasmQueryResult` - Query result with UTXO entries

### Functions

#### Sync Planning
- `computeSyncPlan(catalog, lastHeight?)` - Compute optimal sync path

#### Delta Merging
- `decodeDeltaData(raw)` - Decode delta bytes
- `mergeDelta(snapshot, deltaRaw)` - Apply delta to snapshot

#### Hash Functions
- `splitmix64(xHi, xLo)` - Splitmix64 finalizer
- `computeTag(seedHi, seedLo, scriptHash)` - Compute fingerprint tag
- `deriveGroups(scriptHash, k)` - Derive 3 group indices
- `deriveCuckooKey(seedHi, seedLo, groupId, hashFn)` - Derive cuckoo key
- `cuckooHash(scriptHash, keyHi, keyLo, numBins)` - Cuckoo hash
- `deriveChunkGroups(chunkId, k)` - Derive chunk group indices
- `cuckooHashInt(chunkId, keyHi, keyLo, numBins)` - Cuckoo hash for integers

#### PBC Utilities
- `cuckooPlace(candGroups, numItems, numGroups, maxKicks, numHashes)` - Cuckoo placement
- `planRounds(itemGroups, itemsPer, numGroups, numHashes, maxKicks)` - Multi-round planning

#### Codec
- `readVarint(data, offset)` - Read LEB128 varint
- `decodeUtxoData(data)` - Decode UTXO data

## Building

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web
wasm-pack build --target web --out-dir pkg

# Build for Node.js
wasm-pack build --target nodejs --out-dir pkg-node

# Build with optimizations
wasm-pack build --target web --release --out-dir pkg
```

## License

MIT OR Apache-2.0
