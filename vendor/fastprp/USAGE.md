# fastprp — Fast Pseudo-Random Permutations for Small Domains

Rust implementation of Stefanov & Shi (2012), "FastPRP: Fast Pseudo-Random
Permutations for Small Domains."  Provides bijective, key-controlled
permutations over arbitrary domains {0, 1, ..., N-1} with efficient
single-element lookup (no need to materialise the full table).

Available as a **Rust library** and a **WASM module** for browser/Node.js.

## Quick start (Rust)

```toml
# Cargo.toml
[dependencies]
fastprp = { path = "../fastprp" }   # or git url once published
rayon   = "1.10"                     # only needed for parallel batch
```

```rust
use fastprp::FastPrp;

let key = [0u8; 16]; // 128-bit AES key
let n   = 1_000_000; // domain size

let prp = FastPrp::new(&key, n);

// Single-element encrypt / decrypt  (O(sqrt(N) log N) each)
let y = prp.permute(42);       // 42  -> some y in [0, N)
let x = prp.unpermute(y);      // y   -> 42
assert_eq!(x, 42);
```

## Quick start (WASM / JavaScript)

```bash
# Build the WASM package
wasm-pack build --target web --features wasm    # for browsers
wasm-pack build --target nodejs --features wasm  # for Node.js
```

```js
import init, { WasmFastPrp } from './pkg/fastprp.js';
await init();

const key = new Uint8Array(16); // 128-bit AES key
const n = 1_000_000;

// Build from scratch (builds caches from key)
const prp = new WasmFastPrp(key, n);

const y = prp.permute(42);     // 42  -> some y in [0, N)
const x = prp.unpermute(y);    // y   -> 42
console.assert(x === 42);

// Export cache for server→client transfer
const cacheBytes = prp.exportCacheBytes();  // Uint8Array

// Client: load from server-provided cache
const prp2 = WasmFastPrp.fromCacheBytes(key, n, cacheBytes);

// Client: refine cache locally for faster lookups
prp2.refineTo(2048);  // halve stride until ≤ 2048

prp.free();   // release WASM memory when done
prp2.free();
```

## Rust API reference

### Construction

```rust
// Default cache stride  s = 2*sqrt(N).
let prp = FastPrp::new(key: &[u8; 16], n: u64) -> FastPrp;

// Custom stride — smaller stride = more cache memory, faster per-lookup.
let prp = FastPrp::with_stride(key: &[u8; 16], n: u64, stride: u64) -> FastPrp;

// Reconstruct from pre-built caches (for cache persistence / transfer).
let prp = FastPrp::from_parts(key: &[u8; 16], n: u64, cache: CounterCache, pcache: PartitionCache);
```

`FastPrp` is `Sync + Send` — a single instance can be shared across threads
for concurrent `permute()` / `unpermute()` calls (all read-only).

### Single-element operations

```rust
prp.permute(x: u64) -> u64      // PRP encrypt:  x  -> y
prp.unpermute(y: u64) -> u64    // PRP decrypt:  y  -> x
```

Both are O(sqrt(N) * log N) using the internal counter cache.  No heap
allocation per call.  Thread-safe (`&self`).

### 4-way batched lookup

```rust
prp.permute_4(inputs: [u64; 4]) -> [u64; 4]
```

Processes 4 independent permutations with pipelined AES bit-lookups and
shared partition-cache scans.

### Full-domain batch permute

```rust
prp.batch_permute() -> Vec<u64>
```

Returns a table where `result[x] = permute(x)` for all x in {0, ..., N-1}.
O(N log N) time, O(N) memory. Single-threaded (depth d+1 depends on d).

### Incremental caching (Section 5.3)

```rust
// Build coarse cache (small, fast)
let mut cache = CounterCache::new(&gen, coarse_stride);

// Refine locally — each step halves the stride
cache.refine(&gen);              // one step
cache.refine_to(&gen, 2048);     // refine until stride ≤ 2048

// Cache serialization for transfer
let raw = cache.raw_cache();     // serialize
let cache = CounterCache::from_raw(stride, num_depths, n, raw);  // deserialize
```

### Inspecting the instance

```rust
prp.domain_size()     -> u64    // N
prp.cache_stride()    -> u64    // s
prp.cache_size_bytes() -> usize // total cache memory
```

## WASM API reference

### Construction

```js
// Build from scratch (both caches built from key)
const prp = new WasmFastPrp(key_u8, n);

// Custom stride
const prp = WasmFastPrp.withStride(key_u8, n, stride);

// Load from pre-serialized cache bytes (server → client transfer)
const prp = WasmFastPrp.fromCacheBytes(key_u8, n, cacheBytes_u8);
```

### Operations

```js
prp.permute(x)                    // forward PRP: x → y
prp.unpermute(y)                  // inverse PRP: y → x
prp.permute4(x0, x1, x2, x3)     // returns Float64Array(4)
prp.batchPermute()                // returns Float64Array(N)
```

### Incremental caching

```js
prp.refine()                      // halve stride once
prp.refineTo(targetStride)        // refine until stride ≤ target
```

### Cache transfer

```js
const bytes = prp.exportCacheBytes()  // Uint8Array — send to client
const prp = WasmFastPrp.fromCacheBytes(key, n, bytes)  // client loads
```

### Getters

```js
prp.domainSize      // N
prp.cacheStride     // current stride
prp.cacheSizeBytes  // cache memory in bytes
```

## Recommended patterns

### Server → client workflow (PIR)

1. **Server** builds FastPrp with desired stride, exports cache:
   ```rust
   let prp = FastPrp::with_stride(&key, n, stride);
   let bytes = serialize(prp.counter_cache(), prp.partition_cache());
   // Send key + bytes to client
   ```

2. **Client** (browser, WASM) loads cache and optionally refines:
   ```js
   const prp = WasmFastPrp.fromCacheBytes(key, n, serverBytes);
   prp.refineTo(2048);  // optional: expand cache for faster lookups
   const y = prp.permute(x);
   const x = prp.unpermute(y);
   ```

### Cache stride vs query count tradeoff (N = 2^21)

For a fixed workload of ~2,048 PRP calls (1024 forward + 1024 inverse):

| Stride | Cache | Init time | 2048 queries | Init + queries |
|--------|-------|-----------|-------------|----------------|
| 8√N | 9 KB | 40 ms | 70 ms | **110 ms** |
| 4√N | 20 KB | 52 ms | 56 ms | **108 ms** |
| 2√N [default] | 42 KB | 71 ms | 47 ms | **118 ms** |
| √N | 90 KB | 90 ms | 40 ms | **130 ms** |
| √N/4 | 407 KB | 214 ms | 32 ms | **246 ms** |

Sweet spot for ~2K queries: **stride = 4√N–8√N** (~108 ms total).
For >8K queries, smaller strides pay for themselves.

### Offline full-table generation (one key, all N elements)

Split into independent buckets and parallelise:

```rust
use rayon::prelude::*;

let total_n: u64 = 1 << 27;
let num_buckets: u64 = 200;
let bucket_size = total_n / num_buckets;

let tables: Vec<Vec<u64>> = (0..num_buckets)
    .into_par_iter()
    .map(|b| {
        let mut k = master_key;
        k[0] = (b & 0xFF) as u8;
        k[1] = ((b >> 8) & 0xFF) as u8;
        let prp = FastPrp::new(&k, bucket_size);
        prp.batch_permute()
    })
    .collect();
```

Typical performance at N = 2^27 total (Apple M-series, 24 cores):

| Buckets | Bucket size | Wall-clock |
|---------|-------------|------------|
| 80 | 1.68M | 1.0 s |
| 200 | 671K | 0.85 s |
| 400 | 336K | 0.72 s |

## Performance reference

### Native (Apple M-series, single core, default stride 2√N)

| N | `new()` | `permute()` | `unpermute()` | `batch_permute()` |
|-------|---------|-------------|---------------|-------------------|
| 2^14 | <1 ms | 9 us | 9 us | ~1 ms |
| 2^20 | ~40 ms | 21 us | 13 us | ~87 ms |
| 2^21 | ~70 ms | 28 us | 19 us | ~250 ms |
| 2^23 | ~300 ms | 38 us | 26 us | ~1.8 s |
| 2^27 | ~3 s | 82 us | 63 us | ~14.7 s |

### WASM (Node.js V8)

| N | `permute()` | `unpermute()` | overhead vs native |
|-------|-------------|---------------|--------------------|
| 2^14 | 8 us | 9 us | ~1x |
| 2^20 | 20 us | 18 us | ~1x |
| 2^23 | 40 us | 34 us | ~1.05x |

### WASM (Chrome browser)

| N | `permute()` | `unpermute()` | overhead vs native |
|-------|-------------|---------------|--------------------|
| 2^14 | 18 us | 20 us | ~2x |
| 2^20 | 42 us | 39 us | ~2x |
| 2^23 | 84 us | 76 us | ~2.2x |

WASM package size: **60 KB**.

## Security

The construction is a PRP (pseudo-random permutation) with security
reducible to AES-128.  The max recursion depth is set to `16 * ln(N)`,
giving negligible (< 2^{-80}) probability that any partition remains
unresolved.

Different keys produce independent permutations.  The same key always
produces the same permutation (deterministic, no randomness beyond the key).
