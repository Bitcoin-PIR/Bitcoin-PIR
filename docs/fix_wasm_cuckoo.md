# Fix `buildCuckooBs1` in OnionPIRv2 WASM to match Rust server

## Problem

The WASM `build_cuckoo_bs1` in `wasm/hash_utils.cpp` produces different cuckoo
tables than the Rust server's `build_chunk_cuckoo_for_group`. The web client
needs to reconstruct the **exact same** cuckoo table the server built, so both
implementations must be identical.

**Current WASM implementation (WRONG):**
- 3 hash functions (hardcoded `NUM_HASH_FUNCS = 3`)
- `std::mt19937 rng(42)` for random eviction choice
- 500 max evictions
- Random walk: pick random hash function, swap, check all alternates

**Required (matches Rust server):**
- 6 hash functions
- Deterministic eviction (no RNG)
- 10000 max kicks
- Specific eviction chain logic (see below)

## Reference Rust implementation

From `runtime/src/bin/onionpir2_client.rs`, the function `build_chunk_cuckoo_for_group`:

```rust
/// Chunk cuckoo: 6 hash functions, bucket_size=1
const CHUNK_CUCKOO_NUM_HASHES: usize = 6;
const CHUNK_CUCKOO_MAX_KICKS: usize = 10000;
const EMPTY: u32 = u32::MAX;

#[inline]
fn chunk_derive_cuckoo_key(group_id: usize, hash_fn: usize) -> u64 {
    splitmix64(
        CHUNK_MASTER_SEED  // 0xa3f7c2d918e4b065
            .wrapping_add((group_id as u64).wrapping_mul(0x9e3779b97f4a7c15))
            .wrapping_add((hash_fn as u64).wrapping_mul(0x517cc1b727220a95)),
    )
}

#[inline]
fn chunk_cuckoo_hash(entry_id: u32, key: u64, num_bins: usize) -> usize {
    (splitmix64((entry_id as u64) ^ key) % num_bins as u64) as usize
}

/// Build the chunk cuckoo table for a specific group (deterministic).
fn build_chunk_cuckoo_for_group(
    group_id: usize,
    total_entries: usize,
    bins_per_table: usize,
) -> Vec<u32> {
    // Collect all entries assigned to this group
    let mut entries: Vec<u32> = Vec::new();
    for eid in 0..total_entries as u32 {
        let buckets = derive_entry_buckets(eid);
        if buckets.contains(&group_id) {
            entries.push(eid);
        }
    }
    entries.sort_unstable(); // deterministic insertion order

    let mut keys = [0u64; CHUNK_CUCKOO_NUM_HASHES];
    for h in 0..CHUNK_CUCKOO_NUM_HASHES {
        keys[h] = chunk_derive_cuckoo_key(group_id, h);
    }

    let mut table = vec![EMPTY; bins_per_table];

    for &entry_id in &entries {
        // Phase 1: try direct placement with each of the 6 hash functions
        let mut placed = false;
        for h in 0..CHUNK_CUCKOO_NUM_HASHES {
            let bin = chunk_cuckoo_hash(entry_id, keys[h], bins_per_table);
            if table[bin] == EMPTY {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if placed { continue; }

        // Phase 2: deterministic eviction chain
        let mut current_id = entry_id;
        let mut current_hash_fn = 0;
        let mut current_bin = chunk_cuckoo_hash(entry_id, keys[0], bins_per_table);
        let mut success = false;

        for kick in 0..CHUNK_CUCKOO_MAX_KICKS {
            // Evict the occupant at current_bin
            let evicted = table[current_bin];
            table[current_bin] = current_id;

            // Try to place evicted item in one of its other bins
            for h in 0..CHUNK_CUCKOO_NUM_HASHES {
                let try_h = (current_hash_fn + 1 + h) % CHUNK_CUCKOO_NUM_HASHES;
                let bin = chunk_cuckoo_hash(evicted, keys[try_h], bins_per_table);
                if bin == current_bin { continue; }
                if table[bin] == EMPTY {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if success { break; }

            // No empty slot found — continue eviction chain
            let alt_h = (current_hash_fn + 1 + kick % (CHUNK_CUCKOO_NUM_HASHES - 1))
                        % CHUNK_CUCKOO_NUM_HASHES;
            let alt_bin = chunk_cuckoo_hash(evicted, keys[alt_h], bins_per_table);
            let final_bin = if alt_bin == current_bin {
                let h2 = (alt_h + 1) % CHUNK_CUCKOO_NUM_HASHES;
                chunk_cuckoo_hash(evicted, keys[h2], bins_per_table)
            } else {
                alt_bin
            };

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        if !success {
            panic!("Client cuckoo failed for entry_id={}", entry_id);
        }
    }

    table
}
```

## What to change in `wasm/hash_utils.cpp`

Replace the `build_cuckoo_bs1` function body to match the Rust algorithm above.
Key changes:

1. **`NUM_HASH_FUNCS` → 6** (or better: use `num_keys` parameter which is already passed)
2. **`MAX_EVICTIONS` → 10000**
3. **Remove `std::mt19937 rng(42)`** — no randomness needed
4. **Replace random walk with deterministic eviction chain** (see Phase 2 above)

The corrected C++ should look like:

```cpp
std::vector<uint32_t> build_cuckoo_bs1(
    const uint32_t* entries, size_t num_entries,
    const uint64_t* keys, size_t num_keys,
    uint32_t num_bins) {

    constexpr uint32_t EMPTY_VAL = 0xFFFFFFFF;
    constexpr size_t MAX_KICKS = 10000;

    std::vector<uint32_t> table(num_bins, EMPTY_VAL);

    for (size_t i = 0; i < num_entries; i++) {
        uint32_t entry_id = entries[i];

        // Phase 1: try direct placement
        bool placed = false;
        for (size_t h = 0; h < num_keys; h++) {
            uint32_t bin = hash_cuckoo_int(entry_id, keys[h], num_bins);
            if (table[bin] == EMPTY_VAL) {
                table[bin] = entry_id;
                placed = true;
                break;
            }
        }
        if (placed) continue;

        // Phase 2: deterministic eviction chain
        uint32_t current_id = entry_id;
        size_t current_hash_fn = 0;
        uint32_t current_bin = hash_cuckoo_int(entry_id, keys[0], num_bins);
        bool success = false;

        for (size_t kick = 0; kick < MAX_KICKS; kick++) {
            uint32_t evicted = table[current_bin];
            table[current_bin] = current_id;

            // Try to place evicted in any empty alternate bin
            for (size_t h = 0; h < num_keys; h++) {
                size_t try_h = (current_hash_fn + 1 + h) % num_keys;
                uint32_t bin = hash_cuckoo_int(evicted, keys[try_h], num_bins);
                if (bin == current_bin) continue;
                if (table[bin] == EMPTY_VAL) {
                    table[bin] = evicted;
                    success = true;
                    break;
                }
            }
            if (success) break;

            // Continue chain: deterministic next bucket
            size_t alt_h = (current_hash_fn + 1 + kick % (num_keys - 1)) % num_keys;
            uint32_t alt_bin = hash_cuckoo_int(evicted, keys[alt_h], num_bins);
            uint32_t final_bin;
            if (alt_bin == current_bin) {
                size_t h2 = (alt_h + 1) % num_keys;
                final_bin = hash_cuckoo_int(evicted, keys[h2], num_bins);
            } else {
                final_bin = alt_bin;
            }

            current_id = evicted;
            current_hash_fn = alt_h;
            current_bin = final_bin;
        }

        // If !success after MAX_KICKS, insertion failed (caller should handle)
    }

    return table;
}
```

## Key derivation for the 6 hash functions

The caller computes keys as:
```
for h in 0..6:
    keys[h] = splitmix64(CHUNK_MASTER_SEED + group_id * 0x9e3779b97f4a7c15 + h * 0x517cc1b727220a95)
```

Where `CHUNK_MASTER_SEED = 0xa3f7c2d918e4b065`.

All arithmetic is wrapping u64.

## Embind wrapper note

The embind wrapper `hash_build_cuckoo_bs1_embind` converts JS keys via
`keys_val[i].as<double>()` which loses precision for u64 values > 2^53.

Consider accepting keys as a `BigUint64Array` instead, or accept two `Uint32Array`
values (lo/hi halves). The current `double` conversion may produce wrong hash
results for keys that exceed 2^53.

## Testing

After the fix, the WASM and Rust implementations should produce identical tables.
Test: build a cuckoo table for group 0 with 815,171 total entries and 32,562 bins,
using the 6 keys derived from `CHUNK_MASTER_SEED` for group 0.
Compare the output table byte-for-byte with the Rust version.

## Impact

With this fix, the web client can use `Module.buildCuckooBs1()` (~9ms) instead of
the current JS BigInt fallback (~1-5 seconds per group).
