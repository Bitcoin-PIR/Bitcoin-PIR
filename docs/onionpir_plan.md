# OnionPIR Data Layout Plan

## Global constant

**EntrySize = 3840 bytes** (2048 coefficients x 15 usable bits / 8). PolyDegree = 2048.

Both levels (index and main DB) use the same 3840-byte OnionPIR entry size.
One OnionPIR database per PBC group (75 + 80 = 155 total).

**OnionPIR crate:** https://github.com/weikengchen/OnionPIRv2-fork

---

## Main Database (80 groups)

**Packing:** UTXO data is packed greedily into 3840-byte entries. Multiple addresses
per entry. If the next address's record doesn't fit in the remaining space, pad and
start a new entry. No record straddles an entry boundary.

**Measured entry count (gen_1_onion output):**
- 53.6M addresses packed into **815,171 unique entries** (3.13 GB packed file)
- 95.9% packing efficiency (4.1% padding overhead)
- 65.8 addresses per entry on average
- 88.4% of addresses are ≤40 bytes serialized (single UTXO)
- Max serialized length: 3778 bytes (no address spans multiple entries!)

**PBC distribution:** Each entry assigned to 3 of 80 groups. Stored in all 3.
Per group: ~815K x 3 / 80 = **~30,569 entries**.

**Cuckoo table per group:**
- 6 hash functions, bucket_size=1, load_factor=0.95
- num_bins = 30,569 / 0.95 = **~32,178 bins**
- Table is computed deterministically (sorted by entry_id) -- client computes
  the same table, so client always knows the exact bin -> 1 query per group

**Logical storage per group:** 32,178 x 3840B = ~118 MB
**Logical total (80 groups):** ~9.4 GB

---

## Index Database (75 groups)

**Index slot format** (no flags, keep tags):

| Field        | Size    | Notes                                        |
|--------------|---------|----------------------------------------------|
| Tag          | 8 bytes | Fingerprint for collision resolution         |
| Entry ID     | 4 bytes | u32 -- which 3840B entry in main DB          |
| Byte offset  | 2 bytes | u16 -- start position within entry (0-3839)  |
| Num entries  | 1 byte  | u8 -- how many consecutive entries to fetch   |
| **Total**    | **15 bytes** |                                          |

**Bucket size = floor(3840 / 15) = 256 slots per bin**

**PBC distribution:** ~53.6M addresses, each assigned to 3 of 75 groups, stored in all 3.
Per group: ~53.6M x 3 / 75 = **~2.15M entries**.

**Cuckoo table per group:**
- 2 hash functions, bucket_size=256, load_factor=0.95
- num_bins = 2,150,000 / (256 x 0.95) = **~8,840 bins**
- Client tries bin from hash 0, scans 256 slots for matching tag.
  If miss, tries hash 1. -> 1-2 queries per group

**Logical storage per group:** 8,840 x 3840B = ~34.0 MB
**Logical total (75 groups):** ~2.5 GB

---

## NTT Expansion & Memory Architecture

### NTT expansion factor (MEASURED)

After OnionPIR preprocessing, data is stored in NTT form for fast FHE computation.

- Logical: 2048 coefficients x 15 bits = 3840 bytes per entry
- NTT form: 16,384 bytes per entry
- **Expansion factor: 4.27x** (measured via benchmark — `physical_size_mb / db_size_mb`)
- Plaintext prime: 32771 (15-bit)
- CoeffMods={60,60} in database_constants.h, but SEAL uses a single combined modulus

### Storage estimates (with measured 4.27x expansion)

**Naive storage (without indirection):**

| Level    | Groups | Logical/group | Logical total | NTT-expanded total |
|----------|--------|---------------|---------------|--------------------|
| Index    | 75     | ~34 MB        | ~2.5 GB       | **~10.7 GB**       |
| Main DB  | 80     | ~118 MB       | ~9.4 GB       | **~40.2 GB**       |
| **Total**| **155**|               | **~11.9 GB**  | **~50.9 GB**       |

The 40.2 GB for main DB includes 3x redundancy (each entry stored in 3 groups).

**Shared NTT store with indirection:**

| Component                    | Size      | Notes                                 |
|------------------------------|-----------|---------------------------------------|
| Main DB shared NTT store     | **~13 GB**| 815K entries x 16,384B, stored once   |
| Main DB indirection tables   | ~10 MB    | 80 groups x ~32K entries x 4B         |
| Index NTT databases          | **~10.7 GB**| No cross-group dedup possible (*)   |
| Index indirection tables     | ~2.6 MB   | 75 groups x ~8,840 entries x 4B       |
| **Total**                    | **~24 GB**|                                       |

(*) Index bins are unique per group — each bin contains a different set of 256
slots, so there's nothing to deduplicate.

Savings vs naive: **64 GB → 28 GB** (36 GB saved, all from main DB dedup).

**This fits comfortably in ~40 GB of available RAM.** Both the shared main DB store
(~18 GB) and all index databases (~10 GB) can be resident simultaneously.

### Why indirection still helps: page cache efficiency

Even though the total now fits in RAM, indirection saves physical I/O:

- **Without sharing:** Main DB reads ~54 GB from SSD (3x redundancy)
- **With sharing:** Main DB reads ~18 GB from SSD (each page loaded once, then cached)
- After warmup, everything stays in page cache → zero SSD I/O per batch

### Compute vs I/O bottleneck (MEASURED)

For one chunk group (~43K entries):
- FHE compute (`answer_query`): **20.2 ms** (measured, saturates all CPU cores)
- I/O cold (from NVMe at ~4 GB/s): ~676 MB / 4 GB/s ≈ 169ms per group
- I/O warm (page cache): ~0

For a full batch:
- Index compute: 75 x 11.8 ms = **0.89 s**
- Chunk compute: 80 x 20.2 ms = **1.62 s**
- **Total compute: ~2.5 s per client request**
- I/O (shared store warm): ~0
- I/O (shared store cold, first batch): ~28 GB / 4 GB/s ≈ 7 seconds (one-time warmup)

**Compute clearly dominates once warmed up.**

### OnionPIR indirection — still worth doing

Even though total storage fits in RAM with 4.27x expansion, indirection still
provides value:
- Cuts disk usage from ~51 GB → ~24 GB
- Cuts cold-start SSD reads from ~40 GB → ~13 GB for main DB
- Simpler preprocessing (NTT each entry once, not 3x)

But it is **no longer critical for memory pressure** — the naive approach (~51 GB)
fits in 64 GB RAM. Indirection becomes a nice-to-have optimization rather than
a requirement.

### Shared NTT store layout: LEVEL-MAJOR (not entry-major)

OnionPIR's first-dimension multiply iterates level-by-level (2048 levels for
PolyDegree=2048, rns_mod_cnt=1). For each level, it reads one uint64_t from
each entry. The store layout must match this access pattern.

**Level-major layout** (required):
```
shared_store[level * num_shared_entries + entry_id] = coefficient
```
- Each level is a contiguous slab: 815K entries × 8 bytes = 6.5 MB
- 2048 slabs × 6.5 MB = ~13 GB total
- Per-query: reads within a 6.5 MB slab → good cache/TLB behavior
- With indirection: reads `shared_store[level * N + index_table[pos]]`
  → random within 6.5 MB slab, still fits in L3 cache

**Entry-major layout** (what we originally proposed — DO NOT USE):
```
shared_store[entry_id * 2048 + level] = coefficient
```
- Per-query stride: 16,384 bytes between reads → massive TLB thrashing
- Cache line utilization: 12.5% (64B line, only 8B used)
- Would degrade query latency significantly

**Offline preparation:**
1. NTT-expand each entry (produces 2048 coefficients per entry, entry-major)
2. Transpose to level-major: scatter each entry's coefficients to the correct slab positions
3. This is a one-time (815K × 2048) uint64_t matrix transpose
4. OnionPIR developer offered a C++ utility: `write_shared_ntt_store_level_major()`

### Memory budget summary (with ~40 GB available)

| Approach        | Total NTT on disk | Peak resident | Fits in 40 GB? |
|-----------------|-------------------|---------------|-----------------|
| Naive (no share)| ~64 GB            | ~64 GB        | Tight but yes   |
| Shared store    | ~28 GB            | ~28 GB        | **Comfortable** |

---

## Build pipeline

```
gen_0:       (same) Extract UTXOs -> utxo_set.bin
gen_1_onion: Pack UTXOs into 3840B entries + build index entries
             -> packed_entries.bin, onion_index.bin
gen_2_onion: Build main DB: 80 groups x (cuckoo table -> OnionPIR populate -> preprocess -> save)
gen_3_onion: Build index DB: 75 groups x (cuckoo table -> OnionPIR populate -> preprocess -> save)
```

No stamp_flags step -- chunk placement is deterministic via client-computed cuckoo.

Preprocessing is expensive (NTT over entire DB). A dedicated Rust binary will:
1. Build all 155 databases
2. Preprocess (NTT expansion)
3. Save to disk for mmap-loading at runtime

With the shared store approach, preprocessing becomes:
1. NTT-expand each unique main DB entry once → write shared_ntt_store.bin (~35 GB)
2. Build per-group indirection tables → write group_N_index.bin (small files)
3. For index groups: build conventionally (no dedup), preprocess, save

---

## Query flow

### Index (1 round, possibly 2)
1. Client computes derive_buckets(script_hash) -> assigned to 1 of 75 groups
2. Computes 2 cuckoo bin candidates in that group
3. Sends 75 OnionPIR queries (1 real using hash-0 bin, 74 dummy)
4. Decrypts assigned group's response -> scans 256 slots for matching tag
5. If miss, second round with hash-1 bin
6. Extracts: (entry_id, byte_offset, num_entries)

### Main DB (1+ rounds)
1. Client knows which entries to fetch (from index result)
2. For each entry: computes derive_chunk_buckets(entry_id) -> 3 candidate groups
3. PBC cuckoo-places entries into groups (same as current planning)
4. For each group with a real query: client computes the group's full cuckoo table
   -> knows exact bin -> 1 query
5. Sends 80 OnionPIR queries per round (real + dummy)
6. Decrypts -> extracts packed UTXO data at known offset

---

## Key design decisions

- Entry size: 3840 bytes (natural for PolyDegree=2048, 15 usable bits)
- Index slots: 15 bytes (tag 8 + entry_id 4 + offset 2 + num_entries 1) -> bucket_size=256
- Index cuckoo: 2-hash, bucket_size=256, load 0.95 (client tries both bins)
- Main DB cuckoo: 6-hash, bucket_size=1, load 0.95 (client computes table, 1 query)
- No flags in index (chunk placement is deterministic)
- Tags kept (8-byte fingerprint for index collision resolution)
- K=75 (index), K_CHUNK=80 (main DB) -- same as DPF implementation
- One OnionPIR database per group (155 total)
- PolyDegree=2048, PlainMod=16 bits (plaintext prime = 32,771)
- CoeffMods={60,60} in database_constants.h; SEAL uses single combined modulus
- NTT expansion = 4.27x (measured), physical_size = 16,384 bytes per entry
- Keys NOT reusable across different num_entries (Galois rotations differ).
  Benchmark showed no panic but decryption produces garbage (noise budget=0).
  Client sends 2 key sets sequentially: index keys → index queries → chunk keys → chunk queries.

---

## Communication & Performance (MEASURED via onionpir_bench)

Benchmark binary: `runtime/src/bin/onionpir_bench.rs`
Run with: `cargo run --release --bin onionpir_bench`

### Key exchange (one-time per session)

**Keys are reusable across different num_entries!** (confirmed by benchmark).
A single key set works for both index and chunk levels.

| | Measured size |
|---|---|
| Galois keys | 273.57 KB |
| GSW keys | 323.79 KB |
| **Total one-time upload** | **597.36 KB** |

Key generation time: galois ~11ms, GSW ~20ms.
Key registration time: ~15ms per server instance.

### Per-request communication (MEASURED)

Query uses seed compression — client sends 1 polynomial + seed (not full ciphertext).
Response is also smaller than a full ciphertext.

| | Measured size |
|---|---|
| Query (upload) | **16.19 KB** |
| Response (download) | **13.50 KB** |

Client queries ALL groups per phase (1 real + rest dummy, server can't distinguish):

| Phase | Queries | Upload | Download |
|-------|---------|--------|----------|
| Index | 75 | 75 × 16.19 KB = **1.19 MB** | 75 × 13.50 KB = **0.99 MB** |
| Chunk | 80 | 80 × 16.19 KB = **1.27 MB** | 80 × 13.50 KB = **1.05 MB** |
| **Total** | **155** | **2.45 MB** | **2.05 MB** |

**Total per-request round-trip: ~4.5 MB** (much better than initial 10 MB estimate!)

### Server compute time (MEASURED)

Each `answer_query` saturates all CPU cores (OpenMP), so queries are sequential
within a batch.

| Group type | Entries/group | Measured query time | Batch total |
|---|---|---|---|
| Index | 8,224 (padded to 8,256) | **11.82 ms** | 75 × 11.82 ms = **0.89 s** |
| Chunk | 43,053 (padded to 43,264) | **20.21 ms** | 80 × 20.21 ms = **1.62 s** |
| **Total** | | | **~2.5 s** |

Phases are sequential (chunk queries depend on index result).
If index hash-0 misses, add another ~0.89 s for second round.

Preprocessing times: 190ms (index group), 1.01s (chunk group).
Total preprocessing for all 155 groups: ~75×0.19 + 80×1.01 ≈ **~95 seconds**.

### Client compute time (MEASURED)

| Task | Measured (native) |
|---|---|
| Key generation (one-time) | ~31 ms |
| Generate 1 query | ~1.1 ms |
| Decrypt 1 response | ~0.24 ms |
| **Generate 155 queries** | **~170 ms** |
| **Decrypt 155 responses** | **~37 ms** |

### End-to-end latency (at 50 Mbps broadband)

```
Phase                                  Duration
─────                                  ────────
Generate + upload index queries         ~0.3 s  (1.19 MB up)
Server processes 75 index queries       ~0.89 s
Download + decrypt index responses      ~0.2 s  (0.99 MB down)
Generate + upload chunk queries         ~0.3 s  (1.27 MB up)
Server processes 80 chunk queries       ~1.62 s
Download + decrypt chunk responses      ~0.2 s  (1.05 MB down)
────────────────────────────────────────────────
Total                                   ~3.5 s
```

Much faster than initial 6.9 s estimate! Server compute is ~2.5 s, communication
is ~1 s. Pipelining could overlap upload/compute for further gains.

### Noise budget warning

Measured remaining noise budget after decryption:
- Index (8,256 entries): **4 bits remaining**
- Chunk (43,264 entries): **2 bits remaining** ← very tight!

The chunk level is near the noise floor. If the database grows significantly
or parameters change, decryption may fail. Monitor this closely.

### OnionPIR internal parameters (MEASURED)

| Parameter | Index level | Chunk level |
|---|---|---|
| num_entries (padded) | 8,256 | 43,264 |
| entry_size | 3,840 B | 3,840 B |
| fst_dim_sz | 129 | 169 |
| other_dim_sz | 64 | 256 |
| db_size_mb | 30.23 MB | 158.44 MB |
| physical_size_mb | 129.00 MB | 676.00 MB |
| NTT expansion | 4.27x | 4.27x |
| plaintext prime | 32,771 | 32,771 |

---

## Open questions / next steps

### RESOLVED by benchmark (2026-03-22)

1. ~~Benchmark compute time~~ → **DONE.** Index: 11.82ms, Chunk: 20.21ms.
   Total batch: ~2.5s. Compute dominates over I/O once warmed.
2. ~~NTT expansion factor~~ → **4.27x** (not 8.53x). Total NTT storage ~64 GB
   naive or ~28 GB shared. Fits in 40 GB RAM either way.
3. ~~Key sizes~~ → **597 KB total** (galois 274 KB + GSW 324 KB).
4. ~~Query/response sizes~~ → Query **16.19 KB** (seed-compressed), Response **13.50 KB**.
5. ~~Key reusability~~ → **YES**, keys work across different num_entries.
   Only 1 key set needed for both index and chunk levels.

### Remaining

1. **Test new cuckoo table designs**: Verify 2-hash bs=256 and 6-hash bs=1 work
   at target scale. Verify deterministic client-side replay for 6-hash cuckoo.

2. **OnionPIR indirection patch:** Nice-to-have (not critical now that 4.27x
   expansion means total fits in RAM). But still saves disk space and cold-start
   I/O. See detailed prompt in conversation history.

3. **Noise budget monitoring:** Chunk level has only **2 bits** of noise budget
   remaining after decryption. Very tight. Need to verify this holds with real
   data and investigate whether database growth could push it to failure.

4. **Build pipeline:** Implement gen_1_onion (packing), gen_2_onion (main DB),
   gen_3_onion (index DB).

5. **Client-side cuckoo computation for main DB:** Define the deterministic
   insertion order (sorted by entry_id) and hash function seeds. Both client and
   server must produce identical cuckoo tables. With ~39-43K entries per group,
   this is sub-millisecond on the client.
