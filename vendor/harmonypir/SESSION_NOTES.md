# HarmonyPIR Rust Implementation — Session Notes

## Status: All 7 Algorithms Verified Against Paper

Every algorithm from the paper "Efficient Single-Server Stateful PIR Using
Format-Preserving Encryption" (2026-437) has been verified line-by-line
against the Rust implementation. All match.

### Verification Summary

| Step | Algorithm | File(s) | Verdict |
|------|-----------|---------|---------|
| 1 | Algorithm 1 — Hist (History DS) | `hist.rs` | Matches |
| 2 | Algorithm 2 — Hist' (Segment History) | `hist.rs` | Matches |
| 3 | Algorithm 6 — Relocation DS (DS') | `relocation.rs` | Matches |
| 4+5 | Algorithms 4+5 — Hoang PRP (Original + Phase Grouping) | `prp/hoang.rs` | Matches |
| 6 | Algorithm 3 — HarmonyPIR Client (Offline + Online) | `protocol.rs` | Matches |
| 7 | Algorithm 7 — Optimized Hint Relocation | `protocol.rs` | Matches |

### Differences from C++ Reference (all correct/intentional)

- **PRF plaintext format**: Rust uses different field layout than C++ for
  round key derivation. Produces different permutations but equally secure.
- **`% domain_size` vs `& (N-1)`**: Rust uses modulo (supports non-power-of-2
  domains). C++ uses bitmask (requires power-of-2). Rust is more general.
- **Random cell sampling**: Rust excludes entire segment s when sampling the
  dummy cell. Slightly more restrictive than paper, but safe.
- **Round count formula**: Rust uses provable bound `ceil(log2(2N)) + 40`.
  C++ uses empirical `7.23*log2(2N) + 4.82*40 + 1` (~6x more rounds).
- **Fixed-point detection**: Rust adds cycle detection in chain-walks
  (not in paper). Prevents infinite loops from PRP edge cases.

---

## PRP Performance Benchmarks

All measured on this machine (Apple Silicon / ARM64).
Benchmark code in `benches/pir_bench.rs`.

### Hoang PRP (Algorithm 5, Phase-Grouped)

Domain 2N = 2^28 = 268,435,456. Rounds r = 68, phases = 17.

| Metric | Value |
|--------|-------|
| Forward | 6.1 us/op |
| Inverse | 6.1 us/op |
| Full domain mapping | ~27 min (single core) |

### FF1 (NIST SP 800-38G) — Rust `fpe` crate

Domain 2^28, radix=2 (binary), 4 bytes BNS:

| Metric | Value |
|--------|-------|
| Forward | 125.8 us/op (16x cycle-walk overhead!) |
| Inverse | 134.9 us/op |

Domain 6M (Bitcoin), radix=2:

| Metric | Value |
|--------|-------|
| Forward | 19.5 us/op (2.8x cycle-walk) |
| Inverse | 22.7 us/op |

### FF1 — C++ OpenSSL Implementation (github.com/0NG/Format-Preserving-Encryption)

Cloned to `/Users/cusgadmin/bitcoin-pir/Format-Preserving-Encryption/`.
Benchmarks in `bench_ff1.c` and `bench_aes_sim.c`.

Domain ~2^27 results (radix choice is critical):

| Config | Raw FF1 (ns) | Cycle-walk | Per-op (ns) | Full 2^27 |
|--------|-------------|-----------|------------|-----------|
| radix=2, 27 digits | 18,390 | 1.0x | 18,390 | 41 min |
| radix=10, 9 digits | 7,792 | 7.5x | 58,539 | 2.2 hours |
| radix=16, 7 digits | 6,679 | 2.0x | 13,203 | 30 min |
| radix=512, 3 digits | 4,534 | 1.0x | 4,534 | 10.1 min |
| radix=11586, 2 digits | 3,864 | 1.0x | 3,864 | 8.6 min |

**Key insight**: BIGNUM arithmetic dominates FF1 cost (~80%), not AES (~20%).
Even the best FF1 (radix=11586, 2 digits) is 3,864 ns — vs theoretical
~330 ns if using uint64 arithmetic instead of OpenSSL BIGNUM.

### C++ "Simulated FF1" (10 dummy AES calls, from utils_empirical.cpp)

| Metric | Value |
|--------|-------|
| 10 AES calls | 401 ns |
| Actual FF1 (best) | 3,864 ns |
| **Simulation underestimates by** | **9.6x** |

The paper's HarmonyPIR1 benchmarks used this simulation, so reported
FF1 performance is ~10x faster than reality.

### ALF-2-7b (New FPE, not yet integrated)

Parameters: n=2, t=7, binary, 28 rounds.

| Mode | ns/op | M ops/sec |
|------|-------|-----------|
| Encrypt (single) | 83.2 | 12.0 |
| Encrypt (batch 16x) | 24.1 | 41.5 |
| Decrypt (single) | 126.6 | 7.9 |
| Decrypt (batch 16x) | 30.8 | 32.5 |

**Why ALF is faster than FF1**:
1. Uses AES round functions (single `aesenc`), not full AES-128 (10 `aesenc`)
   → 56 vs 200 aesenc ops per evaluation → 3.6x
2. Binary XOR combining, no modular arithmetic → eliminates BN overhead
3. Short dependency chains enable AES-NI pipelining → 3.6x batch speedup

---

## Bitcoin UTXO PIR — Hint Server Cost Analysis

### Database Parameters

- ~53.6M unique script hashes, excluding dust and whales
- 40-byte entry chunks, ~80M total chunks across addresses
- Two-level PIR: Index (75 PBC groups, ~2.14M/group) + Data (80 PBC groups, ~3M/group)
- Total PRP evaluations per hint generation: ~400M
- Total database size (PBC-expanded): ~12.8 GB

### Hint Server Costs (outsourced hint generation)

Client downloads ONLY the hints (not the full database):

| T choice | Hints to transfer | vs self-generation |
|----------|------------------|-------------------|
| Balanced (T~2,449) | ~11 MB | 1,160x less |
| T=300 | ~94 MB | 136x less |

Per-client hint generation (400M PRP evals + 12.8 GB XOR):

| PRP | Single core | 16-core |
|-----|------------|---------|
| Hoang (6.1 us/eval) | ~41 min | ~2.5 min |
| FF1 best (3.9 us/eval) | ~26 min | ~1.6 min |
| ALF single (83 ns/eval) | ~35 sec | ~2.5 sec |
| ALF batched (24 ns/eval) | ~11 sec | ~1.6 sec |

With ALF batched, PRP is no longer the bottleneck — DB streaming (~1 sec)
and network transfer (~11-94 MB) dominate.

### Incremental Updates (per Bitcoin block)

- ~5,000-10,000 UTXO changes per block, each in 3 PBC groups
- Per-block hint update: ~2 MB pushed to client
- No full hint regeneration needed — just XOR diffs into segments

---

## Architecture Notes

### PRP Trait (for ALF integration)

```rust
pub trait Prp {
    fn forward(&self, x: usize) -> usize;   // Encrypt
    fn inverse(&self, y: usize) -> usize;   // Decrypt
    fn domain(&self) -> usize;               // Domain size [0, N)
}
```

ALF-2-7b needs to implement this trait. The domain is 2N (twice the
number of entries per PBC group). For Bitcoin data level: 2 * 3M = 6M.

### Where PRP is called in the protocol

1. **Offline phase** (`protocol.rs`): `ds.locate(k)` for each DB entry k
   → calls `prp.forward(k)` + chain-walk
2. **Online query** (`protocol.rs`): `ds.locate(q)` + `ds.access(l)` +
   `ds.locate_extended(empty_value)` for hint relocation
3. **Hint relocation** (Algorithm 7): `ds.locate_extended(N + m*T + i)`
   for finding destination cells

### C++ Reference Implementation

Located at `/Users/cusgadmin/bitcoin-pir/HarmonyPIR-13DB/`

- `utils_provably.cpp` = HarmonyPIR0 (Hoang PRP, on-the-fly computation)
- `utils_empirical.cpp` = HarmonyPIR1 (precomputed table + 10 dummy AES = simulated FF1)
- Both use same round count formula: `7.23*log2(2N) + 4.82*40 + 1`
- Both use `& (N-1)` bitmask (requires power-of-2 domains)

### FF1 C++ Implementation

Cloned to `/Users/cusgadmin/bitcoin-pir/Format-Preserving-Encryption/`
from `github.com/0NG/Format-Preserving-Encryption`.

- Uses OpenSSL BIGNUM for modular arithmetic (the bottleneck)
- Benchmarks in `bench_ff1.c` (various radix configs) and `bench_aes_sim.c`
- Built with: `cc -O2 -I$(brew --prefix openssl@3)/include ...`

---

## Three PRP Backends — Integrated

All three now implement `Prp` trait and pass end-to-end protocol tests (43 tests).

- [x] ALF (`prp/alf.rs`) — AlfPrp + AlfEngine factory, native tweak per group
- [x] FastPRP (`prp/fast.rs`) — FastPrpWrapper, cache persistence, derived keys per group
- [x] Hoang (`prp/hoang.rs`) — existing, added BatchPrp
- [x] Feature-gated: `alf`, `fastprp-prp` (both default). WASM uses `--no-default-features`.
- [x] WASM build verified for all three PRPs (ALF uses software AES fallback)
- [x] Browser benchmarks via wasm-pack + Web Workers

---

## Bucket-Size-4 Design Decision

Using cuckoo table bucket size 4: each PIR row = 4 original entries packed together.

| | INDEX | CHUNK |
|---|---|---|
| Buckets | 75 | 80 |
| Rows (N) | 2^18 | 2^19 |
| Row size (w) | 168 B | 352 B |
| Domain (2N) | 2^19 | 2^20 |
| T | 512 | 1,024 |
| Hint/bucket | 168 KB | 352 KB |
| Max queries | 512 | 512 |

**Total hints: ~40 MB** (stored in browser memory or IndexedDB).

Tradeoff vs original (bucket=1): 2× hint size, 2× faster queries, 4× faster batch gen.

---

## Measured Performance — All PRPs (Apple Silicon)

### Per-op (domain 6M)

| PRP | Native forward | Native inverse | WASM forward | WASM inverse |
|-----|---------------|---------------|-------------|-------------|
| ALF | 198 ns | 262 ns | 10.8 us | 8.6 us |
| Hoang | 6.1 us | 6.1 us | 14.0 us | 13.8 us |
| FastPRP | 35.8 us | 23.8 us | 206 us | 185 us |
| FF1 | 19.4 us | 22.4 us | 68 us | - |

### Full address lookup — 155 buckets, bucket-size-4 (estimated from measured)

| PRP | Native 16t | WASM 8 workers |
|-----|-----------|----------------|
| ALF | ~2 ms | **~370 ms** |
| Hoang | ~120 ms | **~720 ms** |
| FastPRP | ~438 ms | **~3,000 ms** |

### Batch hint generation — all 155 buckets, bucket-size-4

| PRP | Native 16t |
|-----|-----------|
| ALF | **~0.8 s** |
| FastPRP | **~1.5 s** |
| Hoang | **~100 s** |

### WASM Web Worker scaling (measured, original bucket=1 params)

| Workers | ALF | Hoang | FastPRP |
|---------|-----|-------|---------|
| 1 | 3,817 ms | 6,192 ms | 30,072 ms |
| 4 | 1,269 ms | 2,427 ms | 10,676 ms |
| 8 | 740 ms | 1,444 ms | 6,018 ms |

---

## Next Steps / TODO

- [ ] Implement hint server mode (outsourced hint generation)
- [ ] Web Worker integration for browser PIR client
- [ ] End-to-end demo with Bitcoin UTXO data
- [ ] The paper (2026-437) PDF is at `/Users/cusgadmin/Downloads/2026-437 (1).pdf`
