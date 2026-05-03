# HarmonyPIR Rust Implementation

Independent Rust implementation of the HarmonyPIR paper (2026-437):
"Efficient Single-Server Stateful PIR Using Format-Preserving Encryption"

Paper PDF: /Users/cusgadmin/Downloads/2026-437 (1).pdf
C++ reference: /Users/cusgadmin/bitcoin-pir/HarmonyPIR-13DB/
FF1 C++ impl: /Users/cusgadmin/bitcoin-pir/Format-Preserving-Encryption/

## Three PRP Backends

All implement the `Prp` trait (`src/prp/mod.rs`). Caller picks one via `Box<dyn Prp>`.

| PRP | Native per-op | WASM per-op | Batch hint gen (16t) | Best for |
|-----|--------------|-------------|---------------------|----------|
| **ALF** (`prp/alf.rs`) | 198 ns | 10.8 us | ~0.8 s | Online queries (native + WASM) |
| **FastPRP** (`prp/fast.rs`) | 35.8 us | 206 us | ~1.5 s | Server-side batch generation |
| **Hoang** (`prp/hoang.rs`) | 6.1 us | 14.0 us | ~100 s | WASM fallback (no deps) |
| FF1 (`prp/ff1.rs`) | 19.4 us | 68 us | N/A | Legacy, not recommended |

Feature flags: `alf` and `fastprp-prp` (both default). Use `--no-default-features` for WASM with Hoang+FF1 only.

## Bitcoin UTXO PIR — Bucket-Size-4 Parameters

Using cuckoo table bucket size 4 (4 entries per row):

| | INDEX | CHUNK |
|---|---|---|
| Buckets | 75 | 80 |
| Rows per bucket | 2^18 (262K) | 2^19 (524K) |
| Row size (4× original) | 168 B | 352 B |
| PIR domain (2×rows) | 2^19 | 2^20 |
| Segment size T | 512 | 1,024 |
| Segments M | 1,024 | 1,024 |
| Max queries before rehint | 512 | 512 |
| Hint per bucket | 168 KB | 352 KB |
| **Total hints (75+80)** | | **~40 MB** |

Per address lookup: 75 INDEX + 80 CHUNK bucket queries (1-chunk address).
PRP calls per query: 75×1,024 + 80×2,048 = **240,640 total**.

## Measured Performance (Apple Silicon)

### Online query — full address lookup (75 INDEX + 80 CHUNK, bucket=4)

| PRP | Native 8t | Native 16t | WASM 8 workers |
|-----|-----------|------------|----------------|
| ALF | ~3.5 ms | ~2 ms | **~370 ms** |
| Hoang | ~194 ms | ~120 ms | **~720 ms** |
| FastPRP | ~736 ms | ~438 ms | **~3,000 ms** |

### Batch hint generation — all 155 buckets (bucket=4)

| PRP | 16 threads |
|-----|-----------|
| ALF | **~0.8 s** |
| FastPRP | **~1.5 s** |
| Hoang | **~100 s** |

## Integration Guide

See `INTEGRATION.md` for API reference, constructor examples, and handoff notes
for integrating with other repos.

## Crate Structure

```
src/
  prp/
    mod.rs      — Prp + BatchPrp traits
    alf.rs      — AlfPrp, AlfEngine (feature: alf)
    fast.rs     — FastPrpWrapper (feature: fastprp-prp)
    hoang.rs    — HoangPrp (always available)
    ff1.rs      — Ff1Prp (always available)
  protocol.rs   — Client (offline + online phases)
  relocation.rs — RelocationDS (uses Box<dyn Prp>)
  server.rs     — Server (database holder)
  params.rs     — Params (N, w, T, etc.)
  hist.rs       — History data structure
  error.rs      — Error types
  util.rs       — XOR helpers
```

Dependencies:
- `alf-nt` at `../ALF` (optional, feature `alf`)
- `fastprp` at `../fastprp` (optional, feature `fastprp-prp`)
- `rayon` (optional, pulled by `alf` feature)
- `serde` + `bincode` (optional, pulled by `fastprp-prp` feature)
