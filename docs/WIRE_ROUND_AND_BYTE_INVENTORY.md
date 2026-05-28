# Wire round and byte inventory across PIR backends

**Status:** snapshot 2026-04-29. Empirical figures for OnionPIR; computed
figures for DPF and HarmonyPIR (no leakage-dump tool wired for them yet —
see [§"Follow-ups"](#follow-ups)).

**Purpose:** baseline data for (a) the Oblivious-HTTP (OHTTP) migration
feasibility study, (b) the formal-verification agent's wire-shape
invariants, (c) future privacy and bandwidth optimization decisions.

---

## 1. Round counts per protocol

Source: empirical witnesses from
[`pir-sdk-client/tests/leakage_integration_test.rs`](../pir-sdk-client/tests/leakage_integration_test.rs)
run against `wss://weikeng1.bitcoinpir.org`, recorded in
[`CLAUDE.md`](../CLAUDE.md) lines 192–200. `A` = `found@h=0`, `B` =
`found@h=1`, `C` = `not-found`. Post-closure all three are
byte-identical (the simulator-property tests assert this).

| Backend | Total rounds (A = B = C) | IndexMerkleSiblings | Decomposition of IndexMerkleSiblings |
|---|---:|---:|---|
| **DPF-PIR** | **19** | 12 | 2 max_items_per_group × 2 servers × 3 INDEX-Merkle levels |
| **HarmonyPIR** | **20** | 6 | 2 × 1 server × 3 levels |
| **OnionPIR** | **10** | 2 | per-group Merkle (ARITY=120) → packs in 1 round at batch=2 |

Pre-closure these counts diverged across A/B/C (e.g. DPF: A=33 / C=21).
The closure work — Merkle INDEX Item-Count Symmetry, INDEX Merkle
Group-Symmetry, CHUNK Round-Presence Symmetry — flattened them.

### What's wall-clock vs total

These are *total wire rounds*, not *wall-clock rounds*. Two
client-side optimizations narrow the wall-clock count without changing
total bytes on the wire:

1. **Within-level pass pipelining** — `query_passes` in
   [`pir-sdk-client/src/merkle_verify.rs:411`](../pir-sdk-client/src/merkle_verify.rs)
   sends multiple passes at the same `(table_type, level)` concurrently.
2. **INDEX/CHUNK Merkle in parallel** —
   [`verify_bucket_merkle_batch_parallel`](../pir-sdk-client/src/merkle_verify.rs:808)
   uses `tokio::try_join!` (native) / `futures::future::try_join` (wasm32).

**Not yet exploited:** sibling fetches *across* Merkle levels are still
sequential, even though DPF alpha at level L is a pure function of
`bin_index` (= `bin_index / 8^(L+1)`) and has no hash-chain dependency
on prior levels. Implementing this would collapse the 12 / 6 / 2
IndexMerkleSiblings wall-clock count to ~1 wave per server.

---

## 2. Message sizes per round

### 2.1 OnionPIR — empirical, from [`web/test/fixtures/onion_corpus.json`](../web/test/fixtures/onion_corpus.json)

Two not-found queries, byte-identical profiles (proves the simulator
property on the wire).

| # | Round kind | server | `request_bytes` | `response_bytes` | items (len × value) |
|---|---|---:|---:|---:|---|
| 0 | `info` | 0 | 5 | 34,578 | — |
| 1 | `info` | 0 | 5 | 93 | — |
| 2 | `onion_key_register` | 0 | **3,145,873** | 5 | — (Galois + GSW keys) |
| 3 | `index` | 0 | **4,917,008** | 1,690,208 | 75 × 2 |
| 4 | `chunk` | 0 | **2,622,408** | 901,448 | 80 × 1 |
| 5 | `merkle_tree_tops` (INDEX) | 0 | 5 | 1,190,009 | — |
| 6 | `index_merkle_siblings` L=0 | 0 | 2,458,508 | 845,108 | 75 × 1 |
| 7 | `index_merkle_siblings` L=1 | 0 | 2,458,508 | 845,108 | 75 × 1 |
| 8 | `merkle_tree_tops` (DATA) | 0 | 5 | 1,190,009 | — |
| 9 | `chunk_merkle_siblings` | 0 | 2,622,408 | 901,448 | 80 × 1 |
| | **per-query total** | | **18,224,733 B (≈ 17.4 MB)** | **7,598,014 B (≈ 7.2 MB)** | |

Observations:
- `onion_key_register` is the big one-time payment per session per
  `db_id`. ~3.1 MB of FHE keys (Galois + GSW). Cacheable on the client.
- A whole steady-state query is **~26 MB on the wire**. FHE is
  expensive. Per-round bytes are dominated by BFV ciphertext size.

### 2.2 DPF-PIR — computed from constants

DPF key bytes formula:
`1 + 16 + 1 + 18·(n−7) + 16` (see
[`vendor/libdpf/src/key.rs:59`](../vendor/libdpf/src/key.rs)).

Main DB has `dpf_n=20` for INDEX (565K bins ⇒ 268 B/key) and
`dpf_n=21` for CHUNK (1.06M bins ⇒ 286 B/key). Slot constants from
[`pir-core/src/params.rs`](../pir-core/src/params.rs):
`INDEX_SLOT_SIZE=13, INDEX_SLOTS_PER_BIN=4` (52 B/bin) and
`CHUNK_SLOT_SIZE=44, CHUNK_SLOTS_PER_BIN=3` (132 B/bin).

| Round (per server; 2 servers in parallel) | request | response | items |
|---|---:|---:|---|
| `info` + `db_catalog` | ~5 + ~5 | small | — |
| `index` | ~40,800 B | ~7,800 B | 75 × 2 |
| `chunk` (every query, post-CHUNK-Round-Presence fix) | ~46,400 B | ~21,100 B | 80 × 2 |
| `merkle_tree_tops` | 5 | ~9.1 MB | — |
| `index_merkle_siblings` L=0 (dpf_n=17) | ~16,400 B | ~19,200 B | 75 × 1 |
| `index_merkle_siblings` L=1 (dpf_n=14) | ~12,300 B | ~19,200 B | 75 × 1 |
| `index_merkle_siblings` L=2 (dpf_n=11) | ~8,300 B | ~19,200 B | 75 × 1 |
| `chunk_merkle_siblings` L=0 (dpf_n=18) | ~18,900 B | ~20,500 B | 80 × 1 |
| `chunk_merkle_siblings` L=1 (dpf_n=15) | ~14,600 B | ~20,500 B | 80 × 1 |
| `chunk_merkle_siblings` L=2 (dpf_n=12) | ~10,300 B | ~20,500 B | 80 × 1 |

`max_items_per_group_per_level = 2` (INDEX Merkle, post-closure), so
each Merkle level emits **two** padded sibling passes. Roughly doubles
the per-level Merkle bytes versus the formula above.

**Per-server steady-state (excluding cacheable tree-tops):**
~250 KB up / ~210 KB down. **Two servers ⇒ ~500 KB up / ~420 KB down
per query.** Roughly 50× cheaper on the wire than OnionPIR.

### 2.3 HarmonyPIR — sketched from per-group structure

Per-group request payload: `T−1` sorted distinct u32 indices = `4·(T−1)`
bytes. `T = round(√(2n))` (see
[`harmonypir`'s `find_best_t`](https://github.com/Bitcoin-PIR/harmonypir)).
For main-DB INDEX with `n ≈ 565K/K = 7,500`, `T ≈ 122` ⇒ ~488 B/group.
Per-group response is the small XOR-cancelled answer (~64 B).

Estimated steady-state numbers (1 server, warm hints, no Merkle
padding overhead):
- `index` round: ~37 KB request / ~5 KB response
- `chunk` round: similar shape with K_CHUNK groups
- `merkle_*` rounds: reuse the DPF Merkle tables (single-server), so
  the per-round sibling bytes match the DPF Merkle column above
- Hints: tens of MB once per `(db_id, prp_backend)`, cached in
  IndexedDB (see `estimate_hint_size_bytes` in
  [`pir-sdk-client/src/harmony.rs:4704`](../pir-sdk-client/src/harmony.rs))

**Per-query (warm) total:** ~200–300 KB up / ~250 KB down. Same
ballpark as DPF.

---

## 3. Summary table

| Backend | Wire rounds (multi-query collision) | Per-query bytes (warm session, not-found) |
|---|---:|---|
| OnionPIR | **10** | ~17.4 MB up / ~7.2 MB down (empirical) |
| DPF-PIR | **19** | ~500 KB up / ~420 KB down (2 servers, computed) |
| HarmonyPIR | **20** | ~200–300 KB up / ~250 KB down (1 server, computed) |

---

## 4. Implications for OHTTP

Each wire round is one OHTTP encapsulated exchange (RFC 9458 is strictly
1 req ↔ 1 resp; no session extension exists or is in flight). Per-round
HPKE overhead is ~55 B for X25519 + AES-128-GCM. Body size limits at
common relay providers:

- Cloudflare Workers (most customer OHTTP gateways): 100 MB body cap.
  All three protocols fit comfortably per round.
- Fastly OHTTP Relay: no published limit.

For latency, each OHTTP exchange adds one relay → gateway → target
RTT versus direct HTTPS. At 19 / 20 / 10 rounds today, that's
~20–60 ms × those counts before any client-side parallelization
optimizations land.

The "all Merkle levels in parallel" refactor (see [§1 wall-clock
note](#whats-wall-clock-vs-total)) would collapse Merkle wall-clock to
≈ 1 wave per server without touching the protocol — a 3× per-query
latency improvement on DPF/Harmony.

---

## 5. Follow-ups

### 5.1 Make DPF / HarmonyPIR numbers empirical, not computed

OnionPIR has
[`pir-sdk-client/examples/onion_leakage_dump.rs`](../pir-sdk-client/examples/onion_leakage_dump.rs)
(~80 LOC) that dumps a `LeakageProfile` to JSON. The recorder is
already attached for DPF and HarmonyPIR — every round goes through
`record_round(RoundProfile { request_bytes, response_bytes, … })` (see
[`pir-sdk-client/src/dpf.rs:560`](../pir-sdk-client/src/dpf.rs)).

Action: copy `onion_leakage_dump.rs` to `dpf_leakage_dump.rs` and
`harmony_leakage_dump.rs`, swap the client type, store fixtures under
`web/test/fixtures/`. This validates the §2.2 and §2.3 numbers and
gives the formal-verification agent the same JSON shape across all
three backends.

### 5.2 All-Merkle-levels-in-parallel refactor

Replace the `for level in 0..n_levels { … await … }` loop in
`verify_sibling_levels` with a concurrent issue (Promise.all / try_join_all)
of all sibling DPF batches across all levels. DPF alpha at level L is
`bin_index / 8^(L+1)` — pure function of leaf position, no dependency
on the level-L−1 hash chain. The local hash-walk runs after all
responses arrive.

Expected impact: wall-clock Merkle phase collapses from L sequential
RTTs to 1 parallel wave per server. ~3× latency reduction per query on
DPF/Harmony. Zero protocol change.

### 5.3 Documented decisions, not action items

- **CHUNK Merkle Item-Count padding is admitted** (see
  [CLAUDE.md "CHUNK Merkle Item-Count — Documented Trade-off"](../CLAUDE.md)).
  The M=16 pad was deliberately removed in Phase 4 (2026-05-17). A
  not-found / small-found / large-found query divergence in
  `chunk_max_items_per_group_per_level` is a known leak axis. Do not
  re-introduce M-padding without re-opening that decision.

- **CHUNK Pass-Count Symmetry** would close the residual leak that M-padding
  was trying to address, and is structurally cheaper: it pads CHUNK PIR
  *round count* per query rather than CHUNK Merkle items per query.
  Because Merkle pass count is upper-bounded by CHUNK PIR round count
  (same items, same PBC groups), constraining CHUNK PIR rounds
  automatically constrains Merkle passes. Not yet implemented — open
  question whether the cost of forcing all queries to a fixed
  `M_rounds` CHUNK rounds is worth the privacy win, given that ~99% of
  mainnet addresses have exactly 1 chunk today.
