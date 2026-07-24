# Wire round and byte inventory across PIR backends

**Status:** refreshed 2026-07-24. Empirical fixtures now cover DPF-PIR,
HarmonyPIR, and OnionPIR. DPF/Harmony figures below come from fresh native
clients querying the production db 0 layout with two deterministic not-found
scripthashes; both transcripts are byte-identical.

**Purpose:** baseline data for (a) the Oblivious-HTTP (OHTTP) migration
feasibility study, (b) the formal-verification agent's wire-shape
invariants, (c) future privacy and bandwidth optimization decisions.

---

## 1. Round counts per protocol

Source: empirical witnesses from
[`crates/sdk/client/tests/leakage_integration_test.rs`](../crates/sdk/client/tests/leakage_integration_test.rs)
run against `wss://weikeng1.bitcoinpir.org`, recorded in
[`CLAUDE.md`](../CLAUDE.md) lines 192–200. `A` = `found@h=0`, `B` =
`found@h=1`, `C` = `not-found`. Post-closure all three are
byte-identical (the simulator-property tests assert this).

| Backend | Fresh-client recorded rounds | Query rounds after setup | IndexMerkleSiblings |
|---|---:|---:|---|
| **DPF-PIR** | **23** | **22** | 12 = 2 passes × 2 servers × 3 levels |
| **HarmonyPIR** | **23** | **13** | 6 = 2 passes × 1 server × 3 levels |
| **OnionPIR** | **10** | **5** | 2 = per-group Merkle at ARITY=120 |

“Recorded round” means one `RoundProfile`; for DPF a logical two-server
exchange contributes one entry per server. Setup is `merkle_tree_tops` for DPF;
for Harmony it is `info`, eight `harmony_hint_refresh` records, and
`merkle_tree_tops`; for Onion it is two `info` records, key registration, and
two tree-top records. The production browser intentionally disconnects after
each query, though Harmony hints may be retained in its browser cache.

Pre-closure these counts diverged across A/B/C (e.g. DPF: A=33 / C=21).
The closure work — Merkle INDEX Item-Count Symmetry, INDEX Merkle
Group-Symmetry, CHUNK Round-Presence Symmetry — flattened them.

### What's wall-clock vs total

These are *total wire rounds*, not *wall-clock rounds*. Two
client-side optimizations narrow the wall-clock count without changing
total bytes on the wire:

1. **Within-level pass pipelining** — `query_passes` in
   [`crates/sdk/client/src/merkle_verify.rs:411`](../crates/sdk/client/src/merkle_verify.rs)
   sends multiple passes at the same `(table_type, level)` concurrently.
2. **INDEX/CHUNK Merkle in parallel** —
   [`verify_bucket_merkle_batch_parallel`](../crates/sdk/client/src/merkle_verify.rs:808)
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

### 2.2 DPF-PIR — empirical, from [`web/test/fixtures/dpf_corpus.json`](../web/test/fixtures/dpf_corpus.json)

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

The fixture pins 23 fresh-client records: **405,563 B up / 9,570,707 B
down**. The one tree-tops response is 9,155,389 B. Excluding that setup
record, the measured query is **22 records, 405,558 B up / 415,318 B down**
across both servers. This confirms the earlier response estimate and shows the
request estimate was conservative.

### 2.3 HarmonyPIR — empirical, from [`web/test/fixtures/harmony_corpus.json`](../web/test/fixtures/harmony_corpus.json)

Per-group request payload: `T−1` sorted distinct u32 indices = `4·(T−1)`
bytes. `T = round(√(2n))` (see
[`harmonypir`'s `find_best_t`](https://github.com/Bitcoin-PIR/harmonypir)).
For main-DB INDEX with `n ≈ 565K/K = 7,500`, `T ≈ 122` ⇒ ~488 B/group.
Per-group response is the small XOR-cancelled answer (~64 B).

The fresh native client records **23 rounds, 2,154,526 B up / 131,221,536 B
down**. Setup contributes one `info`, eight hint-refresh records
(46,067,488 B down), and one 9,155,389 B tree-tops response. Excluding those
setup records, the measured query is **13 records, 2,153,863 B up /
75,998,423 B down**. The previous sketch substantially underestimated the
FHE response payloads; the empirical fixture is now authoritative.

---

## 3. Summary table

| Backend | Fresh / post-setup records | Fresh bytes | Post-setup query bytes |
|---|---:|---|---|
| OnionPIR | **10 / 5** | 18.2 MB up / 7.6 MB down | protocol rounds: 17.4 MB up / 7.2 MB down |
| DPF-PIR | **23 / 22** | 405,563 B up / 9,570,707 B down | 405,558 B up / 415,318 B down |
| HarmonyPIR | **23 / 13** | 2,154,526 B up / 131,221,536 B down | 2,153,863 B up / 75,998,423 B down |

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
RTT versus direct HTTPS. The current fresh-client record counts are
23 / 23 / 10, before any cross-level client-side parallelization
optimizations land.

The "all Merkle levels in parallel" refactor (see [§1 wall-clock
note](#whats-wall-clock-vs-total)) would collapse Merkle wall-clock to
≈ 1 wave per server without touching the protocol — a 3× per-query
latency improvement on DPF/Harmony.

---

## 5. Follow-ups

### 5.1 Make DPF / HarmonyPIR numbers empirical, not computed — complete

OnionPIR has
[`crates/sdk/client/examples/onion_leakage_dump.rs`](../crates/sdk/client/examples/onion_leakage_dump.rs)
(~80 LOC) that dumps a `LeakageProfile` to JSON. The recorder is
already attached for DPF and HarmonyPIR — every round goes through
`record_round(RoundProfile { request_bytes, response_bytes, … })` (see
[`crates/sdk/client/src/dpf.rs:560`](../crates/sdk/client/src/dpf.rs)).

Completed on 2026-07-24 with `dpf_leakage_dump.rs`,
`harmony_leakage_dump.rs`, the two checked-in fixtures, and a Vitest regression
that pins byte-identical not-found transcripts plus exact round/byte totals.

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
