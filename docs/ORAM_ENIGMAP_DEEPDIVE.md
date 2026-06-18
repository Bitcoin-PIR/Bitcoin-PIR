# EnigMap deep-dive

Background dossier for a BitcoinPIR-side decision on whether (and how) to
port the EnigMap oblivious map into our SEV-SNP TEE stack. This is not a
tutorial — it assumes ORAM, ODS, SGX/SEV-SNP, the page-fault adversary,
and CMOV-style data-oblivious programming as prior knowledge. All
section/page references are to the USENIX 2023 camera-ready
(`usenixsecurity23-tinoco.pdf`, pp. 4033-4050, 18 pages including
appendices) or to the ePrint full version
(`eprint.iacr.org/2022/1083`, 23 pages, dated 2023-06-09; appendices C
and D only appear here). Repo refs are to
`github.com/odslib/EnigMap@main` (pushed 2023-08-10, last
inspected 2026-06-13).

---

## 1. Team & lineage

### 1.1 Authors and group

All three authors are at CMU at the time of publication (USENIX paper
title page, p. 4033):

- **Afonso Tinoco** — first author. PhD student in Elaine Shi's group
  at CMU CSD. Per DBLP and his own bio, also affiliated with Oblivious
  Labs Inc. and Instituto Superior Técnico (Lisbon) at various points.
  EnigMap is his first major publication. Follow-ups: *Efficient
  Oblivious Sorting and Shuffling for Hardware Enclaves*
  (ePrint 2023/1258, became Flexway O-Sort at USENIX Security 2025);
  *PicoGRAM* at CRYPTO 2025 (garbled-RAM from DDH).
- **Sixiang Gao** — second author, also Shi's group at CMU. EnigMap is
  also her DBLP-listed publication. No public follow-up under the same
  name as of mid-2026.
- **Elaine Shi** — corresponding/senior author, full prof at CMU
  CSD/ECE. Cofounder of Oblivious Labs. This is her line of work going
  back roughly 15 years.

Acknowledgments (USENIX p. 4050): "DARPA SIEVE grant, Packard
Fellowship, NSF awards 2128519 and 2044679, and ONR award
N000142212064." No industry sponsorship from Signal, Meta, Google etc.
— important: EnigMap is academic, **not a Signal-funded engineering
project**.

### 1.2 Where EnigMap sits in the lineage

The paper itself spells the lineage out in Section 1 and "Additional
Related Work" (USENIX pp. 4033-4036). The lineage is two distinct
strands that EnigMap stitches together:

**Strand A — Oblivious data structures over Path-ORAM.** The direct
predecessor on the algorithm side is:

- Wang, Nayak, Liu, Chan, Shi, Stefanov, Huang, **Oblivious Data
  Structures** (CCS 2014). Reference [1] in the USENIX paper. This is
  the canonical "ODS over Path-ORAM" paper: they showed how to walk an
  AVL tree using O(log N) ORAM accesses per logical operation by
  bundling each AVL node's children's position-identifiers into the
  node itself, so you don't need to recursively look up positions.
  Shi was a coauthor. This is the algorithm EnigMap reimplements,
  not replaces. The header comment in `ods/otree/otree.hpp`
  literally says `"// This file implements
  https://eprint.iacr.org/2014/185.pdf with our optimizations."`
- Mishra, Poddar, Chen, Chiesa, Popa, **Oblix** (S&P 2018). Reference
  [2]. Oblix is the engineering instantiation of Wang et al. inside an
  SGX enclave, with an efficient client-side AVL/B+-tree, doubly
  oblivious, written in Rust. This is the system EnigMap is benchmarking
  against — the explicit baseline, and what "53× faster than prior best"
  refers to.
- Eskandarian and Zaharia, **ObliDB** (VLDB 2019). Reference [3]. SQL
  layer over Oblix-style oblivious primitives in SGX. The EnigMap
  authors note that ObliDB's map performance is *worse* than Oblix
  because ObliDB targets general SQL, so they don't benchmark against
  it (USENIX § 5.1).
- Sasy, Gorbunov, Fletcher, **ZeroTrace** (NDSS 2018). Reference [31].
  EnigMap mentions it alongside Raccoon and Kloski as variants of Path
  ORAM inside SGX, but says they "did not implement an efficient
  oblivious binary search tree, and thus would not be competitive for
  our application" (USENIX p. 4036). ZeroTrace is about exposing
  Path-ORAM as a memory primitive, not building a map.

What each of these *didn't* do, and EnigMap fixes:

| Predecessor | What it didn't do | EnigMap fix |
|---|---|---|
| Wang et al. CCS 2014 | RAM model only, no external-memory analysis; pure theoretical exposition with no enclave implementation | Reframes the whole problem under the external-memory model with B and M as concrete parameters; ships C++ implementation |
| Oblix (S&P 2018) | Heap layout for ORAM tree → O(log N) page swaps per access; double-pass insertion → 2-3× CPU blowup; initialization is bitonic-sort-based with O(N log³ N) work; instruction-trace obliviousness has holes (see §5 of this doc) | Locality-friendly subtree-packed layout → O(log_B N) page swaps; single-pass insertion with rotation plan; O(N log N) init with O((N/B) log_{M/B} N/B) page swaps; CMOV-disciplined throughout |
| ObliDB (VLDB 2019) | Targets general SQL, slower than Oblix on the map operation | EnigMap is map-only and faster than Oblix in turn |
| ZeroTrace (NDSS 2018) | Path-ORAM-as-memory primitive; no oblivious AVL on top | EnigMap is an oblivious *map* on top of Path-ORAM, not just oblivious memory |

**Strand B — External-memory algorithms.** The other strand
EnigMap pulls from is classical algorithm theory:

- Aggarwal and Vitter, **The Input/Output Complexity of Sorting and
  Related Problems** (CACM 1988). Reference [18]. Origin of the
  external-memory model — atomic unit is a block of size B, memory of
  size M, count cache misses not instructions.
- Demaine, **Cache-Oblivious Algorithms and Data Structures** (lecture
  notes 2002). Reference [19].
- Bender, Demaine, Farach-Colton, **Cache-Oblivious B-Trees**
  (SICOMP 2005). Reference [20]. The van Emde Boas layout for
  cache-oblivious trees — EnigMap deliberately uses a *cache-aware*
  variant that knows the enclave page size, beating vEB by up to 2×
  (USENIX § 4.1 and Figure 2a vs. 2b).
- Prokop, **Cache-Oblivious Algorithms** (MIT MSc thesis, 1999).
  Reference [21].

The novelty in *bridging* these two strands is the paper's
self-described main contribution (USENIX § 1.2): "Although
external-memory algorithms are a well-known body of work [...], to the
best of our knowledge, we are among the first to implement such
algorithms in the hardware enclave context."

The CMU PhD blog post (`cs.cmu.edu/~csd-phd-blog/2024/oblivious-maps/`,
written by Tinoco) reaffirms the trio of contributions: (1) identifying
page swaps as the cost metric for TEE oblivious algorithms; (2) faster
oblivious map both asymptotically and concretely; (3) faster
initialization for large DBs.

---

## 2. The actual algorithm

### 2.1 The setting and what's actually inside the enclave

Two layers, stacked (USENIX § 3 and § 4):

1. **Logical layer (AVL):** an oblivious-AVL-tree map, N nodes,
   max depth `1.44 log₂ N` (Adelson-Velsky-Landis bound; literally
   referenced as `[64]` in the paper).
2. **Physical layer (ORAM):** a Path-ORAM tree storing all the AVL
   nodes as Path-ORAM blocks. Z=4 blocks per Path-ORAM bucket
   (confirmed by repo: `applications/signal/Enclave/...signal.hpp`
   instantiates `ORAMClient<Node, ORAM__Z, ...>` and `ods/oram/pathoram/oram.hpp`
   defaults `Z=ORAM__Z` to 4).

So we are *not* doing "AVL inside a generic block-ORAM via WRAM
compilation." We are using the **non-recursive Path-ORAM as a
position-map-less primitive**: each AVL node carries the
position-identifiers of its two children, so the tree walk *itself*
provides the position map — Wang et al.'s trick. This is the core of
ODS.

Concretely, each AVL node in the ORAM is laid out as the C struct
(verbatim from `ods/otree/node.hpp`):

```cpp
struct Node {
  K k;                              // 8 bytes (uint64_t key)
  V v;                              // 8 bytes (uint64_t value)
  _ORAM::ORAMAddress child[2];      // (address, position) pair × 2
  Dir_t balance;                    // uint32_t, B_LEFT / B_RIGHT / B_BALANCED
};
```

`K` and `V` are both `uint64_t` in the shipped code. Note how
explicitly imbalance is tracked as a third state (B_BALANCED) — this is
the AVL balance bit, used directly in the rebalancing CMOV cascade.

### 2.2 What "external-memory" means concretely here

The paper is unusually precise (USENIX § 2.3 + § 4):

- **B = block / page size**, the atomic unit of I/O between enclave
  and external (RAM). For OCall-based EPC swap, B is *flexible*
  (chosen by the implementation); for the SGX-instruction-based EWB
  swap path, B is fixed at 4 KB by hardware.
- **M = enclave resident memory size**, the cache size. 128 MB for
  SGXv1, up to 512 GB for SGXv2 (per Figure 1 and § 2.2).
- The cost metric: **number of page swaps**, where a page swap is an
  EPC eviction (ocall + AES-GCM encrypt + AES-GCM decrypt + optional
  disk I/O if RAM is also exceeded).
- The microbenchmark to motivate this (Figure 1a, USENIX p. 4037):
  on an Azure SGXv2 machine, **one 4 KB EPC page swap is ≈ 47×
  the cost of moving 4 KB within the enclave (no disk swap), or
  ≈ 80× with disk swap.** The breakdown: ocall ≈ 70% of swap cost,
  encrypt+decrypt the other 30%. EWB-based swaps are even worse
  (53-72× over MOV) because EWB requires an IPI-based TLB flush
  across all enclave-resident CPUs.
- The optimal page size: 3992 B for no-disk-swap, 4 KB once disk
  involvement happens (Figure 9, USENIX p. 4045). Smaller pages are
  dominated by the ocall startup cost C_init; larger pages waste
  bandwidth.

So the "external-memory model" is not an abstraction here — they
literally cost-model EPC ↔ DRAM page swaps as the I/O atoms, with B as
a tunable they chose to set to ≈ 4 KB.

### 2.3 The core trick (in one breath)

> Pack the Path-ORAM tree into 4 KB-aligned subtrees of depth `L =
> ⌊log₂ B⌋` ≈ 8 levels, instead of the standard level-by-level heap
> layout. Then a root-to-leaf path in the ORAM tree crosses only
> `O(log_B N)` page boundaries, not `O(log N)`. For 4 KB pages and N
> = 2²⁸, that's 28/8 ≈ 4 page swaps per ORAM path read, versus 28 in
> the naive layout — a ≈ 7× wire-cost reduction, before any caching.

This is **Figure 2a** of the USENIX paper (p. 4041), drawn as a
pyramid of small triangles where each triangle is one page. Compare to
**Figure 2b**, which is Oblix's heap layout where each successive level
is a separate page.

It's the same idea as a cache-oblivious B-tree (Bender et al.
SICOMP 2005), with two differences:

1. **Cache-aware, not cache-oblivious.** Because the enclave knows B
   and M exactly at compile time, EnigMap uses a fixed subtree height
   `L = ⌊log₂ B⌋` instead of the recursive van Emde Boas split. This
   saves up to 2× in page swaps because (a) vEB recursion may not pick
   the concretely optimal split, and (b) vEB can pack two triangles
   into the slack of a page in a way that crosses page boundaries
   mid-triangle (USENIX p. 4041 first column).
2. The thing being laid out is not the AVL tree (whose paths are
   data-dependent and not laid out at all — they're discovered by the
   pointers `child[0]` and `child[1]` inside each node). It's the
   *Path-ORAM tree* that the AVL nodes are stored *inside*. The AVL
   logic still touches `1.44 log₂ N` ORAM blocks per operation;
   what's optimized is the per-block fetch cost from external memory.

### 2.4 Oblivious primitives stack

From the bottom up (the repo layout in `ods/` mirrors this exactly):

1. **CMOV.** x86 `cmovnz` wrapped in inline-asm. From
   `ods/common/mov_intrinsics.hpp` (415 lines), the actual primitive:

   ```cpp
   INLINE void CMOV8_internal(const uint64_t cond, uint64_t& guy1,
                              const uint64_t& guy2) {
     asm volatile(
         "test %[mcond], %[mcond]\n\t"
         "cmovnz %[i2], %[i1]\n\t"
         : [i1] "=r"(guy1)
         : [mcond] "r"(cond), "[i1]"(guy1), [i2] "r"(guy2)
         :);
   }
   ```

   There are CMOV1/2/4/8 variants for different widths, plus a CSWAP8
   (two CMOVNZs and an R9 scratch register). Per-type CMOV
   specializations are provided where needed (e.g. `Node`'s CMOV
   field-by-field, in `node.hpp`).

   The codebase uses `CMOV(cond, dest, src)` *everywhere* — by my
   grep in `otree.hpp` (699 lines), the `Insert` method alone uses
   ≈ 50 CMOV calls to handle the rotation case analysis (lines
   307-470 or so).

2. **Oblivious sort.** `ods/external_memory/algorithm/` has
   `bitonic.hpp`, `kway_butterfly_sort.hpp` (13.6 KB),
   `kway_distri_sort.hpp` (20.4 KB), `ca_bucket_sort.hpp`,
   `naive_bucket_sort.hpp`, `two_way_cache_oblivious_bucket_sort.hpp`,
   `or_compact_shuffle.hpp`, plus `sort_building_blocks.hpp` (27 KB).
   The paper uses bitonic sort for the inner initialization step (cost
   O(n log² n)). The k-way variants are the "Efficient Oblivious
   Sorting and Shuffling for Hardware Enclaves" follow-up
   (ePrint 2023/1258, → Flexway O-Sort USENIX 2025), already vendored.

3. **Oblivious bin placement.** Used inside the initialization
   warmup (USENIX § 4.2.2 and Appendix A.2). Solves "given n input
   elements each destined for one of m bins each of capacity Z, route
   real elements to bins obliviously and emit overflow array of length
   n." Uses ORBA (Oblivious Random Bin Assignment) from Ramachandran &
   Shi SPAA 2021 (reference [16]) for the improved Stage-2 init in
   Appendix A.3.

4. **Path-ORAM** (`ods/oram/pathoram/oram.hpp`, 520 lines). Stash
   size is `S_ = Z * (log₂ N + 1) + ORAM__MS` where `ORAM__MS` is the
   minimum-stash compile constant. The stash lives in
   `std::vector<StashedBlock_t> stash_` — the comment in the
   source says "Needs to be in oblivious memory:". On stash eviction,
   the eviction is performed obliviously (oblivious-sort-based, per
   USENIX Appendix C.2.2: "we rely on 3 oblivious sorts on the path
   (including the stash) to implement the Evict algorithm of Path
   ORAM. The algorithm was described in the earlier work of Wang et
   al. [17] [...], although they employ this idea for a different
   setting"). The repo also ships a Ring-ORAM under
   `ods/oram/ringoram/` but it's not the default for the map.

5. **Oblivious AVL tree** (`ods/otree/otree.hpp`, 699 lines, plus
   `oram_interface.hpp` for the per-node ORAM operations). This is the
   logical layer.

6. **Initialization warmup** — separate algorithm, stages 1 and 2,
   detailed in USENIX § 4.2 and Appendix A.2-A.3.

### 2.5 Is "ODSlib" new?

The library name is `enigmap_lib` in the paper (USENIX § 5 second
column: "The library `enigmap_lib` consists of 5000 lines of C++ code
(3500 lines of code, 1500 lines of tests)") but the repo is
`github.com/odslib/EnigMap` and the directory is `ods/` ("Oblivious
Data Structures"). It is **new in EnigMap** — there is no prior
public ODSlib that they're consuming. Per the paper § 4.1, "[the]
locality-friendly layout adopts an elegant idea that originally comes
from the algorithms community [20, 21]" — so the *idea* is borrowed
from Bender-Demaine-Farach-Colton 2005 and Prokop's 1999 MIT thesis,
but the implementation is theirs.

The 5000 LoC is the library proper. The Signal-shaped enclave
integration is < 100 LoC of C++ + ≈ 10 LoC of Enclave Description
Language (EDL) — they emphasize this to argue the library is
TEE-portable.

### 2.6 Insertions, deletions, lookups, rotations

This is where most of the engineering subtlety lives. The paper
discusses it in USENIX § 3 ("Background on Oblivious AVL Tree") and
Appendix C.3 ("Optimizing the AVL-tree Insertion Algorithm").

**Find(k):** start from a fixed-position root. At each step:

1. Read the ORAM path identified by the current node's `pos`. This
   pulls the bucket(s) on the path and the matching block into the
   stash. Cost: `O(log_B N)` page swaps under the locality-friendly
   layout, `O(log N)` ORAM blocks fetched.
2. The current node's `child[0]` and `child[1]` give the (address,
   position) of the two children — so the *next* ORAM path is known
   immediately without recursion.
3. After read, the node gets a fresh random position and is added
   back to the root bucket, and Evict(old_pos) is called on the path
   just read. This is the standard Path-ORAM read-evict pattern.

**Padding (USENIX § 3, p. 4040):** every Find pads the number of ORAM
fetches to the AVL worst-case depth, **1.44 log₂ N**, regardless of
where the key actually lives (or whether it exists). This is essential
— otherwise the depth at which Find terminates is a side channel.
EnigMap accomplishes this by using a `FAKE_NODE` (visible in
`otree.hpp` line 59-63 in the constructor) that all "dummy" lookups
route through, with its position regenerated each time via CMOV.

**Lookup-as-CMOV.** Inside the Find loop (lines 164-200 of
`otree.hpp`):

```cpp
const bool Get(const K &k, V &ret) {
  // ... loop over depth 1.44*log2(N) ...
  CMOV(curr.address == FAKE_NODE.address, FAKE_NODE.position, newPos);
  // Find where to go next:
  // ...
  CMOV(!right, currBlock.data.child[0].position, newPos);
  CMOV(right,  currBlock.data.child[1].position, newPos);
  // ...
  CMOV(match, contained, true);
  CMOV(match, ret, currBlock.data.v);
  // ...
  CMOV(curr.address == FAKE_NODE.address, curr.position, FAKE_NODE.position);
}
```

Note the symmetric CMOV pair for left/right child position: this is
not "branch on `right`"; both child positions are *read* and a CMOV
selects which one to propagate. Same for `contained` and `ret`.

**Insert(k, v).** This is the interesting one. Naive ODS does Insert
in two passes: walk down to find the insertion point, then walk up to
rebalance. EnigMap argues (Appendix C.3, ePrint p. 21) that re-walking
the path costs 2-3× in computation. Their fix:

> **Rotation plan computed during the first descent.** During the
> descent, at each node on the path, *also* compute the AVL-tree nodes
> that *would be* involved in a rotation at that level — at most 3
> such nodes. By the time you reach the leaf, you know which rotation
> (if any) is needed and which nodes participate. The second pass
> walks the same path but applies the *predetermined* rotation plan
> with no recomputation. The classical AVL rotation case analysis
> (single rotation, double rotation, no rotation) is folded entirely
> into CMOV cascades.

In `otree.hpp` the `Insert` method (lines 257-500+) has the rotation
case analysis as four cases — `case0`, `case0_0`, `case1`, `case1_1`,
`case1_1_1`, `case2_1`, `case2_1_1`, `case2_2` — each with its own
CMOV cascade choosing between `DIRECT_REBALANCE`, `ROT2`, `ROT3`
rotation types and the appropriate child-pointer rewrites. None of the
branches is *taken*; the actual operation is selected by CMOV from
among precomputed candidates.

The pad-to-worst-case applies to both passes: insertion path length is
padded to `1.44 log₂ N` even if the actual insertion point is
shallower (Appendix C.3 last paragraph).

**Delete(k).** USENIX § 3, "Delete(k) can be supported in a similar
manner as the insertion, since it also walks down a logical path, and
then performs rebalancing involving the logical path just looked up,
as well as the sibling of each node on the path." Figure 8 confirms
deletion costs ≈ 5× insertion in practice, "because insertion needs to
perform rebalancing in one node, and deletion needs to perform more
rebalancing than insertion."

### 2.7 Initialization (the asymptotic win)

This is the contribution that really matters for our use case
(loading the UTXO set at startup), so it's worth detailing.

**Naive (Oblix-style) init**: insert N entries one by one via the
Insert procedure. Cost: O(N log³ N) computation and O(N log² N) page
swaps (Table 1, USENIX p. 4035).

**EnigMap init (USENIX § 4.2):** O(N log N) computation and
O((N/B) log_{M/B} (N/B)) page swaps. Algorithm:

- **Stage 1.** Sort the input array by key (non-obliviously is fine
  because the *initial DB is not secret*). Use external-memory
  multi-way merge sort, O((N/B) log_{M/B} (N/B)) swaps. Then encrypt
  everything. Then assign a random ORAM position to each entry.
  Finally, recursively `Propagate(root)`: every parent learns its two
  children's keys and positions.
- **Stage 2 (Warmup).** Pack the entries into ORAM buckets level by
  level, starting from the leaves. Use oblivious bin placement to
  route entries to their target ORAM buckets. The improved version
  (Appendix A.3) uses ORBA from Ramachandran & Shi SPAA 2021 plus the
  "tall cache" assumption M = ω(log N) to get the page-swap bound
  down to O((N/B) log_{M/B} (N/B)).

**Concrete:** for N = 256 M entries (USENIX § 1.2 last paragraph),
EnigMap inits in **9.5 hours**; Oblix takes **80.31 hours**. That's
8.5×. Figure 7 (p. 4045) shows the curves over N from 10⁴ to 10⁹:
naive (one-by-one) is ≈ 2× Oblix below ≈ 32 M and dramatically worse
above; fast init is the bottom line.

(Note for our use case: 9.5 hours is still a lot. If we ever wanted to
initialize a UTXO map of similar size from cold, we'd want to look at
the further-optimized Flexway O-Sort and see whether its k-way
butterfly cuts this further.)

### 2.8 Caching layers

USENIX § 4.3 + Appendix C.1 describe three caching layers, all of
which "do not leak any information" because they cache *physical*
storage which is already encrypted (USENIX C.1.1 last paragraph):

1. **Page-level LRU cache outside the enclave** of recently-used
   memory pages (encrypted). Reduces disk I/O.
2. **Bucket-level LRU cache inside the enclave**, of recently-used
   Path-ORAM buckets. Reduces page swaps.
3. **Binary-search-tree-level cache** — only of the top L levels of
   the ORAM tree (the "tree-top" cache from Path-ORAM optimizations
   like [27, 29, 30]).

Plus there's a fourth, "**sticky entries**" cache (Appendix C.1.2),
which is a logical-AVL cache, used to avoid the 2× pass blowup during
Insert. Security: "the second pass of the AVL-tree's Insert algorithm
touches the same path as the first pass is publicly known" — i.e. it
caches a path that's about to be re-accessed anyway, so no extra
leakage.

---

## 3. The implementation

### 3.1 Language and code layout

C++ throughout, ≈ C++20 (uses `concepts` and `consteval` in
`otree.hpp` and `node.hpp`). Repo
`github.com/odslib/EnigMap@main` is structured as:

```
.
├── CMakeLists.txt              # 1760 B, root config
├── README.md                   # 3601 B
├── ods/                        # The library (≈ 5000 LoC C++)
│   ├── CMakeLists.txt
│   ├── common/                 # CMOV, encryption, cache, profiler
│   │   ├── mov_intrinsics.hpp           # 14.1 KB — CMOV/CSWAP inline asm
│   │   ├── encutils.cpp / .hpp          # AES-GCM via OpenSSL
│   │   ├── encrypted.hpp                # encrypted wrapper
│   │   ├── lrucache.hpp                 # 4.1 KB
│   │   ├── dmcache.hpp                  # direct-mapped cache
│   │   └── tracing/                     # perf counters, profiler
│   ├── external_memory/        # External-memory primitives
│   │   ├── algorithm/                   # 7 sort variants + bin placement
│   │   ├── server/                      # SGX-EDL bindings + mem servers
│   │   │   ├── enclaveFileServer.edl    # ocall declarations
│   │   │   ├── serverFrontend.hpp
│   │   │   └── serverAllocator.hpp
│   │   ├── emvector.hpp / extemvector.hpp / noncachedvector.hpp / dynamicvector.hpp
│   ├── oram/                   # ORAM implementations
│   │   ├── pathoram/oram.hpp            # 15.4 KB, Path-ORAM
│   │   ├── ringoram/oram.hpp            # 15.3 KB, Ring-ORAM (not default)
│   │   ├── notoram/oram.hpp             # passthrough
│   │   └── common/                      # Block, Bucket, position-indexer
│   ├── otree/                  # The oblivious AVL tree
│   │   ├── otree.hpp                    # 27.2 KB, 699 lines — THE algorithm
│   │   ├── node.hpp                     # The AVL Node struct
│   │   └── oram_interface.hpp           # Per-node ORAM ops
│   ├── recoram/                # Recursive ORAM (alternate, not default for map)
│   └── main.cpp                # A tiny demo entrypoint (464 B)
├── tests/                      # GoogleTest unit + perf tests (≈ 1500 LoC)
│   ├── otree.cpp / otree_init.cpp / oram.cpp / sort.cpp
│   ├── perf_ods.cpp / perf_ods_large.cpp / perf_sort.cpp
│   ├── basic_perf.cpp / signal_test.cpp / recursive.cpp
│   ├── improvements_{bucketcache,filecache,none,packing}.cpp
│   └── algorithms.cpp / indexers.cpp / profiling_test.cpp / util_test.cpp
├── applications/               # Enclave-side integrations
│   ├── signal/                 # Private Contact Discovery — the headline app
│   │   ├── Enclave/TrustedLibrary/signal.cpp / .hpp
│   │   ├── Enclave/Enclave.edl
│   │   └── Makefile            # Intel SGX SDK Makefile
│   ├── benchmark_ewb/          # EWB vs ocall page-swap microbench
│   ├── benchmark_sgx/          # SGX microbenchmark enclave
│   ├── sorting/                # Sort benchmark enclave
│   └── omp_example/            # OpenMP demo (unrelated to oblivious)
├── tools/                      # Graph generation, docker
│   └── docker/cppbuilder/      # cppbuilder image
├── cmake/                      # CMake helpers
└── .gitlab-ci.yml              # CI (mirror lives on git.xtrm0.com)
```

The library is template-heavy. The `OBST` class is a template over the
`OramClient` type, which is itself a template over the underlying
PathORAM `ORAMClient`, which is templated on the bucket size Z, the
"levels per pack", the "directly cached levels", and `ObliviousCPUTrace`.
This is how compile-time CMOV-discipline is enforced for the inner
Insert/Get/Delete code.

### 3.2 Dependencies

From `CMakeLists.txt`:

```cmake
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
FetchContent_Declare(googletest ...)
```

- **OpenSSL** — used for AES-256-GCM via `EVP_*` (in `encutils.cpp`).
  The non-SGX build uses libssl/libcrypto directly.
- **Boost** — header-only, used for stacktrace (`BOOST_STACKTRACE_USE_ADDR2LINE`)
  and possibly some containers/algorithms.
- **GoogleTest** — fetched as a pinned commit
  (`3ea587050da9447536d0b55fece0a240273d9927`) for unit tests.
- **Intel SGX SDK** — required for the `applications/*` enclave
  builds. `SGX_SDK ?= /opt/intel/sgxsdk` in the Makefiles, with
  `SGX_MODE ?= SIM` (simulation mode by default — no hardware needed
  for development!) and `SGX_DEBUG ?= 0`.
- **bearssl** — vendored under each enclave's `Enclave/bearssl/` tree
  (≈ 700 KB of source). Used *inside* the enclave for AES-NI-backed
  crypto and as a libc shim, presumably because OpenSSL doesn't run
  cleanly inside the SGX enclave's restricted libc. Note: the
  `benchmark_sgx`, `signal`, and `sorting` applications each have their
  own copy.
- The build system also fetches a pinned **`signalapp/ContactDiscoveryService`**
  vendored under `applications/signal/Enclave/bearssl/src/sgxsd-*.c`
  to drive Signal-shaped contact discovery operations.

No specific crypto library is named in the README; the actual stack is
{OpenSSL outside-enclave, bearssl inside-enclave, AES-NI as the
underlying primitive}.

### 3.3 Build system

CMake + Ninja, plus per-application Makefiles for the SGX enclaves.

Non-SGX library build:

```bash
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
ninja -C build
ninja -C build test       # runs the GoogleTest suite (no SGX needed)
ninja -C build cppcheck   # runs cppcheck
```

The library uses `-march=native -mtune=native -O3` in Release. The
README cautions that `-march=icelake-server` was the original target
but they fell back to native because not every dev machine has the
needed AVX-512VL.

SGX enclave build (e.g. `applications/signal/Makefile`):

```bash
source /startsgxenv.sh    # from the cppbuilder docker image
cd applications/signal
make                      # builds signal.elf + signal.signed.so
```

The docker `cppbuilder` image (`tools/docker/cppbuilder/`) is the
reproducible build environment. `docker run --device=/dev/sgx_enclave
...` runs the built `signal.elf` against a real SGX device, or
`SGX_MODE=SIM` runs without one.

**Non-SGX test target: yes.** `ninja -C build test` is fully
SGX-independent. The library itself doesn't depend on the SGX SDK —
the SGX SDK is pulled in only at the `applications/` level. This is a
big deal for porting: the library can be built and tested on any
x86_64 box.

### 3.4 Public API

The integrator imports two headers (per `applications/signal/Enclave/TrustedLibrary/signal.hpp`):

```cpp
#include "oram/pathoram/oram.hpp"
#include "otree/otree.hpp"

using ORAMClient_t = typename _ORAM::PathORAM::ORAMClient::ORAMClient<
    _OBST::Node, ORAM__Z, false, ORAM_SERVER__LEVELS_PER_PACK>;
using OramClient_t = typename _OBST::OramClient::OramClient<ORAMClient_t>;
using OBST_t      = typename _OBST::OBST::OBST<OramClient_t>;
```

and then exercises the map via:

```cpp
OBST_t* client = new OBST_t(maxNumUsers, /* noInit= */ true);
client->Insert(id, v1);                       // void Insert(K, V)
bool contained = client->Get(id, retval);     // bool Get(K, V&)
// Plus from otree.hpp: Delete(k), Find(k,i,j), Size(k) for multimap
```

For the **initialization** fast-path, the API is:

```cpp
EM::Vector::Vector<std::pair<K,V>> v(sz);     // external-memory vector
OBST_t* client = new OBST_t(sz, v);           // batch-init constructor
```

So in shape: it's a templated `OMap<K,V>` with `Insert`, `Get`,
`Delete`, plus a faster batch constructor that takes a presorted-or-
sortable external-memory vector. The `K` and `V` types are
`uint64_t` in the shipped code; supporting bigger values needs the
data/metadata ORAM-tree split (Appendix C.4) — the map sits over the
metadata ORAM, and a separate data ORAM holds the heavy payloads,
indexed by a vptr in each AVL node. This is *not* exposed as a
templated `V` in the current header — you'd have to wire it manually.

### 3.5 Code volume, tests, recency, maintenance

- **LoC.** Paper says `enigmap_lib` is **5000 lines** of C++ (3500
  code + 1500 tests). Repo as of June 2026: by my file-listing,
  `ods/` is ≈ 24 source files, ≈ 280 KB; `tests/` is ≈ 16 files, ≈ 110 KB;
  applications add ≈ 30 KB of integration glue plus the vendored bearssl
  (~700 KB but not original work). The 5 KLoC claim is plausible
  if you exclude vendored crypto.
- **Test coverage signal.** GoogleTest suite includes:
  `otree.cpp` (8.5 KB), `otree_init.cpp`, `oram.cpp` (12.2 KB),
  `sort.cpp` (17.4 KB), `recursive.cpp` (9.6 KB), `signal_test.cpp`
  (7.0 KB), four `improvements_*.cpp` cache-ablation tests, two
  perf-benchmark tests (`perf_ods.cpp` 6.5 KB, `perf_ods_large.cpp`
  3.7 KB, `perf_sort.cpp` 9.8 KB). The structure suggests "correctness
  + perf-ablation," and the `improvements_{bucketcache,filecache,
  none,packing}.cpp` files map onto the four bars in Figures 5 and 6
  of the paper.
- **Commits.** Default branch has only **3 commits** (per `gh api`).
  Last push was **2023-08-10**. Effectively a code drop tied to the
  USENIX camera-ready, not an ongoing project. The GitLab mirror at
  `git.xtrm0.com/dsf/odsl` (Tinoco's personal GitLab — `xtrm0` is his
  handle) appears to be the canonical dev tree where CI artifacts
  live; the GitHub repo is a polished public-release mirror.
- **License.** *Not specified in the repo as of last inspection.*
  `gh repo view` returns `licenseInfo: null`. The README has no
  license section. **This is a real obstacle for downstream use** —
  per GitHub's policy, no license means "all rights reserved" by
  default; we cannot legally vendor it without contacting the authors
  to confirm intent. The paper's footer phrase "Our code has been open
  sourced" is not a license. This is a blocker we'd need to resolve.
- **Maintainers.** Active contributors are essentially Tinoco
  (handle `xtrm0`). No external committers. Three open issues, all
  unanswered:
  1. Issue #1 (Sept 2023): `cerr`/`endl` missing `<iostream>` include
     — `signal/` enclave doesn't compile. Trivial fix, never made.
  2. Issue #2 (Sept 2023): `signal.elf` crashes with `SGX_DEBUG=1`
     ("Assertion violated: { found }").
  3. Issue #3 (Dec 2024): `OBST(size)` initialization aborts when
     size > 262 140 — "Assertion violated: {bestIdx != (uint64_t)-1}"
     in `serverAllocator.hpp:50` (best-fit allocator). The user
     pasted a 25-frame stack trace. *This is concerning: it suggests
     the public release was not regression-tested at the scales the
     paper benchmarked at*, or that some flag needs to be set
     that isn't documented.

The picture is: **research-quality code, frozen at paper-time, with
known build issues, no license, no active maintenance.** Treat it as a
reference implementation, not a library you depend on.

---

## 4. Benchmark details

The headline numbers everyone quotes come from USENIX § 5.2 (pp.
4043-4046, Figures 3, 4, 5, 6, 7, 8, 9).

### 4.1 Hardware

Two machines (USENIX § 5.1):

- **SGXv1** machine: Intel Xeon E2200 (the paper writes "E2200"; this
  is almost certainly the E-2278G or similar Coffee Lake server),
  128 MB EPC, 16 GB RAM, SSD. SGXv1 caps EPC at 128 MB by hardware.
- **SGXv2** machine: Azure DC32ds_v3 (32-vCPU Confidential VM), 192 GB
  EPC enabled (allegedly Ice Lake Xeon), 256 GB RAM, NVMe SSD at
  80 000 IOPS / 1.2 Gbps. SGXv2 (Ice Lake-SP onward) caps EPC at up to
  512 GB.

The microbenchmark machine used to produce Figure 1a was the same
SGXv2 (paper p. 4038 first column).

### 4.2 Headline speedups (vs. Signal's linear scan)

USENIX § 1.2 and Figure 3 (SGXv1, p. 4044):

| Batch size β | EnigMap / Signal speedup at N = 256 M |
|---|---|
| 1     | **15 000×** |
| 10    | **1 500×**  |
| 100   | **150×**    |
| 1000  | **15×**     |

SGXv2, N = 4 G (= 2³², ≈ 2 TB DB):

| Batch size β | EnigMap / Signal speedup at N = 2³² |
|---|---|
| 1     | 130 000× |
| 10    | 13 000×  |
| 100   | 1 300×   |
| 1000  | 130×     |

The "15× at β=1000" is the conservative number the abstract uses; at
small batches and large N the gap is much bigger. **The crossover**
where EnigMap starts to outperform Signal at β=1000 is N ≈ 512 M
(USENIX § 5.2 paragraph after the table).

### 4.3 Speedup vs. Oblix

Cleaner since Oblix is an apples-to-apples oblivious algorithm.
USENIX § 5.2:

- At N = 2²⁶ ≈ 67 M: **24×** faster than Oblix.
- At N = 2²⁸ ≈ 268 M: **53×** faster than Oblix.

The Oblix code was not directly compilable for them (Rust version
hell — USENIX § 5.1 second column), so they compared by both ratioing
against Signal's open-source baseline; the cited Oblix paper reported
slowdowns of 12× and 3.5× vs Signal at batch 1000 for N=2²⁶ and 2²⁸,
which combined with EnigMap's measured speedups over Signal gives the
24×/53× figures.

### 4.4 Single-query latency at small N (the number we actually care about for wallets)

This is the question the paper doesn't headline. Reading off Figure 3
(SGXv1, EnigMap β=1, p. 4044) and Figure 4 (SGXv2, β=1, p. 4044):

- N = 10⁴ : ≈ 30 µs/query (off the bottom of the chart)
- N = 10⁵ : ≈ 100 µs/query
- N = 10⁶ : ≈ 200 µs/query
- N = 10⁷ : ≈ 400 µs/query
- N = 10⁸ : ≈ 900 µs/query
- N = 10⁹ : ≈ 2-3 ms/query

The CMU blog confirms: "At 2²⁶ entries: 0.45ms per Get vs. Signal's
930ms; at 2³² entries: 2ms per Get vs. Signal's 133s."

So for small DBs (which is what a per-user wallet would use against a
big shared map), single-query latency is in the 100 µs to 1 ms range
— very tolerable for interactive use.

### 4.5 Operation-mix breakdown (Figure 8, p. 4045)

| Operation | Cost relative to Search at N = 10⁶ |
|---|---|
| Search (Get)   | 1×  (≈ 200 µs) |
| Insert         | 1.5× to 2×     |
| Deletion       | ≈ 5× insertion → ≈ 7-10× search |

> "Insertion is about 1.5× to 2× more expensive than search, and
> deletion is 5× more expensive than insertion. This is because
> insertion needs to perform rebalancing in one node, and deletion
> needs to perform more rebalancing than insertion." (USENIX p. 4045)

Inserts and deletes both depend on the rotation case but pad to
worst-case depth, so the variance is small.

### 4.6 Memory footprint inside vs outside the enclave

The paper does not put hard footprint numbers in the body, but the
optimization breakdown (Figures 5 and 6) is illuminating:

- At N = 2²⁴ ≈ 16.8 M (Figure 5 — "RAM swap but no disk swap"):
  the database fits in 16 GB RAM but not in 128 MB EPC.
- At N = 2²⁸ ≈ 268 M (Figure 6 — "both RAM and disk swaps"):
  database exceeds RAM, disk I/O dominates the cost breakdown.

Path-ORAM stash size: `S_ = Z * (log₂ N + 1) + ORAM__MS` (from
`pathoram/oram.hpp` line 47), so at N = 2²⁸ and Z = 4, stash ≈ 116
blocks, negligibly small. The dominant in-enclave footprint is the
bucket-level LRU cache + the tree-top cache + the page-level
software cache the enclave maintains over external memory.

### 4.7 Multi-threading and contention

> "Snoopy [25] also implements oblivious algorithms in a hardware
> enclave context. Snoopy's focus, however, is how to *parallelize*
> multiple instances of oblivious data structures to increase
> throughput. In their experiments, they used Oblix [2] as one choice
> of a single instance. In this sense ENIGMAP is orthogonal and
> complementary to Snoopy, and it should not be hard to replace Oblix
> with ENIGMAP in Snoopy's implementation which should lead to
> significantly better performance." (USENIX § 1.3)

So **EnigMap is a single-threaded data structure.** Concurrent reads/
writes against one OMap instance are not directly supported; the
Snoopy (SOSP 2021) replication-and-sharding wrapper is the suggested
multi-instance path. The repo has an `omp_example` application but it
appears to be a generic OpenMP demo, not a parallel OMap.

The standalone-TS comparison with Signal-HT (Appendix D, ePrint
Figure 12) compares to Signal's batched-parallel HT-over-Path-ORAM
running multiple instances; even single-instance EnigMap is 3× faster.

### 4.8 Updates / insertions vs. lookups

Critical for our delta-stream use case (where every accepted block
inserts a few hundred SPKs and deletes a few hundred). The paper does
benchmark inserts and deletes — Figure 8, discussed in §4.5 above —
but the **macrobenchmark in Figures 3 and 4 is *batched lookups
only***. The asymptotic claim (Table 1, "Cost per batch of operations
... O(β log_B N · log N) page swaps") covers all of Size, Find,
Insert, Delete, but the *concrete* speedup numbers are for batches of
Find queries only.

For our use case this is acceptable — wallet deltas would do a small
number of inserts per block (≪ batched lookup load), so the operation
mix is dominated by lookups anyway. But the **bulk-update**
performance (e.g. ingesting 1 day of UTXO churn at once) is not
characterized in the paper.

### 4.9 Performance degradation as working set exceeds EPC

This is the whole point of the paper. From Figures 3 and 4:

- Below EPC capacity: nearly flat. EnigMap and Signal both look like
  in-memory operations.
- Once N exceeds EPC: Signal's curve hockey-sticks because Signal
  linearly scans, so it touches the full DB per query; the linear
  scan is dominated by EPC↔RAM page swaps. EnigMap's curve has a much
  gentler kink because Path-ORAM only touches `1.44 log N`
  blocks/query and the locality-friendly layout means O(log_B N)
  page swaps.
- Once N exceeds RAM: disk swap kicks in, both curves get a second
  kink upward, but EnigMap's curve is still ≈ flat-ish while Signal's
  is grim.

The transition points are explicitly marked on the figures: on SGXv1
(128 MB EPC, 16 GB RAM), the EnigMap RAM-swap line is at N ≈ 10⁶, the
disk-swap line at N ≈ 10⁸. On SGXv2 (192 GB EPC, 256 GB RAM), both
transitions happen ≈ 100× later in N.

---

## 5. Security model

### 5.1 Threat model (USENIX § 2.1)

> "We assume that the server is equipped with secure hardware enclaves
> such as Intel's SGX. [...] We assume that the server's operating
> system may be compromised, and there may be insiders in the
> facilities hosting the server who can perform physical attacks — we
> assume that the physical attacks cannot break the tamper-resistance
> of the hardware enclave."

Concretely they assume the adversary can:

- Observe page-level access patterns (page-fault adversary — Xu et al.
  "Controlled-channel attacks" style; reference [11] is Ristenpart et
  al. CCS 2009 hey-you-get-off-my-cloud, references [58-60] cover SGX
  cache-timing exposures).
- Observe **fine-grained memory accesses within the enclave**, "e.g.,
  through well-known cache-timing attacks [11, 58-60]." Cited works:
  Brasser et al. WOOT 2017 (SGX cache attacks are practical),
  Götzfried et al. EuroSec 2017 (cache attacks on Intel SGX).

They explicitly assume the hardware tamper-resistance holds — SEV is
not mentioned, neither is the SEV ciphertext side channel from Li et
al. S&P 2022.

### 5.2 Strong obliviousness / constant-time argument

This is the *important* part for our porting question, so it's worth
detailing. The paper devotes Appendix C.2 (ePrint pp. 19-21) to this.

**Strong / double obliviousness (Appendix C.2.1):** access patterns
include both **data accesses** and **instruction fetches** are required
to be statistically indistinguishable between any two
"trace-equivalent" request sequences. Trace-equivalent means: same
length, same operation types in the same positions, and for Find(k,
i, j) operations the difference j-i is the same. That last clause is
critical — the variable-length-output multimap Find inherently leaks
the output length j-i+1, but the *position pad* on the output is to a
public, request-derived length.

**Two sub-properties:**

1. **Data obliviousness within the enclave (C.2.2):** the Path-ORAM
   eviction is implemented with 3 oblivious sorts over the path +
   stash, following Wang et al. CCS 2014 (reference [17] — note
   reference numbering shifts in appendix). This is what guarantees
   the *physical* access trace is independent of secrets.
2. **Instruction-trace obliviousness (C.2.3):** every `if (X)
   { B = C; } else { D = E; }` is compiled to two CMOVs:
   `CMOV(X, B, C); CMOV(!X, D, E);`. Function calls inside
   secret-dependent branches use the "phantom function call" idea
   from Liu, Hicks, Shi CSF 2013 — both branches' callees execute,
   but the "no-op" branch's flag short-circuits its side effects.

> "Function calls inside secret branches are a more complex problem.
> We use the phantom function call idea from prior work [22]. [...]
> Whenever convenient, we simply hoist function calls outside secret
> ifs to avoid this issue." (ePrint p. 20)

**No formal proof.** There is no type-system argument and no
mechanized proof. The argument is informal: "we use CMOV-style
discipline everywhere, we examined Oblix's code and noted these
two specific places where they break it." Section C.2.3 even includes
the Oblix Rust snippet (Figures 10 and 11 of the ePrint) and points
out: (i) Oblix's `find_helper` early-exits on match, leaking depth via
instruction trace; (ii) Oblix's `insert_helper` has a secret-dependent
big if-else with different recursive call structures per branch.

**No automated checker either.** No SecVerifier, no
ct-verif/CTGRIND/Microwalk integration. Reliance on "[22, 23]" =
ObliVM (IEEE S&P 2015) and the Liu-Hicks-Shi CSF 2013 paper, both as
*conceptual* references, not as tools applied to the EnigMap source.

This is the **single most worrying** aspect of the security story
from a porting standpoint — the obliviousness is defended by code
review against a published baseline (Oblix). If the same code is
compiled with a different compiler or runs on a different ISA, the
inline-asm CMOVs would survive, but any CMOVs that fall back to
compiler-generated `cmov*` instructions could regress. They don't
appear to have a check.

### 5.3 SEV ciphertext side channel

**Not discussed.** The paper is strictly an SGX paper. SEV is not
mentioned, neither is Li et al. "CIPHERLEAKS" (S&P 2022) which is the
canonical SEV ciphertext side channel showing that AMD's pre-SEV-SNP
deterministic AES-XTS leaks plaintext changes through ciphertext
patterns. SEV-SNP fixes this with non-deterministic encryption (XEX),
which mitigates that specific attack, but the EnigMap paper has
nothing on SEV-SNP either.

This matters for us: SEV-SNP's threat model is *different* from SGX's
in two ways relevant to EnigMap's security argument:

1. SEV-SNP gives **VM-level encryption**, not enclave-level. Page
   tables are fully under the guest OS, not visible to the host.
   Page-fault adversaries (Xu/Peinado-style) don't directly apply —
   the host hypervisor can't take page faults inside the guest
   address space the same way.
2. There's **no EPC ceiling** on SEV-SNP. The whole guest's encrypted
   RAM is one homogeneous block, up to ~all of the host's memory.

What stays the same:

1. **Cache-timing attacks** still apply if the host shares cores with
   the guest. EnigMap's CMOV discipline still defends against these
   in the same way.
2. **DRAM-level side channels** (rowhammer-style, controlled channel
   via memory-controller scheduling, the SEV ciphertext channel pre-
   SNP) are SEV-specific. The CMOV discipline doesn't directly help
   here; you need careful avoidance of secret-dependent memory
   *contents* changing, not just secret-dependent access patterns. On
   SEV-SNP, the ciphertext side channel is closed (XEX), so this is
   *less* of a concern than pre-SNP SEV.

### 5.4 Known follow-ups, attacks, critiques

I found no published attacks or critiques of EnigMap specifically.
The line of follow-up work from the same group:

- **Efficient Oblivious Sorting and Shuffling for Hardware Enclaves**
  (Gu, Wang, Tinoco, Chen, Shi, Yi — ePrint 2023/1258), which became
  **Flexway O-Sort** (USENIX Security 2025). Improves the sorting
  primitive that EnigMap uses for initialization. Should plug into
  EnigMap's `external_memory/algorithm/` directly.
- **PicoGRAM** (Tinoco, Gu, Rajan, Shi — CRYPTO 2025). Practical
  garbled RAM from DDH. Different setting (2PC, not enclaves), but
  same algorithmic tradition.

No paper extends EnigMap to SEV-SNP or TDX. The CMU blog post mentions
"SGXv2/TDX" once in a footnote but doesn't extend the analysis.

---

## 6. Practical considerations for porting to SEV-SNP

### 6.1 What's SGX-specific in the codebase

Searching the source tree (per the listing in §3.1) for SGX
dependencies:

- **`applications/*/Enclave/` directories** — all SGX-specific:
  Enclave.edl (Enclave Description Language) files, Makefiles that
  invoke `sgx_edger8r`, `Enclave.lds` linker scripts, signed-enclave
  build steps. **None of this would survive a port to SEV-SNP** —
  EDL/edger8r is purely an SGX SDK concept for the ocall/ecall ABI.
  On SEV-SNP your "enclave boundary" is the VM boundary; there's no
  ocall, just syscalls and shared-memory channels.
- **`ods/external_memory/server/enclaveFileServer.edl`** — declares
  the ocalls used to swap pages out of the enclave. Same story: EDL,
  ocall-shaped, not portable.
- **`ods/external_memory/server/enclaveFileServer_{trusted,untrusted}.hpp`**
  — split into trusted-side (in-enclave) and untrusted-side
  (untrusted-app) halves. The trusted side does the encrypt/decrypt
  + ocall, the untrusted side does the file I/O. On SEV-SNP this
  whole split goes away: the VM is the trust boundary, file I/O
  happens inside the VM. **This part needs a rewrite, not a port.**
- **`applications/*/Enclave/bearssl/`** — vendored bearssl. Was
  needed inside SGX because OpenSSL doesn't run cleanly in the SGX
  restricted libc. **On SEV-SNP we have a full Linux userspace and
  can drop bearssl entirely**, going back to OpenSSL.
- **`#ifdef ENCLAVE_MODE`** — sprinkled in the source (visible in
  `encutils.cpp`, `node.hpp`). Gates the SGX-specific `Enclave_t.h`
  include and stream-print formatting. **Trivial to repurpose**:
  define our own `#define ENCLAVE_MODE` or strip the guards.
- **`-march=native`** — fine on SEV-SNP, which is x86_64.

### 6.2 Is the oblivious-primitives library SGX-portable?

**The `ods/` library proper is essentially SGX-clean.** The library
has no `#ifdef SGX` or `#ifdef SGX_*` in the public-API headers (I
checked `otree.hpp`, `node.hpp`, `pathoram/oram.hpp`,
`mov_intrinsics.hpp`, `encutils.cpp`). The library *is* built and
tested in the non-SGX target (`ninja -C build test`) — that's how the
GoogleTest suite runs. So the algorithmic core is portable.

What's SGX-shaped but lives in the library:

- The `external_memory/server/` directory — abstracts where the
  "external memory" lives. There are three backends:
  `enclaveFileServer*` (SGX-specific, ocall to host fs),
  `enclaveMemServer_untrusted.hpp` (RAM-backed mock for tests),
  `enclaveMmapFileServer_untrusted.hpp` (mmap-backed). For SEV-SNP
  port: we'd write a fourth backend that uses ordinary `read`/`write`
  inside the VM, or just bind to `enclaveMmapFileServer_untrusted.hpp`
  as-is (mmap works fine inside an SEV-SNP guest).
- The encryption layer (`ods/common/encutils.cpp`) uses OpenSSL via
  `EVP_*`. On SGX inside `Enclave_t.h` it presumably switches via
  `#ifdef NOOPENSSL` (visible at top of `encutils.cpp`) to bearssl or
  to Intel-provided crypto. **On SEV-SNP we use OpenSSL directly**;
  in fact, we might not even need to encrypt the "external memory" at
  all, because SEV-SNP guest RAM is already AES-encrypted at the
  memory controller. This is a *real performance win* — we could
  potentially drop the encryption layer entirely.

### 6.3 The CMOV discipline on a non-SGX TEE

This is the question that matters most.

**The CMOV is x86-`cmovnz` inline asm**, in
`ods/common/mov_intrinsics.hpp`:

```cpp
INLINE void CMOV8_internal(const uint64_t cond, uint64_t& guy1,
                           const uint64_t& guy2) {
  asm volatile(
      "test %[mcond], %[mcond]\n\t"
      "cmovnz %[i2], %[i1]\n\t"
      ...);
}
```

**This works equally on SEV-SNP**, since SEV-SNP is the same
x86_64 ISA. The CMOV instruction is identical — it's a Pentium Pro
(1995) instruction. The semantics are: conditional register-to-register
move, executes in constant time per Intel/AMD's optimization manuals,
no microarchitectural dependence on the condition flag for the load
side. SEV-SNP doesn't change `cmov*` behavior.

What *might* differ:

- **Compiler-generated CMOVs.** Outside the inline-asm hot path, the
  C++ code uses `CMOV(cond, dest, src)` which expands to the inline
  asm — *all* of the explicit CMOV-discipline sites in `otree.hpp`
  go through `mov_intrinsics.hpp`. So this is fine.
- **Branchless higher-level expressions.** Some code uses
  multiplication-based branchless idioms — visible in `node.hpp`'s
  `operator==`: `(k == other.k) * (v == other.v) * ...`. The compiler
  might or might not emit CMOV here depending on `-march=native`. We'd
  want to verify with `objdump` post-port.
- **AES-NI for encryption.** EnigMap uses AES-NI via OpenSSL. Both
  SGX and SEV-SNP guests have AES-NI available (no architecture
  difference).

**The CMOV discipline ports cleanly.** No inline-asm changes, no
intrinsic replacement, no ARM port concerns (we're x86_64 in both
cases). The repo has *no* `cmov_intrinsics_arm.hpp` — they never
tried ARM, which is fine for us.

### 6.4 Does the external-memory trick still help on SEV-SNP?

**This is the key question.** The whole framing of the paper is "EPC
is small, page swap is expensive, optimize for `log_B N` instead of
`log N`." On SEV-SNP the EPC ceiling is gone — the encrypted guest can
have hundreds of GB of "secure" memory. So is the trick a no-op?

My read: **the trick is no longer a *security* necessity but it's
still a *performance* win**, just for a different reason.

- The ORAM tree at N = 10⁹ entries is ≈ 64 GB if buckets are 64 B and
  Z=4. On SEV-SNP we could pin all of it in VM memory; no EPC↔RAM
  swap. Page-swap cost goes away.
- *But* the DRAM ↔ L3 ↔ L2 ↔ L1 hierarchy is unchanged. A heap-layout
  tree access touches O(log N) cache lines spread across the tree; a
  locality-friendly subtree-packed tree access touches O(log_B N)
  cache lines clustered into the same 64-byte cache line (for B=64).
  At N = 10⁹, that's 28 vs 30/log(64) = 5 cache-line groups. **The
  same factor-of-6 wire reduction shows up at the cache-line level
  instead of the page level**, just with B reset from 4 KB to 64 B
  and M reset from 128 MB EPC to 30 MB L3.
- The initialization wins (O(N log N) work vs O(N log³ N)) are
  *algorithm* wins independent of the cache hierarchy. They still
  matter on SEV-SNP.
- The locality wins also matter for **disk swap** if the DB exceeds
  VM RAM. On SEV-SNP without sharding, a 100 GB UTXO map exceeds
  most VPS sizes. So if we're going past RAM, the same logic kicks
  in at the RAM↔SSD boundary.

So the external-memory trick is "slightly counterproductive" in the
sense that the *concrete page-size B* we'd choose for SEV-SNP is
probably 64 B (cache line) instead of 4 KB (EPC page) — but we still
want the layout. EnigMap exposes B as a template parameter (it's
`LEVELS_PER_PACK` etc. in the ORAM client template), so we'd just
retune.

### 6.5 What else to budget for the port

- **Build system rewrite.** The SGX-specific Makefiles are not
  reusable. We'd take the `ods/` library as-is, build it with CMake
  in a normal Linux container, and write a thin Rust/C++ shim to
  expose `OBST::{Insert,Get,Delete}` over our own RPC.
- **Persistence to disk.** EnigMap as shipped is RAM-only — there's
  no commit-to-disk story. The page-level "external memory" mmap
  backend gets you persistence as a side effect, but there's no
  documented restart-from-disk path. We'd need to add a snapshot/
  restore layer if we want to survive a VM restart without rebuilding
  the 9.5-hour init.
- **Crash safety.** Same issue. The Path-ORAM stash plus mid-rotation
  state is fragile to crashes. EnigMap doesn't address this.
- **Multi-client (concurrency).** Single-threaded only. Either we
  serialize all requests through a single OMap instance, or we shard
  the way Snoopy (SOSP 2021) suggested.
- **License.** Must contact Tinoco/Shi to confirm permissive license
  intent before we vendor a single line.

---

## 7. Open questions / gaps

What the paper does not address that matters to us:

### 7.1 Persistent storage and recovery

EnigMap is a RAM-resident OMap with an optional ocall-based page-swap
mechanism to an untrusted backing store. **There is no story for**:

- Restart from a previously-built OMap on disk. After a 9.5-hour
  init, if the enclave crashes, you start over.
- Checkpoint / snapshot. No explicit periodic-flush mechanism.
- Concurrent modification + read (single-threaded, see §4.7).
- Log-and-replay or write-ahead-log for in-flight Insert / Delete.

The repo's third open issue (Issue #3, Dec 2024) is exactly a
"can't initialize large OBST" scenario — the public release doesn't
robustly do the thing the paper benchmarked at scale.

### 7.2 Authenticated integrity and freshness

Appendix C.5 of the ePrint says the implementation uses AES-GCM mode
with a customized Merkle tree overlaid on the ORAM-tree structure to
provide integrity and freshness (so the untrusted host can't roll
back). They claim "1-2% overhead" for the integrity. **In the public
code repo, this Merkle-overlay code is not obviously isolated** —
it's intermixed with the encryption layer in `encutils.cpp` and
`encrypted.hpp`. Porting it cleanly to a different freshness mechanism
(e.g. monotonic counter from TPM / vTPM on SEV-SNP) needs source-
level surgery.

### 7.3 Multi-tenant / multi-DB

Each `OBST_t` instance is its own ORAM tree. There's no native concept
of "shared OMap with per-user namespaces." For a Bitcoin wallet
scenario where many users query the same UTXO map, this is fine. For a
scenario where many users have their own private maps, you'd
instantiate many `OBST_t`s and pay per-instance overhead.

### 7.4 Range queries

The map is a key-value store. The multimap abstraction supports
`Find(k, i, j)` (return the i-th to j-th value for key k), but **does
not support a range query over keys** (e.g. "return all keys in
[k_low, k_high]"). The AVL tree underneath could in principle support
this, but it's not exposed in the API and would need careful
worst-case-padding to remain oblivious. For our UTXO-by-scripthash
scenario this is fine (queries are point lookups).

### 7.5 Open GitHub issues (all unresolved as of June 2026)

1. **#1 (Sept 2023).** Missing `#include <iostream>` in
   `oram/common/oram_client_interface.hpp` — `signal` enclave build
   fails on `main` branch. Five-line fix, not made. *Indicates the
   public repo is not regularly built by the authors.*
2. **#2 (Sept 2023).** `signal.elf` crashes with `SGX_DEBUG=1`:
   "Assertion violated: { found }". Triggered immediately after
   `Constructor done`.
3. **#3 (Dec 2024).** `OBST(size)` initialization aborts at
   size > 262 140 — "Assertion violated: {bestIdx != (uint64_t)-1}"
   in `serverAllocator.hpp:50` (best-fit free-list allocator out of
   memory). Stack trace shows the failure is in
   `LargeBlockAllocator::Allocate`. The user is trying to init at 262 144
   nodes (~256 K) with a 150 MB initial slot — the allocator can't
   find a 300 MB extent. **This is a real bug in the public release;
   the paper-time builds probably had a different default extent
   size.**

These signal that the released code is **fragile in default
configuration** and that paper-time scale (N=256M) needs flags / build
flavors that aren't documented in the README.

### 7.6 Reproducibility of the benchmark numbers

There is no published artifact (e.g. on Zenodo) for EnigMap. The only
documentation is the README and the `applications/signal/` Makefile.
The `applications/signal/algo_runner.sh` is 1458 B — a thin runner.
The lack of an Artifact-Evaluation-style badge means the headline
benchmark numbers in §1.2 of the paper are not independently
reproducible from the public code without significant guesswork about
EPC sizing, flag settings, and whether to use the `enclaveMemServer`
or `enclaveFileServer` backend.

---

## 8. References (paper bibliography, BitcoinPIR-relevant subset)

Numbered as in the USENIX 2023 paper:

- [1] Wang et al., **Oblivious Data Structures**, CCS 2014 — the
  direct algorithmic predecessor.
- [2] Mishra et al., **Oblix**, IEEE S&P 2018 — the engineering
  baseline.
- [4] Signal Technology Preview, *Private Contact Discovery for
  Signal* (2017 blog post) — the linear-scan baseline.
- [6] Stefanov et al., **Path ORAM**, CCS 2013 / JACM 2018 — the
  underlying ORAM.
- [16] Ramachandran & Shi, **Data-Oblivious Algorithms for Multicores**,
  SPAA 2021 — the ORBA primitive used in Stage-2 init.
- [17] Wang et al., **Scoram**, ACM CCS 2014 — strong-obliviousness
  technique used in §4.
- [18] Aggarwal & Vitter, **The I/O Complexity of Sorting**, CACM
  1988 — external-memory model origin.
- [20] Bender, Demaine, Farach-Colton, **Cache-Oblivious B-Trees**,
  SICOMP 2005 — the layout idea EnigMap adapts.
- [22] Liu et al., **ObliVM**, IEEE S&P 2015 — instruction-trace
  obliviousness framework.
- [23] Liu, Hicks, Shi, **Memory Trace Oblivious Program Execution**,
  CSF 2013 — same.
- [24] Signal, *Technology Deep Dive: Building a Faster ORAM Layer for
  Enclaves* (2022 blog post) — the concurrent Signal-HT system.
- [25] Dauterman et al., **Snoopy**, SOSP 2021 — multi-instance
  parallelization wrapper; suggested as where EnigMap could plug in.
- [31] Sasy et al., **ZeroTrace**, NDSS 2018 — Path-ORAM in SGX.
- [42] Zhang et al., **Klotski**, ASPLOS 2020 — another SGX Path-ORAM.
- [58] Costan & Devadas, **Intel SGX Explained**, ePrint 2016/086.
- [61] Ngoc et al., **Everything You Should Know About Intel SGX
  Performance on Virtualized Systems**, SIGMETRICS 2019 — confirms
  EnigMap's microbenchmarks.

---

## Bottom line for our porting decision

EnigMap is the right reference algorithm for an oblivious-map-in-TEE
deployment. The library is small (5 KLoC), the algorithm is clearly
described, and the asymptotic and concrete wins over Oblix are
genuine. The CMOV discipline ports cleanly to SEV-SNP because the
ISA is the same.

What we'd pay for porting it:

1. **Rewrite the `external_memory/server/` SGX-EDL backend** as a
   plain Linux file/mmap backend. Probably 1-2 KLoC of new code.
2. **Drop bearssl, go back to OpenSSL** — net code reduction, win.
3. **Consider disabling the OMap's own AES-GCM encryption layer**
   inside SEV-SNP guest RAM since SEV-SNP already encrypts at the
   memory controller. Real perf win; needs threat-model think.
4. **Retune B from 4 KB to 64 B** (cache line) if we're staying in
   RAM, or keep at 4 KB if we expect disk swap.
5. **Add persistence + crash recovery.** Not in EnigMap, not
   trivial.
6. **License negotiation.** No license declared on the repo — this is
   a blocker, not an inconvenience.
7. **Resolve open Issue #3** (large-init failure) before trusting
   the public release at scale.

The performance budget at our targeted N (probably 10⁷ to 10⁸ SPK
entries) is **roughly 100 µs to 1 ms per Get and ~5× that for an
Insert/Delete**. For an interactive wallet that's comfortably fast.
For batched delta ingestion (a few hundred SPKs per block), at 1 ms
per Insert and Z=4 buckets, we'd budget ≈ 500 ms per block of delta
ingestion — well below the 10-minute block interval.

The single biggest concern is the **lack of any mechanized
obliviousness proof** combined with the **lack of an automated
constant-time checker** in the build pipeline. We would not want to
ship EnigMap into production without first writing our own
ct-verif / Microwalk pass over the compiled binary to confirm that no
secret-dependent branch or memory access slipped through the C++
template machinery.
