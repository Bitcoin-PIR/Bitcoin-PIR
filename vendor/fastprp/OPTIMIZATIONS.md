# Remaining Optimization Opportunities from Stefanov & Shi (2012)

Status of all paper optimizations relative to our implementation.

## Implemented

| Optimization | Section | Impact |
|---|---|---|
| Counter cache (C1 at stride boundaries) | 4.0 | Core speedup: O(N) → O(√N log N) per query |
| Counter alignment (partition-boundary cache) | 4.2 | 2.6x on permute (3 scans → 1 scan per depth) |
| AES-NI / ARM Crypto Extensions | 5.1 | Hardware-accelerated AES via `aes` crate |
| POPCNT | 5.1 | `u128::count_ones()` compiles to hardware popcount |

## Not Yet Implemented

### 1. Bidirectional Scanning (Section 4.1)

**What**: When computing C1 via the stride cache, scan **backward** from the
next cached boundary when that is shorter than scanning forward from the
previous boundary.

**Current**: Always scan forward from the nearest lower stride boundary.
Average scan per C1 call = s. Maximum = 2s.

**With optimization**: Pick shorter direction. Average scan = s/2. Maximum = s.

**Expected impact**: ~2x reduction in remaining scan work. Since the partition
cache already eliminates 2 of 3 scans, this would speed up the remaining
1 scan by ~2x. Net: ~30-40% faster permute.

**Complexity**: Low. Modify `CounterCache::cumulative_ones()` to check both
directions and pick the shorter one.

---

### 2. Cache Compression (Section 5.2)

**What**: Huffman-code the cached C1 counters. Each counter is a binomial
random variable with entropy ~(log2(πes) - 1)/2 + O(1/s) bits. For
N=2^31 and s=2^16, this is ~9 bits per counter vs 32 bits (u32), giving
57% compression.

**Current**: Raw `u32` per counter. Simple, no decode overhead.

**Expected impact**: ~3.5x smaller stride cache. Allows using a much smaller
stride (= faster lookups) within the same memory budget. Or: same stride
with much less memory, useful for embedded / multi-key scenarios.

**Complexity**: Medium. Need Huffman codec, variable-length decode on lookup.
Adds decode latency per cache access. May not be worth it unless memory
is constrained.

---

### 3. Incremental Caching (Section 5.3)

**What**: Build the cache in halving increments. Increment I1 caches at
stride s, I2 caches at stride s/2 (only the new midpoints), etc. Each
increment halves the stride. Increments can be stored as separate files
and loaded on demand.

**Example** (N=16, s=8):
- I1 = {C1(β_d, 0, 8), C1(β_d, 8, 8)} → stride 8
- I2 = {C1(β_d, 0, 4), C1(β_d, 8, 4)} → combining I1+I2 gives stride 4

**Current**: Single full cache built at initialization.

**Expected impact**: Enables progressive cache refinement. Build a coarse
cache quickly, start serving queries, refine in the background. Also
enables disk-backed caching for very large N.

**Complexity**: Medium. Refactor cache build to be incremental. The
partition-boundary cache makes this less critical (it already eliminates
most scanning), but useful for disk persistence.

---

### 4. Bidirectional Scanning for C0_inv / C1_inv (Section 4.1)

**What**: The inverse functions (used by unpermute) do binary search + linear
scan within a stride block. The linear scan can also be bidirectional.

**Current**: Forward-only linear scan after binary search.

**Expected impact**: ~2x faster C0_inv/C1_inv. Since unpermute is already
~3x slower than permute (due to the binary search + inverse scan), this
could significantly close the gap.

**Complexity**: Low. Add backward `find_kth_one` / `find_kth_zero` variants
in `bitstring.rs`.

---

### 5. Assembly-Level AES+POPCNT Fusion (Section 5.1, Figure 6)

**What**: The paper shows hand-written x86-64 assembly that fuses AES
encryption and popcount into a single tight loop: encrypt block, split
into two u64 halves, popcount each, accumulate. This avoids intermediate
memory traffic.

**Current**: The `aes` crate handles AES, and `count_ones()` handles popcount.
The compiler probably generates reasonable code but may not fuse them
optimally.

**Expected impact**: Small (5-15%). The Rust compiler with LTO already does
well. May matter more for ARM where the AES+CNT instruction sequence
differs from x86.

**Complexity**: High. Requires `#[cfg(target_arch)]` inline assembly or
intrinsics. Hard to maintain across platforms.

---

## Priorities (recommended order)

1. **Bidirectional scanning** (Section 4.1) — low effort, ~30-40% on permute
2. **Bidirectional C0_inv/C1_inv** (Section 4.1) — low effort, big win for unpermute
3. **Incremental caching** (Section 5.3) — medium effort, enables disk persistence
4. **Cache compression** (Section 5.2) — medium effort, memory-constrained scenarios
5. **ASM fusion** (Section 5.1) — high effort, marginal gains
