# Ring ORAM Experiment Plan

This branch is an isolated experiment. The BitcoinPIR deployment path should
continue to use the current direct INDEX+CHUNK deterministic tree ORAM until
this branch proves a clear latency win.

## Question

Can a Ring ORAM layout reduce BitcoinPIR ORAM request latency enough to justify
the extra implementation and crash-consistency complexity?

The comparison target is the current direct ORAM shape:

```text
pack = 16
Z = 2
leaf_divisor = 2
stash_capacity >= 128
padded_slots = 25
access_budget = 75
auth_store = 1
cache_levels = 0 initially
```

The deployment branch keeps `drain_per_access=2` because the current image state
schedules two public evictions per logical access. This experiment may also test
`evictions_per_access=1, drain_per_access=1` for the existing deterministic tree
ORAM as a baseline, but Ring ORAM should be evaluated separately.

## Non-Goals

- Do not wire Ring ORAM into `/Users/cusgadmin/BitcoinPIR`.
- Do not change BitcoinPIR runtime flags or systemd deployment here.
- Do not optimize away Merkle authentication in the headline comparison.
- Do not require recursive position maps for the first experiment.

## Prototype Scope

Build the smallest Ring ORAM prototype that can answer these measurements:

1. FULL and DELTA direct INDEX+CHUNK geometry sizing.
2. Metadata-only stash pressure for public eviction periods `A`.
3. Estimated and measured path IO count with `auth_store=1`.
4. Request latency estimate for padded-25 / budget-75.
5. Crash-state inventory: counters, per-bucket read counters, permutations,
   stash, position map, auth roots/state.

The prototype can initially be metadata-only. A disk-backed authenticated
payload implementation is only worth doing after the metadata stress result
looks promising.

## Ring ORAM Design Points To Test

Ring ORAM is only interesting if the read path can avoid rewriting every bucket
payload page on every access. Track these cases separately:

```text
Case A: current PageStore granularity
  ReadPath still reads full bucket pages.
  Expected win is mostly from less frequent EvictPath work.

Case B: slot-addressable layout
  ReadPath reads one selected slot per bucket plus metadata.
  Expected win is larger, but layout/auth/crash complexity rises.
```

The public parameters to sweep:

```text
bucket_size Z: 4, 8, 16, 32
eviction_period A: 4, 8, 16, 32, 48
stash_capacity: 128, 256, 512
cache_levels: 0, 2, 3, 4
```

The first pass should keep the same direct block packing:

```text
INDEX item block = 16 packed direct index bins
CHUNK item block = 16 packed 40-byte chunk records
```

## Success Bar

Ring ORAM is worth integrating only if it meets all of these:

```text
same direct INDEX+CHUNK semantics
same or stronger public access-shape story
auth_store enabled in the final benchmark
stash overflow absent in long random and adversarial-pattern stress
crash-state model is documentable and implementable
padded-25 request latency improves by at least 1.5x over the current backend
```

If the win is less than 1.5x, prefer improving the current backend with top-tree
cache, better IO batching, and public background eviction.

## Suggested Milestones

1. Add `ring_stress.rs` with metadata-only simulation over direct geometries.
2. Add `oramctl stress-ring-direct` to sweep `(Z, A, stash_capacity)`.
3. Add an IO estimator that reports read-path and evict-path page touches for
   current-page and slot-addressable layouts.
4. Compare against deterministic tree ORAM with:

```text
evictions_per_access=2, drain_per_access=2
evictions_per_access=2, drain_per_access=1 plus bounded public debt
evictions_per_access=1, drain_per_access=1
```

5. Only after the above looks good, implement a minimal authenticated
   slot-addressable disk layout.

