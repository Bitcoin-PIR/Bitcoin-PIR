# Fix Plan: HarmonyPIR Variable-Count Side-Channel

**Status:** Ready for implementation.
**Scope:** Close a privacy leak where the HarmonyPIR per-group query sends a *variable* number of indices per round, letting the Query Server observe how many real-segment cells are non-empty — a statistic that drifts upward as hints get consumed, leaking both query count and fresh-vs-aged status.

---

## TL;DR for the implementing session

You are landing a single protocol-level privacy fix in the HarmonyPIR client layer. No server-side wire-format change is required — the fix is entirely client-side padding. When done, every HarmonyPIR INDEX/CHUNK/sibling query slot sends **exactly `T − 1` indices**, regardless of real segment state, query count, or which round it is.

Primary file to edit: [`harmonypir-wasm/src/lib.rs`](harmonypir-wasm/src/lib.rs). Secondary: tests in the same file, plus a scoped audit pass on call-sites in [`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs) to confirm response lengths line up.

🔒 **Padding is load-bearing. Do not add any code path that emits fewer than `T − 1` indices, and do not add a "skip when empty" early-exit.** This matches the existing "NEVER optimize away padding" invariant in [`CLAUDE.md`](CLAUDE.md).

---

## 1. The bug, concretely

### Where it is

[`harmonypir-wasm/src/lib.rs:295-351`](harmonypir-wasm/src/lib.rs#L295) (`HarmonyGroup::build_request`):

```rust
// Batch-access all cells in the segment except position r.
let mut cells: Vec<usize> = Vec::with_capacity(t);
let mut cell_positions: Vec<usize> = Vec::with_capacity(t);
for i in 0..t {
    if i != r {
        cells.push(s * t + i);
        cell_positions.push(i);
    }
}
let values = self.ds.batch_access(&cells)?;

let mut filtered: Vec<(u32, usize)> = Vec::new();
for (k, &val) in values.iter().enumerate() {
    if val != EMPTY {                             // ← variable count leak
        filtered.push((val as u32, cell_positions[k]));
    }
}
filtered.sort_unstable_by_key(|&(idx, _)| idx);
// Serialize only the sorted indices (no EMPTY markers, no dummy).
let mut request_bytes = Vec::with_capacity(filtered.len() * 4);
for &(idx, _) in &filtered {
    request_bytes.extend_from_slice(&idx.to_le_bytes());
}
```

Wire encoder at [`pir-sdk-client/src/harmony.rs:2815-2835`](pir-sdk-client/src/harmony.rs#L2815) serializes `[4B count LE][count × 4B indices LE]` per group — the count is directly readable on the wire.

Server decoder at [`pir-runtime-core/src/protocol.rs:667-706`](pir-runtime-core/src/protocol.rs#L667) reads the same variable count and returns a variable-length response at [`pir-runtime-core/src/handler.rs:239`](pir-runtime-core/src/handler.rs#L239) (`Vec::with_capacity(indices.len() * entry_size)`). The **response length** therefore also leaks the count.

`build_synthetic_dummy` at [`harmonypir-wasm/src/lib.rs:410-442`](harmonypir-wasm/src/lib.rs#L410) samples `count ~ Binomial(T, 0.5)` — matching the **fresh-client** distribution, not the aged-client one. So real-query groups and padding-group dummies drift apart over time.

### Why the count leaks "hint usage"

For a still-usable segment `s` at query `k`:

- `C_original` = originally-non-empty cells in `s` (constant, ~Binomial(T, 0.5))
- `C_relocated` = originally-empty cells in `s` that received a relocated value from some earlier query's segment

`batch_access(s)` returns `C_original + C_relocated` values. `C_relocated` grows **monotonically** with `k` because every `RelocateSegment` call appends to the history and `Access` chain-walks through it, so originally-empty cells in `s` progressively fill up.

Expected count drifts from `T/2` toward `T − 1` as the client works through its query budget (max queries = `M/2 = N/T`). The server can fit per-group trajectories and infer:

1. Approximate queries-per-group since last offline refresh.
2. Which padded slot is the real query each round (the slot whose count is drifting faster than `Binomial(T, 0.5)`).
3. When the client is about to re-run offline.

### Existing partial acknowledgement

[`harmonypir-wasm/src/lib.rs:362-369`](harmonypir-wasm/src/lib.rs#L362):

```rust
/// # TODO (privacy)
///
/// The count of non-empty indices per segment follows a distribution that
/// depends on T and N.  A truly indistinguishable dummy would need to sample
/// from that same distribution (~Binomial(T, 0.5)) rather than using an
/// actual segment.  For now we query a random real bin, which produces a
/// realistic but not perfectly simulated count.  This must be revisited
/// before production — see the protocol's privacy analysis.
```

This TODO understates the problem — the count itself is non-stationary, not just "not perfectly simulated".

---

## 2. Chosen fix: pad to fixed `T − 1` indices with cancel-out dummies

### Why this approach

Three alternatives were considered (see original investigation transcript for discussion):

| Option | Count hidden? | Position leak? | Server change? | Cost |
|---|---|---|---|---|
| **A. Pad with cancel-out dummy indices** (chosen) | ✅ fully | ❌ none | ❌ none | ~2× bandwidth on average |
| B. EMPTY sentinel in slot | ✅ fully | ⚠️ per-slot empty bit visible | ✅ server must treat sentinel | same ~2× |
| C. Dither count to `T_max(k)` | ⚠️ partially | ❌ none | ❌ none | less than 2× but leak not fully closed |

Option A is the one that matches the rest of the codebase's posture (mandatory `K`/`K_CHUNK`/`25-MERKLE` fixed-size padding in [`CLAUDE.md`](CLAUDE.md)). The server literally cannot tell a real query from a padded one because *from the server's view, both are just `T − 1` sorted indices into the DB*.

### How cancellation works

HarmonyPIR's recovery formula:

```
answer = H[s] XOR (XOR of DB[v] for every non-empty cell v in segment s)
```

If we pad the request with extra indices `D` (drawn uniformly from `[0, real_n) \ R`, where `R` is the real non-empty segment values), the server returns entries for `R ∪ D`. Computing:

```
XOR_all_response = XOR over (R ∪ D) of DB[i]
                 = (XOR over R of DB[i]) XOR (XOR over D of DB[i])

answer' = H[s] XOR XOR_all_response XOR (XOR over D of DB[i])
        = H[s] XOR (XOR over R of DB[i])
        = DB[q]   ✓
```

The client knows exactly which response entries correspond to `D` (by looking up indices from `merged` against `R`), so it can XOR those out in a second pass. Hint update stays correct because we only call `xor_into(hints[d_i], entry_for_position_i)` for positions `i` that had a *real* segment value — dummies are not in `cell_positions` and therefore don't touch hints.

### Invariants after the fix

- Every HarmonyPIR per-group request contains exactly `T − 1` u32 indices. (Note: `T` here is the per-group `params.t`; it varies per group, so "fixed" means fixed *per group*, not across groups. The leak we care about is *within a group across queries*, which this closes.)
- Every `HarmonyGroup::build_request`, `build_synthetic_dummy`, and `build_dummy_request` emits the same `T − 1` count.
- The indices in a request are sorted ascending, uniform-looking to the server, drawn from `[0, real_n)`, all distinct.
- `process_response` and `process_response_xor_only` cancel dummy contributions before the answer is returned.
- `relocate_and_update_hints` uses only real-entry-position mappings; dummy entries are discarded after cancellation.
- **No wire-format change, no server change, no protocol version bump.**

---

## 3. Implementation checklist

### 3.1 Files to edit

1. **[`harmonypir-wasm/src/lib.rs`](harmonypir-wasm/src/lib.rs)** — primary fix. Functions to change:
   - `HarmonyGroup::build_request` (lines 290–351)
   - `HarmonyGroup::build_synthetic_dummy` (lines 390–442)
   - `HarmonyGroup::build_dummy_request` (lines 353–388) — still routes through `build_request`, so it inherits the fix, but re-check the "save/restore state" dance still works when `last_position_map` contains only real-entry positions.
   - `HarmonyGroup::process_response` (lines 444–476) — add dummy-cancellation pass.
   - `HarmonyGroup::process_response_xor_only` (lines 478–507) — same cancellation.
   - `HarmonyGroup::relocate_and_update_hints` (in the bottom `impl` block around line 697) — confirm it only touches real positions. The current logic already uses `pos_to_entry[i]` keyed by segment position, so dummies (which never get a segment position) naturally fall out. **Verify this assumption holds with the new data flow before shipping.**
   - Add new private state field(s) on `HarmonyGroup` to record dummy indices for the current round (see §3.2 below).
   - Update the existing `test_group_lifecycle` test at line ~935 — the assertion `assert_eq!(req.request_bytes.len(), group.t() as usize * 4)` will currently pass only by coincidence (when all T − 1 non-r slots happen to be non-empty). After the fix this assertion should become deterministically true: change it to `assert_eq!(req.request_bytes.len(), (group.t() as usize - 1) * 4)` and make it not depend on happening to catch a full segment.
   - Add new tests (see §3.4).
   - Keep serialization format unchanged — the new fields are per-round scratch, not persisted state. Verify this.

2. **[`harmonypir-wasm/src/state.rs`](harmonypir-wasm/src/state.rs)** — if `HarmonyGroup`'s persistent state format touches any of the new fields, update the serializer. Expected answer: no touch needed, but check.

3. **[`pir-sdk-client/src/harmony.rs`](pir-sdk-client/src/harmony.rs)** — audit-only pass. Confirm:
   - `run_index_round` (around line 1520) and `run_chunk_round` (around line 2465) pass the new fixed-length `req.request()` through `bytes_to_u32_vec` unchanged — they should.
   - `process_response` calls downstream of this module expect the new fixed response length. Since the response length = `(T − 1) * w` now is deterministic per group, any assertion on response length should pass; `harmony.rs` currently trusts the WASM wrapper's `process_response` to validate, so no change expected.
   - `HarmonySiblingQuerier::query_pass` (around line 3040) — same audit, same expected outcome.

4. **[`pir-sdk-client/src/hint_cache.rs`](pir-sdk-client/src/hint_cache.rs)** — audit-only. The hint cache fingerprint depends on `(master_prp_key, prp_backend, db_id, height, index_bins, chunk_bins, tag_seed, index_k, chunk_k)`. None of those change. Cache stays valid across the fix. **But**: if the fix is ever reverted or altered, make sure hint-cache semantics don't silently break. Leave a comment referencing this plan.

5. **[`CLAUDE.md`](CLAUDE.md)** — add an entry to "CRITICAL SECURITY REQUIREMENTS" (sibling of the existing "Query Padding" and "Merkle INDEX Item-Count Symmetry" sections):

   ```markdown
   ### HarmonyPIR Per-Group Request-Count Symmetry (MANDATORY for Privacy)

   Every HarmonyPIR per-group query slot (INDEX, CHUNK, or sibling) MUST
   send exactly `T − 1` sorted distinct u32 indices in `[0, real_n)`,
   regardless of segment state, query count, or round.

   Filtering `EMPTY` and sending only the surviving indices leaks the
   per-group count, which drifts upward as hints get consumed and as
   cells fill via relocation. Do NOT add any code path that emits fewer
   than `T − 1` indices, and do NOT add a "skip if empty" early-exit.

   The fix is implemented in `HarmonyGroup::build_request` /
   `build_synthetic_dummy` (see PLAN_HARMONY_COUNT_LEAK_FIX.md) by
   padding the shortfall with random distinct indices drawn from
   `[0, real_n) \ R` and XOR-cancelling their contributions in
   `process_response`.
   ```

### 3.2 New `HarmonyGroup` fields

Scratch state for the in-flight round — not serialized, not persisted, reset on every `build_request`:

```rust
/// Merged sorted indices actually sent to the server in the last
/// `build_request` / `build_synthetic_dummy` call. Length is always
/// `params.t - 1`.
last_sent_indices: Vec<u32>,
/// Subset of `last_sent_indices` that came from dummy padding (i.e.,
/// not from real non-empty segment cells). Used by `process_response`
/// to cancel those entries out of the final XOR.
last_dummy_indices: Vec<u32>,
```

`last_position_map` keeps its current meaning: one entry per **real** segment cell, mapping that cell's position-in-segment (0..T, excluding `r`) to its index in the *sorted merged* response. Update its semantics comment to make this explicit.

For `build_synthetic_dummy`, `last_sent_indices` is filled but the real/dummy concepts don't apply (no response is ever processed because dummy-group slots discard the server's reply). Simpler: just have `build_synthetic_dummy` not touch `last_*` state at all, exactly as today. The pir-sdk-client orchestration already relies on this: only real-query groups call `process_response`, padding groups don't.

### 3.3 Pseudocode for the three hot functions

#### `build_request`

```rust
pub fn build_request(&mut self, q: u32) -> Result<HarmonyRequest, JsError> {
    // ... existing setup: q bounds check, max_queries check ...
    let t = self.params.t;
    let c = self.ds.locate(q_usize)?;
    let s = c / t;
    let r = c % t;

    // Same as before: collect cells for positions i ≠ r.
    let mut cells = Vec::with_capacity(t - 1);
    let mut cell_positions = Vec::with_capacity(t - 1);
    for i in 0..t {
        if i != r {
            cells.push(s * t + i);
            cell_positions.push(i);
        }
    }
    let values = self.ds.batch_access(&cells)?;

    // Real non-empty cells: (db_index, segment_position).
    let mut real: Vec<(u32, usize)> = Vec::new();
    for (k, &val) in values.iter().enumerate() {
        if val != EMPTY {
            real.push((val as u32, cell_positions[k]));
        }
    }

    // Pad with distinct random indices from [0, real_n) \ real_indices.
    // Target: exactly (t - 1) total indices sent.
    let target = t - 1;
    let real_set: std::collections::HashSet<u32> =
        real.iter().map(|&(idx, _)| idx).collect();
    let mut dummies: Vec<u32> = Vec::with_capacity(target - real.len());
    let mut chosen: std::collections::HashSet<u32> = real_set.clone();
    while dummies.len() < target - real.len() {
        let cand = self.rng.next_u32() % self.real_n;
        if chosen.insert(cand) {
            dummies.push(cand);
        }
    }

    // Merge and sort for cache-friendly server lookups.
    let mut merged: Vec<u32> = real.iter().map(|&(idx, _)| idx)
        .chain(dummies.iter().copied())
        .collect();
    merged.sort_unstable();
    debug_assert_eq!(merged.len(), target);

    // Build position map: for each real (idx, pos), find its location in merged.
    // Use a sorted-pair lookup (binary search works since merged is unique + sorted).
    // last_position_map[real_rank] = segment_position where real_rank is the
    // ordinal of that real entry when iterating `merged` in sorted order and
    // keeping only entries in real_set. This is the same invariant as today,
    // just expressed against the padded list.
    let real_by_idx: std::collections::HashMap<u32, usize> =
        real.iter().map(|&(idx, pos)| (idx, pos)).collect();
    self.last_position_map = merged.iter()
        .filter(|idx| real_by_idx.contains_key(idx))
        .map(|idx| real_by_idx[idx])
        .collect();

    self.last_sent_indices = merged.clone();
    self.last_dummy_indices = dummies; // unsorted is fine; lookups use set in process_response
    self.last_segment = s;
    self.last_position = r;
    self.last_query = q_usize;

    // Serialize (still u32 LE each).
    let mut request_bytes = Vec::with_capacity(target * 4);
    for &idx in &merged {
        request_bytes.extend_from_slice(&idx.to_le_bytes());
    }

    Ok(HarmonyRequest {
        request_bytes,
        segment: s as u32,
        position: r as u32,
        query_index: q,
    })
}
```

#### `build_synthetic_dummy`

```rust
pub fn build_synthetic_dummy(&mut self) -> Vec<u8> {
    let t = self.params.t;
    let n = self.real_n;
    let target = t - 1;

    // Sample `target` unique values from [0, n).
    let mut indices: Vec<u32> = Vec::with_capacity(target);
    let mut seen = std::collections::HashSet::with_capacity(target);
    while indices.len() < target {
        let v = self.rng.next_u32() % n;
        if seen.insert(v) {
            indices.push(v);
        }
    }
    indices.sort_unstable();

    let mut bytes = Vec::with_capacity(target * 4);
    for &idx in &indices {
        bytes.extend_from_slice(&idx.to_le_bytes());
    }
    bytes
}
```

Drop the Binomial-coin-flipping loop entirely — the count is now deterministic. The `HashSet` collision-rejection loop stays (same as today).

The existing doc comment paragraph "count ~ Binomial(T, 0.5)" is now wrong — replace it with a note about the new `T − 1` invariant and a back-reference to this plan.

#### `process_response`

```rust
pub fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>, JsError> {
    let w = self.params.w;
    let target = self.params.t - 1;
    let expected = target * w;
    if response.len() != expected {
        return Err(JsError::new(&format!(
            "expected {} bytes response ({} entries × {}B), got {}",
            expected, target, w, response.len()
        )));
    }
    debug_assert_eq!(self.last_sent_indices.len(), target);

    let s = self.last_segment;
    let r = self.last_position;

    // Build a quick lookup of which positions in `merged` are dummies.
    let dummy_set: std::collections::HashSet<u32> =
        self.last_dummy_indices.iter().copied().collect();

    // Split response into per-slot entries (sorted order matches last_sent_indices).
    let entries: Vec<&[u8]> = (0..target)
        .map(|i| &response[i * w..(i + 1) * w])
        .collect();

    // answer = H[s] XOR (XOR of REAL entries only).
    let mut answer = self.hints[s].clone();
    for (i, &idx) in self.last_sent_indices.iter().enumerate() {
        if !dummy_set.contains(&idx) {
            xor_into(&mut answer, entries[i]);
        }
    }

    // relocate_and_update_hints needs a list of real entries keyed by
    // segment position. Re-project `entries` using last_position_map:
    // the k-th real entry (in merged/sorted order) is at position
    // last_position_map[k]. Hand `relocate_and_update_hints` only the
    // real entries, in merged-sorted order — same ordering it already
    // assumes via last_position_map.
    let real_entries: Vec<&[u8]> = self.last_sent_indices.iter().enumerate()
        .filter(|(_, idx)| !dummy_set.contains(idx))
        .map(|(i, _)| entries[i])
        .collect();
    debug_assert_eq!(real_entries.len(), self.last_position_map.len());

    self.relocate_and_update_hints(s, r, &real_entries, &answer)?;
    self.query_count += 1;
    Ok(answer)
}
```

`process_response_xor_only` mirrors the same change; `finish_relocation` continues to hand the stashed `real_entries` + `answer` into `relocate_and_update_hints`.

### 3.4 Tests to add

In `harmonypir-wasm/src/lib.rs` `#[cfg(test)] mod tests`:

1. **`test_request_is_fixed_length`** — build a group, issue several queries, assert `req.request_bytes.len() == (t - 1) * 4` *every* time, including immediately after offline (fresh) and after many queries (aged). Should pass trivially after the fix and fail before it for most segments.

2. **`test_synthetic_dummy_is_fixed_length`** — same assertion on `build_synthetic_dummy().len()`.

3. **`test_dummies_distinct_from_reals_and_each_other`** — build a request, scan `request_bytes` for duplicates, assert none. Also check no dummy index equals any real index.

4. **`test_correctness_survives_padding`** — extend `verify_protocol_impl` or add a sibling test that runs a full offline + `max_queries` query sequence and asserts every query returns `db[q]`. This is the main correctness safety net — if dummy cancellation is wrong, some query will return garbage.

5. **`test_count_constant_across_aging`** — offline + query N/T/2 times, sample the request length at each query, assert it's identical throughout. Directly validates the fix's security claim.

6. **`test_serialize_deserialize_roundtrip_with_aging`** — serialize mid-session, deserialize, continue queries, assert correctness + fixed count. Guards against the new scratch fields accidentally being persisted.

7. **`test_dummy_collision_budget`** — stress test: set `real_n` small (e.g., 32) and `t` close to `real_n` (e.g., `t = 16`, `t - 1 = 15`, so `real_n - real.len() ≥ 15` needed). Verify the rejection-sampling loop terminates in reasonable time and always produces distinct indices. This is a sanity check for edge cases where `T - 1` approaches `real_n`. If that case is mathematically impossible under `Params::new`, document the lower bound and skip the test — but verify.

### 3.5 Integration-test audit

`pir-sdk-client/tests/integration_test.rs` runs 12 HarmonyPIR tests against live servers (see CLAUDE.md "CI integration tests"). After the fix:

- `test_harmony_client_sync_single` should still pass unchanged.
- Any test that asserts on request byte length (unlikely, but grep) will break — update.
- Any test that counts bytes over the wire will see ~2× on some rounds — update expectations.

Run the full suite: `cargo test -p pir-sdk-client --lib` locally (native) and — if changing observable behavior — push and let `.github/workflows/pir-sdk-integration.yml` exercise it against `wss://pir1.chenweikeng.com`.

### 3.6 Rebuild the WASM bindings

After Rust-side changes:

```bash
cd harmonypir-wasm && wasm-pack build --target web --out-dir pkg
cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg
```

`web/src/harmonypir-adapter.ts` wraps `WasmHarmonyClient` and doesn't touch request wire bytes — no TS change expected. `web/src/dpf-adapter.ts` is unaffected (DPF backend).

---

## 4. Things NOT in scope

- **Response-length obfuscation in non-HarmonyPIR backends.** DPF and Onion have their own padding regimes documented in CLAUDE.md. This fix touches HarmonyPIR only.
- **Timing side channels.** Server-side processing time for `T - 1` lookups is deterministic modulo cache, already uniform enough across groups. Not addressed here.
- **Found-vs-not-found leak at the CHUNK round level.** This is a separate, documented trade-off in CLAUDE.md ("What the Server Learns"). Not closed by this fix.
- **The per-slot empty-cell position bitmap** (Option B in the alternatives table). Considered and rejected as weaker than Option A.
- **Protocol version bump on the wire.** Not needed — the wire format already carries a `count` field, we're just always setting it to `T − 1`.

---

## 5. Open decisions for the implementer

Default answers in bold; change only if you have a reason.

1. **Where does the fix land: `harmonypir-wasm` wrapper, or upstream `harmonypir` crate at `github.com/Bitcoin-PIR/harmonypir`?**
   → **`harmonypir-wasm` wrapper.** The upstream crate is an academic reference; it doesn't know about `real_n` vs `padded_n` (the wrapper adds that), and the wrapper is where `build_request` currently lives anyway. Leave the upstream `Client::query` in [`/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/protocol.rs`](/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/protocol.rs) untouched. If the upstream crate ever gets published to crates.io or used in a non-BitcoinPIR context, it will need its own fix — flag this in the PR description.

2. **RNG source for dummy indices: the existing `self.rng` (ChaCha20 seeded from `(key, group_id, query_count)`), or a fresh thread RNG?**
   → **Existing `self.rng`.** Keeps determinism for tests and avoids platform-dependent randomness on wasm32. Do re-seed `self.rng` via `make_rng_seed` on every `build_request` boundary if not already — verify by reading the constructor.

3. **Fallback if `T - 1 > real_n`?**
   → **Return an error.** `Params::new` should reject this — double-check in `Params::new` at `/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/params.rs`. If the invariant holds, document it in `build_request`'s doc comment. If it doesn't hold, the PR should also tighten `Params::new`.

4. **Should `relocate_and_update_hints` change signature to take `&[Option<&[u8]>]` (one slot per segment position, `None` for empty) instead of the current `&[&[u8]]` + `last_position_map` indirection?**
   → **No, keep the existing shape.** It's ugly but it works and it's tested. The pseudocode above threads real entries in the same order the current code expects.

5. **Separate commit or squash with the plan?**
   → **One commit**, message template:

   ```
   fix(harmonypir): pad per-group request to fixed T−1 indices

   Closes a side channel where HarmonyPIR requests sent a variable
   number of non-empty segment indices per round, leaking per-group
   query count and hint-aging status. See
   PLAN_HARMONY_COUNT_LEAK_FIX.md for the full analysis.

   Every build_request / build_synthetic_dummy now emits exactly
   T−1 sorted distinct u32 indices, padding the shortfall with
   random dummies drawn from [0, real_n) \ real. process_response
   XOR-cancels the dummy entries before returning the recovered
   DB row. No wire-format or server change.
   ```

---

## 6. Verification steps for the implementer

Run in order. All must pass before the PR goes up.

1. `cd harmonypir-wasm && cargo test` — native unit tests, including the new ones in §3.4.
2. `cd harmonypir-wasm && wasm-pack build --target web --out-dir pkg` — WASM build must succeed.
3. `cargo test -p pir-sdk-client --lib` — native SDK unit tests (89/89 currently; expect 89 + any new ones).
4. `cargo build --target wasm32-unknown-unknown -p pir-sdk-client` — wasm build must succeed.
5. `cd pir-sdk-wasm && wasm-pack build --target web --out-dir pkg` — downstream wasm build must succeed.
6. `cd web && npx tsc --noEmit` — TS typecheck must be clean (no expected TS changes, but guardrail).
7. `cd web && npx vite build` — web build must succeed.
8. `cd web && npx vitest run` — web unit tests must pass.
9. **Optional but recommended**: run `pir-sdk-client/tests/integration_test.rs` against the live public servers (set `PIR_TEST_LIVE=1` or whatever the crate's ignored-by-default marker is). Confirms the fix works against the actual deployed query server without a server-side update.
10. Manual smoke: build the web client, run `npm run dev`, load the page, issue a sync against the live server, confirm scripthashes resolve correctly and the residency panel/logs don't show errors.

### Red flags to stop and reassess

- Any query test fails with wrong DB content → dummy-cancellation logic is wrong. Check `last_position_map` ordering and the `dummy_set.contains(&idx)` filter.
- Correctness test passes but response-length assertion fails → `pir-sdk-client`'s `process_response` wrapper is computing `count` from a stale field; wire the fixed expected-length `(t - 1) * w` through instead.
- Live integration test hangs → server isn't responding because the request with `T − 1` indices is genuinely too large for some path (e.g., frame size on a sibling round). Check the 256 MiB frame cap noted in CLAUDE.md; should be fine, but verify.
- Hint cache miss after restart → a new field snuck into `serialize()`. Undo that; new state should be round-local only.

---

## 7. Appendix: paper / reference pointers

- **Reference `Client::query`** at [`/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/protocol.rs:100-153`](/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/protocol.rs). In the reference, `request` is `Vec<usize>` of length `T`, with EMPTY sentinels for empty cells and a random `Access(l)` at position `r`. The BitcoinPIR wrapper deviates by (a) dropping position `r`, (b) dropping EMPTY slots. This plan keeps the wrapper's "drop position r" deviation but closes the "drop EMPTY" one.
- **`RelocationDS::batch_access`** at [`/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/relocation.rs:258-304`](/Users/cusgadmin/.cargo/git/checkouts/harmonypir-aac576c921f1c76e/a849ded/src/relocation.rs) — returns `EMPTY` for cells that are logically empty after chain-walking.
- **Wire format** at [`pir-runtime-core/src/protocol.rs:110-140`](pir-runtime-core/src/protocol.rs) (structure comment) and 647–706 (encoder/decoder).
- **Existing padding invariants** in [`CLAUDE.md`](CLAUDE.md) under "CRITICAL SECURITY REQUIREMENTS" → "Query Padding" and "Merkle INDEX Item-Count Symmetry". This fix adds a sibling invariant at the per-group-count level.
