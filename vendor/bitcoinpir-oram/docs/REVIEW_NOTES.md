# ORAM Review Notes

Status: review-only document, no code changes proposed for execution here.
Author: external review of the Circuit/Path ORAM implementation as it would
run inside an SEV-SNP guest. Captures findings, recommendations, and open
questions for the maintainer to act on.

The goal of this document is to record (a) what the security review of the
existing code actually found, (b) the maintainer's decision to drop Path ORAM
in favor of Circuit ORAM, and (c) the open follow-up questions the maintainer
asked about during the review. No implementation work has been performed.

## Errata

Section 4.1 ("Always rewrite path on online access") originally contained a
paragraph arguing that leaving stale ciphertext in an empty slot was itself a
security concern, on the grounds that the bytes would persist until slot
reuse. That argument was incorrect: stale ciphertext sitting in an empty
slot until eviction overwrites it is the standard Path ORAM and Circuit ORAM
overwrite-on-reuse behavior, and is fine. The "concern" paragraph invented
a problem that did not exist. The reviewer pushed back on it, the reviewer
was right, and Section 4.1 has been rewritten to state only the real concern
(write-set shape as a side channel).

## 1. Threat model recap

The crate is explicit that the untrusted host sees:

- Encrypted bucket pages (ChaCha20-Poly1305 in `AeadPageStore`, src/aead.rs;
  per-page nonce, page index as AAD).
- An ORAM page trace: full root-to-leaf path reads and writes, with a
  fixed per-operation shape.
- Public deterministic eviction leaves from
  `CircuitEvictionSchedule::eviction_leaf_at` (src/circuit.rs:147).
- Authentication tree roots when `EmbeddedTreePageStore` or
  `TieredMerklePageStore` is enabled.

The trusted side holds the position map, fixed-capacity stash, RNG state,
eviction counters, and authentication roots. The implicit invariant is that
the page trace and trusted-memory access pattern are independent of any
BitcoinPIR logical id.

## 2. Maintainer decision: drop Path ORAM

Decision: keep Circuit ORAM as the only controller; remove `PathOram`,
`Bucket`, `OramState`, and the path-ORAM CLI subcommands.

Reasoning:

- The constant-time hardening (volatile-store fix in `clear_payload_if`,
  branchless full-scan position map, `CircuitEvictionSchedule`, embedded-tree
  authentication, batched online access with deterministic eviction) lives
  only in the Circuit ORAM code path.
- `PathOram::access` (src/oram.rs:188-190) still does direct indexed reads
  into `pos_map[logical_id]`, which is a secret-dependent load inside the
  TEE.
- `OramBlock::clear_if` (src/block.rs:71-81), which `PathOram::write_path_from_stash`
  uses, does per-byte `cmov_u8(byte, 0, choice)` and is *not* protected
  against LLVM recognizing the all-zero case and emitting a `bzero`-like
  branch. The same hazard is explicitly documented and fixed for
  `clear_payload_if` in src/circuit.rs:1452-1462.
- `audit-ct-assembly.sh` only audits Circuit ORAM symbols (`scan_pos_map_*`,
  `plan_eviction_placements`, `apply_eviction_plan_to_overlays`,
  `load_eviction_payloads_from_overlay`, `ensure_eviction_stash_capacity`,
  `insert_candidate_into_stash`, `select_and_remove_target_slots`,
  `clear_payload_if`). Path ORAM has no equivalent.
- Production deployment (DESIGN_README.md:18-47, the direct-entry split-store
  design) is entirely Circuit-ORAM-shaped.

### Path-ORAM deletion plan (not yet executed)

Files and symbols to remove:

- `src/oram.rs` — entire file. Contains `PathOram`, the `greedy_flush_all`
  initializer, and the path-ORAM test module (lines 390-542).
- `src/block.rs` — delete the `Bucket` struct (src/block.rs:147-197) and its
  impl block. `OramBlock` stays; it is used by `CircuitOram` for the stash.
- `src/state.rs` — delete `OramState` (src/state.rs:31-158) and its
  `*_encrypted_atomic`/`load*` impls. The two path-ORAM state tests in
  src/state.rs:507-571 also go.
- `src/bin/oramctl.rs`:
  - Remove the `Build` and `Bench` subcommands (src/bin/oramctl.rs:37-105
    and the match arms at lines 704-819).
  - Remove unused imports: `PathOram`, `OramState`, `PageStore`.
  - Remove helpers used only by `Build`/`Bench`:
    `open_file_store` (src/bin/oramctl.rs:4284),
    `load_state` (src/bin/oramctl.rs:4231), `save_state` (src/bin/oramctl.rs:4255),
    `deterministic_payloads` (src/bin/oramctl.rs:5257).
- `src/lib.rs` — drop `pub mod oram;` and `pub use oram::PathOram;`.
  Drop `pub use block::Bucket;` (keep `OramBlock`).
- `src/state.rs` — drop `pub use state::OramState;` from `lib.rs`.
- Docs — update `README.md` (mentions `OramState` at line 39, `PathOram` is
  not mentioned in README but is in DESIGN_README.md:7).

Sanity checks before deletion:

- `grep -rn "PathOram\|use crate::oram\|from oram::\|oram::PathOram\|::PathOram"`
  across `*.rs`, `*.md`, `*.toml`. Confirm only the files listed above are
  matched.
- `grep -rn "\bBucket\b"` to confirm no external reference to `Bucket` (the
  path-ORAM page-encoded struct) outside `oram.rs` and `lib.rs`.

Post-deletion: `cargo test`, `cargo clippy --all-targets -- -D warnings`,
`scripts/audit-ct-assembly.sh`.

Note on `OramBlock::bucket_bytes()` (src/params.rs:94-96): the sizing helper
`bucket_bytes` returns `bucket_size * OramBlock::serialized_len(block_size)`,
which is `bucket_size * (1 + 8 + 4 + block_size)`. The Circuit ORAM split
store uses `bucket_size * (13 + block_size)` for metadata + payload
combined. The two are the same formula, so sizing estimates in `cuckoo.rs`
and `direct.rs` are unaffected. The function stays.

## 3. Security findings

Severity is the maintainer's call, not a formal ranking.

### 3.1 High severity

#### H1. `PathOram::access` indexes `pos_map` directly

src/oram.rs:188-190:

```rust
let old_leaf = self.pos_map[logical_id as usize];
let new_leaf = random_leaf(&self.params, &mut self.rng);
self.pos_map[logical_id as usize] = new_leaf;
```

This is a secret-dependent load and store on trusted memory. Inside the
TEE, the indexed read has data-dependent cache footprint and timing on any
realistic CPU. The Circuit ORAM equivalent (src/circuit.rs:759, 774) uses
`scan_pos_map_lookup`/`scan_pos_map_update`, which iterate the full map.
Path ORAM was kept as a "correctness baseline" but should not be used in
production. The README and DESIGN_README should make this explicit, or the
controller should be removed.

#### H2. `OramBlock::clear_if` may compile to a secret-dependent `bzero`

src/block.rs:71-81:

```rust
for byte in &mut self.payload {
    ct::cmov_u8(byte, 0, choice);
}
```

`clear_payload_if` in src/circuit.rs:1452-1462 is the explicit fix for this:
use `read_volatile` + `write_volatile` to prevent LLVM from recognizing the
all-zero case and emitting `memset`/`bzero` (which can branch on pointer
alignment or size). The path-ORAM controller (src/oram.rs:252) and the
Circuit ORAM eviction planner (src/circuit.rs:1146, which calls
`OramBlock::clear_if` via `self.stash[slot].clear_if(...)`) both rely on
this. After dropping Path ORAM (see Section 2), only the Circuit ORAM call
site remains. The fix is to either:

- Inline the volatile-store pattern into `OramBlock::clear_if` itself, or
- Have the Circuit ORAM call site use a new `clear_block_payload_if` helper
  that wraps `clear_payload_if`.

The same fix should also cover `OramBlock::clear_if`'s metadata fields
(`occupied`, `logical_id`, `leaf`). Those are scalar `cmov`s and are not
subject to the `bzero` recognition, but the body of `clear_payload_if` is
what's documented as risky; consider applying the volatile pattern to the
whole method for symmetry.

#### H3. Variable shift in `node_contains_leaf_choice`

src/circuit.rs:1194-1197 calls `OramParams::node_index` (src/params.rs:99-108):

```rust
let shift = self.leaf_bits() - depth;
level_offset + (((leaf as usize) >> shift) & ((1usize << depth) - 1))
```

The shift amount is public (`leaf_bits - depth`), but the *value shifted*
(`leaf`) is per-block secret. Variable-shift latency has historically been
CPU-dependent. Recent AMD Zen 3/4 documentation and `uops.info` data show
constant-latency `shr reg, cl` on those targets, but earlier micro-
architectures had input-dependent shift latency.

This is the dominant remaining timing channel in the eviction planner. The
planner iterates `candidates * height * bucket_size` candidate placements;
for the production direct-entry geometry (`leaves = 4_194_304`,
`height = 23`, `bucket_size = 2`, `stash = 4096`), that is roughly
`(4096 + 46) * 46 ≈ 190_000` `node_contains_leaf_choice` calls per eviction,
each doing a variable shift on a 32-bit secret.

Options if hardening is needed:

- **Barrel-select via precomputed bit choices.** For each bit position `k`
  in `0..32`, precompute a `Choice` array `bit_choices[k] = (leaf >> k) & 1`
  once per candidate. The shift `(leaf >> k) & 1` is still there, but it is
  done once per candidate rather than once per (candidate, depth, slot).
  Walk the tree from root to leaf using `cmov` on the precomputed bit
  choices. This shifts the variable-shift cost from `O(candidates * height *
  bucket_size)` to `O(candidates * 32)` per eviction.
- **Precomputed placement map per candidate.** For each candidate, the set
  of depths at which it can be placed is exactly the path from root to
  `leaf`. If we accept building a `Vec<usize>` of depth indices per
  candidate (which is itself public once `leaf` is fixed, but `leaf` is
  secret), this doesn't help unless we recompute it without the shift.
- **Accept the current code.** Document that the SEV-SNP target is Zen 3 or
  newer, where variable shifts are constant-latency, and add an audit
  check that flags `shr reg, cl` in audited symbols so any future
  regression on a different target gets caught.

Note: the `audit-ct-assembly.sh` script currently only greps for symbol
names. It does not inspect instruction mix. Adding a `objdump`-based check
for `shr reg, cl` / `shl reg, cl` in audited symbols would close this gap.

#### H4. `PathOram::write_path_from_stash` is not audited

src/oram.rs:231-261 iterates the stash for every (depth, slot) pair, using
masked selection. The loop shape is constant, but as noted in H2, the
underlying `OramBlock::clear_if` is not protected against `bzero`
recognition. After dropping Path ORAM (Section 2), this concern goes away
for path-ORAM. The Circuit ORAM equivalent (`apply_eviction_plan_to_overlays`
in src/circuit.rs:1132-1188) uses the same stash iteration and calls
`OramBlock::clear_if` at src/circuit.rs:1146, which falls under H2.

### 3.2 Medium severity

#### M1. `BTreeMap<usize, Vec<u8>>` page overlay

Used per-batch in `access_batch`, `drain_evictions`, `dummy_access_batch`
(src/circuit.rs:16, 960-994, 1007-1130, 1464-1530). The map is keyed by
public `page_idx` and stores opaque page bytes.

Concern: `BTreeMap`'s internal node layout depends on insertion order.
`overlay_path_pages` (src/circuit.rs:1464) inserts in the order returned by
the storage layer's `read_paths_pages`, which iterates paths in batch order
and pages in depth order (low-to-high). Both are public. Lookups via
`get_mut(page_idx)` (src/circuit.rs:966-971, 1030-1037) traverse the tree
on a public key. The cache footprint of BTreeMap internal nodes is
therefore determined by public data, not by block contents.

Conclusion: the BTreeMap is OK as long as the invariants hold. The fix is
documentation, not code:

- Add comments at `overlay_path_pages`, `apply_eviction_plan_to_overlays`,
  and `remove_target_from_overlays` stating that the keys are public and
  the insertion order is public.
- Add a test that asserts the loop bounds in these functions are public
  (i.e., that no code path takes a different number of iterations based
  on block contents).

A `Vec<Option<Vec<u8>>>` indexed by `page_idx` would make the
constant-time guarantee structurally obvious, but pre-allocates
`bucket_count * 24` bytes per batch — for the largest CHUNK image
(`bucket_count ≈ 8.4M`), that's ~192 MiB per batch. Likely acceptable for
SEV-SNP (guests have GBs of RAM) but worth deciding explicitly.

A hybrid approach (Vec for small images, BTreeMap for large) is also
possible. The maintainer's call.

#### M2. `CircuitOram::from_state` does not bind authentication state

src/circuit.rs:594-611. The caller passes a freshly-constructed `meta_store`
and `payload_store` plus a `CircuitOramState`. The auth roots live in the
*store* (constructed from `EmbeddedTreePageStore::from_state` or
`TieredMerklePageStore::from_trusted_state`), not in the controller
snapshot. There is no check that the auth state used to construct the
stores matches the controller snapshot.

Risk: the caller could load a `*.auth.state` from one point in time and a
`*.state` from another, and the controller would silently operate against
inconsistent roots. With the embedded-tree layout this is detectable on
the next `read_path` (the auth check would fail), but it's a fail-loud
behavior, not fail-safe.

Fix: add an optional `auth: Option<CircuitStoreAuthLayout>` field to
`CircuitOramState`. In `CircuitOram::from_state`, after constructing the
controller, call `meta_store.embedded_tree_state()` (and
`tiered_merkle_state()`) and compare the reported root against the
controller's expected root from `state.auth`. Refuse to open on mismatch.

This requires:
- `PathPageStore::embedded_tree_state()` already exists
  (src/store.rs:122-125); same for `tiered_merkle_state()`.
- `CircuitOram::from_state` would need to handle both auth layouts (the
  enum `CircuitStoreAuthLayout` already exists in src/state.rs:316-331).
- `CircuitOramState` serialization would gain a new field; the magic is
  unchanged so old state files remain readable (the new field defaults to
  `None`).

#### M3. `EmbeddedTreePageStore::write_paths` updates root before disk

src/embedded_tree.rs:208-286. The function updates `self.root_hash` for
each path before calling `self.inner.write_pages(...)`. If the write fails
partway through (e.g., disk full), the in-memory root has changed but the
disk has not. On the next `read_paths`, authentication will fail and the
ORAM will refuse to serve requests.

This is fail-closed but not recoverable without external coordination.
Possible mitigations:

- Write to a staging file, fsync, then atomic-rename into place, with the
  in-memory root update conditional on the rename success. This is a
  journal/WAL pattern.
- Use a small per-page write-ahead log on a separate file, replayed at
  startup if the image is in an inconsistent state.

The maintainer's call. Documenting the current behavior and adding a test
that exercises a partial-write failure (e.g., by truncating the underlying
file mid-write) would be a smaller step.

#### M4. `state.rng` is part of the trusted snapshot with no monotonic counter

src/state.rs:160-178. The persisted `ChaCha20Rng` clone determines future
leaf assignments. A rollback attack that restores a previous `state.rng`
plus a previous `pos_map` would not be detected — both are signed/encrypted
together, but the *combination* is not bound to anything that proves
"this is the most recent state." An attacker who can write to the state
file could roll back to a previously-observed state.

In SEV-SNP the state file is supposed to be sealed to the guest; the
README and DESIGN_README say so explicitly. For prototype deployments that
store the state file unencrypted or rely on the AEAD layer, a monotonic
counter or external log binding would close this. Not strictly required
if production always seals the state, but worth flagging.

### 3.3 Low severity / observations

- **L1. `random_leaf` uses `% leaves`.** src/circuit.rs:1709-1711 and
  src/oram.rs:386-388. Modulo by a runtime value can have data-dependent
  timing. The leaf is itself a public ORAM observable (the host sees which
  path was accessed), so this is not a confidentiality leak, but on a CPU
  where modulo is variable-latency it adds noise. `OramParams::leaves` is
  always a power of two (enforced in `OramParams::with_leaves`), so
  `leaves.next_power_of_two()` is identity and the `%` is actually a
  constant-time bitmask. Could simplify to `leaf & (leaves - 1)` for
  clarity.

- **L2. Greedy eviction planner is not the paper's `deepest`/`target`
  circuit.** src/circuit.rs:1042-1129. Two scans of the path metadata both
  read the same data (`deepest_meta` and `target_meta` are literally the
  same `Vec` per src/circuit.rs:1011-1013). The planner is acknowledged in
  DESIGN_README.md and the design notes as a placeholder for the paper's
  algorithm. The stash-bound proof in the Circuit ORAM paper assumes the
  deepest/target scheduler. With the greedy planner, `Z=2` and
  `evictions_per_access=2` are empirical, not proved.

- **L3. `FrontCachedPageStore` reveals top-of-tree access rate.** src/store.rs:486-672.
  Pages `[0, cached_pages)` are served from trusted memory without disk
  IO. The host can observe that the top `cached_pages` pages are
  accessed more frequently than lower pages. This is fine for ORAM (top
  pages are root-adjacent and visited on every path), but the threat
  model should explicitly state that the access-rate distribution is
  public.

- **L4. `debug_assert!` invariants are stripped in release builds.**
  src/circuit.rs and src/params.rs use `debug_assert!` for path-length
  consistency, leaf-range checks, and bucket-size matches. In release
  these are stripped, so a corrupted state could pass silently. Consider
  promoting the path-length and leaf-range checks to `assert!`.

- **L5. `OramState` and `OramBlock` test fixtures in src/state.rs use
  different magic constants than the production `CircuitOramState`.** Not
  a security issue, just a cleanup opportunity once Path ORAM is removed.

- **L6. Plaintext block payloads are not zeroized on drop.** `OramBlock::payload`
  is a `Vec<u8>` cloned throughout the stash operations. SEV-SNP
  attestation covers guest memory, so swap-out is not a concern inside
  the guest, but if the state file is ever written in plaintext the
  plaintext could end up on swap. Acceptable for SEV-SNP; document it.

- **L7. The CLI's `--build` and `--bench` subcommands use `PathOram` and
  are dead code once Path ORAM is removed.** See Section 2.

- **L8. The docs are inconsistent on `leaf_divisor`.** DESIGN_README.md:38-45
  says `leaf_divisor=4`; README.md mentions `leaf_divisor=2` for direct
  FULL images. One of these is stale.

- **L9. The stash-pressure simulator (`stress-circuit`) uses the same
  greedy planner as the controller.** src/stress.rs. This makes the
  simulator self-consistent but does not prove the controller's planner
  is safe. The DESIGN_README acknowledges this. To stress the actual
  controller, run a controller-driven simulation, not a metadata-only
  model. An adversary-pattern simulator (greedy lookahead for stash
  growth) would also help — current patterns are random and round-robin,
  not worst-case.

## 4. Open questions from the maintainer

These came up during the review; the maintainer asked for clarification
before deciding. None have been resolved into code yet.

### 4.1 Always rewrite path on online access

Maintainer's position: the payload bytes do not need to be cleared on
online access; only the metadata bit needs updating, so we should not have
to rewrite every page on the path.

#### Errata: the original stale-payload paragraph in this section was wrong

An earlier draft of this section argued that "leaving stale payloads" was
itself a concern, on the grounds that the bytes would persist until the
slot was reused. That argument was incorrect. The lifecycle described —
stale ciphertext sits in an empty slot until a future eviction reassigns
the slot and overwrites it — is exactly the standard Path ORAM and
Circuit ORAM overwrite-on-reuse behavior, and is fine: the bucket page
is encrypted via `AeadPageStore`, so the host sees ciphertext, and the
metadata bit correctly marks the slot as empty, so no controller code
path treats the stale bytes as live. The "concern" paragraph invented
a problem that did not exist. The reviewer pushed back on this, the
reviewer was correct, and this section has been rewritten below to
state only the real concern.

#### The real concern: write-set shape as a side channel

The actual objection to skipping path-page rewrites is *not* about stale
ciphertext. It is about the access trace shape.

In the current design, every online access rewrites every page on the
old-leaf path. The host sees a fixed-size write set (one write per page
on the path), regardless of which page held the target. The rewrite set
is determined by the public leaf label, not by the secret target
location.

If we instead rewrote only the pages whose metadata actually changed
(i.e., the page that contained the target), the host would see a
variable-size write set per access. The write set size would be 1 if
the target was at the leaf, 2 if it was at the parent's slot, up to
`height` if it was at the root. The number of writes directly reveals
the target's depth in the path, which is secret.

This is the side channel that the maintainer's optimization opens. It is
a confidentiality leak, not an integrity one: the slot contents remain
correct (metadata says empty, payload bytes are stale ciphertext that
no code path reads), but the *trace* tells the host something it should
not know.

Decision: keep the current behavior of rewriting every path page on
online access. Document this in `read_and_remove_target_path` and
`remove_target_from_overlays` as a deliberate side-channel mitigation.
The cost is the I/O and AEAD for unmodified pages, which is the price
of ORAM's fixed-trace guarantee.

Possible optimizations that preserve the fixed-trace guarantee:

- Rewrite every page on the path but skip the payload clear for slots
  whose metadata did not change. The stale payload bytes get re-encrypted
  by AEAD anyway, so the host sees a fresh ciphertext. The optimization
  saves the `clear_payload_if` cost (which is small) but not the AEAD
  cost. Marginal benefit, simpler audit story than skipping writes.
- Cache the AEAD result for unchanged pages across consecutive access
  batches. Complex; probably not worth it for the current workload.

Optimizations that *break* the fixed-trace guarantee (skip writes for
unmodified pages, write only changed bytes, etc.) should be rejected
on security grounds, not just performance ones.

### 4.2 BTreeMap constant-time guarantee

Maintainer's position: BTreeMap is fine if the online access algorithm
visits every page in the map regardless of how soon the target is found.

Reviewer's position: the current code already does this. `select_and_remove_target_slots`
(src/circuit.rs:1417-1434) iterates every slot in the bucket, and
`remove_target_from_overlays` (src/circuit.rs:956-994) iterates every page
on the path. The `removed` mask suppresses matches after the first, but
the iteration is constant-shape within a page.

The BTreeMap's `get_mut(page_idx)` lookup is on a public key, so the
memory access pattern on the BTreeMap's internal nodes is determined by
public data. The "constant time" guarantee is about block contents not
leaking via the access pattern, and the BTreeMap doesn't see block
contents (only opaque byte vectors).

Decision: keep the BTreeMap, add documentation comments at
`overlay_path_pages`, `apply_eviction_plan_to_overlays`, and
`remove_target_from_overlays` stating the invariant. No code change
beyond comments.

### 4.3 Barrel-select for `node_contains_leaf_choice`

Not yet decided. Options are summarized in H3 above. The maintainer has
not stated a preference between barrel-select and the current
"document + audit-script check" approach.

### 4.4 Authentication state binding

Not yet decided. The fix is mechanical (Section M2) but touches the
public state file format. Need to decide whether to:
- Make `auth` mandatory (breaking change for existing state files).
- Make `auth` optional, fail-safe by default (recommended; old state files
  remain usable, new ones gain the binding).
- Defer until production deployment.

### 4.5 Deletion vs. security-first ordering

Maintainer's decision: do all of this sequentially — delete Path ORAM
first, then apply the security fixes (H2, H3, audit-script enhancement),
then bind the auth state (M2). One pass, tests after each step.

This order is sensible because the security fixes are scoped to Circuit
ORAM, and the path-ORAM deletion reduces the audit surface before the
security fixes are written.

## 5. What the implementation gets right

For balance, the implementation is significantly better than a typical
first-attempt ORAM:

- Full-scan position map and stash operations are correctly implemented,
  and `ct::*` helpers delegate to `subtle` (the right thing to do;
  hand-rolled CMOV in Rust is fragile).
- The `clear_payload_if` volatile-store fix (src/circuit.rs:1452) is the
  right defense against LLVM `bzero` recognition, and the comment
  explains why.
- Split metadata/payload stores are correctly designed for Circuit ORAM.
- `PathPageStore` (src/store.rs:75) is the right abstraction to let the
  embedded-tree store implement path-level authenticated IO without a
  per-page `PageStore` overlay.
- `CircuitOramState::save_encrypted_atomic` (src/state.rs:213-246) uses
  ChaCha20-Poly1305 with AAD = magic bytes, which prevents a
  chosen-ciphertext rewrite of the state file under a different key.
- `direct_index_candidate_bins` (src/direct.rs:1281-1312) correctly
  avoids duplicate candidates, which would have been a soundness bug.
- Bulk initialization (src/circuit.rs:531-590) plans metadata first, then
  writes payload pages sequentially — the correct pattern for
  non-oblivious bulk init.
- The fixed-shape trace tests in src/circuit.rs:2442-2534 explicitly
  verify that every operation (real read, dummy access, eviction drain)
  produces the same `height * 2` IO shape. `PathOram` has only a partial
  equivalent (src/oram.rs:435-466).
- ChaCha20-Poly1305 is the correct AEAD choice for SEV-SNP; AES-GCM has
  table-lookup side channels without hardware acceleration.

## 6. Summary of recommended follow-ups

In rough priority order:

1. Delete `PathOram` and path-ORAM-only code per Section 2.
2. Apply the volatile-store fix to `OramBlock::clear_if` (H2).
3. Add a variable-shift detection step to `audit-ct-assembly.sh` and a
   documenting comment at `node_contains_leaf_choice` (H3).
4. Bind authentication roots into `CircuitOramState` (M2).
5. Document the "always rewrite path" invariant (Section 4.1) and the
   BTreeMap constant-time invariant (Section 4.2).
6. Decide on the `node_contains_leaf_choice` rewrite vs.
   audit-script-only approach (Section 4.3).
7. Run `cargo test`, `cargo clippy --all-targets -- -D warnings`,
   `scripts/audit-ct-assembly.sh` after each step.

The architecture is sound. The remaining work is hardening the
constant-time story, locking the auth state to the controller, and
removing the path-ORAM code that does not have the same hardening.

## 7. Maintainer response after review

Applied after this review:

1. Removed the Path ORAM controller, `Bucket`, `OramState`, and the
   path-ORAM-only `oramctl build` / `oramctl bench` subcommands.
2. Changed `OramBlock::clear_if` to use a volatile conditional payload clear,
   with an audited `clear_payload_volatile_if` helper.
3. Added review output for variable-shift instructions to
   `scripts/audit-ct-assembly.sh`.
4. Documented the public-key invariant for BTreeMap overlays and the
   always-rewrite-full-path invariant for online target removal.
5. Replaced random-leaf modulo with a power-of-two mask.
6. Updated README/design docs so Circuit ORAM is the only controller path.
7. Bound authenticated-store roots into `CircuitOramState`; new snapshots carry
   the roots in trusted controller state, and CLI reopen uses those roots when
   present.

Deferred:

- Replacing the prototype compatibility path with one production sealed-state
  envelope. The CLI still writes `*.auth.state` for old state files and external
  tooling, but new controller snapshots also include the auth roots and verify
  them on reopen.
