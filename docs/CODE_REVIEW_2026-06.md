# Bitcoin-PIR — Code Review Findings (2026-06-09)

Full-repo review. Build health at time of review: clean
`cargo check --workspace --offline --locked`; **489 lib tests pass**
(pir-core 66, pir-sdk 74, pir-sdk-client 199, pir-sdk-wasm 69,
pir-runtime-core 74), 0 failures.

Findings tagged ✅ were verified by reading the code directly during the
review; untagged findings come from the area sub-reviews with high
confidence.

Overall theme: the codebase is hardened against an **honest-but-curious**
server and a passive network (the privacy/padding invariants are
genuinely enforced), but **fragile against an actively malicious server
or client**. The must-fix set below closes that gap.

---

## Must-fix (memory-safety / DoS / soundness)

| ID | Sev | Location | Issue |
|----|-----|----------|-------|
| S1 | crit | `pir-runtime-core/src/handler.rs:407,454,498` | ✅ `DpfKey::from_bytes(k).expect("bad dpf key")` on client bytes → process abort |
| S2 | crit | `pir-runtime-core/src/eval.rs:133` (+ `protocol.rs:1225`) | ✅ `let mut bits = [false; 8]` indexed by uncapped `keys_per_group` → OOB write |
| S3 | crit | `pir-runtime-core/src/handler.rs:412` | ✅ `key_refs[0]`/`key_refs[1]` no length guard; `keys_per_group < 2` → panic |
| S4 | crit | `pir-runtime-core/src/table.rs:135` (callers `handler.rs:322,359`) | `group_bytes` slices mmap with unchecked `group_id` on Harmony path |
| S5 | major | `pir-runtime-core/src/handler.rs:324,365` | `Vec::with_capacity(indices.len()*entry_size)` before range check → alloc amplification (~50–130×) |
| C2 | major | `pir-core/src/codec.rs:19,22` (callers `dpf.rs:2650`, `harmony.rs:5945`, `onion.rs:2033`) | ✅ `read_varint` panics by design on adversarial server chunk data, *before* Merkle verify |
| C3 | major | `pir-sdk-client/src/dpf.rs:1258,1465,1665` | ✅ `results0[assigned_group][h]` double-index OOB on short/truncated server batch response (DPF-specific) |
| C4 | minor | `pir-sdk-client/src/harmony.rs:576` | Master 128-bit PRP key derived from `splitmix64(seed_nanos())` (wall clock), not a CSPRNG |
| W1 | major | `web/src/merkle.ts:107` (exported `index.ts:96`) | ✅ `verifyMerkleProof` is unsound — overwrites leaf hash at line 122, never binds the leaf; returns `true` for any data |
| W3 | major | `web/src/dpf-adapter.ts:593`, `harmonypir-adapter.ts:903,918` | `disconnect().catch(); free()` races wasm-bindgen borrow → `free()` can throw "value while borrowed" |

**Amplifier for S1–S5:** `Cargo.toml:32` sets `panic = 'abort'`
workspace-wide, so every panic is a **full-process abort**, not a dropped
connection — and it makes the `catch_unwind` blocks in `unified_server.rs`
dead code. In the default config (ARC/Cashu opt-in, cleartext frames
allowed) the server crashes are **unauthenticated**.

### Fix notes
- **S1–S4**: validate `keys_per_group` (`≥2` for INDEX, `≤ MAX` for all),
  `group_id < k`, and key-count *at decode time* in `decode_batch_query`;
  replace `expect`/raw indexing with `PirError`/`io::Error` returns. No
  wire-format change.
- **S5**: cap `with_capacity` (e.g. clamp to `k * something` or
  validate `indices.len()` against `real_n` before allocating).
- **C2**: add a `Result`-returning varint reader (e.g.
  `try_read_varint`) and route the UTXO-decode callers through it; keep
  the change additive to avoid rippling the signature across all callers.
  Note `pir-sdk/src/sync.rs:504` already has a panic-free variant.
- **C3**: validate `results{0,1}` group-count and per-group key-count
  against the request before indexing; return `PirError::Decode`.
- **C4**: source the key from `getrandom` (already a dependency, used a
  few lines away). The web Harmony adapter already uses WebCrypto here —
  only the Rust path regressed.
- **W1**: delete the export (live verifiers are `walkTreeTopToRoot` and
  the WASM `verifyBucketMerkleItem`), or fix the leaf insertion at
  `merkle.ts:121-124`. Also drop `computeLeafHash`/`parseTreeTopCache`
  from the public surface if only used by it.
- **W3**: `await this.wasmClient.disconnect()` before `free()` (make
  `teardown` async), or rely on `Drop` (which calls `detach_ws_handlers`).

### Status update (2026-06-11): S1–S5 closed end-to-end

S1–S5 were fixed in `pir-runtime-core` (decode-time key validation,
eval guards, `try_group_bytes`, index-count caps — 24 new tests in that
crate's `dos_guard_tests`). Because `unified_server.rs` parses frames
via the shared `Request::decode`, the decode-time S1–S3 guards covered
its duplicated DPF batch handlers automatically; its **private copies
of the Harmony handlers** were then given the S4/S5 treatment directly:

- `harmony_query_response` / `harmony_batch_response` (the inline
  dispatch handlers, extracted to testable seams) now use
  `MappedSubTable::try_group_bytes` and validate
  `indices.len() <= bins_per_table` before allocating.
- The binary-only `REQ_HARMONY_HINTS` path had the same S4 class:
  client-controlled `level` hit `panic!("invalid hint level")` and
  client-controlled `group_id` sliced the mmap unchecked inside the
  rayon pool — one frame killed the **hint server (pir1)**.
  `compute_hints_for_group` is now total (`Result`, shared
  `harmony_level_table` resolution, `try_group_bytes`), and requests
  are pre-screened by `validate_harmony_hints_request`, which also
  caps `group_ids.len() <= k` (closing a 255×-duplicate PRP-work
  amplifier, S5-adjacent).
- 12 new tests in `unified_server.rs::harmony_dos_guard_tests`.

**New finding closed in the same pass — C7 (major): client-side
infinite loop on malicious catalog geometry.** Surfaced by this
review's own C3 regression tests: the `tiny_db_info` fixture used
`index_k = 2`, and the suite hung forever in CI (20-min job timeout)
and locally. Root cause: `pir_core::hash::derive_groups_3` /
`derive_int_groups_3` rejection-sample until they hold 3 **distinct**
groups mod k — with k < 3 the loop never terminates. `index_k` /
`chunk_k` are **server-supplied** (`DatabaseInfo` via catalog or
GET_INFO), so a malicious server advertising k = 2 pinned any client
(native or WASM — both decode through the same path) at 100 % CPU
forever; zero `index_bins`/`chunk_bins` would likewise panic bin
hashing (`h % bins`). Closed by `protocol::validate_db_geometry`
(k ≥ 3, bins ≥ 1) called from both catalog and legacy-GET_INFO
decodes, + fixture fixes (k = 4) and decode-rejection tests. The
standalone TS client is not exposed (its `deriveGroups` uses the
compile-time K; `deriveIntGroups3(id, k)` has no production callers).

---

## Architectural / trust-model (needs a decision)

| ID | Sev | Location | Issue |
|----|-----|----------|-------|
| C1 | major | `pir-sdk-client/src/merkle_verify.rs:1145`, `onion_merkle.rs:281,610` | ✅ Merkle anchors to **server-supplied** `top.root()`, never compared to attested `manifest_roots` (which appear *only* in `attest.rs`) |
| W2 | major | `web/src/dpf-adapter.ts:526`, `harmonypir-adapter.ts:595`, `arc-present.ts:29` | Attestation is **advisory**: queries + ARC/Cashu credential presentation proceed even when attestation resolves to `mismatch` |

**Why this matters:** The README promises "verify results
cryptographically… a malicious server can't lie." As wired, the Merkle
layer proves *one server's internal self-consistency*, not soundness
against a cheating server — a malicious server can fabricate a
self-consistent root + siblings and every leaf "verifies." Integrity
*does* hold today, but via the attestation/pinning path (pinned SEV
measurement → trusted binary → binary self-verifies its DB), which is a
different and weaker-sounding guarantee than the headline claim. The
`onion_merkle.rs` "pinned trust anchor" comments overstate the current
state.

These two are the same theme (fail-closed vs advisory trust) and are
deferred to a human decision because **fail-closed by default would break
the live demo** (pir1/Hetzner has no SEV measurement).

---

## Hygiene / CI / supply chain

| ID | Sev | Issue |
|----|-----|-------|
| I1 | major | Privacy **leakage suite never runs in CI** (`leakage_integration_test.rs` is `#[ignore]`d + invoked nowhere); ~half of 678 Rust tests not in CI; no `cargo fmt --check`; clippy on one crate only. Adding `--test leakage_integration_test -- --ignored` to the daily canary is a one-line, high-value fix |
| I2 | major | `libdpf` floats unpinned (no `rev`) in `pir-sdk-client/Cargo.toml:60`, `pir-runtime-core/Cargo.toml:25`, `runtime/Cargo.toml:66`, and `.cargo/config.toml`; pinned only by `Cargo.lock`. Every other git dep is rev-pinned |
| I3 | major | `.gitignore:47` (`build/`) shadows the Rust `build/` workspace crate — new files under `build/src/` are silently untracked |
| I4 | major | `PLAN_*.md` design docs are gitignored (`.gitignore:54`) but referenced as normative from `CLAUDE.md`, source comments, and `proofs/easycrypt/README.md:184` — dangling links for any cloner |
| I5 | major⚠ | `docs/RATELIMIT_INTEGRATION.md:187` asserts a committed live `TUNNEL_TOKEN` in `deploy/cloudflared_tunnel.env`. File not in tracked tree; **confirm the token was rotated / history scrubbed**, then fix the doc |
| I6 | minor | CI uses `dtolnay/rust-toolchain@stable`, which exports `RUSTUP_TOOLCHAIN` and bypasses the `rust-toolchain.toml` 1.94.1 pin |
| I7 | minor | No dependabot / `cargo-audit` / `cargo-deny` — 317 vendored crates, no CVE signal |
| I8 | minor | `pir-channel`, `pir-identity`, `pir-attest-verify` declare dual license but ship no in-crate LICENSE files and are not `publish = false` |

### Status update (2026-06-26): I4/I5 closed

- **I4**: historical `PLAN_*.md` files are now tracked under
  `docs/plans/`, with root-level symlink shims preserving the old
  references from source comments, CLAUDE.md, and EasyCrypt docs.
  `.gitignore` now reserves `LOCAL_PLAN_*.md` for private scratch
  notes instead of hiding referenced project plans.
- **I5**: resolved by operations decision — the old Cloudflare tunnel
  token path is gone. `docs/RATELIMIT_INTEGRATION.md` no longer
  describes a live committed `TUNNEL_TOKEN`; if a tunnel path returns,
  the doc now requires out-of-git token handling and a rotation
  procedure.
- **I7**: partially closed by the cargo-audit CI job added in June;
  dependabot / cargo-deny remain optional future hygiene.

---

## Lower-severity / nits (not auto-fixing)

- **S6** (major): no connection cap / rate limit by default; `pir-sdk-server`
  runs handlers with no `spawn_blocking` and no gating — cleanest repro of
  S1–S5.
- **S7** (nit): `panic = 'abort'` makes `unified_server.rs:2238-2287`
  `catch_unwind` dead code (misleading "panic isolation").
- **S8** (nit): `admin.rs:126` / `pir-identity` use ed25519 `verify`, not
  `verify_strict` (malleability hardening).
- **C5** (minor): `merkle_verify.rs:1068,1079` coerces malformed sibling
  rows to `ZERO_HASH` — benign given the root compare, but a future
  refactor trusting "walked successfully" could turn this into a hole.
- **C6** (minor): `dpf.rs:765,1074`, `harmony.rs:2977` —
  `start_chunk_id + num_chunks as u32` can overflow (release wrap / debug
  panic). `checked_add` is free.
- **W4** (minor): `onionpir_client.ts:681` comment claims
  `crypto.getRandomValues` dummies; actual path uses
  `DummyRng = splitmix64(Date.now())`. **Not** an OnionPIR privacy break
  (dummy bins are FHE-encrypted with SEAL's own randomness), but the
  comment misleads. Fix the comment.
- **W5** (minor): `web/package.json:23` declares `aes-js`, used nowhere —
  drop it.
- **W6** (minor): `dpf-adapter.ts:766` measurement-pin check no-ops when
  the report omits `launchMeasurementHex` — fail-closed when a
  `measurementHex` pin is configured.
- **W7** (minor): `onionpir_client.ts:1102` `keygenClient` leaks on a
  keygen throw — move creation inside the `try`.

### Status update (2026-06-26): small nits closed

- **S8**: ed25519 signature checks in `pir-runtime-core::admin` and
  `pir-identity` now use `verify_strict`.
- **C6**: DPF and Harmony chunk-id range expansion now uses
  `checked_add`, returning `PirError::Decode` on malicious overflow
  instead of release wrap / debug panic.
- **W4/W5/W7**: already closed in the web client (accurate dummy-RNG
  comment, unused `aes-js` dependency removed, `keygenClient.delete()`
  guarded by `finally`).
- **W6**: the DPF and Harmony web adapters now fail closed when a
  `measurementHex` pin is configured but the attestation report omits
  `launchMeasurementHex`.

---

## What's done notably well

- **Privacy invariants are enforced, not aspirational** — both cuckoo
  positions probed with no early exit; HarmonyPIR T−1 count symmetry with
  CSPRNG padding + XOR-cancellation; forced CHUNK rounds for
  not-found/whale — across all three backends and the hand-rolled TS
  client, several factored into `#[cfg(kani)]` proof harnesses.
- **Reproducibility is best-in-class** — committed lockfile, full
  vendored mirror with rev-pinned sources, `SOURCE_DATE_EPOCH=0`, pinned
  toolchain, locked Nix flake building both server and Tier 3 UKI, CI
  determinism gate.
- **The EasyCrypt mechanization is real and honestly scoped** — 31
  lemmas, zero `admit`s (verified), explicit "not modelled" list.
- **The crypto subsystems that got attention are solid** — admin auth
  (ed25519 challenge/response, nonce consumed on failure, per-connection
  state, path-traversal defense), `pir-channel` (X25519 + ChaCha20-Poly1305,
  in-order sequence, direction-bound nonces), chain-anchored seed
  derivation (fully wired client-side).
- **The recent WASM closure-teardown fix is complete and correct**
  (detaches handlers on both `close()` and `Drop`, idempotent).

---

## Follow-up: strict verification mode (tracked)

*Appended 2026-06-09 after the C1/W2 documentation pass. This is a
tracking note, not an implementation.*

**Decision.** C1/W2 are documented as the current (advisory) trust model
rather than fixed in this pass — fail-closed by default would break the
live pir1 demo, which has no SEV measurement to pin against. The wording
fixes landed in `pir-sdk-client/src/merkle_verify.rs` and
`pir-sdk-client/src/onion_merkle.rs` (comments only) and `README.md`;
behavior is unchanged. (Line references in the C1 row above are as of
the review commit; the added comments shift lines in both files.) The
proper closure is an **opt-in strict verification mode**, scoped as:

- **Plumb the attested roots into Merkle verification.**
  `attest.rs::AttestResponse` already carries
  `manifest_roots: Vec<Hash256>` (per-DB, db_id order; folded into SEV
  REPORT_DATA as `combined_root` via the V2 preimage). Thread the
  relevant attested root into the DPF/Harmony verifier
  (`fetch_tree_tops` / `verify_bucket_merkle_batch_*`) and into
  `OnionMerkleInfo` construction (OnionPIR), so the served commitment
  (per-group `top.root()` / `super_root`) is checked against an anchor
  the query server cannot choose.
- **Fail closed on mismatch.** With strict mode on, refuse to verify
  (all leaves fail) — or refuse to query at all — when the served root
  is not endorsed by the attested manifest root. Refusing to query is
  the stronger posture and also closes W2's "queries proceed on
  attestation mismatch" gap; failing verification is the minimum.
- **Gate on attestation quality.** The anchor is only as strong as the
  attestation behind it: require `SevStatus::ReportDataMatch` (plus VCEK
  chain validation where available) before treating `manifest_roots` as
  trusted. On `ReportDataMismatch`, strict mode must refuse — never fall
  back to the self-reported value.
- **Opt-in, default off.** Default stays today's advisory behavior so
  the unattested pir1 demo (no SEV; self-reported binary hash) keeps
  working. Suggested surface: a `strict_verification` flag on the client
  builders and the WASM / TS constructors, off unless explicitly set.
- **Open design points** (settle at implementation time):
  - *Root binding.* `manifest_roots[db]` is `SHA-256(MANIFEST.toml)`,
    which commits to per-file hashes (including the tree-tops blobs) —
    not directly to `top.root()` / `super_root`. Strict mode needs
    either the manifest body client-side (check the fetched tree-tops
    blob hash against its manifest entry) or a manifest/attest schema
    extension that surfaces the Merkle roots directly.
  - *Root rotation.* Delta sync changes the DB ⇒ the attested root
    changes. Strict mode must re-attest on epoch change rather than
    permanently reject the new root.
  - *pir1 story.* Without SEV, the strongest available pin is the
    reproducible-build binary hash plus operator-published roots —
    weaker than pir2's measurement but better than verbatim trust.
    Decide whether strict mode admits that tier or refuses non-SEV
    hosts outright.
