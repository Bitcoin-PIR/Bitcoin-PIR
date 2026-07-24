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
| S1 | crit | `crates/protocol/runtime/src/handler.rs:407,454,498` | ✅ `DpfKey::from_bytes(k).expect("bad dpf key")` on client bytes → process abort |
| S2 | crit | `crates/protocol/runtime/src/eval.rs:133` (+ `protocol.rs:1225`) | ✅ `let mut bits = [false; 8]` indexed by uncapped `keys_per_group` → OOB write |
| S3 | crit | `crates/protocol/runtime/src/handler.rs:412` | ✅ `key_refs[0]`/`key_refs[1]` no length guard; `keys_per_group < 2` → panic |
| S4 | crit | `crates/protocol/runtime/src/table.rs:135` (callers `handler.rs:322,359`) | `group_bytes` slices mmap with unchecked `group_id` on Harmony path |
| S5 | major | `crates/protocol/runtime/src/handler.rs:324,365` | `Vec::with_capacity(indices.len()*entry_size)` before range check → alloc amplification (~50–130×) |
| C2 | major | `crates/protocol/core/src/codec.rs:19,22` (callers `dpf.rs:2650`, `harmony.rs:5945`, `onion.rs:2033`) | ✅ `read_varint` panics by design on adversarial server chunk data, *before* Merkle verify |
| C3 | major | `crates/sdk/client/src/dpf.rs:1258,1465,1665` | ✅ `results0[assigned_group][h]` double-index OOB on short/truncated server batch response (DPF-specific) |
| C4 | minor | `crates/sdk/client/src/harmony.rs:576` | Master 128-bit PRP key derived from `splitmix64(seed_nanos())` (wall clock), not a CSPRNG |
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
  Note `crates/sdk/core/src/sync.rs:504` already has a panic-free variant.
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

## Architectural / trust-model (resolved)

| ID | Sev | Location | Issue |
|----|-----|----------|-------|
| C1 | major | `crates/sdk/client/src/merkle_verify.rs:1145`, `onion_merkle.rs:281,610` | ✅ Closed in PRs #54/#56/#57: strict clients install verified database roots and bind tree-tops before querying |
| W2 | major | `web/src/dpf-adapter.ts:526`, `harmonypir-adapter.ts:595`, `arc-present.ts:29` | ✅ Closed in PRs #56/#57: the production web query path fails closed on runtime/pin/channel/identity or database-root verification failure |

**Why this mattered at review time:** The Merkle layer proved only one
server's internal self-consistency, so a malicious server could fabricate a
self-consistent root and siblings. The later strict-root rollout made the
database proof and production pins the trust input, then bound the exact
tree-tops to the installed bucket or Onion super-root before any address
query. Pir1 remains explicitly described as operator identity plus binary
pinning rather than SEV hardware attestation.

---

## Hygiene / CI / supply chain

| ID | Sev | Issue |
|----|-----|-------|
| I1 | major | Privacy **leakage suite never runs in CI** (`leakage_integration_test.rs` is `#[ignore]`d + invoked nowhere); ~half of 678 Rust tests not in CI; no `cargo fmt --check`; clippy on one crate only. Adding `--test leakage_integration_test -- --ignored` to the daily canary is a one-line, high-value fix |
| I2 | major | `libdpf` floats unpinned (no `rev`) in `crates/sdk/client/Cargo.toml:60`, `crates/protocol/runtime/Cargo.toml:25`, `runtime/Cargo.toml:66`, and `.cargo/config.toml`; pinned only by `Cargo.lock`. Every other git dep is rev-pinned |
| I3 | major | `.gitignore:47` (`build/`) shadows the Rust `build/` workspace crate — new files under `build/src/` are silently untracked |
| I4 | major | `PLAN_*.md` design docs are gitignored (`.gitignore:54`) but referenced as normative from `CLAUDE.md`, source comments, and the then-local EasyCrypt README (now [`protocol-proofs/README.md`](https://github.com/Bitcoin-PIR/protocol-proofs/blob/main/README.md)) — dangling links for any cloner |
| I5 | major⚠ | `docs/RATELIMIT_INTEGRATION.md:187` asserts a committed live `TUNNEL_TOKEN` in `deploy/cloudflared_tunnel.env`. File not in tracked tree; **confirm the token was rotated / history scrubbed**, then fix the doc |
| I6 | minor | CI uses `dtolnay/rust-toolchain@stable`, which exports `RUSTUP_TOOLCHAIN` and bypasses the `rust-toolchain.toml` 1.94.1 pin |
| I7 | minor | No dependabot / `cargo-audit` / `cargo-deny` — 317 vendored crates, no CVE signal |
| I8 | minor | `pir-channel`, `pir-identity`, `pir-attest-verify` declare dual license but ship no in-crate LICENSE files and are not `publish = false` |

### Status update (2026-06-26): I4/I5/I6 closed

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
- **I6**: first-party GitHub Actions workflows no longer install
  `dtolnay/rust-toolchain@stable`. They invoke `rustup toolchain
  install` without a toolchain argument, so rustup installs the active
  toolchain from `rust-toolchain.toml`; WASM jobs add
  `wasm32-unknown-unknown` to that pinned toolchain.
- **I7**: partially closed by the cargo-audit CI job added in June;
  dependabot / cargo-deny remain optional future hygiene.

### Status update (2026-07-13): I1/I7/I8 closed

- **I1**: the scheduled/manual SDK workflow now runs serialized core leakage
  invariants for DPF, HarmonyPIR, and OnionPIR after the ordinary live
  integration jobs pass. Each backend covers per-message shape, the
  two-not-found simulator property, and found/not-found byte-identical
  profiles; HarmonyPIR receives one transport-only retry.
- **I7**: Dependabot now covers the Cargo workspace, both npm applications,
  and GitHub Actions on a weekly grouped cadence. Together with the existing
  cargo-audit workflow this closes the selected dependency-hygiene scope;
  cargo-deny remains an optional future policy layer rather than a blocker.
- **I8**: `pir-channel`, `pir-identity`, and `pir-attest-verify` now ship the
  declared MIT/Apache-2.0 license texts. All three complete `cargo package`
  packaging, verification, and compilation; remaining downstream registry
  blockers are recorded in `PUBLISHING.md`.

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

### Status update (2026-07-13): S6/S7/C5 closed

- **S6**: `pir-sdk-server` now applies conservative global connection and
  CPU-heavy request concurrency caps, runs PIR evaluation on Tokio's blocking
  pool, and bounds WebSocket handshake/idle time. Configuration validation,
  cap/backpressure tests, and a real loopback WebSocket allowed-traffic test
  cover the public defaults and tuning surface.
- **S7**: removed the ineffective `catch_unwind` wrappers and stale
  panic-isolation logging from `unified_server`; comments now state that the
  active `panic = 'abort'` policy requires a process boundary for isolation.
- **C5**: malformed or wrong-sized Merkle sibling evidence is tracked per item
  and forces verification failure after the privacy-padded round shape
  completes. Tests cover valid, missing, short, and oversized rows.

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

## Follow-up: strict verification mode (resolved)

*Originally appended 2026-06-09; updated after the 2026-07-20 production
rollout.*

C1/W2 are closed by PRs
[#54](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/54),
[#56](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/56), and
[#57](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/57):

- Native DPF, HarmonyPIR, and OnionPIR clients expose `Advisory` and
  `RequireVerified` policies. Verification returns a typed
  `VerifiedDatabaseRoots` handle; installation is a separate explicit action.
- `RequireVerified` refuses to query unless every database in the sync plan
  has an installed verified root. Disconnect and catalog/height rotation clear
  the installed roots and authenticated tree-top caches.
- DPF/HarmonyPIR require the exact ordered INDEX + CHUNK root list to hash to
  the installed `bucket_super_root`. OnionPIR binds its consolidated tree-tops
  to the installed `onion_super_root`; `server-info.super_root` is diagnostic
  only.
- The production web client verifies each database proof in Rust/WASM,
  compares every returned field with the production TypeScript pin, installs
  that same verified handle, preflights tree-tops, and then permits the query.
  Database proof and tree-top mismatch are fail-closed for all three backends;
  the DPF/HarmonyPIR runtime pins, secure-channel upgrade, and configured
  operator identity are fail-closed as well.
- Pir1's accepted production tier is operator identity plus binary pinning;
  only pir2 is described as SEV-SNP hardware attestation.

Production Pages deployment and all three backend smokes passed on 2026-07-20.
The complete closure record is in
[`STRICT_VERIFICATION_PROGRESS.md`](STRICT_VERIFICATION_PROGRESS.md).

The scheduled/manual native SDK canary now exercises proof-pin verification,
typed root installation, tree-top binding, fresh and delta sync-plan gates,
result verification, and disconnect for every backend. Browser-only runtime,
identity, encrypted-channel, and v1 Onion layout automation remains a
non-blocking follow-up. A v2 database proof should commit the complete
OnionPIR query layout so the current fail-closed v1 layout pins can be removed.
Root changes are operationally covered by
[`DATABASE_ROOT_ROTATION_RUNBOOK.md`](DATABASE_ROOT_ROTATION_RUNBOOK.md).
Neither item makes C1/W2 open again.
