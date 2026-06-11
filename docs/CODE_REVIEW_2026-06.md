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
