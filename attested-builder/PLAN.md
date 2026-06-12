# Attested Builder — Execution Plan

Status: Phase 0 started 2026-06-12 (this directory). Owner decision log
at the bottom.

## Goal

Close the trust gap tracked in `docs/CODE_REVIEW_2026-06.md` (C1) and
README ("Trust-model note", 2026-06): the Merkle roots clients verify
against are currently supplied by the serving server itself. Replace
that with **builder-signed root bundles**: independent builders (plain
hosts, an AWS Nitro enclave, the SEV box) each rebuild the PIR database
from a muhash-verified UTXO snapshot and sign the identical canonical
bundle; clients accept roots only with a k-of-n quorum of pinned
builder keys.

Two trust layers, deliberately separate:

1. **"M is the real chain state."** The `gettxoutsetinfo muhash` at the
   chain anchor is checked by each builder operator against their *own*
   Bitcoin Core node. With independent operators this is socially
   verified, the same model as Core's assumeutxo hashes.
2. **"Roots R were honestly derived from the set committed by M."**
   This is what a builder asserts by signing, and what the Nitro
   enclave makes verifiable for a *single* operator: the enclave
   recomputes muhash over the ingested snapshot, refuses to build on
   mismatch, and its signing key never leaves the enclave.

Clients only ever verify plain Ed25519 k-of-n signatures (~50 lines).
Nitro attestation documents are an **auditor-level** artifact published
once per enclave generation — they prove a given builder pubkey is
enclave-resident with pinned PCRs; browsers never parse them.

## What exists in this directory (Phase 0, in progress)

- `coremuhash/` — MuHash3072 bit-compatible with Bitcoin Core
  (`src/crypto/muhash.cpp`). Verified against Core's canonical
  cross-implementation vector (`10d312b1…`) and RFC 8439 ChaCha20.
  Includes `combine()` for sharded snapshot scans.
- `rootbundle/` — the canonical signed bundle: chain anchor (reusing the
  `chain_anchor.bin` block-hash+height shape, snapshot and delta forms),
  full-UTXO-set muhash, **filter params** (576-sat dust threshold,
  100-UTXO whale cap — bound so "correct roots for different filtering"
  cannot be substituted), `params_hash` (SHA256 of a canonical
  K/K_CHUNK/bin-count/format blob), and a sorted list of named Merkle
  roots. Domain-separated Ed25519 signing, strict canonical
  encode/decode, `verify_quorum(trusted, threshold)`.

This is a standalone cargo workspace (NOT a member of the repo root
workspace) pinned to the repo's vendored crate versions, so it builds
offline here today and can be lifted into its own repository unchanged.

## Phase 1 — snapshot verification + builder binary (plain host)

Goal: a `pir-attested-builder` binary that runs on any host (no enclave
yet): ingest snapshot → verify muhash → run build pipeline → emit
signed bundle.

1. **`dumptxoutset` parser + coin serialization** (new crate
   `utxosnapshot/`): parse Core's snapshot format (v2, Core ≥28:
   magic/version header, per-tx coin groups with compressed coins), and
   reproduce the exact per-coin bytes Core feeds `MuHash3072::Insert`
   in `gettxoutsetinfo` (`ApplyHash`): `COutPoint ‖ VARINT(height·2 +
   coinbase) ‖ CompressAmount ‖ compressed scriptPubKey`. Needs Core's
   VARINT, amount compression, and 6-case script compression — port
   with test vectors from Core's `compress_tests.cpp` /
   `serialize_tests.cpp`, then a golden end-to-end test against a tiny
   regtest snapshot (see "Tasks needing the node").
2. **Pipeline ingestion refactor** (in the main repo, `build/`): the
   gen stages currently read hardcoded `/Volumes/Bitcoin/...` paths via
   mmap. Introduce a streaming input abstraction (trait over
   file/stdin/vsock) and a `--data-dir`-style configuration so the same
   stage code runs on a workstation, a server, and (later) inside the
   enclave. Memory budget: keep the existing partition-by-prefix
   design; target ≤64 GB peak so the enclave parent doesn't need to be
   exotic.
3. **Builder binary**: snapshot in → muhash verify (sharded via
   `combine()`) → run gen_0…gen_4 → collect super-roots → construct
   `RootBundlePayload` → sign → emit bundle + tables. Hard-fail on
   muhash mismatch, well before any table is written.
4. **`params_hash` definition**: canonical little-endian blob of every
   layout-affecting parameter in `pir-core/src/params.rs` + format
   versions. Document field order in `rootbundle`'s docs; add a
   cross-check test against `pir-core`.

Exit criteria: builder reproduces the production database byte-for-byte
from a snapshot on a clean host (two runs, two machines, same roots),
and the signed bundle's muhash matches `gettxoutsetinfo muhash` from an
independent node.

## Phase 2 — client strict mode (k-of-n verification)

This is exactly the "strict verification mode" follow-up scoped in
`docs/CODE_REVIEW_2026-06.md`, with the trusted root source being the
bundle instead of attested `manifest_roots`:

1. Serve the latest `SignedRootBundle` (e.g. alongside tree-tops /
   `databases.toml`; the transport doesn't need to be trusted).
2. Client pins: builder pubkeys + threshold + expected `params_hash` +
   network magic (next to the SEV pins in `web/src/attest-pin.ts`).
3. Plumb the quorum-verified roots into `merkle_verify.rs` /
   `onion_merkle.rs` / the TS `verifySubTree`, replacing "trust the
   server's own tree-tops root" — fail closed in strict mode, advisory
   badge otherwise (keeps unattested demo servers working).
4. Each delta gets its own bundle (`BuildKind::Delta`, from/to
   anchors); the sync planner checks the delta bundle chain is
   contiguous from the snapshot anchor.

Ship order note: Phases 1+2 deliver real value with ZERO enclave work —
signatures from your existing build hosts already kill the
"forged-but-self-consistent database" attack for clients who pin your
keys. Everything after this only upgrades *who* signs.

## Phase 3 — Nitro enclave builder

1. **Architecture**: parent EC2 instance fetches the snapshot
   (untrusted), streams it over vsock; enclave verifies muhash, builds,
   streams tables back out (untrusted — clients verify them against the
   signed roots anyway), and emits the signed bundle. The ONLY
   trust-bearing outputs are the bundle and the once-per-generation
   attestation document.
2. **Key handling**: Ed25519 builder key generated inside the enclave
   at first boot; pubkey bound into the attestation document
   (`public_key` field) via the NSM API (`aws-nitro-enclaves-nsm-api`
   crate). Decide persistence: ephemeral per-build keys (rotate the pin
   with every enclave generation, simplest) vs. sealed via KMS
   (operational complexity; defer).
3. **Reproducible EIF**: build the enclave image from the nix
   derivation (`dockerTools` → `nitro-cli build-enclave`), same
   discipline as `nix build .#unified-server` / the Tier-3 UKI. Publish
   PCR0/1/2 next to the existing pins; auditors check the attestation
   doc chains to AWS's root cert and matches the PCRs.
4. **Memory**: enclave RAM is hugepage-carved from the parent. Start
   with an r7i.8xlarge-class parent (256 GB) and the ≤64 GB pipeline
   budget from Phase 1; tighten later if cost matters.

## Phase 4 — builder diversity

- Second builder on the VPSBG SEV-SNP box (vendor diversity: AMD +
  AWS), reusing the Phase 1 binary under the existing measured-boot
  pipeline.
- Optionally certify builder keys with the existing Tier-1 operator key
  (`pir-identity` `IdentityCert` pattern) so builder-key rotation
  doesn't require client redeploys.
- Recruit ≥1 external operator when possible; raise threshold to 2-of-3.
- Future: the ZK build proof (see conversation history / earlier
  analysis) slots in as just another signer over the same payload.

## Tasks needing the owner's Bitcoin node (once connected)

1. `bitcoin-cli gettxoutsetinfo muhash` at the intended anchor height —
   first real pin, and the integration-test expectation.
2. `bitcoin-cli dumptxoutset <file> rollback=<height>` (Core ≥28) — the
   Phase 1 input. Record Core version + snapshot sha256.
3. **Golden vectors for `utxosnapshot`**: a regtest node with a handful
   of blocks → `dumptxoutset` + `gettxoutsetinfo muhash` → tiny
   committed fixture that exercises parser + coin serialization + muhash
   end-to-end. This is the single most valuable test in the whole plan.
4. Re-run `gen_1_onion` and record the dust/whale skip counts the build
   prints (they were never persisted) — they size the documented filter
   and belong in the bundle docs.

## Repository split

This directory is the seam: it has no path dependencies on the parent
workspace and pins vendored crate versions. When the new repo exists
(suggested: `Bitcoin-PIR/attested-builder`), move it with history
(`git filter-repo --subdirectory-filter attested-builder` or plain `git
mv` + fresh history), then vendor or fetch deps there. The main repo
keeps: the pipeline refactor (Phase 1 step 2) and the client strict
mode (Phase 2), which touch existing crates.

## Decision log

- 2026-06-12 — chose signed-bundle + TEE path over ZK (practicality);
  full-set muhash (not filtered) with filter params bound in the
  bundle; clients verify plain k-of-n Ed25519, attestation docs are
  auditor-level.
