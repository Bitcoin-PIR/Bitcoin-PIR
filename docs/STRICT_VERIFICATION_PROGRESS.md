# Strict verification rollout

Rollout status: **complete as of 2026-07-20**. PRs
[#53](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/53),
[#54](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/54),
[#56](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/56), and
[#57](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/57) closed the
database-root trust gap. PR
[#58](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/58) recorded the merged
state. For code items, a checked box means the behavior is merged into `main`,
not merely implemented on an open branch.

## PR A — publish complete database proof material

Status: **merged** ([#53](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/53)).

- [x] Publish the complete snapshot proof bundle.
- [x] Verify the snapshot bundle locally with `bpir-admin db-proof verify`.

## PR B — strict native SDK root policy

Status: **merged** ([#54](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/54)).

- [x] Add `Advisory` and `RequireVerified` root policies to DPF, HarmonyPIR,
      and native OnionPIR clients.
- [x] Keep a session-local `db_id -> VerifiedDatabaseRoots` map.
- [x] Add an explicit typed install API. `verify_database_proof()` must only
      return a verified handle and must not install it implicitly.
- [x] Before a query, require every database in the sync plan to have an
      installed root when strict mode is selected.
- [x] Clear or invalidate installed roots on disconnect and catalog/height
      rotation.
- [x] Before the first address query, bind bucket tree-tops to the installed
      `bucket_super_root` using
      `SHA256(INDEX roots || CHUNK roots)` and require exactly
      `index_k + chunk_k` roots in protocol order.
- [x] Cache tree-tops only after that binding succeeds.

## PR C — strict WASM and DPF/Harmony web flow

Status: **merged** ([#56](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/56)).
The production proof prerequisite is also complete: on 2026-07-19,
`bpir-admin db-proof verify-live` returned `status=ok` for db 0 and db 1 on
both hosts. On 2026-07-20, strict DPF and HarmonyPIR production browser queries
passed end to end after the Pages deployment.

- [x] Verify DB proof in Rust/WASM and compare every field with the production
      pin in TypeScript.
- [x] Install the same live `WasmDatabaseProof` handle into the client only
      after the TypeScript pin comparison succeeds.
- [x] Preflight trusted tree-tops before querying.
- [x] Fail closed on runtime attestation/pin, secure-channel upgrade, and any
      configured operator-identity failure.
- [x] Describe Hetzner as operator identity + binary pin, and VPSBG as the
      SEV-SNP deployment.
- Production deployment complete: both hosts serve the snapshot and delta
  proof bundles and pass live proof verification.

Completed production proof activation for PR C:

1. Copied `web/public/proofs/oram-source/mainnet_948454/db/` to a stable proof
   directory on Hetzner and VPSBG, for example
   `/home/pir/data/attestations/mainnet_948454_sev_snp/`.
2. Added that path as the `proof_dir` of the `main` / `db_id=0` entry in each
   host's `databases.toml`; keep the existing delta proof directory on
   `db_id=1`.
3. Restarted each `unified_server` through its normal supervisor/UKI boot path.
   This is a data/config rollout; it does not require a new server binary or a
   rebuilt UKI for the PR C frontend code.
4. Verified db 0 and db 1 against both hosts with `bpir-admin db-proof
   verify-live`.
5. Completed strict DPF and HarmonyPIR browser smokes against production:
   both server summaries were `YES`, database proof/tree-top preflight passed,
   query results received automatic Merkle `Verified` marks, and each query
   ended with the client disconnected. Harmony hints remained browser-cached.

## PR D — standalone OnionPIR web client

Status: **merged** ([#57](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/57)).
Merged on 2026-07-20 as `4adb5924`.

- [x] Add a stateless WASM verifier for `REQ_GET_DB_PROOF` responses.
- [x] Install `onion_super_root` only after production-pin matching.
- [x] Bind Onion tree-tops to the installed trusted root.
- [x] Treat `server-info.super_root` as diagnostics only.
- [x] Pin the remaining standalone OnionPIR query layout until a v2 database
      proof commits those fields directly.
- [x] Verify every found, absent, and whale result before merging or committing
      sync state, and disconnect at the end of every query.

Pre-merge validation completed on 2026-07-20:

- Rust client: 276 unit tests passed; 6 non-network integration/doc tests
  passed (network-dependent tests remain intentionally ignored).
- WASM: 73 tests passed, `wasm32-unknown-unknown` check passed, and `wasm-pack`
  produced the browser package.
- Web: TypeScript build passed; 240 tests passed and 2 optional leakage tests
  remained skipped.
- Browser smoke against `wss://weikeng1.bitcoinpir.org`: both production DB
  proofs and consolidated tree-tops passed preflight; both found and not-found
  results received automatic `Verified` marks; each session ended disconnected.
- This rollout uses the existing proof and OnionPIR Merkle protocol. It does
  not require a new server binary or rebuilt UKI.

Post-merge production validation completed on 2026-07-20:

- The Pages deployment for PR #57 completed successfully in
  [Actions run 29723261461](https://github.com/Bitcoin-PIR/Bitcoin-PIR/actions/runs/29723261461).
  The follow-up Pages deployment for PR #58 also completed successfully in
  [Actions run 29723409814](https://github.com/Bitcoin-PIR/Bitcoin-PIR/actions/runs/29723409814).
- A production OnionPIR query reported `Data integrity: YES`; both returned
  results received automatic `Verified` marks, INDEX verification completed
  `4/4`, DATA verification completed `2/2`, and the session disconnected after
  the query.

## Continuous verification

The SDK integration workflow now runs a scheduled/manual native
database-root canary for DPF, HarmonyPIR, and OnionPIR. For both production
databases it verifies the proof against reviewed pins, installs the typed
roots, preflights tree-tops, and exercises fresh and delta sync. It also proves
that a sync plan fails before the required root is installed, checks result
Merkle status, disconnects, and confirms session roots were cleared.

Pre-merge production validation on 2026-07-20 passed all three native
canaries: DPF and HarmonyPIR completed their fresh and delta paths in one run,
and standalone OnionPIR completed the same paths in its Onion-enabled run.
The canaries caught and drove fixes for several issues that ordinary unit
tests did not expose:

- native HarmonyPIR now honors the production FastPRP backend exactly instead
  of silently constructing HMR12 state;
- the db-0-bound V2 hint pool is never used for a delta database, and only the
  exact pool-empty response may fall back to V1;
- V2-half errors, mismatches, and timeouts close both hint sockets rather than
  reusing a partially drained stream;
- persisted server hint-pool entries are versioned, fingerprinted, consumed
  durably, and never block a Tokio worker while the pool is empty;
- native OnionPIR verifies a v1 DB proof against the standard DPF catalog
  geometry while retaining the distinct Onion geometry for queries; and
- a client built without the `onion` feature fails explicitly instead of
  returning an unverified empty result.

This native canary deliberately does not claim to automate the production web
runtime/binary pin, operator-identity, secure-channel, or temporary v1 Onion
layout gates. Those browser-level gates remain covered by release smokes; an
end-to-end browser canary is a non-blocking automation follow-up.

The server-side HarmonyPIR hint-pool hardening was deployed on 2026-07-20 from
commit `d126f36a`. Hetzner and the VPSBG Tier 3 UKI use the same ORAM-enabled
`unified_server` binary (SHA-256 `4cf7d467...045b4`). The Hetzner primary now
maintains eight fingerprint-bound HMPOOLV2 entries in its persistent pool;
consumed entries are removed durably before use and replenished in the
background. Both services stayed at zero restarts during rollout. Post-deploy
strict production canaries passed for DPF, HarmonyPIR, and OnionPIR, and the
VPSBG direct-ORAM smoke passed for both production database IDs.

On 2026-07-22, VPSBG moved independently to BitcoinPIR commit `837108b6`
(binary SHA-256 `61d74a9c...f178`, UKI SHA-256 `3d511f88...aa6ce`, launch
MEASUREMENT `478fb4ac...c3f7`). This keeps the certified
`bitcoinpir-oram` revision unchanged while serializing each database's complete
ORAM request and state-commit transaction. A fixed-pin AMD attestation,
encrypted-channel test, and padded direct-ORAM smoke for db_id 0 and db_id 1
passed on the full-feature UKI after it reopened state written by the diagnostic
UKI. Hetzner intentionally remains on the independently pinned 2026-07-20
binary above.

On 2026-07-24, VPSBG moved to the boot-regeneration UKI built from measured
startup commit `7b6cf108`. It reuses the unchanged `unified_server` binary from
BitcoinPIR commit `66034c82` (SHA-256 `1134b8a4...09c37`) and the source-bound
`oramctl` from bitcoinpir-oram commit `cd2c1a22`. The UKI SHA-256 is
`5b854888...7b13e` and its live launch MEASUREMENT is
`a3a8fb0f...04040b86`. Every boot now regenerates both authenticated ORAM
images from proof-bound inputs in SEV-protected tmpfs, verifies the emitted-page
Merkle roots and the exact published bulk/trusted-state path contract, and only
then opens the query server. Fixed-pin AMD attestation, the encrypted channel,
dummy padded lookups, and known-present padded results for both db_id 0 and
db_id 1 passed against the live full-feature UKI.

## Non-blocking follow-ups

The strict-root rollout above is closed. The following improvements do not
reopen it:

- Automate the remaining browser-only runtime, identity, encrypted-channel,
  and v1 Onion layout gates without weakening the native database-root canary.
- Harden malformed HarmonyPIR V2 streams further by rejecting duplicate group
  IDs and inconsistent preamble/terminal metadata immediately, and discard the
  single-stream V2 socket after any mid-stream error. Strict Merkle binding
  already prevents such a stream from yielding trusted data; this follow-up is
  fail-fast protocol hygiene and connection recovery.
- Implement the separately scoped
  [v2 database-proof migration](DB_PROOF_V2_PLAN.md), which commits the three
  remaining OnionPIR layout values and replaces the explicit v1 layout pins
  only after new builder evidence and production sidecars exist. Until then,
  the production client safely fails closed against the explicit pins in
  `web/src/attest-pin.ts`.
- Follow [the database/root rotation runbook](DATABASE_ROOT_ROTATION_RUNBOOK.md)
  for every new snapshot or delta generation.

The separate ORAM live-image claim remains out of scope for the completed
strict-root rollout. Its threat model and implementation sequence are tracked
in [ORAM_LIVE_IMAGE_BINDING_PLAN.md](ORAM_LIVE_IMAGE_BINDING_PLAN.md).
