# Strict verification rollout

This file tracks the work that closes the database-root trust gap. For code
items, a checked box means the behavior is merged into `main`, not merely
implemented on an open branch. Production deployment state is recorded
separately and reflects the live hosts.

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

Status: **Draft PR open** ([#56](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/56)).
Implementation and validation are complete. The production proof prerequisite
is also complete: on 2026-07-19, `bpir-admin db-proof verify-live` returned
`status=ok` for db 0 and db 1 on both hosts. Strict DPF and HarmonyPIR browser
queries passed end to end. Merge is now gated on review and CI.

- [ ] Verify DB proof in Rust/WASM and compare every field with the production
      pin in TypeScript.
- [ ] Install the same live `WasmDatabaseProof` handle into the client only
      after the TypeScript pin comparison succeeds.
- [ ] Preflight trusted tree-tops before querying.
- [ ] Fail closed on runtime attestation/pin, secure-channel upgrade, and any
      configured operator-identity failure.
- [ ] Describe Hetzner as operator identity + binary pin, and VPSBG as the
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

Status: **not started**; depends on the proof/install contract established by
PR B and the WASM patterns established by PR C.

- [ ] Add a stateless WASM verifier for `REQ_GET_DB_PROOF` responses.
- [ ] Install `onion_super_root` only after production-pin matching.
- [ ] Bind Onion tree-tops to the installed trusted root.
- [ ] Treat `server-info.super_root` as diagnostics only.
