# Strict verification rollout

This file tracks the work that closes the database-root trust gap. A checked
item means the behavior is merged into `main`, not merely implemented on an
open branch.

## PR A — publish complete database proof material

Status: **merged** ([#53](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/53)).

- [x] Publish the complete snapshot proof bundle.
- [x] Verify the bundle locally and on the production servers.

## PR B — strict native SDK root policy

Status: **draft PR open** ([#54](https://github.com/Bitcoin-PIR/Bitcoin-PIR/pull/54)).
Implementation and local validation are complete; the checklist remains
unchecked until the PR is merged, per this file's convention.

- [ ] Add `Advisory` and `RequireVerified` root policies to DPF, HarmonyPIR,
      and native OnionPIR clients.
- [ ] Keep a session-local `db_id -> VerifiedDatabaseRoots` map.
- [ ] Add an explicit typed install API. `verify_database_proof()` must only
      return a verified handle and must not install it implicitly.
- [ ] Before a query, require every database in the sync plan to have an
      installed root when strict mode is selected.
- [ ] Clear or invalidate installed roots on disconnect and catalog/height
      rotation.
- [ ] Before the first address query, bind bucket tree-tops to the installed
      `bucket_super_root` using
      `SHA256(INDEX roots || CHUNK roots)` and require exactly
      `index_k + chunk_k` roots in protocol order.
- [ ] Cache tree-tops only after that binding succeeds.

## PR C — strict WASM and DPF/Harmony web flow

Status: **not started**; depends on PR B.

- [ ] Verify DB proof in Rust/WASM and compare every field with the production
      pin in TypeScript.
- [ ] Install the same live `WasmDatabaseProof` handle into the client only
      after the TypeScript pin comparison succeeds.
- [ ] Preflight trusted tree-tops before querying.
- [ ] Fail closed on runtime attestation/pin, secure-channel upgrade, and any
      configured operator-identity failure.
- [ ] Describe Hetzner as operator identity + binary pin, and VPSBG as the
      SEV-SNP deployment.

## PR D — standalone OnionPIR web client

Status: **not started**; depends on the proof/install contract established by
PR B and the WASM patterns established by PR C.

- [ ] Add a stateless WASM verifier for `REQ_GET_DB_PROOF` responses.
- [ ] Install `onion_super_root` only after production-pin matching.
- [ ] Bind Onion tree-tops to the installed trusted root.
- [ ] Treat `server-info.super_root` as diagnostics only.
