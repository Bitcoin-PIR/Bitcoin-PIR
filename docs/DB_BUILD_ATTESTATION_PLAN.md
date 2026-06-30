# Database Build Attestation Plan

Status: server/API proof distribution is deployed for the production delta DB.
The web frontend now fetches and verifies the production delta proof for DPF
and HarmonyPIR and renders an advisory DB/MuHash badge. Strict query-path root
installation and standalone OnionPIR proof verification remain.

Goal: bind BitcoinPIR database Merkle roots to an independently verifiable
Bitcoin Core UTXO MuHash computation. The runtime server attestation proves
"this server is serving these files"; the database build attestation proves
"these Merkle roots came from the claimed Core snapshot or delta."

## Current Anchor Artifact

The first production-grade artifact is the VPSBG SEV-SNP roots-only delta run:

- range: `940611 -> 948454`
- from block hash:
  `000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99`
- block hash:
  `00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4`
- MuHash:
  `cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee`
- deployed proof dir on Hetzner and VPSBG:
  `/home/pir/data/attestations/delta_940611_948454_sev_snp`
- local mirror:
  `deploy/attested-builder-runs/delta_940611_948454_sev_snp/`
- builder commit:
  `01e8db91d76037cd5562fce85c40e832ad156431`
- builder binary sha256:
  `34a677847b9be6580385c73f163279c81561772f8d3ad782d0ca08f1c01fad4a`
- Bitcoin Core version:
  `Bitcoin Core v31.0.0`
- params hash:
  `2b3e488c04433ed8bd293fd3adab72b49bf52346b81160365486d76f9b4d4e39`
- network magic:
  `f9beb4d9`
- build evidence sha256:
  `977abca3ca8dc5dfce06d69006feeb6c0df5e7df3d7c1d758fc717254ff10697`
- SEV-SNP report sha256:
  `4c27672968a1faf0a77d3554393dfd1faa9bd84702e625817a037ef7b1d30df6`
- root bundle payload sha256:
  `70cf9ab65f753a9c3a265f24a7220d52534e53a5739cc23921706b57afd907d4`
- bucket super root:
  `e2ba2eee6788424309a95f771893d5401cc8e3ceec6188dc2708900e211a910a`
- onion super root:
  `f86baa3966a61cdcd70d8c0ad9bed233f591806eb351db2ae35ac0192a3fe997`

Known cleanups:

- `delta-inputs.txt` records `*_snapshot_bytes` through a shell path that
  overflowed on the UKI. The cryptographic evidence records the target
  snapshot size and sha256 correctly, so this is metadata hygiene rather than a
  binding failure.
- The original sketch reserved `0x03` for `REQ_GET_DB_PROOF`, but production
  `unified_server` already uses `0x03` for `REQ_GET_INFO_JSON`; DB proof uses
  `0x0a` instead.

## Implementation Stages

### 1. Shared Verifier Library

- Add a shared verifier crate for attested-builder evidence.
- Reuse the existing canonical `rootbundle` encoding from
  `attested-builder/rootbundle`.
- Decode and verify:
  - `build-evidence.bin`
  - `root-bundle-payload.bin`
  - `build-evidence.sev-snp-report.bin` `REPORT_DATA`
  - artifact manifest hashes
  - expected anchors, MuHash, builder binary hash, network magic, params hash.
- Keep AMD VCEK chain validation as a separate policy hook; first version checks
  REPORT_DATA binding and preserves raw report bytes for external verifiers.

### 2. Admin CLI

- Add `bpir-admin db-proof verify`.
- Add `bpir-admin db-proof verify-live`.
- Inputs:
  - local proof directory, or a live server URL + db id
  - optional expected range, MuHash, roots, builder binary sha256
- Output a concise machine-readable and human-readable summary.
- This command is the first acceptance gate before touching clients.

### 3. Server Proof Distribution

- Add protocol request/response:
  - `REQ_GET_DB_PROOF = 0x0a`
  - request payload: `[db_id]`
  - response payload: versioned `DatabaseProofBundle`.
- Extend `databases.toml` entries with optional `proof_dir`.
- Runtime loads proof sidecars at startup, but does not trust them; it only
  serves bytes to clients.

### 4. Client Strict Mode

- Add client API:
  - `fetch_database_proof(db_id)`
  - `verify_database_proof(db_info, proof, policy)`
  - `VerifiedDatabaseRoots`.
- Strict policy validates:
  - SEV-SNP `REPORT_DATA` matches `BuildEvidence::report_data()`.
  - evidence binds the root bundle payload and artifact manifests.
  - build kind and anchors match the catalog entry, including block hashes
    from the catalog's chain-anchor extension.
  - delta chain is contiguous.
  - network magic and params hash match client policy.
  - root labels include bucket and onion super roots.
- Failure behavior:
  - strict mode: fail closed.
  - compatibility mode: mark DB proof advisory/failed but keep old demo flow.

### 5. Merkle Root Plumbing

- DPF and HarmonyPIR bucket Merkle verification should consume
  `VerifiedDatabaseRoots.bucket_super_root`.
- OnionPIR verification should consume `VerifiedDatabaseRoots.onion_super_root`.
- The server's tree tops are no longer the root of trust in strict mode.

### 6. Web/WASM Policy

- `pir-sdk-wasm` exposes:
  - `WasmDpfClient.verifyDatabaseProof(dbId, params_hash, builder_hash,
    builder_commit)`
  - `WasmHarmonyClient.verifyDatabaseProof(dbId, params_hash, builder_hash,
    builder_commit)`
  - `verifyDatabaseProofResponse(dbInfo, rawResponse, policy)` for the
    standalone TypeScript OnionPIR client remains.
- DPF and Harmony web adapters accept `databaseProofPins` and
  `onDatabaseProof`, fetch `REQ_GET_DB_PROOF`, verify in WASM, compare against
  `web/src/attest-pin.ts::PRODUCTION_DB_PROOF_PINS`, and store status in
  `databaseProofs`.
- The demo UI renders a DB proof badge with the verified MuHash, block range,
  bucket root, onion root, and builder pins.
- DPF and Harmony should install verified bucket/onion roots into their native WASM
  clients before queries.
- standalone OnionPIR should fetch `REQ_GET_DB_PROOF` directly, verify it through
  the WASM verifier, and use the attested onion super-root as the Merkle
  anchor instead of trusting `server-info`'s `super_root`.
- `scripts/smoke_db_proof_attestation.sh` wraps local and live proof checks
  with the pinned expected values below.

### 7. Deployment

- Place proof dirs under a stable path, for example:
  `/home/pir/data/attestations/delta_940611_948454_sev_snp/`
- Add `proof_dir` to Hetzner and VPSBG `databases.toml`.
- Serve the same self-verifying proof from both hosts.
- Run `bpir-admin db-proof verify-live` against both servers.

### 8. Missing Artifact

Current production strict mode still needs a full snapshot proof for the full DB
if the client must verify the whole sync chain from zero. Run the same UKI in
`BUILD_KIND=snapshot` for height `948454` and bind its bucket/onion roots.

## Progress Log

- [x] Shared verifier library.
- [x] `bpir-admin db-proof verify` for local proof dirs.
- [x] `bpir-admin db-proof verify-live` for deployed proof bundles.
- [x] Server `REQ_GET_DB_PROOF`.
- [x] `databases.toml` `proof_dir` loading.
- [x] Client proof fetch and strict verification.
- [x] Post-deploy smoke helper script.
- [x] Production delta proof deployment and live smoke tests.
- [x] Web/WASM proof policy for DPF and HarmonyPIR.
- [x] Dedicated UI badge/status rendering for DPF and HarmonyPIR database
      build attestation.
- [ ] Merkle verification consumes verified roots in strict query paths.
- [ ] Web/WASM verified-root installation before queries.
- [ ] standalone OnionPIR DB proof verifier and UI badge.

## Production Deployment Record

Deployed on 2026-06-16:

- Hetzner runs the db-proof-enabled `unified_server` binary:
  `d01e5b7aab2b3075eed4dd154ffc2079aae394b418a40155128166a50ace750a`.
- VPSBG Tier 3 UKI runs the same binary and has SEV-SNP launch measurement:
  `892bb625705e8df9ff587553b11900e4fa7c28df732a77cf0d417446d63d2dff82fbefac334e0d97eaf3a5c0d1ce1013`.
- Both hosts serve `main` at height `948454` and `delta_940611_948454` at
  `base_height=940611`, `height=948454`.
- Both `databases.toml` files set:
  `proof_dir = "attestations/delta_940611_948454_sev_snp"`.
- Live smoke passed against `wss://weikeng1.bitcoinpir.org` and
  `wss://weikeng2.bitcoinpir.org` with:
  `scripts/smoke_db_proof_attestation.sh`.
