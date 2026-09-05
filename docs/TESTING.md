# Testing entry points

This is Flow B in [Production operations](PRODUCTION_OPERATIONS.md).
Green CI is not a deploy. Publishing the browser client is Flow C
(manual `deploy-web.yml` on `main`).

Pick your checks by *change class*, not by a single default command. The
matrix below maps what you touched to the minimum local checks and to the CI
that will actually run on your PR (most workflows are path-filtered; two run
on every PR regardless).

Payment V1 (signed policy, clearing, PoW, the admission gate) and the
ARC/Cashu verifiers are deleted. Paid queries present a cashier-signed
session grant on opcode 0x0b ([Session grants](SESSION_GRANTS.md)); free
queries are open.

## Change-class → required checks

| You changed | Minimum local checks | CI triggered on the PR | Known gaps |
|---|---|---|---|
| `crates/protocol/core` (cuckoo, Merkle, anchors) | `cargo test --locked --offline -p pir-core --test cross_build_determinism`; `cargo test --locked --offline -p pir-core`; `cargo clippy --locked --offline -p pir-core --tests -- -D warnings` | `build-determinism.yml` | A determinism break means operators can no longer reproduce the database byte-for-byte — treat failures as release blockers |
| `crates/sdk/{core,client}` | `cargo test -p pir-sdk-client` (add `--features onion` if you touched the Onion path) | `pir-sdk-integration.yml` (deterministic jobs; live tests run only on schedule/dispatch) | — |
| `crates/sdk/wasm` or the WASM↔TS boundary | `wasm-pack build crates/sdk/wasm --target web --out-dir pkg -- --locked --offline`, then `cd web && npm run build && npm test` | `web-build.yml` | — |
| `apps/server` / `crates/protocol/runtime` | `cargo test --locked --offline -p runtime --lib hint_pool`; `cargo test --locked --offline -p runtime --bin unified_server`; do **not** run the full `rust-ci-lane.sh` locally unless asked | `rust-ci.yml` (via `apps/server/**`); `pir-sdk-integration.yml` only if you touched `hint_pool.rs`, `apps/server/src/bin/unified_server/`, or the crate manifest | A deployed binary/UKI is a separate authorized release, never implied by green CI |
| `web/` (TypeScript, pins, tests) | `cd web && npm run build && npm test && npm run build-web` | `web-build.yml`; `deploy-web.yml` adds Playwright gates only at the manual release dispatch | Pin edits: keep `PRODUCTION_DB_PROOF_PINS`, `PRODUCTION_ONION_DB_PROOF_V2_PINS`, `PRODUCTION_ORAM_DB_PROOF_V2_PINS`, `verification/locks/generated-proofs.json`, and the duplicate pins in `crates/sdk/client/tests/integration_test.rs` consistent (rotation runbook §3 / Flow H.0) |
| Session grants (`crates/trust/session-grant`, the server gate, client presentation) | `cargo test --locked --offline -p pir-session-grant`; `cargo test --locked --offline -p runtime --bin unified_server -- session_grant`; `cargo test --locked --offline -p pir-sdk-client session_grant`; `cd web && npx vitest run src/__tests__/session-grant.test.ts` | `rust-ci.yml`, `pir-sdk-integration.yml`, `web-build.yml` | The cashier is a separate repository; enabling grants in production is an operator decision ([Production operations](PRODUCTION_OPERATIONS.md)) |
| `verification/locks`, contracts, verifier scripts | `cargo test --locked --offline -p pir-sdk --features serde --test wire_shape_contract`; `python3 -m unittest verification/scripts/test_verify_formal_lock.py`; `cd web && npm test` (lock↔pin tests) | `formal-proof.yml` (every PR, unfiltered); `generated-proof-lock.yml` (lock paths) | Protocol framing / round-shape / padding changes must update the contract and proof lock (`REPOSITORY_BOUNDARIES.md`) |
| `tools/db-builder`, `scripts/build_*.sh` | `cargo build -p build`; there is no test suite | **None** | Production databases come from the locked attested-builder, not these scripts; see `DATABASE_ARTIFACT_RETENTION.md` before any rebuild |
| UKI scripts, VPSBG operator scripts, `.github/workflows/**` | `node scripts/github-workflow-supply-chain-gate.mjs`; `node --test scripts/tier3-uki-policy-contract.test.mjs`; `node scripts/vpsbg-tier3-generation.test.mjs` (runs the measured run script against fixtures, ~30 s); `bash scripts/vpsbg-production-status.test.sh`; `bash scripts/ops-operator-scripts.test.sh` | `workflow-supply-chain.yml` | UKI builds and live VPSBG mutations are operator actions, not CI |
| Documentation only | none | none (all workflows are path-filtered) | CI does not check documentation truth; identity values (hashes, image IDs) must be pointers to `web/src/attest-pin.ts` / `docs/data-retention/`, not copies |

Merges are manual: there is no aggregate **required** check on `main`. The
"CI summary" workflow runs on every PR and waits for all sibling workflow runs
on the head SHA, so its single green/red status is the one signal to inspect
before merging. Agents must not poll that workflow (`gh run watch`, `sleep`
loops, repeated `gh run list`). Open the PR, paste the URL, and stop.

Local agents: one foreground `cargo check -p <crate>`, then at most one
`--exact` test. Missing progress before the hard stop in
[Production operations](PRODUCTION_OPERATIONS.md) means stop and report.
