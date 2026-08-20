# Testing entry points

Pick your checks by *change class*, not by a single default command. The
matrix below maps what you touched to the minimum local checks and to the CI
that will actually run on your PR (most workflows are path-filtered; two run
on every PR regardless).

The Payment V1 profiles further down remain the default entry **for agents
and for Payment work** (`AGENTS.md` points here for that purpose). `--quick`
runs one focused service-admission test; it is not a whole-repository test
and passing it says nothing about non-Payment changes.

## Change-class → required checks

| You changed | Minimum local checks | CI triggered on the PR | Known gaps |
|---|---|---|---|
| `crates/protocol/core` (cuckoo, Merkle, anchors) | `cargo test --locked --offline -p pir-core --test cross_build_determinism`; `cargo test --locked --offline -p pir-core`; `cargo clippy --locked --offline -p pir-core --tests -- -D warnings` | `build-determinism.yml` | A determinism break means operators can no longer reproduce the database byte-for-byte — treat failures as release blockers |
| `crates/sdk/{core,client}` | `cargo test -p pir-sdk-client` (add `--features onion` if you touched the Onion path) | `pir-sdk-integration.yml` (deterministic jobs; live tests belong to the scheduled canary) | The OnionPIR job currently also runs live `--ignored` tests on PRs (workflow line ~235, missing an event filter) — a red there may be production availability, not your change |
| `crates/sdk/wasm` or the WASM↔TS boundary | `wasm-pack build crates/sdk/wasm --target web --out-dir pkg -- --locked --offline`, then `cd web && npm run build && npm test` | `web-build.yml` | — |
| `crates/sdk/server` | `cargo test --locked --offline -p pir-sdk-server`; `cargo build -p pir-sdk-server` | **None** — no workflow watches this path | Crate has ~0 lib tests; CI stays green if you break it |
| `apps/server` / `crates/protocol/runtime` | `cargo test --locked --offline -p runtime --lib hint_pool`; `cargo test --locked --offline -p runtime --bin unified_server`; for admission/process behavior run `scripts/payment-v1-local-check.sh --pr` or the matching `scripts/payment-v1-ci-lane.sh --lane runtime-*` | `payment-platform.yml` (via `apps/server/**`); `pir-sdk-integration.yml` only if you touched `hint_pool.rs`, `unified_server.rs`, or the crate manifest | A deployed binary/UKI is a separate authorized release, never implied by green CI |
| `web/` (TypeScript, pins, tests) | `cd web && npm run build && npm test && npm run build-web` | `web-build.yml`; `deploy-web.yml` adds Playwright gates only at the manual release dispatch | Pin edits: keep `web/src/attest-pin.ts`, the `verification/locks` files, and the duplicate pins in `crates/sdk/client/tests/integration_test.rs` consistent (rotation runbook §3) |
| Payment V1 (crates/payment, issuer apps, deploy templates) | Profiles below (`--quick` / `--pr`; `--deploy-template-audit` only for template work) | `payment-platform.yml`, sometimes `directory-relay-artifact.yml` | Source-ready and production handoff are recorded in [Current production state](CURRENT_PRODUCTION_STATE.md) |
| `verification/locks`, contracts, verifier scripts | `cargo test --locked --offline -p pir-sdk --features serde --test wire_shape_contract`; `python3 -m unittest verification/scripts/test_verify_formal_lock.py`; `cd web && npm test` (lock↔pin tests) | `formal-proof.yml` (every PR, unfiltered); `generated-proof-lock.yml` (lock paths) | Protocol framing / round-shape / padding changes must update the contract and proof lock (`REPOSITORY_BOUNDARIES.md`) |
| `tools/db-builder`, `scripts/build_*.sh` | `cargo build -p build`; there is no test suite | **None** | Production databases come from the locked attested-builder, not these scripts; see `DATABASE_ARTIFACT_RETENTION.md` before any rebuild |
| UKI scripts, `.github/workflows/**` | `node --test scripts/github-workflow-supply-chain-gate.test.mjs scripts/tier3-uki-policy-contract.test.mjs` | `workflow-supply-chain.yml` (every PR, unfiltered) | UKI builds themselves are operator actions on the build host, not CI |
| Documentation only | none | `formal-proof.yml` + `workflow-supply-chain.yml` still run (unfiltered PR events) | CI does not check documentation truth; identity values (hashes, image IDs) must be pointers to `web/src/attest-pin.ts` / `docs/data-retention/`, not copies |

Merges are manual: there is no aggregate **required** check on `main`
(`PROJECT_CLOSEOUT_TODO.md:124-126`, reaffirmed 2026-08-15). The advisory
"CI summary (advisory)" workflow runs on every PR and waits for all sibling
workflow runs on the head SHA, so its single green/red status is the one
signal to inspect before merging; it does not block a merge. If a red check
ever slips through a manual merge, upgrading it to a required check is the
recorded escalation path.

## Payment V1 profiles

Use the repository-owned payment check as the default local and agent entry
for Payment work:

```sh
scripts/payment-v1-local-check.sh
```

It is the `--quick` profile: one focused locked/offline service-admission test,
no browser, no external network, and no privileged environment. It is the only
profile agents should run by default.

```text
--quick    Default focused service-admission check; no browser or deployment audit.
--pr       Deterministic offline Rust, process, WASM, Web typecheck, Web unit
           tests, and production bundle; it does not first run --quick.
--deploy-template-audit
           Explicit static deployment/template, renderer, runtime-evidence,
           publisher, namespace, Caddy, and relay-gate audit; no deployment.
--browser  Explicit opt-in: --pr plus local headless Chromium payment checks.
--full     Explicit compatibility alias for --browser.
```

`--pr` approximates the Payment-platform CI lanes plus the Web gates. It does
**not** cover `pir-core`, `tools/db-builder`, or UKI contracts — use the
matrix above for those.

Run `--deploy-template-audit` only while changing or preparing a Payment
deployment template. Run `--browser` or `--full` only when browser coverage is explicitly requested.
AI manual browser inspection also requires an explicit user request. Automatic
headless browser checks belong only to an explicit browser profile, nightly, or
release validation.

Historical acceptance records in `docs/archive/payment/LOCAL_ACCEPTANCE.md` and related
rollout documents record prior evidence; they are not current operating entry
points. Production deployment, public-server canaries, and real-fund flows are
separate approved operations.

## Mainnet Lightning V1 source readiness

For changes limited to the versioned Mainnet Lightning V1 source profile, use:

```sh
scripts/payment-v1-mainnet-lightning-v1-check.sh
```

It runs the focused offline Rust profile/CLI contract, deployment source and
rendered-artifact contracts, and the Web independent Direct BOLT11/DPF pair
contract. It does not run the broader Payment V1 suite, a browser, a render,
remote Core/CLN, or any funds flow. Continue with the
[production enablement runbook](runbooks/production-enable.md).
