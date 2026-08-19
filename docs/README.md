# Documentation and operations index

Start here. This index answers two questions: *which document is the current
entry point for each operation*, and *which class a given document belongs
to*. When two documents disagree, the one listed under "Current norms and
runbooks" wins; dated records never override it.

## Live state is queried, never inferred

The repository contains no document that describes the current production
state. Point-in-time records (retention inventory, release `.env` files,
preflights) are evidence of what *was* true when written.

```bash
scripts/vpsbg-production-status.sh   # read-only control-plane + status.json
```

Client-side release identity (binary hashes, SEV measurement, database proof
pins) has exactly one authority: [`web/src/attest-pin.ts`](../web/src/attest-pin.ts).
Do not copy those values into prose documents; link them.

## The five routine operations

| Operation | Entry point | Notes |
|---|---|---|
| Ordinary development | [`TESTING.md`](TESTING.md) change-class matrix → PR → manual merge once the advisory "CI summary" check is green | The summary check aggregates all triggered workflows but is deliberately not required; see `TESTING.md` |
| Database / root rotation | [`DATABASE_ROOT_ROTATION_RUNBOOK.md`](DATABASE_ROOT_ROTATION_RUNBOOK.md), with [`DATABASE_ARTIFACT_RETENTION.md`](DATABASE_ARTIFACT_RETENTION.md) read first | The legacy refresh flow in `scripts/README.md` is **not** the production path |
| Web release | Manual `deploy-web.yml` dispatch from `main` with the production confirmation ([`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md)) | The workflow deployment record is the release evidence |
| Tier 3 UKI / VPSBG release | [VPSBG measured-boot skill](../.agents/skills/vpsbg-measured-boot/SKILL.md) + `scripts/build_uki_tier3.sh` (policy digest is locked in the script) | Upload/switch/reboot require explicit authorization |
| Rollback | Same unit as the forward release: Web = prior Pages artifact/commit; database = prior complete generation + catalog + pins; UKI = the retained previous VPSBG image | [`DATABASE_ROOT_ROTATION_RUNBOOK.md`](DATABASE_ROOT_ROTATION_RUNBOOK.md) §7 for data; the measured-boot skill for images |

Production diagnosis always starts at
[`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md) — status first, never
a browser or log search.

## Current norms and runbooks

- [`../AGENTS.md`](../AGENTS.md) — agent working rules (delivery priority,
  bounded investigation, testing defaults, git hygiene).
- [`TESTING.md`](TESTING.md) — change-class → required checks matrix, plus
  the Payment V1 profiles.
- [`PRODUCTION_OPERATIONS.md`](PRODUCTION_OPERATIONS.md) — operator/agent
  entry point for status, release routing, and canary policy.
- [`DATABASE_ROOT_ROTATION_RUNBOOK.md`](DATABASE_ROOT_ROTATION_RUNBOOK.md)
  — the only supported database/proof/pin rotation procedure.
- [`DATABASE_ARTIFACT_RETENTION.md`](DATABASE_ARTIFACT_RETENTION.md) — what
  may never be deleted and where retained artifacts live; read before any
  rebuild or cleanup.
- [`ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md`](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md) —
  bounded Direct ORAM debug workflow (time limits are part of acceptance).
- [`ATTESTED_BUILDER_TIER3_UKI.md`](ATTESTED_BUILDER_TIER3_UKI.md) — the
  temporary builder UKI runbook.
- [`REPOSITORY_BOUNDARIES.md`](REPOSITORY_BOUNDARIES.md) — normative for
  repository moves and split gates.
- [`payment/IMPLEMENTATION_STATUS.md`](payment/IMPLEMENTATION_STATUS.md) —
  exact Payment V1 method/test/activation status. Source-ready ≠ deployed.
- [`payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md`](payment/MAINNET_SHARED_BAT_PRODUCTION_PLAN.md)
  — revised issuer-wide BAT target: cross-provider acceptance, issuer-global
  first-spend, payment-storeless providers, phased source work and separate
  live-operation approvals.
- [`payment/OPERATOR_RUNBOOK.md`](payment/OPERATOR_RUNBOOK.md) — Payment
  deployment phases and approval scopes.

## Verification and trust inputs

- [`../verification/locks/`](../verification/locks/) — exact external proof
  pins (formal proofs, generated proof bundles, rootbundle, whitepaper).
  The locks are the trust inputs; default-branch links are navigational.
- [`VERIFICATION_OVERVIEW.md`](VERIFICATION_OVERVIEW.md) — consolidated
  verification final state.
- [`../web/src/attest-pin.ts`](../web/src/attest-pin.ts) — client pin
  authority (operator key, server binaries/measurement, database proofs).

## Historical evidence, plans, and status snapshots

- [`history/README.md`](history/README.md) — indexed historical preflights,
  incidents, and completed plans. Evidence only.
- [`data-retention/`](data-retention/) — point-in-time inventories and
  release identity records (e.g. `production-release-image-265.env`).
  Every production release gets one record: generate it with
  `scripts/generate-release-record.sh` (schema:
  [`data-retention/release-record.env.template`](data-retention/release-record.env.template)).
- [`PROCESS_AUDIT_2026-08.md`](PROCESS_AUDIT_2026-08.md) — the audit that
  produced this index; includes the known documentation-drift list.
- Dated plans and completed rollout records still in this directory
  (`PHASE3_*`, `ORAM_LIVE_IMAGE_BINDING_PLAN.md`, `STRICT_VERIFICATION_PROGRESS.md`,
  `PROJECT_CLOSEOUT_TODO.md`, `PR_CLEANUP_TRACKER.md`, `CODE_REVIEW_2026-06.md`,
  `release_checklist.md`, …) are records of past work. They are not
  operating instructions, and identity values inside them (image IDs,
  binary hashes, measurements) are stale by construction.

## Legacy documents

- [`../doc/`](../doc/) (singular) predates this directory.
  `doc/DEPLOYMENT.md` is a historical self-hosting sketch, not the pir1/pir2
  release path; `doc/WEB.md` partially describes legacy opcodes (tracked as
  P2-5 in `PR_CLEANUP_TRACKER.md`).
- The database build/refresh sections of
  [`../scripts/README.md`](../scripts/README.md) describe the pre-attested
  local pipeline. Production rotations use the runbook above.
