# Historical Planning Notes

This directory is now the consolidated archive for old `PLAN_*.md` files.
The detailed plan drafts were removed after their durable information was
folded into source comments and current docs.

New durable design docs should live under `docs/`. Private scratch notes should
use `LOCAL_PLAN_*.md`, which is ignored by git.

## Current Sources Of Truth

| Topic | Current document |
|---|---|
| Wire-shape privacy invariants and verification status | [`../VERIFICATION_OVERVIEW.md`](../VERIFICATION_OVERVIEW.md) and [`../../CLAUDE.md`](../../CLAUDE.md) |
| Rate limiting | [`../RATELIMIT_INTEGRATION.md`](../RATELIMIT_INTEGRATION.md) and [`../RATELIMIT_DEMO.md`](../RATELIMIT_DEMO.md) |
| Tier 3 / UKI operations | [`../PHASE3_ROADMAP.md`](../PHASE3_ROADMAP.md) and [`../PHASE3_SLICE3_RECOVERY.md`](../PHASE3_SLICE3_RECOVERY.md) |
| Database build attestation | [`../DB_BUILD_ATTESTATION_PLAN.md`](../DB_BUILD_ATTESTATION_PLAN.md) |

## Retired Plan Index

| Retired file | Resolution |
|---|---|
| `PLAN_LEAKAGE_VERIFICATION.md` | Closed on 2026-04-29. Consolidated into `VERIFICATION_OVERVIEW.md`; EasyCrypt spec lives in `proofs/easycrypt/`. |
| `PLAN_MULTI_QUERY_SIMULATOR_TEST.md` | Shipped. Multi-query simulator-property tests are covered by the verification overview and `pir-sdk-client/tests/leakage_integration_test.rs`. |
| `PLAN_CHUNK_MAX_CLOSURE.md` | Historical only. The M=16 chunk-Merkle pad later shipped and was deliberately removed; current trade-off is documented in `VERIFICATION_OVERVIEW.md` and `CLAUDE.md`. |
| `PLAN_scripthash_padding.md` | Obsolete because the M=16 chunk-Merkle pad it optimized was removed. |
| `PLAN_MERKLE_CODING.md` | Shipped historical coding plan. The lasting decision is the Phase 4 / WS-A removal of M=16 padding, documented in `VERIFICATION_OVERVIEW.md` and code comments. |
| `PLAN_MERKLE_COLOCATION.md` | Superseded by the per-group Merkle redesign work and the later M=16 removal. |
| `PLAN_HARMONY_COUNT_LEAK_FIX.md` | Implemented. The invariant is now documented in `CLAUDE.md` and enforced in `harmonypir-wasm/src/lib.rs`. |
| `PLAN_ANONYMOUS_RATE_LIMIT.md` | Superseded by the production status doc `RATELIMIT_INTEGRATION.md`. |
| `PLAN_ONION_SHARDING.md` | Historical handoff for the OnionPIR sharding work; implementation details are now in code/tests. Remaining deployment work should get a fresh `docs/` status doc if resumed. |
| `PLAN_PIR2_UKI_V17.md` | Stale one-off deployment draft. Current Tier 3 values and operating flow are in `PHASE3_ROADMAP.md` / `CLAUDE.md`. |
