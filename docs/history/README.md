# Historical records

Files in this directory are kept only because current code, build scripts, or
deploy configs still cite them for rationale. They are frozen evidence — not
operating instructions — and any identity values inside them (hashes, image
IDs, measurements) are stale by construction. Current state is queried, never
inferred: see [Production operations](../PRODUCTION_OPERATIONS.md).

| Record | Why it is kept |
| --- | --- |
| [CODE_REVIEW_2026-06.md](CODE_REVIEW_2026-06.md) | Security findings C1–C4 cited by client robustness code |
| [BUILD_REPRODUCIBILITY.md](BUILD_REPRODUCIBILITY.md) | Chain-anchored PRG seed rationale cited by `pir-core` and `db-builder` |
| [PHASE3_SLICE3_REPRO_PLAN.md](PHASE3_SLICE3_REPRO_PLAN.md) | Reproducible-build rationale cited by build scripts, `Cargo.toml`, `flake.nix` |
| [PHASE3_ROADMAP.md](PHASE3_ROADMAP.md) | Attestation design cited by `web/src/attest-pin.ts` and `web/reproduce.html` |
| [DB_BUILD_ATTESTATION_PLAN.md](DB_BUILD_ATTESTATION_PLAN.md) | Database attestation design cited by `web/reproduce.html` |
| [OPERATOR_IDENTITY.md](OPERATOR_IDENTITY.md) | REQ_ANNOUNCE protocol description cited by `crates/trust/identity` |
| [PIR1_REGISTER_KEYS_TRUNCATION.md](PIR1_REGISTER_KEYS_TRUNCATION.md) | Transport-chunking RCA cited by server, client, and web code |
| [PIR1_STARTUP_HINT_POOL_THRASHING.md](PIR1_STARTUP_HINT_POOL_THRASHING.md) | Startup RCA cited by the systemd units |
| [UPSTREAM_REQUEST_2402b16_REGRESSION.md](UPSTREAM_REQUEST_2402b16_REGRESSION.md) | Upstream regression context cited by the systemd units |
| [GIT_CLEANUP_2026-08-13.md](GIT_CLEANUP_2026-08-13.md) | Records which branches/worktrees were removed and which were preserved |
| [EPOCH5_ENTITLEMENT_ROTATION.md](EPOCH5_ENTITLEMENT_ROTATION.md) | Entitlement-rotation RCA cited by `docs/runbooks/pir2-sealed-release.md` |

Everything else — completed plans, dated preflights, rollout records, status
trackers, process audits, probe dumps, and research surveys — was removed from
the working tree in the 2026-08-21 process cleanup and lives in git history
(`git log --diff-filter=D -- docs/` shows the deletions).
