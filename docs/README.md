# Documentation index

Start production work at [Production operations](PRODUCTION_OPERATIONS.md).
Live production state is queried, never inferred from documents:
`scripts/production-status.sh` for pir1+pir2,
`scripts/vpsbg-production-status.sh` for pir2 only, and each operation
script's status subcommand for the rest.

## Runbooks

| Work | Entry |
| --- | --- |
| Diagnose, CI/PR, Pages, pir1, pir2 runtime UKI, data-disk, sealed release, DB/proofs | [Production operations](PRODUCTION_OPERATIONS.md) (flows A–H) |
| Database and root rotation (DPF / Harmony / Onion v2 / ORAM proofs) | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| Producer (attested-builder) UKI | [Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md); producer *scope* is that repo's README |
| Database source and artifact retention | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |
| Direct ORAM diagnosis | [Direct ORAM debug](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md) |
| Development and PR checks | [Testing](TESTING.md) |

## Technical references

- Paid queries present a cashier-signed session grant on opcode `0x0b`;
  the design, metering rule, and server flags are in
  [Session grants](SESSION_GRANTS.md); the cashier's HTTP contract is
  [Cashier API](CASHIER_API.md). The cashier (payment side) is a separate
  repository. The retired Payment V1 material and the 2026-09
  ARC/Cashu verifiers live only in git history.
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md) and the
  repository's [`verification/locks/`](../verification/locks/).
- Repository ownership: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
