# Documentation index

Start production work at [Production operations](PRODUCTION_OPERATIONS.md).
Live production state is queried, never inferred from documents:
`scripts/production-status.sh` for pir1+pir2,
`scripts/vpsbg-production-status.sh` for pir2 only, and each operation
script's status subcommand for the rest.

## Runbooks

| Work | Entry |
| --- | --- |
| Diagnose, CI/PR, Pages, pir1, pir2 runtime UKI, data-disk, sealed release, DB/proofs, payment source-ready | [Production operations](PRODUCTION_OPERATIONS.md) (flows A–I) |
| Database and root rotation (DPF / Harmony / Onion v2 / ORAM proofs) | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| Producer (attested-builder) UKI | [Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md); producer *scope* is that repo's README |
| Database source and artifact retention | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |
| Direct ORAM diagnosis | [Direct ORAM debug](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md) |
| Development and PR checks | [Testing](TESTING.md) |

## Technical references

- Paid queries present a designated issuer's cashu/ARC credential on
  opcodes `0x08`/`0x09`. The issuer app is [`apps/payment-issuer`](../apps/payment-issuer).
  Retired Payment V1 design notes live in the [payment archive](archive/payment/README.md).
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md) and the
  repository's [`verification/locks/`](../verification/locks/).
- Repository ownership: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Payment plans, dated status, drills, reviews, and migrations:
  [Payment archive](archive/payment/README.md).
- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
