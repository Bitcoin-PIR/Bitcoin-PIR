# Documentation index

Start production work at [Production operations](PRODUCTION_OPERATIONS.md).
Live production state is queried, never inferred from documents:
`scripts/vpsbg-production-status.sh` for pir2, and each operation script's
status subcommand for the rest.

## Runbooks

| Work | Entry |
| --- | --- |
| UKI, VPSBG images, Payment artifacts, issuer state, sealed release, private start, and production source readiness | [Production operations](PRODUCTION_OPERATIONS.md) |
| Database and root rotation | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| Database source and artifact retention | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |
| Direct ORAM diagnosis | [Direct ORAM debug](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md) |
| Development and PR checks | [Testing](TESTING.md) |

## Technical references

- Payment architecture: [Architecture](payment/ARCHITECTURE.md),
  [Protocol](payment/PROTOCOL.md),
  [Directory protocol](payment/DIRECTORY_PROTOCOL.md),
  [Persistence](payment/PERSISTENCE.md), and [Security](payment/SECURITY.md).
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md) and the
  repository's [`verification/locks/`](../verification/locks/).
- Repository ownership: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Payment plans, dated status, drills, reviews, and migrations:
  [Payment archive](archive/payment/README.md).
- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
