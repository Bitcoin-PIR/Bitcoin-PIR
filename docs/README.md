# Documentation index

Start production work at [Production operations](PRODUCTION_OPERATIONS.md).
Live production state is queried, never inferred from documents:
`scripts/production-status.sh` for pir1, the pir2 MacBook node and the
Direct ORAM TEE host (VPSBG server 26939), and each operation script's
status subcommand for the rest.

## Runbooks

| Work | Entry |
| --- | --- |
| Diagnose, CI/PR, Pages, pir1, pir2 MacBook node, VPSBG runtime UKI, data-disk, sealed release, DB/proofs | [Production operations](PRODUCTION_OPERATIONS.md) (flows A–I) |
| Database and root rotation (DPF / Harmony / Onion v2 / ORAM proofs) | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| Producer (attested-builder) UKI | [Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md); producer *scope* is that repo's README |
| Database source and artifact retention | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |
| Direct ORAM diagnosis | [Direct ORAM debug](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md) |
| Development and PR checks | [Testing](TESTING.md) |

## Technical references

- Paid queries are gas-priced credits verified at the issuer:
  [Credits and gas](CREDITS.md) is the design, the rate card, the
  measurements behind it, the access policy each server publishes, and the
  issuer contract; `pir-credit` holds the model. The v1 session grants
  (opcode `0x0b`) are retired. The issuer (payment side) is
  [Bitcoin-PIR/issuer](https://github.com/Bitcoin-PIR/issuer); running it
  and the mint on pir1 is [Issuer and mint](runbooks/issuer-and-mint.md).
  The retired Payment V1 material and the 2026-09 ARC/Cashu verifiers live
  only in git history.
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md); the
  EasyCrypt proof lives in
  [Bitcoin-PIR/protocol-proofs](https://github.com/Bitcoin-PIR/protocol-proofs).
- Related repositories: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
