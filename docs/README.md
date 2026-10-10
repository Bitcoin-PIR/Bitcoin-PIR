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
| Directory relay on pir1 (install, publish entries, upgrade) | [Directory relay](runbooks/directory-relay.md) |
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
- Provider discovery over Nostr: [Directory protocol](DIRECTORY_PROTOCOL.md)
  is the contract for the service directory (NIP-01/NIP-78 entries and
  checkpoints, operator assertions, client rollback state, relay profile);
  the codec is `crates/directory/nostr`, the operator commands are
  `bpir-admin directory-artifact`, the relay is `apps/directory-relay`
  ([Directory relay](runbooks/directory-relay.md)).
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md) and the
  repository's [`verification/locks/`](../verification/locks/).
- Repository ownership: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
