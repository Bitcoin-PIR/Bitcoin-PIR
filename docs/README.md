# Documentation index

Start production work at [Production operations](PRODUCTION_OPERATIONS.md).
Live production state is queried, never inferred from documents:
`scripts/production-status.sh` for pir1, the pir2 MacBook node and the
Direct ORAM TEE host (VPSBG server 26939), and each operation script's
status subcommand for the rest.

## Runbooks

| Work | Entry |
| --- | --- |
| Diagnose, CI/PR, Pages, pir1, pir2 MacBook node, VPSBG runtime UKI, data-disk, DB/proofs | [Production operations](PRODUCTION_OPERATIONS.md) (flows A–I) |
| A release across pir1, the MacBook node, the ORAM host, pins, Pages and the playground | [Release checklist](RELEASE.md) (`scripts/release-preflight.sh`) |
| Database and root rotation (DPF / Harmony / Onion v2 / ORAM proofs) | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| Producer (attested-builder) UKI | [Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md); producer *scope* is that repo's README |
| Database source and artifact retention | [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md) |
| A new database generation from a fresh Core snapshot | [Database rebuild](DATABASE_REBUILD.md) |
| Directory relay on pir1 (install, publish entries, upgrade) | [Directory relay](runbooks/directory-relay.md) |
| Run a node of your own (other operators) | [Operator guide](OPERATOR_GUIDE.md) |
| Development and PR checks | [Testing](TESTING.md) |

## Technical references

- Wire protocol: [Protocol v1](PROTOCOL.md) is the opcode registry: framing,
  the encrypted channel, each message's wire shape, errors, and the retired
  opcodes that stay reserved.
- Paid queries are gas-priced credits verified at the issuer:
  [Credits and gas](CREDITS.md) is the design, the rate card, the
  measurements behind it, the access policy each server publishes, and the
  issuer contract; `pir-credit` holds the model. The v1 session grants
  (opcode `0x0b`) are retired. The issuer (payment side) is
  [Bitcoin-PIR/issuer](https://github.com/Bitcoin-PIR/issuer); running it
  and the mint on pir1 is [Issuer and mint](runbooks/issuer-and-mint.md).
- Provider discovery over Nostr: [Directory protocol](DIRECTORY_PROTOCOL.md)
  is the contract for the service directory (NIP-01/NIP-78 entries and
  checkpoints, operator assertions, client rollback state, relay profile);
  the codec is `crates/directory/nostr`, the operator commands are
  `bpir-admin directory-artifact`, the relay is `apps/directory-relay`
  ([Directory relay](runbooks/directory-relay.md)), the browser client is
  `web/src/nostr-directory.ts` and the operator readback is
  `scripts/directory-readback.mjs`.
- Verification: [Verification overview](VERIFICATION_OVERVIEW.md); the
  EasyCrypt proof lives in
  [Bitcoin-PIR/protocol-proofs](https://github.com/Bitcoin-PIR/protocol-proofs).
- Related repositories: [Repository boundaries](REPOSITORY_BOUNDARIES.md).

## Historical records

- Earlier release and incident evidence: [History](history/README.md).
- Point-in-time retained release records: [`data-retention/`](data-retention/).
