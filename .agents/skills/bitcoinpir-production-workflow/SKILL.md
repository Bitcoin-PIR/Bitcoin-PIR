---
name: bitcoinpir-production-workflow
description: Run BitcoinPIR's production workflow through its repository commands.
---

# BitcoinPIR production workflow

Do not run this skill as one end-to-end payment-to-UKI chain. Open
[`docs/PRODUCTION_OPERATIONS.md`](../../../docs/PRODUCTION_OPERATIONS.md),
pick **one** flow A–I, and run only that flow's numbered steps.

Wrapper commands print `PASS` and `NEXT_STEP`. Begin any mutation that
supports `--dry-run` with that option. `--apply` is per step: never
combine `upload` with `switch`, or `put` with `close`.

## Classify, then estimate

| Ask | Flow |
| --- | --- |
| Is pir up / what image is attached | A |
| PR, tests, CI | B |
| Publish www.bitcoinpir.org | C |
| Restart or rebuild Hetzner | D |
| New **runtime** pir2 UKI / switch / rollback | E |
| Edit `/home/pir/data/` or place `startup.env` | F |
| Sealed Observe / Enroll / Probe / Ready | G |
| New DB / DPF / Harmony / Onion / ORAM proofs / pins | H (producer scope: attested-builder README; UKI: ATTESTED_BUILDER_TIER3_UKI.md) |
| Payment artifacts or source-readiness | I |

Before a long step, state the duration, hard stop, and progress signal
from the workload table on that page.

## Commands the flows already own

Status, images, UKI, measured-boot, data-disk, post-switch check, sealed
phase/release, payment wrappers, and Pages dispatch are listed in
Production operations. Copy commands from the matching flow; do not
invent issuer deploy, keygen, funds, or image delete.

Human-only work stays human-only even if this skill is invoked.
