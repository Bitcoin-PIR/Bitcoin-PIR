---
name: vpsbg-measured-boot
description: Inspect, upload, switch, or roll back a BitcoinPIR VPSBG measured-boot UKI using the repository command.
---

# VPSBG measured boot

This is Flow E in
[`docs/PRODUCTION_OPERATIONS.md`](../../../docs/PRODUCTION_OPERATIONS.md); the
steps are in [`docs/runbooks/vpsbg-image.md`](../../../docs/runbooks/vpsbg-image.md).
Use `scripts/vpsbg-measured-boot.sh` for status, images, upload, switch and
rollback. Data-disk edits are Flow F (`scripts/vpsbg-data-disk.sh`).
