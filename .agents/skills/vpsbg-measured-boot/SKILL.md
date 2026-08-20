---
name: vpsbg-measured-boot
description: Inspect, upload, switch, or roll back a BitcoinPIR VPSBG measured-boot UKI using the repository command.
compatibility: Requires scripts/vpsbg-measured-boot.sh, jq, curl, a VPSBG API token file, and a built UKI for upload.
---

# VPSBG measured boot

Run all VPSBG operations through `scripts/vpsbg-measured-boot.sh`. It is the
only API entry point.

## Inputs

- `--server-id ID` for status, switch, or rollback.
- `VPSBG_API_TOKEN_FILE` for status, or `--token-file PATH` for a mutation,
  when the default token location is not appropriate.
- `--uki PATH` for `upload`.
- `--image-id ID` for `switch` or `rollback`.

## Commands

Start with the read-only view:

```bash
scripts/vpsbg-measured-boot.sh status --server-id ID
```

Success prints `PASS action=status` and status fields. Record a concrete image
ID when one is attached; `image_id=unavailable` is a valid observation, not an
image selection.

For an authorized mutation, confirm that this exact upload, switch, or rollback
is authorized, then run one command:

```bash
scripts/vpsbg-measured-boot.sh upload --uki /absolute/path/release.efi --apply
scripts/vpsbg-measured-boot.sh switch --server-id ID --image-id ID --apply
scripts/vpsbg-measured-boot.sh rollback --server-id ID --image-id PREVIOUS_ID --apply
```

`upload` prints `PASS action=upload`; `switch` and `rollback` print
`PASS action=... server_id=... image_id=...`. Re-run `status` and proceed to
the next release phase only when it prints `PASS action=status` with the
intended active image.
