# Manage a VPSBG image

Use [`scripts/vpsbg-measured-boot.sh`](../../scripts/vpsbg-measured-boot.sh)
for image inspection, upload, switch, and rollback. Switching or rolling back
an image applies it with an immediate reboot.

## Inputs

- VPSBG API configuration accepted by the command.
- For upload, the completed UKI path.
- For switch or rollback, the image ID printed by `status` or `upload`.

## Run

```sh
scripts/vpsbg-measured-boot.sh --help
scripts/vpsbg-measured-boot.sh status --server-id SERVER_ID
scripts/vpsbg-measured-boot.sh upload --uki /absolute/path/bpir-tier3.efi --dry-run
scripts/vpsbg-measured-boot.sh switch --server-id SERVER_ID --image-id IMAGE_ID --dry-run
scripts/vpsbg-measured-boot.sh rollback --server-id SERVER_ID --image-id IMAGE_ID --dry-run
```

Mutation commands default to a dry-run preview. After confirming this run's
authorization, repeat the required mutation with `--apply`. Each successful
operation prints `PASS action=status|upload|switch|rollback` and `NEXT_STEP`.
