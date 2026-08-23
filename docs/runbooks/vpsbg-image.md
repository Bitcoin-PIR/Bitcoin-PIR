# Manage a VPSBG image

This is Flow E in [Production operations](../PRODUCTION_OPERATIONS.md)
(steps 1–2, 4–7). Use
[`scripts/vpsbg-measured-boot.sh`](../../scripts/vpsbg-measured-boot.sh)
for image inspection, listing, upload, switch, and rollback. Switching or
rolling back an image applies it with an immediate reboot. The default API
token path is `.secrets/vpsbg-api-token`. There is no delete action.

After an authorized switch, use
[`scripts/pir2-post-switch-check.sh`](../../scripts/pir2-post-switch-check.sh)
to wait for `boot_mode=measured` and verify the live host against
[`web/src/attest-pin.ts`](../../web/src/attest-pin.ts). A mismatch is a
hard stop; the check does not edit the pin file.

## Inputs

- VPSBG API configuration accepted by the command.
- For upload, the completed UKI path.
- For switch or rollback, the image ID printed by `status`, `images`, or `upload`.

## Run

```sh
scripts/vpsbg-measured-boot.sh --help
scripts/vpsbg-measured-boot.sh status --server-id SERVER_ID
scripts/vpsbg-measured-boot.sh images
scripts/vpsbg-measured-boot.sh upload --uki /absolute/path/bpir-tier3.efi --dry-run
scripts/vpsbg-measured-boot.sh switch --server-id SERVER_ID --image-id IMAGE_ID --dry-run
scripts/vpsbg-measured-boot.sh rollback --server-id SERVER_ID --image-id IMAGE_ID --dry-run
scripts/pir2-post-switch-check.sh --dry-run
```

Mutation commands default to a dry-run preview. After confirming this run's
authorization, repeat the required mutation with `--apply`. Each successful
operation prints `PASS action=status|images|upload|switch|rollback` or
`PASS action=post_switch_check` and `NEXT_STEP`.
