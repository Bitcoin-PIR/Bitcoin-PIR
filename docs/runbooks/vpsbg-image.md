# Manage a VPSBG image

This is Flow E in [Production operations](../PRODUCTION_OPERATIONS.md)
(steps 1–2, 4–7). Use
[`scripts/vpsbg-measured-boot.sh`](../../scripts/vpsbg-measured-boot.sh)
for image inspection, listing, upload, and switch. A switch applies the image
with an immediate reboot; rolling back is a switch to the previous image ID.
The default API token path is `.secrets/vpsbg-api-token`. There is no delete
action.

After a switch, [`scripts/oram-host-check.sh`](../../scripts/oram-host-check.sh)
waits for `boot_mode=measured`, then attests the host against the pins in
[`web/src/attest-pin.ts`](../../web/src/attest-pin.ts) (edit them first for
a new image), tests the encrypted channel, and sends one padded ORAM query to
each database.

## Run

```sh
scripts/vpsbg-measured-boot.sh status --server-id SERVER_ID
scripts/vpsbg-measured-boot.sh images
scripts/vpsbg-measured-boot.sh upload --uki /absolute/path/bpir-tier3.efi
scripts/vpsbg-measured-boot.sh switch --server-id SERVER_ID --image-id IMAGE_ID
scripts/oram-host-check.sh
```

`upload` prints the new image ID; `switch` takes the ID that `status`,
`images`, or `upload` printed.
