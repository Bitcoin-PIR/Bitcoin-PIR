# Run the pir2 sealed release

This is Flow G in [Production operations](../PRODUCTION_OPERATIONS.md).
Placing `startup.env` is Flow F, not a provisioner UKI.

Use [`scripts/pir2-sealed-ceremony.sh`](../../scripts/pir2-sealed-ceremony.sh)
to advance the prepared pir2 release through Observe, sealed release, Enroll,
Probe, and Ready.

## Inputs

- An unused output path for each phase's `startup.env`.
- The phase ordinal and a fresh verifier nonce.
- The exact measured UKI/OVMF values and Observe receipt required by the
  sealed-release command.

## Run

```sh
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64 --dry-run
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64
scripts/pir2-sealed-ceremony.sh release [existing release arguments]
```

After `PASS sealed_phase_config=observe`, place that exact file with
[`scripts/vpsbg-data-disk.sh`](../../scripts/vpsbg-data-disk.sh):

```sh
scripts/vpsbg-data-disk.sh open --server-id 25285 --image-id CURRENT --apply
scripts/vpsbg-data-disk.sh put --local /absolute/observe.startup.env \
  --remote /home/pir/data/pir2-sealed/startup.env --apply
scripts/vpsbg-data-disk.sh close --server-id 25285 --image-id CURRENT --apply
```

Do not build a provisioner UKI. Run the release after the Observe receipt is
available. Generate new startup files for `enroll`, `probe`, and `ready`, and
boot each in that order. A completed release prints `PASS sealed_release`;
every phase file prints `PASS sealed_phase_config=<phase>` and `NEXT_STEP`.

## Receipt acceptance

A phase status marker proves only that the guest persisted a receipt. The
recovery HTTP root is served through Cloudflare with
`Cache-Control: max-age=14400`, and a phase's receipt URL can return a cached
receipt from an earlier phase (observed in the field: an Enroll fetch returned
the previous Observe receipt with `CF-Cache-Status: HIT`). Before trusting any
downloaded receipt, require its hash to equal the receipt hash declared by the
phase's status response; if the two disagree, treat the download as rejecting
evidence, rename it out of the way, and retrieve the persisted receipt through
the Flow F data-disk window instead of retrying the public URL.

Before a later authority signs or activates anything derived from an Enroll,
Probe, or Ready receipt, an offline verifier must accept all of the following
together:

- the AMD ARK pin, ARK-to-ASK-to-VCEK chain, and SNP report signature;
- the receipt digest duplicated in the signed SNP `REPORT_DATA`;
- the exact signed release digest, measurement, guest policy, and TCB floor;
- the expected phase, ordinal, fresh verifier nonce, and current boot ID; and
- for non-Observe phases, a valid Ed25519 service identity public key, its
  fingerprint, and the identity generation.

The repository currently has a dedicated verifier for the fixed Observe
receipt as part of `bpir-admin pir2-sealed-release`, but no generic offline
decoder/verifier command for Enroll, Probe, or Ready receipts. Do not treat a
successful hex/field parser, the status JSON, or a file hash as a substitute.
Until a reviewed repository command exists, stop after downloading the receipt
and use a reviewed offline verifier that performs the checks above before
constructing identity or accounting artifacts.

Ready writes two receipts for the same boot: `ready-preflight-BOOT.bin` before
ORAM access and `ready-runtime-BOOT.bin` when the final server opens the sealed
keys. Unlike Observe, Enroll, and Probe, a successful Ready boot does not expose
either receipt through the finite recovery HTTP root. Retrieve them only in a
separately authorized Flow F maintenance window, using the exact boot ID from
the persisted ORAM published marker; a later boot must use a new ordinal and
fresh nonce.

After the ORAM progress API releases port 8091, the final server still loads the
large database mappings before it listens. During that interval the public
origin can return HTTP 502 even though the control plane is healthy. Once the
server is listening it is WebSocket-only, so an ordinary HTTPS request to
`/status.json` is not a Ready health check. Use the repository attestation and
encrypted-channel checks instead.

Free queries are open, so the ORAM smoke query in
`scripts/verify_oram_tier3_deploy.sh` (run by `pir2-post-switch-check.sh`)
is a valid Ready canary together with attestation, channel verification, and
strict Ready receipt acceptance. The measured image carries no admission
policy or payment artifact; paid access is handled outside it.

The incident that motivated the receipt-transport and acceptance rules in this
section is recorded in
[History: epoch-5 entitlement rotation](../history/EPOCH5_ENTITLEMENT_ROTATION.md).
