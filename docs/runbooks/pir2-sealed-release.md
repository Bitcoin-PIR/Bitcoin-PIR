# Run the pir2 sealed release

Use [`scripts/pir2-sealed-ceremony.sh`](../../scripts/pir2-sealed-ceremony.sh)
to advance the prepared pir2 release through Observe, sealed release, Enroll,
Probe, and Ready.

## Inputs

- An unused output path for each phase's `startup.env`.
- The phase ordinal, verifier nonce, current policy digest, BAT V2 class digest,
  public artifact-set SHA-256, and minimum authorization epoch.
- The exact measured UKI/OVMF values and Observe receipt required by the
  sealed-release command.

## Run

```sh
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64 --policy-digest-hex HEX64 \
  --class-digest-hex HEX64 --artifact-set-sha256 HEX64 \
  --minimum-authorization-epoch EPOCH --dry-run
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64 --policy-digest-hex HEX64 \
  --class-digest-hex HEX64 --artifact-set-sha256 HEX64 \
  --minimum-authorization-epoch EPOCH
scripts/pir2-sealed-ceremony.sh release [existing release arguments]
```

After `PASS sealed_phase_config=observe`, use that exact file as
`/home/pir/data/pir2-sealed/startup.env` for the measured Observe boot. Run the
release after the Observe receipt is available. Generate new startup files for
`enroll`, `probe`, and `ready`, and boot each in that order. A completed release
prints `PASS sealed_release`; every phase file prints
`PASS sealed_phase_config=<phase>` and `NEXT_STEP`.
