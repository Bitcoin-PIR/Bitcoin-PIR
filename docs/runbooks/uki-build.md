# Build a Tier 3 UKI

Use [`scripts/build_uki_tier3.sh`](../../scripts/build_uki_tier3.sh) to produce
a UKI for a reviewed service-policy artifact.

## Inputs

- A Linux build host with the Tier 3 build dependencies.
- The approved policy file path.
- Optional output path and kernel selection.

## Run

```sh
sudo BPIR_TIER3_SERVICE_POLICY=/absolute/path/service-policy.bin \
  OUT=/absolute/path/bpir-tier3.efi \
  scripts/build_uki_tier3.sh --dry-run
sudo BPIR_TIER3_SERVICE_POLICY=/absolute/path/service-policy.bin \
  OUT=/absolute/path/bpir-tier3.efi \
  scripts/build_uki_tier3.sh
```

The build prints dependency checks, the selected kernel, and the output path.
Successful completion prints `PASS uki_build` and `NEXT_STEP`. Record the UKI
path and digest, then continue with the [VPSBG image runbook](vpsbg-image.md).
