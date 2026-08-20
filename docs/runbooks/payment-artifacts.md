# Generate Payment V1 artifacts

Use [`scripts/payment-v1-artifacts.sh`](../../scripts/payment-v1-artifacts.sh)
to build and self-verify one selected Payment V1 or BAT V2 artifact.

## Inputs

- Existing CLI arguments for the selected artifact operation.
- The source-policy inputs expected by that existing CLI.

## Run

```sh
scripts/payment-v1-artifacts.sh --help
scripts/payment-v1-artifacts.sh KIND --help
scripts/payment-v1-artifacts.sh KIND [existing CLI arguments] --dry-run
scripts/payment-v1-artifacts.sh KIND [existing CLI arguments]
```

The command prints the selected operation and forwards the existing CLI's
progress and output. Success prints `PASS artifact=<kind>` and `NEXT_STEP`.
These commands build protocol artifacts; they do not render service templates.
