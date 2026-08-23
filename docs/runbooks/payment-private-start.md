# Start the private publisher network

This is Flow I step 3 in
[Production operations](../PRODUCTION_OPERATIONS.md).

Use [`scripts/payment-v1-activate.sh`](../../scripts/payment-v1-activate.sh)
with the `private` subcommand.

## Inputs

- Absolute publisher plan and apply-approval paths.
- Approved plan, source, launcher, launcher-manifest, and approval SHA-256
  values.

## Run

```sh
scripts/payment-v1-activate.sh private --plan /absolute/path/plan.json \
  --approved-plan-sha256 HEX --approved-source-sha256 HEX \
  --approved-launcher-sha256 HEX --approved-manifest-sha256 HEX \
  --approval /absolute/path/apply-approval.json \
  --approved-approval-sha256 HEX --dry-run
```

Review the complete launcher command, then rerun it with `--apply` in place of
`--dry-run`. Success prints `PASS private_start` and `NEXT_STEP`; record the
committed receipt and collect the requested private runtime evidence.
