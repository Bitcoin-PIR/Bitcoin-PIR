# Initialize issuer state

This is Flow I step 2 in
[Production operations](../PRODUCTION_OPERATIONS.md).

Use [`scripts/payment-v1-issuer-state.sh`](../../scripts/payment-v1-issuer-state.sh)
after Payment V1 artifacts are ready and an issuer environment has been selected.

## Inputs

- `--store PATH`, `--issuer-id-hex HEX`, and `--network NETWORK`.

## Run

```sh
scripts/payment-v1-issuer-state.sh init --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin
scripts/payment-v1-issuer-state.sh check --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin
```

The command forwards the issuer-state CLI output and prints the selected
operation. Success prints `PASS issuer_state=init|check` and `NEXT_STEP`.
