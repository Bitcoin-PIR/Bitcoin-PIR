# Initialize issuer state

Use [`scripts/payment-v1-issuer-state.sh`](../../scripts/payment-v1-issuer-state.sh)
after Payment V1 artifacts are ready and an issuer environment has been selected.

## Inputs

- `--store PATH`, `--issuer-id-hex HEX`, and `--network NETWORK`.
- `--rollback-authority PATH`: a separate local SQLite rollback-floor file,
  created by `init` and required by every later open.

## Run

```sh
scripts/payment-v1-issuer-state.sh init --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin \
  --rollback-authority /absolute/path/rollback.sqlite3
scripts/payment-v1-issuer-state.sh check --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin \
  --rollback-authority /absolute/path/rollback.sqlite3
```

The command forwards the issuer-state CLI output and prints the selected
operation. Success prints `PASS issuer_state=init|check` and `NEXT_STEP`.
