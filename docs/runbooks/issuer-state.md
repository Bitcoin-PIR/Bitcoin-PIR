# Initialize issuer state

Use [`scripts/payment-v1-issuer-state.sh`](../../scripts/payment-v1-issuer-state.sh)
after Payment V1 artifacts are ready and an issuer environment has been selected.

## Inputs

- `--store PATH`, `--issuer-id-hex HEX`, and `--network NETWORK`.
- Production authority input: `--remote-rollback-authority-config PATH` and,
  for `init`, `--store-instance-id-hex HEX`.
- Development and test environments may use `--rollback-authority PATH`.

## Run

```sh
scripts/payment-v1-issuer-state.sh init --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin \
  --remote-rollback-authority-config /absolute/path/authority.toml \
  --store-instance-id-hex HEX
scripts/payment-v1-issuer-state.sh check --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin \
  --remote-rollback-authority-config /absolute/path/authority.toml
```

The command forwards the issuer-state CLI output and prints the selected
operation. Success prints `PASS issuer_state=init|check` and `NEXT_STEP`.
