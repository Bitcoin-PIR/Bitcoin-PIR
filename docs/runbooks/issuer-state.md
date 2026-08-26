# Initialize issuer state

This is Flow I step 2 in
[Production operations](../PRODUCTION_OPERATIONS.md).

Use [`scripts/payment-v1-issuer-state.sh`](../../scripts/payment-v1-issuer-state.sh)
after Payment V1 artifacts are ready and an issuer environment has been selected.

## Inputs

- `--store PATH`, `--issuer-id-hex HEX`, and `--network NETWORK`.

The current no-funds BAT V2 owner environment keeps its schema-v9 issuer
store on the Hetzner host at
`/var/lib/bitcoinpir-mainnet-bat-v2-issuer/issuer.sqlite3`. Run owner CLI
commands as the dedicated `bitcoinpir-mainnet-issuer` user; the private-file
checks intentionally reject opening this service-owned store as `root`. The
presence of this store does not mean an issuer service is installed, active,
funded, or publicly enabled.

## Run

```sh
scripts/payment-v1-issuer-state.sh init --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin
scripts/payment-v1-issuer-state.sh check --store /absolute/path/store \
  --issuer-id-hex HEX --network bitcoin
```

The command forwards the issuer-state CLI output and prints the selected
operation. Success prints `PASS issuer_state=init|check` and `NEXT_STEP`.

## Activate a reserved BAT V2 clearing epoch

Activation is a separate owner-authorized production mutation. First use the
owner CLI's `read-bat-v2-clearing-epoch` command as the dedicated issuer user
and require the exact issuer, network, provider, and reserved authorization
epoch to report `reservation_state=inactive`. Do not derive the epoch from an
old artifact or increment a remembered value.

Then activate the exact signed authorization and approval against their pinned
public verification keys:

```sh
payment-issuer activate-bat-v2-accounting-authorization \
  --store /absolute/path/store \
  --issuer-id-hex ISSUER_ID_HEX \
  --network bitcoin \
  --authorization /absolute/path/accounting-authorization.bin \
  --approval /absolute/path/issuer-approval.bin \
  --operator-verifying-key /absolute/path/operator-verifying-key.bin \
  --issuer-settlement-verifying-key \
    /absolute/path/issuer-settlement-verifying-key.bin
```

Immediately run `read-bat-v2-clearing-epoch` again and require
`reservation_state=active`, the exact authorization epoch, clearing verifying
key, authorization digest, and activation commit sequence returned by the
activation. Run both commands as the store's dedicated owner, never as `root`.
Activation alone does not install or start an issuer service, move funds,
publish an artifact, or update the production pin.
