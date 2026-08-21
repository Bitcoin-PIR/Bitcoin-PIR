# payment-issuer

The executable integration surface for BitcoinPIR BOLT11 acquisition. Default
artifacts expose only the Core Lightning listener. The deterministic fake
Lightning backend, `serve-fake` subcommand, and `/__test/fake/settle` route are
absent unless the `test-only-fake-lightning` Cargo feature is explicitly
enabled. That feature is accepted only by debug/test profiles: the build script
and a source-level guard both reject release builds, including release profiles
that force debug assertions on. A feature-enabled artifact must never be
deployed or used with real funds.

Core Lightning support is exposed as the loopback-only `serve-cln` mode behind
the checked `pir-lightning-backend` Unix-socket boundary. The V1 shared-issuer
HTTP settlement surface is ledger-accrual only: providers may use
`POST /v1/redeems` and `POST /v1/settlement/balance`. Payout protocol, store and
state-machine support remains transport-neutral; the default and production
binaries return the same `not_found` response for payout-intent, payout and
payout-status paths as for an unknown path, before parsing their payloads. Only
the Rust unit suite has a private fixture switch for exercising the historical
payout HTTP roundtrip. Production constructs the shared service with
`new_ledger_only`; the transport-neutral payout methods themselves also return
`NotFound` before decoding input or accessing the store. There is no production
payout mode or target, fee, or intent-TTL flag. The store's legacy non-zero
payout-target column receives one fixed domain-separated disabled sentinel,
never operator or request input. The issuer settlement signing key remains
required for redeem and balance signatures. Retained settlement verifying keys
remain optional because exact committed issuer-side replay and verification
after signing-key rotation may need them; they are not payout-only keys. This
does not give `unified_server` retained clearing authorizations: the shipped
provider runtime loads one authorization/approval and cannot recover an
outcome-unknown old redeem after replacing it. V1 operators must drain and
reconcile shared-issuer admission before such a rotation. Production TLS, node
custody, payout execution, real-funds activation and remote deployment remain
separate approval gates.

Each `--clearing-authorization` and `--clearing-approval` pair must have one
same-position `--clearing-provider-request-verifying-key` file containing a raw
32-byte Ed25519 public key. Startup rejects a missing/invalid key and rejects
reuse among the provider request, provider clearing, provider operator and
current/retained issuer settlement roles. Ledger-only balance requests continue to use the
authorized clearing key; the request key is registered separately for future
payout recovery/status compatibility and is never replaced by a schema filler.
Generate the signed artifacts with the two independent, self-verifying
builders linked from
[`docs/runbooks/payment-artifacts.md`](../../docs/runbooks/payment-artifacts.md).

`serve-fake` is explicitly test-only.

`init-store` refuses overwrite and creates the issuer database only inside a
private owner-controlled directory. On Unix, the main file is mode 0600; all
modes reject symlinks, public/wrong-owner files, non-0700 parents and
same-inode aliases. The private parent also protects
SQLite `-wal`/`-shm` files, which can contain invoice, payment-hash and recovery
state. Initialization failure never automatically deletes partial files.

The unit suite retains fake coverage through `cfg(test)`. External local
HTTP/browser harnesses must exercise the explicit feature separately:

```sh
cargo test --locked --offline -p payment-issuer
cargo test --locked --offline -p payment-issuer \
  --features test-only-fake-lightning
cargo run --locked --offline -p payment-issuer \
  --features test-only-fake-lightning -- serve-fake --help
```

Without that feature, `serve-fake` is an unknown subcommand. This is an
artifact boundary, not an operator convention.
