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

`init-store`, `check-store`, and every available serving mode require exactly
one floor boundary:

- `--rollback-authority <sqlite>` is retained for local development/tests.
  `serve-cln` additionally requires
  `--allow-local-rollback-authority-dev`; it cannot be mistaken for the
  production path. `serve-fake` is already explicitly test-only.
- `--remote-rollback-authority-config <owner-only.toml>` loads the independent
  pinned-HTTPS production authority. It has no local or unpinned fallback.

Remote initialization requires a caller-generated, nonzero 16-byte
`--store-instance-id-hex`. Preserve this public identifier before starting:
if the remote CAS commits and the local process then fails, recovery must reuse
the exact same ID and config. Changing the ID or resetting/lowering the remote
floor is forbidden.

Local `init-store` refuses overwrite and creates the issuer database and local
test floor only inside private owner-controlled directories. On Unix, both
main files are mode 0600; all modes reject symlinks, public/wrong-owner files,
non-0700 parents and same-inode aliases. The private parent also protects
SQLite `-wal`/`-shm` files, which can contain invoice, payment-hash and recovery
state. Initialization failure never automatically deletes partial files or
resets a remote namespace.

The non-default `remote-authority-process-e2e` feature exists only for the
offline integration test. It starts the rollback-authority application and a
`localhost` test-TLS edge in separate OS processes, then executes the real
`payment-issuer` binary directly (never through `cargo run`):

```sh
cargo test --locked --offline -p payment-issuer \
  --features remote-authority-process-e2e \
  --test remote_authority_process_e2e \
  payment_issuer_remote_authority_real_process_tls_e2e \
  -- --exact
```

The test covers remote `init-store`, a new-process `check-store`, authority
restart against the durable floor, wrong CA, wrong leaf-SPKI pin and an offline
authority. Every failure remains closed, and captured issuer/authority/TLS logs
are checked for namespace, key, invoice, payment-hash, preimage and remote
config-path leakage. Remote success output uses a fixed redacted config marker.
The feature only forwards the private test-CA hook; enabling it in a release
build fails at compile time.

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
