# payment-issuer

The executable integration surface for BitcoinPIR BOLT11 acquisition. Both
listener modes accept only a loopback bind address. `serve-fake` uses the local
deterministic fake Lightning backend and must never be deployed or used with
real funds.

Core Lightning support is exposed as the loopback-only `serve-cln` mode behind
the checked `pir-lightning-backend` Unix-socket boundary. Production TLS, node
custody, payout execution, real-funds activation and remote deployment remain
separate approval gates.

`init-store` refuses overwrite and creates the issuer database and independent
rollback authority only inside private owner-controlled directories. On Unix,
both main files are mode 0600; serve modes reject symlinks, public/wrong-owner
files, non-0700 parents and same-inode aliases. The private parent also protects
SQLite `-wal`/`-shm` files, which can contain invoice, payment-hash and recovery
state. Initialization failure never automatically deletes partial files.
