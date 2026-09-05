# Bitcoin PIR — Private Bitcoin Wallet Lookups

Query the Bitcoin UTXO set without revealing which addresses you're interested in.

Today's light wallets leak every address you own to their server, enabling full surveillance of your balances, transactions, and spending habits. Bitcoin PIR uses **Private Information Retrieval** — a family of cryptographic protocols where the server(s) provably learn nothing about which records you look up — to give light wallets the same privacy as a full node, without the storage cost.

## Try It

A live demo runs at **[https://www.bitcoinpir.org/](https://www.bitcoinpir.org/)**. You can paste any Bitcoin address in the browser and watch it resolve to UTXOs privately. The servers run on a home machine and load data on demand, so the first query may be slow — please be patient.

## What It Does

- **Look up any Bitcoin address privately** — balance, UTXOs, and transaction history, with zero leakage to the server
- **Batch many addresses at once** — wallet sync performs dozens of lookups in a single round
- **Verify results cryptographically** — each result comes with an optional Merkle proof tying it to the database's Merkle root; together with remote attestation of the server binary, this stops a malicious server from silently returning wrong data (the proof alone establishes consistency with a server-supplied root — see the trust-model note under "Key Features")
- **Three privacy backends** for different trust and performance trade-offs
- **Works with existing wallets** via plugins and adapters — no need to build a wallet from scratch

## Privacy Backends

You can pick the backend that matches your threat model and performance needs:

| Backend | Trust Model | Best For |
|---------|-------------|----------|
| **DPF (2-server)** | Privacy holds as long as two servers don't collude | Fast, lightweight queries |
| **OnionPIR (1-server, FHE)** | Single server, cryptographic privacy from lattice hardness | Strongest single-server guarantee |
| **HarmonyPIR (1 or 2-server, stateful)** | Offline setup phase; deployed here as 2-server (query server + dedicated hint server) | Fast online queries after initial sync |

All three backends expose the same high-level API — clients can switch between them without changing their code.

## Supported Wallets and Clients

Bitcoin PIR plugs into the existing Bitcoin ecosystem rather than replacing it:

- **Web browser** — a TypeScript + WASM client runs entirely in-browser, no extension needed
- **Rust CLI** — a reference command-line client for testing and scripting

Wallet-library integration (BDK) is a possible future direction; earlier
adapter experiments (an Electrum plugin, a bitcoinjs explorer adapter) were
removed in 2026-08 after falling behind the protocol.

## Key Features

### Cryptographic result verification
Each UTXO lookup can be paired with a Merkle proof query that checks the result against the database's Merkle root. Verification is **batched** across all addresses in a wallet sync — one proof round covers the whole batch. The server can refuse to answer, but it cannot return data that contradicts the root it committed to; whether that root itself can be trusted is an attestation question — see the trust-model note below.

> **Trust-model note on Merkle verification (2026-07).** Native SDK clients default to `Advisory`, where a server-supplied root establishes self-consistency only. Applications can verify a database proof, explicitly install the returned `VerifiedDatabaseRoots`, and select `RequireVerified`; this fail-closed mode binds the exact ordered tree-top roots to the attested database super-root before any address query. The production web client enables the strict proof → production pin → typed install → tree-top preflight flow for DPF, HarmonyPIR, and standalone OnionPIR. OnionPIR uses the attested `onion_super_root`; its `server-info.super_root` is diagnostic only. On pir2, runtime integrity is backed by SEV-SNP and a verified AMD VCEK chain. Pir1 (Hetzner) has no SEV hardware, so its strict tier is operator identity plus binary pinning and must not be described as hardware attestation. See [the database/root rotation runbook](docs/DATABASE_ROOT_ROTATION_RUNBOOK.md).

> **Privacy note on Merkle verification.** Within each PIR round, queries are padded to a fixed count (75 for index, 80 for chunk) so the server cannot tell which group is real. Every query — found, not-found, or whale — performs at least one CHUNK PIR round and at least one CHUNK-Merkle sibling pass, so a not-found query stays indistinguishable from a found one (the **round-presence** invariant). INDEX Merkle items are distributed across PBC groups so the per-level sibling-pass count does not depend on a batch's collision pattern (**INDEX Merkle Group-Symmetry**). **Trade-off (2026-05-17):** all three backends (DPF, HarmonyPIR, OnionPIR) no longer pad each query's CHUNK Merkle items to a fixed `M = 16`; a query now fetches and verifies its *real* chunk count, so the server learns the approximate UTXO count of a found address. This is an admitted leak — mild for the ~99% of addresses with a single chunk. See [docs/VERIFICATION_OVERVIEW.md](docs/VERIFICATION_OVERVIEW.md) for the full picture.

### Batch queries
Wallet sync typically touches dozens of addresses at once. Bitcoin PIR packs multiple addresses into a single PIR round using probabilistic batch codes, so syncing a wallet with 50 addresses takes roughly the same time as syncing one.

### Full UTXO dataset
The server hosts the complete Bitcoin UTXO set (~815K active script types at time of writing), filtered to exclude dust and very heavy addresses. Light wallets see the same data a full node would return.

### Open and self-hostable
Anyone can run PIR servers from a public Bitcoin Core snapshot. Free queries
are open; a provider can gate paid queries behind cashier-signed session
grants ([`docs/SESSION_GRANTS.md`](docs/SESSION_GRANTS.md)) without giving
the PIR host any payment secret. No payment gate is enabled by merely
building this repository.

## Project Layout

```
BitcoinPIR/
├── crates/
│   ├── protocol/      Shared database, channel, and server-runtime primitives
│   ├── sdk/           Rust core, native-client, and WASM SDK crates
│   └── trust/         Identity, attestation, and database-proof verification
├── apps/
│   ├── server/        Production server and diagnostic binaries
│   └── admin/         Operator CLI
├── tools/
│   ├── db-builder/    Database generation pipeline
│   └── block-reader/  Bitcoin Core block/UTXO inspection utilities
├── web/               Production browser query application
├── deploy/            Reproducible build and deployment integration
├── docs/              Design, verification, and operating documentation
└── verification/      External proof locks and implementation contracts
```

Production diagnosis starts at
[`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md). Database and
Direct ORAM source/intermediate retention is mapped in
[`docs/DATABASE_ARTIFACT_RETENTION.md`](docs/DATABASE_ARTIFACT_RETENTION.md);
consult it before deleting artifacts or starting an expensive rebuild.

The repository is being reorganized into stable `apps/`, `crates/`, `tools/`,
and `verification/` boundaries. Reusable protocols, formal proofs, generated
proof bundles, demos, and research sources live in separate repositories under
the [Bitcoin-PIR organization](https://github.com/Bitcoin-PIR). See
[`docs/REPOSITORY_BOUNDARIES.md`](docs/REPOSITORY_BOUNDARIES.md) for the
ownership rules and migration gates.

## Getting Started

1. **Clone and build**:
   ```bash
   git clone https://github.com/Bitcoin-PIR/Bitcoin-PIR.git
   cd Bitcoin-PIR && cargo build --release
   ```
2. **Point clients at the live demo servers** (no database build needed) — see `web/` for the browser client.
3. **Or host your own**: generate the databases from a Bitcoin Core UTXO
   snapshot with `scripts/build_full.sh` (takes a few hours), then start the
   PIR servers with `scripts/start_pir_servers.sh`.

For development, see [`docs/TESTING.md`](docs/TESTING.md).

## Documentation

- [`docs/README.md`](docs/README.md) — documentation index; start here
- [`docs/TESTING.md`](docs/TESTING.md) — which checks to run for which change
- [`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md) — operator
  entry point; every production operation routes through this page
- [`docs/VERIFICATION_OVERVIEW.md`](docs/VERIFICATION_OVERVIEW.md) — the
  privacy invariants and formal-verification final state
- [`Bitcoin-PIR/whitepaper`](https://github.com/Bitcoin-PIR/whitepaper) — Research paper sources, generated PDF, and benchmark material (the exact consumed revision is recorded in [`verification/locks/whitepaper.json`](verification/locks/whitepaper.json))

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Contributing

Contributions are welcome — please open a pull request or issue.
