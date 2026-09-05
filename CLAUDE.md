# BitcoinPIR project memory

Bitcoin Private Information Retrieval system. Three backends — DPF-PIR
(2-server), OnionPIR (1-server FHE), HarmonyPIR (stateful hint) — serving
private UTXO lookups from a snapshot of the Bitcoin UTXO set. Working rules
for agents are in [`AGENTS.md`](AGENTS.md); read that first.

## Where things are decided

| Question | Authority |
| --- | --- |
| Which docs are current | [`docs/README.md`](docs/README.md) |
| Which tests to run | [`docs/TESTING.md`](docs/TESTING.md) |
| Any production operation | [`docs/PRODUCTION_OPERATIONS.md`](docs/PRODUCTION_OPERATIONS.md) |
| Client trust pins (binary hashes, SEV measurement, DB proofs) | [`web/src/attest-pin.ts`](web/src/attest-pin.ts) — never copy values into prose |
| Live production state | Query it (`scripts/production-status.sh`); never infer from documents |
| Privacy invariants and proofs | [`docs/VERIFICATION_OVERVIEW.md`](docs/VERIFICATION_OVERVIEW.md) + [`verification/locks/`](verification/locks/) |

## Privacy invariants (NEVER weaken; details in VERIFICATION_OVERVIEW.md)

1. **Fixed query padding.** Every PIR round sends exactly K=75 INDEX groups,
   K_CHUNK=80 CHUNK groups, 25 Merkle sibling queries. Padding is the privacy
   mechanism — never "optimize" it away.
2. **Merkle INDEX item-count symmetry.** Every INDEX query emits exactly 2
   Merkle items (both cuckoo positions probed, no early exit), in all four
   clients: `crates/sdk/client/src/{dpf,harmony,onion}.rs` and
   `web/src/onionpir_client.ts`.
3. **CHUNK round-presence symmetry.** Every query — found, not-found, whale —
   triggers at least one K_CHUNK-padded CHUNK round, so found/not-found is
   invisible on the wire.
4. **HarmonyPIR request-count symmetry.** Every per-group slot sends exactly
   T−1 sorted distinct indices; never filter empty cells.
5. **INDEX Merkle group-symmetry.** INDEX Merkle items are distributed via
   `pbc_plan_rounds`, never hard-coupled to `derive_groups_3[0]`.

One admitted trade-off: per-query CHUNK Merkle item count reveals approximate
UTXO count (M=16 pad deliberately removed 2026-05-17; do not re-add without
reopening that decision).

## Layout

`crates/protocol` (core primitives, server runtime), `crates/sdk`
(core/client/wasm), `crates/trust`, `apps/server`
(unified_server), `apps/admin`, `apps/payment-issuer`, `tools/db-builder`,
`web/` (browser client), `deploy/`, `verification/`. Full map in
[`README.md`](README.md);
terminology in [`GLOSSARY.md`](GLOSSARY.md).

## Common commands

```bash
cargo test -p pir-sdk-client --lib          # client SDK tests
cargo test -p pir-core                      # protocol primitives
cd crates/sdk/wasm && wasm-pack build --target web --out-dir pkg
cd web && npm run build && npm test
```

## Production notes

- Two hosts: pir1 (Hetzner, DPF-0 + OnionPIR + Harmony hint) and pir2
  (VPSBG AMD SEV Tier 3, Direct ORAM). All operations route through
  `docs/PRODUCTION_OPERATIONS.md` and its runbooks — never improvise from
  memory or old documents.
- Production binaries are bare-Cargo builds (`--locked --release -p runtime`,
  pir2 adds `--features cuckoo-oram`) + `strip --strip-debug`. The Nix flake
  is a development harness only.
- Production databases come from the locked external attested-builder;
  `scripts/build_full.sh` and `tools/db-builder` are development-only.
  Read `docs/DATABASE_ARTIFACT_RETENTION.md` before deleting or rebuilding
  any database artifact — two raw Core snapshots are irreplaceable.
- Shell gotcha: never `echo "$var" | grep -q` under `set -o pipefail`
  (SIGPIPE 141); use `grep -q ... <<< "$var"`.
