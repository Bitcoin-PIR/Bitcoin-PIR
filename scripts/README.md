# Bitcoin PIR Scripts

Helper scripts for running and testing the PIR system.

> **Scope note (2026-08).** The database build and refresh sections below
> describe the local development pipeline. They are **not** the production
> database release path: production rotations use the locked
> `Bitcoin-PIR/attested-builder` producer (that repo's README is the
> coverage map) and
> [`docs/DATABASE_ROOT_ROTATION_RUNBOOK.md`](../docs/DATABASE_ROOT_ROTATION_RUNBOOK.md),
> and every retention/cleanup decision is governed by
> [`docs/DATABASE_ARTIFACT_RETENTION.md`](../docs/DATABASE_ARTIFACT_RETENTION.md).
> Where this file and those documents disagree, those documents win.

## Production status

For production diagnosis (Flow A in
[`docs/PRODUCTION_OPERATIONS.md`](../docs/PRODUCTION_OPERATIONS.md)),
run this read-only command first:

```bash
./scripts/production-status.sh
```

That prints pir1 SSH health and then attests the pir2 MacBook node
against `PIR2_MACBOOK_PIN` (set `BPIR_ADMIN` to reuse a prebuilt
`bpir-admin`). `./scripts/vpsbg-production-status.sh` GETs the VPSBG
control plane and the public `/status.json` of the Direct ORAM host, never
uses SSH, and defaults to `.secrets/vpsbg-api-token`. The ORAM endpoint exists only during
build/switch; after `unified_server` owns 8091, its fields are expected
to be `unavailable`.
Do not infer profile, attestation, generation, database identity, or other unavailable fields. `--root` reads an offline evidence directory only. See [`docs/PRODUCTION_OPERATIONS.md`](../docs/PRODUCTION_OPERATIONS.md) for release and canary routing.

Before a database or Direct ORAM rebuild, read
[`docs/DATABASE_ARTIFACT_RETENTION.md`](../docs/DATABASE_ARTIFACT_RETENTION.md).
It names the retained snapshots, Direct input sets, exact manifests, and the
external/Hetzner handoff directories; do not rebuild merely because a path was
not checked there first.

## Scripts

### `start_pir_servers.sh`

Starts two Batch PIR WebSocket servers for UTXO lookups.

```bash
./scripts/start_pir_servers.sh
```

The script builds the `server` binary (`runtime` crate), kills any existing servers on ports 8091/8092, and starts two background server processes. Press Ctrl+C to stop both.

Server logs are written to `/tmp/pir_primary.log` and `/tmp/pir_secondary.log`.

### `build_full.sh`

Builds a complete full-snapshot UTXO PIR database (DPF + HarmonyPIR +
OnionPIR + all Merkle artifacts) from a Bitcoin Core dumptxoutset.
Single orchestrator that runs the full 10-stage pipeline.

```bash
./scripts/build_full.sh <dumptxoutset_file> <height>
```

Layout:
- Intermediate (raw UTXO + chunks; ~10–20 GB; safe to delete after build):
  `/Volumes/Bitcoin/data/intermediate/full_<H>/`
- Final checkpoint (~40 GB, ready for the server):
  `/Volumes/Bitcoin/data/checkpoints/<H>/`

The pipeline:
1. `gen_0_extract_utxo_set` — dumptxoutset → 68B flat UTXOs
2. `gen_1_build_utxo_chunks` — pack into 80B chunks + 25B index (no dust)
3. `build_cuckoo_generic index` — INDEX cuckoo (DPF/Harmony)
4. `build_cuckoo_generic chunk` — CHUNK cuckoo (DPF/Harmony)
5. `gen_4_build_merkle_bucket --data-dir` — per-bucket bin Merkle
6. `gen_1_onion` — pack UTXOs into 3840B OnionPIR entries
7. (move `onion_packed_entries.bin` + `onion_index.bin` into checkpoint dir)
8. `gen_2_onion --data-dir` — NTT store + chunk cuckoo + DATA bin hashes
9. `gen_3_onion --data-dir` — per-group INDEX PIR DBs (consolidated to `onion_index_all.bin`)
10. `gen_4_build_merkle_onion --data-dir` — per-bin OnionPIR Merkle (INDEX + DATA)

### `build_delta.sh`

Builds a complete delta UTXO database between two block heights, including
the per-bucket bin Merkle verification files. Runs the full pipeline:
`delta_gen_0` -> `delta_gen_1` -> `build_cuckoo_generic` (index + chunk) ->
`gen_4_build_merkle_bucket`.

```bash
./scripts/build_delta.sh <dumptxoutset_file> <bitcoin_datadir> <start_height> <end_height>
```

Output goes to `/Volumes/Bitcoin/data/deltas/<start>_<end>/`.

### `build_delta_onion.sh`

Builds the OnionPIR artifacts for an existing delta UTXO database, enabling
the 1-server OnionPIR backend on that delta. Must be run **after**
`build_delta.sh` for the same height range. Runs:
`delta_gen_1_onion` -> `gen_2_onion --data-dir` -> `gen_3_onion --data-dir`
-> `gen_4_build_merkle_onion --data-dir`.

```bash
./scripts/build_delta_onion.sh <start_height> <end_height>
```

Produces the `onion_*.bin` files and per-bin `merkle_onion_*.bin` Merkle trees
in the same `/Volumes/Bitcoin/data/deltas/<start>_<end>/` directory that
`build_delta.sh` wrote to. Once these exist, the server (re)started via
`start_pir_servers.sh` will automatically serve the delta via OnionPIR and the
web client's OnionPIR tab can query `db_id=1`.
