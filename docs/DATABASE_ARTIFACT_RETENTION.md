# Database artifact retention and debug handoff

This is the canonical map for the production database lineage at heights
`940611 -> 948454`. It exists to prevent another incident from turning into a
full rebuild merely because an intermediate file cannot be found.

The machine-readable identities and paths are in
[`data-retention/production-940611-948454.inventory.tsv`](data-retention/production-940611-948454.inventory.tsv).
The inventory is an operator record, not a production activation instruction.

## Keep these three layers

### A. Irreplaceable source inputs

Keep both Bitcoin Core V2 snapshots and verify their full-file SHA-256 before
using them:

- `txoutset_940611.dat`: 9,427,476,008 bytes,
  `f864896ea6d9789a7d0f7d21e1405096f4e44a7bd674cdeca1b8ac354980d8c8`.
- `txoutset_948454.dat`: 9,422,874,286 bytes,
  `e5ed70c794830d6db2d7ebb7ad3965b126067457a977f370ec5e876139dcf6ff`.

The later snapshot plus the grouped delta is not enough to reconstruct the
earlier Core snapshot: spent entries do not retain the complete Coin fields
needed by MuHash. Never delete the 940611 snapshot because a delta directory
appears to cover the same heights.

The accepted V2 outputs were produced with Bitcoin Core `v31.0.0`, evidence
schema V2, and `Bitcoin-PIR/attested-builder` commit
`8d9d21a6be560236cb666269cf1f93a3de53bb1f`. Their locked MuHash values are
`aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b`
at 940611 and
`cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee`
at 948454.

### B. Expensive intermediate products

Keep one verified copy of each:

- the 948454 deterministic server checkpoint;
- the exact Hetzner 940611-to-948454 canonical delta;
- db0 and db1 `oram-direct-inputs` (`utxo_chunks_index_nodust.bin`,
  `utxo_chunks_nodust.bin`, and their hashes);
- exact V2 `server-db-MANIFEST.toml`, `build-evidence.bin`,
  `root-bundle-payload.bin`, SNP report, and the two build manifests.

These files are enough to diagnose source binding and to avoid repeating the
most expensive materialization stages. The current live V2 server manifest
roots are:

- db0: `91421138ba94e44665bef2617af296b1c1847dea13c4df29b565012d1e0b74a6`;
- db1: `047a5b6713bf0df29d9de308fb47ff757243e365a9818cf746f399bea457d00c`.

### C. Release evidence

For every retained UKI keep the `.efi`, `.efi.sha256`, and `.efi.meta` files.
For the current production lineage also keep the exact repository revision,
binary hash, measurement, reviewed policy identity, and post-boot acceptance
record. Keep the immediately preceding VPSBG image as the rollback target.
The point-in-time identity for image 265 is recorded in
[`data-retention/production-release-image-265.env`](data-retention/production-release-image-265.env);
it is evidence, not a substitute for querying current VPSBG state.

## Derived data that is not a source archive

Mutable Direct ORAM payload, metadata, auth pages, controller roots, and runtime
logs are derived state. A known-good sample may be retained for debugging, but
those bytes are not required to establish the browser's source-binding verdict
and do not replace the source inputs above.

Do not retain every failed bulk output. Keep the small status/progress/evidence
files and one representative failure when it explains a distinct bug; remove
only derived bulk files after the source and evidence copies have been checked.

## Where to look first

External Bitcoin volume:

```text
/Volumes/Bitcoin/data/archive/production-940611-948454/
```

Hetzner archive host:

```text
/home/pir/data/debug-handoff/production-940611-948454/
```

Each handoff directory contains a README and inventory. The large files may
remain at their established canonical paths; the handoff inventory names those
paths rather than silently duplicating everything.

The external handoff also carries a byte-for-byte mirror of the currently
served Hetzner canonical delta manifest/tree. Keep it distinct from older local
`940611_948454` directories: a matching height range is not proof of matching
bytes.

## Debug sequence

1. Run `scripts/vpsbg-production-status.sh`. Do not infer unavailable fields.
2. Identify the exact image, database id, active manifest root, and failing
   stage before reading broad logs.
3. Compare the active V2 server manifest with the retained db0/db1 manifest.
4. Verify the relevant raw snapshot or Direct input hash before starting a
   builder.
5. Reproduce in none/local mode with the retained Direct inputs before testing
   a new UKI. Use the timing and stop limits in
   [`ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md`](ORAM_DIRECT_TEE_DEBUG_RUNBOOK.md).
6. Build or switch a production UKI only after a separate preflight and explicit
   authorization.

The attested database producer lives in the separate
`Bitcoin-PIR/attested-builder` repository. Use the exact locked producer
revision and its `build-snapshot-database.sh` / `build-delta-database.sh`; do
not reconstruct a pipeline from an old chat transcript.
