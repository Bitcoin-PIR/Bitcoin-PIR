# Database proof v2: complete OnionPIR layout binding

Status: design proposed and independently reviewed; maintainer approval,
implementation, and production activation belong in a separate
cross-repository PR series. The deployed v1 strict flow remains fail-closed
because the web client pins the remaining OnionPIR layout fields explicitly.

## Goal and trust model

Database proof v2 should make the proof handle itself carry every value that
controls an OnionPIR query. After migration, clients must not obtain trusted
layout values from `server-info`, and the temporary
`PRODUCTION_ONION_QUERY_LAYOUT_PINS` table can be removed.

The first v2 deployment will retain the current production-pin model:

1. WASM decodes a typed v2 layout and recomputes its canonical
   `params_hash_v2` locally.
2. The recomputed hash must equal the hash in both builder evidence and the
   root payload.
3. TypeScript pins that hash together with the database's chain anchors,
   MuHash, Onion super-root, builder binary, and builder revision.
4. Query code consumes only the typed layout returned by the verified proof
   handle.

This is distinct from dynamically accepting any future builder-attested
layout. The current `ProofBundle::verify()` checks the SNP report's
`REPORT_DATA` binding but does not authenticate the report through the AMD
VCEK/ASK/ARK chain or enforce measurement, TCB, and debug policy. Dynamic
rotation without a frontend pin therefore remains a separate attestation-PKI
project.

## Minimal v2 commitment

The current canonical `BuildParamsV1` already commits the shared INDEX/CHUNK
K values and table shape, the Onion entry and index-slot shape, Onion chunk K,
and Merkle hash geometry. Seeds are deterministically derived from the
proof-bound chain anchor.

The three production query values that v1 does not commit and cannot derive
are:

```text
onion_total_packed_entries: u32
onion_index_bins_per_table: u32
onion_chunk_bins_per_table: u32
```

Define a versioned, canonical `BuildParamsV2` rather than appending an
unsigned extension:

```text
params_hash_v2 = SHA256("BPIR_BUILD_PARAMS_V2\0" || canonical(BuildParamsV2))
```

The encoding must be fixed-width, explicitly little-endian, reject trailing
bytes, and have golden vectors shared by the producer and verifier. If a
future build allows Onion K or slot geometry to diverge from the shared table
parameters, v2 must be widened to a complete typed `OnionQueryLayoutV2`
before that configuration is accepted.

The verifier must also enforce all redundant relationships, including:

- K and seeds agree with the proof-bound catalog and chain anchor;
- slot counts and sizes fit the committed Onion entry size;
- Merkle arity and tree-top counts are exactly those implied by the committed
  table geometry;
- the exact ordered tree-tops still hash to the proof-bound
  `onion_super_root`.

Comparing a server-supplied `params_hash` without locally recomputing it is
not verification.

## Compatibility and wire migration

The runtime currently transports length-prefixed proof files opaquely under
`REQ_GET_DB_PROOF = 0x0a`. Replacing its sidecar with v2 would not require the
runtime to understand the inner schema, but every deployed v1 client would
then reject the proof.

The preferred compatibility design is dual serving:

- keep `0x0a` for the existing v1 sidecar;
- add a versioned request or a new opcode for the v2 sidecar;
- require v2 in new `RequireVerified` OnionPIR clients;
- never silently fall back from v2 to v1 in strict mode;
- retain v1 until the supported-client migration window closes.

Dual serving requires a small query-server binary update. If maintainers
instead choose a coordinated same-opcode cutover, the query server can remain
opaque and unchanged, but old strict clients will stop working permanently.
That compatibility trade-off must be made explicitly before implementation.

## Re-attest existing databases without rebuilding them

The expensive snapshot-to-PIR build does not need to run again if the complete
deployed database files and tree-tops remain available. Add an
`attest-existing-layout` mode to the lower-case attested-builder repository:

1. Verify the existing v1 evidence, root payload, manifests, chain anchors,
   and MuHash inputs.
2. Parse `onion_index_meta.bin`, `onion_chunk_cuckoo.bin`, and the Onion
   Merkle headers; reject unknown versions, bad lengths, or inconsistent
   geometry.
3. Re-derive the anchor-bound seeds and check every header value.
4. Recompute or scan the existing Onion tree-tops and confirm their ordered
   commitment equals the v1 `onion_super_root`.
5. Recheck the deterministic packed-entry/chunk mapping rather than copying
   `total_packed_entries` from a log or server JSON response.
6. Emit canonical v2 evidence with `evidence_mode = reattest_existing` and a
   digest of the predecessor v1 evidence/report.
7. Obtain a new SNP report inside the attested-builder guest and archive the
   new evidence, quote, inputs, and verifier output.

This is an artifact scan and cryptographic re-seal, not a database rebuild.
It must not be described as a fresh full build.

## PR and deployment sequence

1. **Producer PR (lower-case attested-builder repository):** freeze
   `BuildParamsV2`, golden vectors, artifact consistency checks, and the
   existing-database re-attest command.
2. **Verifier PR (this repository):** add v1/v2 parsing, typed verified Onion
   layout, recomputation tests, WASM getters, and native strict-policy tests.
3. **Runtime compatibility PR, if dual serving is selected:** load and serve
   both proof versions without interpreting their contents.
4. **Evidence generation:** run the new attested-builder image on VPSBG for
   production db 0 and db 1; verify and archive both bundles.
5. **Server activation:** stage identical v2 sidecars on Hetzner and VPSBG,
   restart through the normal supervisor/UKI path, and verify both database
   IDs on both hosts.
6. **Web cutover:** publish the new `params_hash_v2` pins, consume layout only
   from the live proof handle, and remove the temporary per-field layout pins.
7. **Acceptance:** run the strict production canary for DPF, HarmonyPIR, and
   OnionPIR, then follow the rollback rules in
   `DATABASE_ROOT_ROTATION_RUNBOOK.md` if any host or proof disagrees.

Before starting the producer PR, inventory the retained files on both hosts
and record which consistency checks can be reconstructed from final artifacts
alone. Missing intermediate files can change the cost estimate, but they do
not justify accepting an uncommitted server-info value.

### Initial artifact inventory (2026-07-20)

Hetzner retains the complete final OnionPIR artifacts for both production
databases under:

- `/home/pir/data/checkpoints/948454_deterministic`
- `/home/pir/data/deltas/940611_948454_canonical_20260615`

Both directories contain `onion_index_meta.bin`,
`onion_chunk_cuckoo.bin`, the packed/index tables and bin hashes, the Onion
Merkle roots/siblings/tree-tops, and `MANIFEST.toml`. This is sufficient to
implement and benchmark the existing-artifact checker without starting a new
database build.

The current manifests use an all-zero placeholder hash for the large DPF and
Onion cuckoo files. The re-attester must therefore verify the actual tables
against their Merkle roots and proof-bound super-roots; verifying only
`MANIFEST.toml` is insufficient. VPSBG's corresponding on-disk inventory
still needs to be recorded before the SEV run; its SSH endpoint was not
reachable during this read-only inventory, so no claim is made about missing
files there.
