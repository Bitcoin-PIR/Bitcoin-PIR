# ORAM TEE Leakage Sketch

This note records the proof-facing shape for the native TEE + ORAM backend.
It is not a checked proof. The checked proof tree in this checkout is
`proofs/easycrypt/`; no Lean sources are currently present here.

## Backend Model

The TEE receives plaintext scripthashes and explicit empty-slot markers over an
attested encrypted channel.
The untrusted host may observe:

- request and response sizes,
- ORAM image sizes and public ORAM parameters,
- the fixed number of logical ORAM path accesses,
- public deterministic eviction work per read,
- state/image file reads and writes.

The host must not learn the INDEX bin or CHUNK id selected by a query. That
address privacy is delegated to the Circuit ORAM implementation.

## Current Lookup Shape

For each padded request, the direct ORAM lookup over `INDEX + CHUNK` direct
entry images does:

1. Read a fixed number of direct INDEX ORAM paths for every padded slot.
   Present slots probe the direct INDEX candidate bins; explicit empty slots
   spend the same count as random dummy INDEX path accesses and do not select a
   logical element.
2. Decode `[start_chunk_id, num_chunks]` inside the TEE only for present slots.
3. Build a private list of required CHUNK ids.
4. Read the real CHUNK ORAM paths if the demand fits the remaining public
   access budget.
5. Fill the rest of the budget with random dummy CHUNK ORAM path accesses.

With `hash_fns=2`, the fixed access shape is:

```text
INDEX accesses = 2 * padded_slot_count
CHUNK accesses = access_budget - INDEX accesses
```

For example, `padded_slot_count=50` requires at least 100 INDEX ORAM accesses;
`access_budget=120` leaves 20 CHUNK accesses, while `access_budget=150` leaves
50 CHUNK accesses. This mirrors the existing PIR decision that request width is
padded, while aggregate CHUNK demand and response size remain admitted axes
unless a later response-padding layer is added.

## Leakage Record Candidate

The ORAM backend proof should use a leakage record analogous to
`proofs/easycrypt/Leakage.ec`, but with ORAM transcript fields rather than PIR
wire rounds:

```text
type oram_leakage = {
  query_db_id;
  padded_slot_count;
  access_budget;
  aggregate_chunk_payload_bytes;
  session_query_index;          // if state checkpoint cadence is visible
  public_oram_geometry;         // tree size, pack, cache levels, drain count
}
```

Axes intended to remain closed:

- scripthash bytes,
- real script-hash count up to the padded slot width,
- INDEX bin,
- INDEX cuckoo match position,
- CHUNK id,
- empty-slot positions.

Axes intentionally admitted for now:

- padded request size,
- database id,
- aggregate result size / approximate UTXO count,
- timing and persistence cadence unless separately padded.

## Deployment Artifact Boundary

The source integration and smoke-test helpers are repository artifacts. The
real Circuit ORAM image/state files are not:

- `index.meta.oram`, `index.payload.oram`, `index.state`
- `chunk.meta.oram`, `chunk.payload.oram`, `chunk.state`
- ORAM page-encryption keys and state-encryption keys

Those files are VPSBG-only deployment data for the SEV-SNP query server. They
belong on the VPSBG data volume next to the server database, not in git, not in
the web bundle, and not in generic client/SDK releases. The server CLI boundary
is `--cuckoo-oram-dir <vpsbg-local-path>` plus the matching key flags when page
or state encryption is enabled.

## Code Witness

The current Rust witness is in `runtime/src/bin/unified_server.rs`:

- `direct_native_lookup_slots` implements the padded-slot direct ORAM shape.
- `direct_oram_lookup_spends_dummy_index_reads_for_empty_slots` checks that
  empty slots consume dummy INDEX accesses, return not-found items, and do not
  create CHUNK demand.
- `native_lookup_mmap_reads_expected_data_and_presence_padding` and
  `native_lookup_oram_matches_mmap_lookup` remain as legacy cuckoo/PBC ORAM
  witnesses.
