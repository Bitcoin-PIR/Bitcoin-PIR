# ORAM TEE Leakage Sketch

This note records the proof-facing shape for the native TEE + ORAM backend.
It is not a checked proof. The checked proof tree in this checkout is
`proofs/easycrypt/`; no Lean sources are currently present here.

## Backend Model

The TEE receives plaintext scripthashes over an attested encrypted channel.
The untrusted host may observe:

- request and response sizes,
- ORAM image sizes and public ORAM parameters,
- the number of logical ORAM bin reads,
- public deterministic eviction work per read,
- state/image file reads and writes.

The host must not learn the INDEX group/bin or CHUNK group/bin selected by a
query. That address privacy is delegated to the Circuit ORAM implementation.

## Current Lookup Shape

For each scripthash, the native lookup over the existing INDEX + CHUNK cuckoo
tables does:

1. Choose one valid INDEX PBC group with `derive_groups_3(scripthash, K)[0]`.
   The same scripthash is replicated to all three candidate groups at build
   time, so any one candidate group is sufficient for correctness.
2. Read exactly both INDEX cuckoo positions from that group. There is no early
   exit when position 0 matches.
3. Decode `[tag, start_chunk_id, num_chunks]` inside the TEE.
4. If `num_chunks > 0`, read exactly both CHUNK cuckoo positions for every real
   chunk id in `[start_chunk_id, start_chunk_id + num_chunks)`.
5. If the INDEX entry is missing or is a whale (`num_chunks == 0`), read exactly
   both CHUNK cuckoo positions for one fresh dummy chunk id and discard the
   result.

So the ORAM logical read count per query is:

```text
INDEX reads = 2
CHUNK reads = 2 * max(real_num_chunks, 1)
```

This mirrors the existing PIR decision: zero-CHUNK round presence is closed,
while approximate UTXO count remains an admitted axis.

## Leakage Record Candidate

The ORAM backend proof should use a leakage record analogous to
`proofs/easycrypt/Leakage.ec`, but with ORAM transcript fields rather than PIR
wire rounds:

```text
type oram_leakage = {
  query_db_id;
  batch_len;
  chunk_probe_count_per_query;  // max(real_num_chunks, 1)
  session_query_index;          // if state checkpoint cadence is visible
  public_oram_geometry;         // tree size, pack, cache levels, drain count
}
```

Axes intended to remain closed:

- scripthash bytes,
- INDEX group/bin,
- INDEX cuckoo match position,
- CHUNK group/bin,
- zero-CHUNK found/not-found presence.

Axes intentionally admitted for now:

- batch size,
- database id,
- approximate per-query UTXO count through `chunk_probe_count_per_query`,
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

- `cuckoo_native_lookup_batch_from_tables_with_dummy` implements the access
  shape above over the shared `CuckooTableAccess` trait.
- `native_lookup_mmap_reads_expected_data_and_presence_padding` checks found,
  not-found, and whale shapes against a synthetic cuckoo DB.
- `native_lookup_oram_matches_mmap_lookup` checks the same lookup through
  `CircuitOram` returns the same result as the mmap baseline.
