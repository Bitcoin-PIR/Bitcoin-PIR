# ORAM Crash Consistency

This note tracks the durability issue in the native cuckoo-table ORAM backend.
It is intentionally separate from the leakage sketch: this is about preserving
the ORAM data structure across errors, restarts, and host-visible storage
failures.

## Current State

The production-facing ORAM path added in PR #20 uses the standalone
`bitcoinpir-oram` crate and serves BitcoinPIR's existing INDEX + CHUNK cuckoo
tables through `CuckooTableAccess`.

Important code paths:

- `runtime/src/bin/unified_server.rs`
  - `CuckooOramTable::append_entries`
  - `CuckooOramTable::finish_request`
  - `cuckoo_native_lookup_batch_from_tables_with_dummy`
- `~/bitcoin-pir/oram/src/circuit.rs`
  - `CircuitOram::access`
  - `read_and_remove_target_path`
  - `drain_evictions`
  - `apply_eviction_plan`
- `~/bitcoin-pir/oram/src/store.rs`
  - `FilePageStore`
  - `FrontCachedPageStore`
- `~/bitcoin-pir/oram/src/state.rs`
  - `CircuitOramState::save_atomic`
  - `CircuitOramState::save_encrypted_atomic`

`CircuitOramState::save_atomic` is atomic for the state file itself, but the
ORAM page images are updated in place before that state file is saved.

## The Failure Mode

An ORAM access is not a pure read. It mutates the tree and trusted controller
state:

1. Look up the current leaf in the position map.
2. Read the old path.
3. Move the target block from the path into the stash.
4. Clear that slot in the page image.
5. Pick a new leaf and update the position map / stash metadata.
6. Schedule deterministic eviction debt.
7. Drain some eviction paths, which can also rewrite page images and move
   blocks between paths and stash.
8. Flush page stores and save the new `CircuitOramState`.

The risky part is step 3-4: once the target block is removed from the page
image, the only complete copy may be in the in-memory stash until the state file
is saved. If the process returns an error and later crashes, or if the host
crashes mid-write, the old state file can point to a page image where the block
has already been removed. On restart, the block is lost.

This is not only theoretical. `read_and_remove_target_path` writes pages during
the access, and `apply_eviction_plan` also writes pages during eviction. A later
failure can occur before `finish_request` saves the state.

## What Is Safe Today

Some errors are checked before mutation:

- invalid logical id is rejected before page writes;
- invalid cuckoo group/bin is rejected before ORAM reads;
- `CircuitCuckooBinReader::new` checks `logical_blocks` and block size before
  serving;
- eviction stash capacity is checked before `apply_eviction_plan` mutates
  stash or path pages.

These checks are useful, but they do not cover I/O errors, AEAD read failures,
partial writes, process termination, or a failure after one ORAM read in a
multi-read request.

## Short-Term Guard

The runtime should not return early after a mutating ORAM read and then keep
serving from an ambiguous state.

For the current server this means:

- Track whether `CuckooOramTable::append_entries` performed at least one real
  ORAM read.
- On any error after mutation, either finish the request's disk-page / Merkle /
  trusted-root updates enough to keep serving safely, or poison the ORAM
  instance before returning `Response::Error`.
- Do this for both native ORAM lookup and Harmony query/batch paths when they
  are backed by ORAM.
- Log loudly if this emergency completion fails, and treat the ORAM instance as
  poisoned for the rest of the process. Continuing after a failed completion
  risks making corruption harder to reason about.

This guard helps with ordinary decode / lookup errors in a still-running
process. If startup always regenerates ORAM from the immutable cuckoo DB, this
guard does not need to make the ORAM controller state trustworthy across reboot;
it only needs to keep the current process from serving after an incomplete
mutation.

Implementation status: `runtime/src/bin/unified_server.rs` now tracks whether a
`CuckooOramTable` has performed a real ORAM read in the current request. If a
post-mutation read, flush, state-save, or request-abort path fails, the table is
marked poisoned and later reads are rejected until restart/regeneration.

## Production Fix

The production fix should be a transactional page-store layer. The safest
minimal design is a rollback journal under the ORAM page encryption layer.

Recommended shape:

1. Add a `JournaledFilePageStore` in the ORAM crate.
2. The journal records physical page bytes, not decrypted logical page bytes.
   This lets it sit below `AeadPageStore` and keeps rollback independent of the
   page encryption format.
3. Start one transaction before the first ORAM page write in a request.
4. Before the first write to a physical page in that transaction:
   - read the old page bytes;
   - append `{store_id, page_idx, old_page_bytes, checksum}` to the journal;
   - fsync the journal record before overwriting the page.
5. Perform normal in-place page writes.
6. At commit:
   - flush meta and payload page stores;
   - write the new state to `state.pending` and fsync it;
   - append a commit-ready marker to the journal and fsync it;
   - rename `state.pending` to `state`;
   - fsync the state directory;
   - clear the journal.
7. At recovery:
   - if a journal exists without a commit-ready marker, restore old page bytes
     from the journal and keep the old state;
   - if a journal exists with a commit-ready marker, complete the state install
     if needed and keep the new page images;
   - only then open `CircuitOramState`.

The order matters. A plain atomic rename of the state file is not enough,
because a crash can occur after page writes but before the state rename, or
after the state rename but before journal cleanup.

## Why Not Just Save State On Error?

Saving state on error is still useful, but it is not sufficient:

- It cannot recover from a process kill or host crash during the access.
- It cannot make multi-page writes atomic.
- It cannot repair a torn page write.
- It cannot decide whether to keep or roll back page mutations after a crash.

It should be implemented as a short-term safety belt, not as the final
production consistency mechanism.

## Rollback Safety After Restart

Crash consistency and rollback safety are different problems.

- Crash consistency asks whether the ORAM image and state are internally
  coherent after a failure.
- Rollback safety asks whether the coherent state is the newest state the TEE
  is allowed to use.

SEV-SNP helps with memory integrity while the VM is running, including
hypervisor attempts to replay or remap guest memory pages. It does not, by
itself, give the guest a durable monotonic counter for application state stored
on an untrusted disk. A disk snapshot can therefore be rolled back to an older
sealed ORAM state unless the guest checks freshness against something outside
that disk snapshot.

For ORAM this matters for security, not only correctness. The ORAM state
contains at least:

- the position map;
- the stash;
- the RNG state used for future remapping;
- the deterministic eviction schedule counters.

If the host rolls all of these files back together, the ORAM may still be
internally valid and pass local integrity checks. But it reuses old randomness
and old position-map assignments. A malicious host can then compare physical
ORAM traces across executions from the same old state. Replaying the same
starting state turns ORAM from "fresh randomized access sequence" into "same
logical access tends to begin from the same old leaf/path", which is exactly the
kind of linkage the ORAM layer is meant to avoid.

Encrypted or sealed state is not enough. It proves "this state was produced by
the right TEE/key" but not "this is the latest state".

For BitcoinPIR, the cleanest way to avoid cross-restart rollback is not to keep
ORAM state across restarts at all. If startup regenerates a fresh ORAM image and
fresh ORAM controller state from the immutable cuckoo DB, then a disk snapshot
rollback after reboot cannot replay old ORAM randomness: the service simply
does not trust any prior ORAM image/state as live state.

That changes the remaining problem:

- restart rollback is handled by regeneration;
- runtime rollback still matters, because the live ORAM may keep only part of
  the tree in trusted memory and spill the rest to untrusted disk.

## Rollback Protection Options

### 1. Regenerate ORAM on every start

This is the preferred direction for BitcoinPIR if build time is acceptable.

At service start:

1. Open the immutable `batch_pir_cuckoo.bin` and `chunk_pir_cuckoo.bin`.
2. Choose fresh ORAM randomness inside the TEE.
3. Build a fresh ORAM layout from the immutable cuckoo tables.
4. Initialize in-memory trusted state from the fresh layout.
5. Serve queries only after the generated image passes a sample or full
   verification pass.

This also simplifies recovery: if the process crashes, loses state, or sees an
unrecoverable disk consistency error, discard the generated ORAM directory and
rebuild. The immutable cuckoo DB is the recovery source, not the previous ORAM
state.

The cost is startup time and temporary disk space. It also means we should
measure build time honestly on VPSBG, because it becomes part of the operational
restart budget.

### 2. Runtime authenticated disk pages

Regeneration does not solve rollback while the process is live. If part of the
ORAM is on disk, a malicious host can try to replay an older disk page during
the same VM lifetime. The TEE must authenticate disk-resident pages against
trusted in-memory roots.

Recommended shape:

```text
TEE memory:
  ORAM controller state
  stash
  position map, or the trusted prefix of a recursive position map
  Merkle roots / top subtree hashes for disk-backed page stores

Disk:
  ORAM meta pages
  ORAM payload pages
  lower Merkle tree nodes, if the full tree does not fit in memory
```

Hash domains should include at least:

```text
leaf = H("bpir-oram-page-v1" || store_id || page_idx || page_bytes)
node = H("bpir-oram-node-v1" || level || node_idx || left || right)
```

The `store_id` should distinguish:

- index metadata image;
- index payload image;
- chunk metadata image;
- chunk payload image.

On read:

1. Read the page and the needed authentication path.
2. Recompute the path to a root or trusted subtree hash held in TEE memory.
3. Reject and poison the ORAM instance on mismatch.
4. Only then pass the page bytes to `CircuitOram`.

On write:

1. Write the updated page.
2. Recompute the affected authentication path.
3. Update disk-backed lower Merkle nodes as needed.
4. Update the trusted in-memory root / top-subtree hash last.

If the lower Merkle nodes are also on disk, their own paths must be validated
up to a trusted in-memory root. Keeping the top `d` levels in TEE memory gives a
simple tradeoff: more memory buys shorter disk authentication paths and fewer
untrusted hash-node reads.

This protects against runtime rollback/tampering of disk pages. It does not
need to survive reboot if startup always regenerates the ORAM.

### 3. External freshness service

An external freshness service is still useful if we later decide to persist ORAM
state across restarts. It is not the preferred path if every start rebuilds ORAM
from the immutable DB.

In the persistent-state variant, the service maintains a signed record:

```text
service_id
state_epoch
state_digest
binary_measurement / server_identity
updated_at
signature
```

The boot rule is to compare local `(epoch, digest)` against the latest external
record before serving. The commit rule is to update that record with
compare-and-set after each persisted request/batch.

### 4. Hardware monotonic counter

A true hardware monotonic counter, TPM NV counter, HSM-backed counter, or
equivalent secure service can replace the external freshness service in the
persistent-state variant.

For SEV-SNP specifically, do not assume that sealing or attestation alone gives
application-level rollback protection for disk state. If a vTPM is used, its
rollback resistance depends on how the vTPM state is protected. A host-backed
vTPM state file on the same rollbackable disk does not solve the problem.

### 5. Rebuild-only mode

This is the same idea as regenerate-on-start, but framed as an operational
fallback rather than the normal policy:

- if rollback or inconsistency is suspected, delete the ORAM state/image;
- rebuild from the immutable cuckoo DB;
- serve again only after verification passes.

## Recommended BitcoinPIR Policy

For the next stage, use short-term crash guard plus regenerate-on-start plus
runtime authenticated disk pages.

The minimum viable production policy is:

1. Every ORAM request that mutates state must either complete its page /
   Merkle-root update sequence before returning or poison the ORAM instance.
2. The server must not trust persisted ORAM state across restart. It should
   regenerate ORAM from the immutable cuckoo DB.
3. Runtime disk-backed ORAM pages must be authenticated by Merkle roots or
   top-subtree hashes held in TEE memory.
4. Any Merkle mismatch, page authentication failure, or failed state flush should
   poison the ORAM instance and stop ORAM serving until restart/regeneration.
5. Startup should log the ORAM generation parameters, generated image size,
   trusted Merkle memory footprint, and verification result.

This avoids cross-restart rollback without an external monotonic counter. It
does not make disk authentication free: the engineering cost moves into a
Merkle-authenticated page store and a measured startup regeneration path.

## Alternative: Shadow Pages

A copy-on-write shadow-page design is also valid:

1. Write modified pages to a shadow store.
2. Reads in the same transaction consult the shadow store first.
3. Commit by publishing a new generation manifest atomically.
4. Garbage-collect old generations later.

This avoids in-place page overwrite during the request, but it is more invasive:
the page store needs an overlay lookup path and a generation manifest. For the
current prototype, rollback journaling is smaller and fits the existing
`PageStore` abstraction better.

## Test Plan

Before VPSBG deployment, add tests that intentionally fail at each point:

1. Fail after removing a block from a path but before state save.
2. Fail during `drain_evictions`.
3. Fail during meta-page write.
4. Fail during payload-page write.
5. Fail during best-effort emergency state save.
6. Verify the ORAM instance is poisoned if emergency save fails.
7. Replay an old authenticated payload page while the process is still running
   and verify the Merkle root rejects it.
8. Replay an old authenticated metadata page while the process is still running
   and verify the Merkle root rejects it.
9. Replay or corrupt a disk-backed lower Merkle node and verify the trusted
   in-memory top hash rejects the path.
10. Restart from a copied old ORAM directory and verify startup ignores it and
    regenerates a fresh ORAM layout from the immutable cuckoo DB.

Each test should reopen the ORAM and verify:

- every sampled cuckoo bin still matches the source cuckoo table;
- repeated reads of the same logical block keep working;
- Merkle-authenticated page rollback is rejected during one process lifetime;
- after restart, old ORAM state/image files are not trusted as live state;
- regeneration is deterministic in input coverage but fresh in ORAM randomness.

The existing `scripts/oram_local_smoke.sh` uses `--cuckoo-oram-no-save`, so it
does not cover this. A new restart smoke should cover regeneration:

1. Build a tiny ORAM image.
2. Query found / missing / whale.
3. Stop the server cleanly.
4. Restart with a fresh generated ORAM directory from the same immutable DB.
5. Query again and compare against the mmap baseline.
6. Confirm the second run uses different ORAM randomness / roots from the first
   run.

## Deployment Rule

Do not run the VPSBG production ORAM image as the only live serving state until
one of these is true:

- the ORAM is fully memory resident for the intended production size; or
- startup regeneration from the immutable cuckoo DB is implemented, timed on
  VPSBG, and accepted operationally; and runtime disk-backed pages are protected
  by trusted in-memory Merkle roots / top-subtree hashes; or
- the production ORAM directory is explicitly treated as disposable and can
  always be rebuilt from the immutable cuckoo DB after any crash or mismatch.

For the current memory budget, the second option is the preferred design. It
avoids cross-restart rollback by construction and limits runtime rollback to
authenticated disk-page checks.

## References

- AMD SEV-SNP adds memory integrity protections against hypervisor data replay
  and remapping while the VM is running:
  https://www.amd.com/en/developer/sev.html
- AMD SEV-SNP attestation reports include platform / TCB information, which is
  useful for checking the TEE and firmware baseline but is not an application
  monotonic counter:
  https://www.amd.com/content/dam/amd/en/documents/developer/lss-snp-attestation.pdf
- "Rollback Protection for Confidential Cloud Services" summarizes why
  encryption alone does not prevent rollback attacks on TEE persistent state:
  https://eprint.iacr.org/2023/761.pdf
- "TEE Is Not a Healer" states the same core limitation: sealed state proves
  origin, not recency:
  https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.DISC.2025.39
- AMD-SB-3034 is a reminder that production attestation policy must also track
  current SEV-SNP firmware / TCB advisories:
  https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3034.html
