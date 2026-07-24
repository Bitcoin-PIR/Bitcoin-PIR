# ORAM live-image binding

Status: **production rollout complete as of 2026-07-24**. BitcoinPIR PR #70
landed the regenerate-on-boot implementation, and PR #71 fixed the final
trusted-state path contract and published the deployed pins. The
proof-producing and trusted-state-separation changes landed in Bitcoin-PIR/oram
PRs #4 and #5. The selected production model discards prior mutable ORAM state
and rebuilds from proof-bound inputs before listening. This document also
retains the more complex persistent-lineage design for any future node that
cannot afford regeneration; that design is not an outstanding requirement for
the current deployment.

## Regenerate-on-boot rollout status

- [x] Regenerate db 0 and db 1 ORAM images from fixed-hash direct inputs before
      the server listens.
- [x] Copy direct inputs and proof artifacts into SEV-protected `/run` tmpfs
      before hashing/building, eliminating the disk hash/build TOCTOU.
- [x] Keep controller state, authenticated roots, and lookup metadata in
      `/run`; only authenticated bulk ORAM pages remain on persistent disk.
- [x] Embed and verify the existing 940611 BHTM inclusion proof for the delta
      starting MuHash, block hash, height, and pinned tree root.
- [x] Bind the BHTM starting anchor to the attested-builder DB evidence and add
      source/proof mutation tests.
- [x] Require the frontend trust-chain manifest and production pin to agree on
      `fromMuhashHex`.
- [x] Merge the implementation and build the final binaries from the merged
      commit.
- [x] Build, archive, upload, and boot the final Tier 3 UKI.
- [x] Pass AMD attestation, encrypted-channel, operator-identity, db 0/db 1
      proof, padded ORAM, and strict browser acceptance gates.
- [x] Publish the final binary/UKI/MEASUREMENT pins and deployment record.

The final deployment record and reviewed values are in
[`STRICT_VERIFICATION_PROGRESS.md`](STRICT_VERIFICATION_PROGRESS.md) and
[`PHASE3_ROADMAP.md`](PHASE3_ROADMAP.md). The archived production UKI is
`main-7b6cf108-trusted-path-fix-20260724T001409Z-5b8548888b5b.efi`.

## The missing link

The source-binding proof establishes a statement of the following form:

```text
approved inputs + approved builder code + committed parameters
    -> archived ORAM image identity A
```

Runtime attestation establishes a different statement:

```text
approved UKI/runtime binary + channel key
    -> live process B
```

Neither statement, by itself, says that process B opened image A. A deployment
could present a valid proof for archive A, boot the expected measured binary,
and configure that binary to open a different but internally consistent image
C. A successful ORAM query only shows that C is usable; it does not close the
A-to-C identity gap.

This is why a source-binding proof cannot, on its own, prove byte-for-byte
identity of the files currently opened by the service.

The gap is concrete in the current implementation:

- `mainnet_948454.json` commits SHA-256 and size for the fourteen initial
  `direct-index.*` / `direct-chunk.*` artifacts, plus the initial controller
  state and authenticated meta/payload roots;
- `unified_server` opens the configured paths and validates pages against the
  `CircuitStoreAuthState` loaded beside those paths; and
- runtime attestation commits the UKI/binary, channel key, and database
  manifests, but not the source-proof manifest digest, ORAM genesis identity,
  or the roots in the opened `CircuitStoreAuthState`.

Consequently, the page authentication protects a live process against a page
that disagrees with the roots it loaded, but the client has no attested reason
to believe those loaded roots are the roots certified by the source proof. A
substituted image can bring its own internally consistent auth-state file.

## Why hashing the archive on every query is not the right fix

ORAM storage is stateful. Reads normally reshuffle or rewrite paths, and the
position map, stash, metadata, and authenticated storage state advance. After
the first access, a healthy live image need not be byte-identical to its
initial archive.

There are therefore two useful but distinct checks:

1. **Point-in-time byte equality:** while the service is quiesced, hash every
   file in a stable snapshot and compare the manifest digest with an archived
   copy. This is expensive, blocks writes, and proves only that snapshot.
2. **Cryptographic lineage:** bind the initialized image identity and each
   authenticated state transition to the attested runtime. This is the normal
   online security property and does not require reading every byte after each
   query.

The production design should implement lineage. A full snapshot hash remains
an operator audit and disaster-recovery check. In particular, the archived
initial image has already diverged from any production copy that has answered
queries; literal equality is neither expected nor a suitable steady-state
badge.

## Proposed protocol

### 1. Canonical image identity

Define a fixed-width, versioned `OramImageIdentityV1` containing at least:

- network and `db_id`;
- source evidence/root-payload digest and archive-manifest digest;
- ORAM implementation revision and complete layout parameters;
- ordered file roles, sizes, and genesis digests for every immutable or
  initialized component;
- initial authenticated ORAM/controller roots; and
- a domain-separated `genesis_image_id` computed over all fields.

The archive, expanded runtime directory, and configuration must all name the
same `genesis_image_id`. Paths are diagnostic only and must not be committed as
identity.

### 2. Verify the opened storage

When opening a database, the attested runtime must:

1. open all files through one database handle and reject substitutions,
   missing roles, duplicate roles, unexpected sizes, or unsupported formats;
2. validate immutable components against the image manifest;
3. validate the persistent ORAM controller metadata and authenticated roots;
4. require those roots either to equal the genesis roots or to continue a
   valid state chain rooted at `genesis_image_id`; and
5. refuse to serve ORAM requests until the binding succeeds.

The verified handle, not a config path or self-reported root, must be passed to
the query engine.

### 3. Bind the live handle into runtime attestation

Extend the attested runtime commitment with an ordered per-database value:

```text
live_image_binding = SHA256(
    "BitcoinPIR/oram-live-image/v1" ||
    db_id || genesis_image_id || state_epoch ||
    current_authenticated_roots || state_chain_head
)
```

Commit the set of `live_image_binding` values, together with the runtime binary
and encrypted-channel public key, into the SEV-SNP `REPORT_DATA` derivation.
The server must expose the corresponding typed fields in a versioned runtime
attestation response. Clients recompute the commitment; a server-reported
string is not evidence.

Because the quote describes a moment in time, the secure session must be bound
to the attested channel key. The database handle may not be swapped after the
quote without invalidating or rotating the attestation state.

### 4. Authenticate state transitions

Persist a crash-consistent transition record after each complete ORAM
transaction:

```text
state_chain[n + 1] = SHA256(
    "BitcoinPIR/oram-state/v1" || genesis_image_id ||
    (n + 1) || authenticated_roots[n + 1] || state_chain[n]
)
```

The files, controller metadata, epoch, and chain head must become durable as
one recoverable transaction. Startup must reject torn or internally
inconsistent state instead of silently rolling back part of it. This binding
also needs to cover any position map, stash, or journal whose substitution can
change ORAM semantics.

This step builds on, rather than replaces, the existing authenticated meta and
payload page stores. `CircuitStoreAuthState` already supplies useful live
roots. The missing work is to bind its genesis roots to the source proof, make
its mutable controller/auth-state transaction crash-consistent, and expose the
verified binding through attestation.

### 5. Add a typed client check

Add a versioned `REQ_GET_ORAM_LIVE_IMAGE_PROOF` response or include the fields
in the existing runtime attestation response. Strict clients should require,
in order:

1. valid runtime identity, operator policy, and (on VPSBG) AMD SEV-SNP chain;
2. an encrypted channel bound to the attested channel key;
3. a source proof whose `genesis_image_id`/manifest digest matches the live
   image binding for every ORAM database in the query plan; and
4. a well-formed current state commitment under that genesis identity.

Only then may an ORAM query start. The frontend can summarize this as
`ORAM image: VERIFIED`, with the genesis ID, epoch, current roots, and evidence
chain available in the verification-details panel.

## Rollback is a separate trust problem

A valid SNP quote can attest an old but internally valid disk snapshot after a
reboot. A hash chain detects torn or unrelated state, but a client that has
never seen a newer head cannot know that the server rolled back.

If freshness across reboots is required, publish `(genesis_image_id, epoch,
state_chain_head)` to an external witness or append-only transparency log, or
use a trusted monotonic counter with suitable durability and availability.
Returning clients may additionally pin the highest accepted epoch locally.
Without one of these mechanisms, the precise claim is **live image consistency
and lineage**, not global anti-rollback freshness.

There is a simpler alternative when startup cost is acceptable: discard prior
mutable ORAM state at every boot, read the immutable proof-bound direct source
tables, and generate a fresh ORAM image inside the measured Tier 3 startup
path. In that model the attested claim changes to “this measured runtime path
generated the live ORAM from source identity X,” and an external monotonic
counter is unnecessary. The archived ORAM output is then a reproducibility
witness, not the byte-for-byte runtime image. This is the model implemented by
`scripts/dracut/97bpir-tier3-init/unified-server-run.sh`; the persistent
lineage protocol above is needed only if nodes must reuse an existing large
image across restarts.

The implementation must not hand the generated controller state back through
untrusted persistent storage between `oramctl` and `unified_server`. Direct
inputs and DB evidence are first copied from disk into the SEV-protected
`/run` tmpfs; `oramctl` hashes and reads those same trusted copies. It writes
the small controller states, authenticated roots, and direct lookup metadata
directly into `/run/bitcoinpir-oram-state`. `unified_server` opens and updates
those trusted files while accessing only the large authenticated
payload/meta/hash page images on persistent disk. This closes both the source
hash/build TOCTOU and the process-boundary whole-image substitution window.

The sidecar Merkle roots are also bound to the page bytes emitted by that same
trusted build. While writing each metadata and payload page in order,
`oramctl` accumulates its expected domain-separated Merkle root using only
`O(log N)` trusted memory. It then builds the disk-backed sidecar tree and
requires both resulting roots to equal those expected roots before saving the
trusted controller state. A host replacement between ORAM generation and the
sidecar scan therefore fails closed instead of becoming the installed trust
root. Strict source-bound authenticated builds use the sidecar layout; the
embedded-tree layout is rejected for that mode until it has an equivalent
construction-time binding.

For the production delta, the measured startup path also embeds and verifies
the existing BHTM inclusion proof for height 940611. `oramctl` recomputes the
Core MuHash from the proof's complete 384-byte MuHash, recomputes the leaf and
Merkle path, and requires the resulting tree root, height, block hash, and
starting MuHash to equal the reviewed UKI pins. It also requires the
attested-builder DB evidence to name the same starting height and block hash.
This closes the previous gap where `--expected-from-muhash` was recorded but
not compared to certified proof material, without regenerating the expensive
database or BHTM proof.

## Persistent-reuse delivery sequence

1. Inventory the ORAM file/controller format and identify the authoritative
   `CircuitStoreAuthState` roots, position map, stash, and journal boundaries;
   choose explicitly between regenerate-on-boot and persistent reuse.
2. Freeze `OramImageIdentityV1` and golden vectors in the ORAM library and
   source-proof producer.
3. Add an offline quiesced-image verifier so retained archives can be checked
   before any runtime changes.
4. Make runtime open return a verified image handle and fail closed before
   listening; add corruption, substitution, torn-write, and wrong-image tests.
5. Extend runtime attestation and native/WASM verification with live image
   bindings, then rebuild and remeasure the VPSBG UKI and update reviewed pins.
6. Deploy one database in audit mode, compare offline and live identities,
   then enforce strict mode for both databases and run padded direct-ORAM
   canaries.
7. Add an external freshness witness only if rollback resistance is part of
   the public claim.

The first implementation decision should be made after step 1. The library
already exposes authenticated meta/payload roots, but those roots do not by
themselves cover freshness or prove that controller, stash, position-map, and
journal state advance atomically with the page images. Any uncovered mutable
component must be added to an authenticated checkpoint before runtime
attestation can make a complete live-image claim.
