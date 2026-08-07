# Database and root rotation runbook

Use this runbook whenever production moves to a new full snapshot, adds or
replaces a delta, or rebuilds an existing height with different database
roots. It covers the proof, server catalog, production pins, and strict v2
OnionPIR proof pins as one release unit. DPF/HarmonyPIR retain their v1 proof
compatibility surface; strict OnionPIR does not use a v1 layout-pin fallback.

The safety rule is simple: a client may be temporarily unavailable during a
rotation, but it must never fall back to an unverified root. A proof/pin or
catalog mismatch is an expected fail-closed state while the two sides are
being switched.

## Invariants

- Every database selected by the sync plan has one independently verified
  `DatabaseProofBundle` and one matching entry in
  `PRODUCTION_DB_PROOF_PINS`.
- Every sync plan selectable from a supported starting height is contiguous in
  both height and block hash. Overlapping alternatives in the active catalog do
  not have to form one full-snapshot-to-delta chain: production may serve a
  latest full snapshot for fresh clients and a delta from an older retained
  client height to the same tip.
- Both hosts serve byte-identical database generation, catalog metadata,
  proof bundles, and bucket tree-tops before DPF/HarmonyPIR traffic is
  considered healthy. The Onion-enabled primary serves OnionPIR tree-tops;
  the secondary may retain matching Onion artifacts without exposing that
  protocol.
- DPF/HarmonyPIR bind the exact ordered `index_k + chunk_k` tree roots to the
  verified `bucket_super_root`. OnionPIR binds its consolidated tree-tops to
  the verified `onion_super_root`.
- `server-info.super_root` is diagnostic only. It must never be copied into a
  trusted-root store.
- Production remains strict throughout the rotation. Do not enable
  `Advisory`, weaken runtime/operator pins, skip the proof, or accept an
  unpinned layout to restore availability.
- Keep the prior complete generation and configuration until the rollback
  window closes. Never overwrite the known-good directories in place.

## 1. Freeze and identify the new generation

Before the expensive build begins, record:

- snapshot height and block hash;
- for every delta, the start/end heights and both endpoint block hashes;
- Bitcoin Core MuHash, network magic, builder commit and binary hash, and
  build-parameter hash;
- intended database IDs and catalog order;
- the directory names that will hold database files and immutable proof
  sidecars.

Verify the endpoint block hashes against an independent Bitcoin source. When a
delta is the first step for an incremental client, its starting height and hash
must match that client's independently trusted prior state. When deltas are
chained, each delta's starting anchor must exactly match the preceding delta's
ending anchor. It need not match the active full snapshot when the catalog
offers those databases as alternative paths to the same tip. Height continuity
alone is insufficient across a reorg.

## 2. Build and verify before deployment

Produce the database files, bucket and OnionPIR Merkle artifacts, and the
attested-builder proof bundle. Preserve the original builder output and
manifest; do not regenerate only the pins from copied server metadata.

Run the local verifier with explicit expected values rather than accepting
values printed by the proof itself:

```bash
cargo run --release -p bpir-admin -- db-proof verify \
  --proof-dir <immutable-proof-dir> \
  --expect-build-kind <snapshot-or-delta> \
  --expect-height <height> \
  --expect-block-hash <block-hash> \
  --expect-muhash <muhash> \
  --expect-bucket-root <bucket-super-root> \
  --expect-onion-root <onion-super-root> \
  --expect-builder-binary-sha256 <builder-sha256> \
  --expect-builder-git-commit <builder-commit> \
  --expect-network-magic <network-magic> \
  --expect-params-hash <params-hash>
```

For a delta, also pass `--expect-from-height` and
`--expect-from-block-hash`. Treat any verifier error as a build rejection, not
as a deployment warning.

Before copying anything to production, exercise a local catalog containing the
entire proposed sync plan. In `RequireVerified` mode, test fresh and delta sync
with DPF, HarmonyPIR, and OnionPIR. Include a found address, an absent address,
and a whale fixture; every result must finish Merkle verification before sync
state is committed.

## 3. Prepare the matching frontend pins

In the same change set, update `web/src/attest-pin.ts`:

1. Add or replace the `DatabaseProofPin` for every affected database in
   `PRODUCTION_DB_PROOF_PINS`. Copy values from the independently accepted
   proof record, not from a live server response.
2. For strict OnionPIR, update the matching entry in
   `PRODUCTION_ONION_DB_PROOF_V2_PINS`. Confirm the complete typed layout,
   packed-entry counts, table sizes, slot sizes, arity, and Merkle geometry
   against the independently accepted v2 proof. Do not recreate the removed
   `PRODUCTION_ONION_QUERY_LAYOUT_PINS` table or a v1 layout fallback.
3. Update the duplicate `PRODUCTION_DATABASE_PINS` in
   `crates/sdk/client/tests/integration_test.rs`. The scheduled native canary must
   fail on an unreviewed rotation; keep these values synchronized with the
   independently reviewed web pins.
4. Update proof artifacts under `web/public/proofs/` and any public block links
   or reproducibility manifests for the new endpoints.

Run the Rust/WASM/web tests that cover proof parsing, full-field pin matching,
typed installation, tree-top preflight, layout mismatch, found/absent/whale
verification, and disconnect cleanup. Strict OnionPIR is v2-only: do not add
v1 layout pins or a silent v2-to-v1 fallback. DPF/HarmonyPIR v1 proof
compatibility remains covered by their separate database-proof pins.

## 4. Stage both hosts without activating them

Copy the new database generation and proof directory to immutable paths on
Hetzner and VPSBG. Verify file hashes after transfer. Prepare a new
`databases.toml` for each host and retain a timestamped copy of the active
configuration.

Hetzner can be staged over its normal SSH/operator path. VPSBG Tier 3 has no
SSH, so a complete proof/root rotation must use a planned portal maintenance
boot: select `UKI: None`, reboot into the maintenance system, stage the
immutable directories over SSH, verify them, and write the proposed config to
a separate file without replacing the active `databases.toml`. Then reselect
the known-good Tier 3 UKI and reboot with the old active config until the
activation window.

The authenticated `bpir-admin upload --no-activate` path may stage an ordinary
database directory while Tier 3 is running, but it is not a substitute for the
maintenance boot and config swap: it cannot edit `databases.toml`, and the
current uploader generates a new `MANIFEST.toml`. Do not use it for an
attested-builder generation or proof bundle whose original manifest bytes are
part of the evidence. Preserve and hash-copy those artifacts through the
maintenance path instead.

Do not point either active server at the new generation until all of the
following are ready:

- complete files and proof sidecars exist on both hosts;
- the two proposed catalogs are identical for all fields used by sync
  planning and root verification;
- the matching frontend proof-pin change has passed review and CI;
- the prior generation, config, frontend commit, proof values, and Pages
  artifact are identified for rollback.

A data/proof rotation with an unchanged protocol does not by itself require a
new `unified_server` binary or UKI. A proof-schema or wire-protocol change does;
in that case, validate and deploy the compatible binary/UKI as a separate gate
before following the activation steps below.

## 5. Activate in a fail-closed maintenance window

There is no single atomic switch across both hosts and GitHub Pages. Use a
short maintenance window and accept temporary fail-closed queries:

1. Stop or drain the Hetzner services through their normal supervisor. In the
   VPSBG portal, select `UKI: None` and reboot into the SSH-capable maintenance
   system; this stops the Tier 3 query path without launching an ad hoc server.
2. Atomically replace each host's active `databases.toml` with the prepared
   version. Restart the normal Hetzner services. On VPSBG, reselect the same
   known-good Tier 3 UKI and reboot; an unchanged data/proof schema needs this
   config reload but does not require rebuilding the UKI. Do not run a second
   server that bypasses either deployed supervisor/boot path.
3. Until both hosts agree, treat the fleet as unavailable. DPF and the
   HarmonyPIR hint/query split must not mix generations.
4. Verify every database ID directly on both hosts:

   ```bash
   cargo run --release -p bpir-admin -- db-proof verify-live \
     --server wss://weikeng1.bitcoinpir.org --db-id <db-id> <expected-args>
   cargo run --release -p bpir-admin -- db-proof verify-live \
     --server wss://weikeng2.bitcoinpir.org --db-id <db-id> <expected-args>
   ```

5. Confirm runtime pin and operator identity on Hetzner, and runtime pin,
   operator identity, SEV-SNP measurement, AMD certificate chain, and secure
   channel on VPSBG.
6. Merge/deploy the already-reviewed frontend proof pins. Wait for the exact
   commit's Pages workflow to complete successfully.

Activating the servers before the new web pins makes old clients reject the
new proof; deploying the pins first makes new clients reject old servers.
Either ordering is safe but temporarily unavailable. Do not bridge that gap by
accepting both generations without an explicit verified multi-generation
design.

## 6. Post-deployment acceptance

Use a new browser session so no installed root can survive from a pre-rotation
connection. Run at least:

- one fresh DPF query and one previous-height delta sync;
- one fresh HarmonyPIR query and one previous-height delta sync;
- one standalone OnionPIR query;
- found and absent results on every backend, plus a whale result on at least
  one backend.

For each run, record that:

- DPF/HarmonyPIR runtime/identity summaries reach the expected strict tier;
- every database proof matches its production pin;
- tree-top preflight completes before the first address query;
- every displayed result receives `Verified` only after Merkle verification;
- sync state is merged only after all database results verify;
- the connection ends disconnected.

HarmonyPIR hints may remain browser-cached. Their native blob fingerprint
includes database height, geometry, tag seed, and master seeds; a stale blob is
rejected and fetched again. Confirm that behavior rather than manually
relabeling an old cache as current. Long-lived native clients must disconnect
and reconnect so session roots and authenticated tree-top caches are cleared.

Record the proof values, host config hashes, server/UKI pins, frontend commit,
Pages run URL, `verify-live` output, and browser smoke result in the deployment
record. Update `STRICT_VERIFICATION_PROGRESS.md` only if the trust policy
itself changes; routine rotations belong in a dated operations record.

## 7. Rollback

Rollback the generation as a unit:

1. Stop the Hetzner services and use the VPSBG portal to select `UKI: None` and
   reboot into the SSH-capable maintenance system.
2. Restore the prior `databases.toml`, database directories, and proof
   directories on both hosts. Restart the normal Hetzner services, then
   reselect the prior known-good Tier 3 UKI in the VPSBG portal and reboot.
3. Run `verify-live` for every restored database ID on both hosts and confirm
   both catalogs agree.
4. Redeploy the prior known-good frontend proof pins and wait for Pages.
5. Repeat the strict browser acceptance checks above.

If only one host fails after activation, do not leave a mixed fleet serving.
Restore both to the last generation proven on both hosts, then investigate
offline. A frontend/server mismatch during rollback should remain
fail-closed; never use `Advisory` as a rollback mechanism.
