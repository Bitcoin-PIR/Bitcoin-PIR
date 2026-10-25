# Database rebuild: a new generation

How to build a new production database generation from a fresh Bitcoin Core
snapshot and roll it out: one Flow H campaign in
[Production operations](PRODUCTION_OPERATIONS.md#h-database-proofs-and-pins--auth),
with its step types. This page orders the runbooks: [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md)
("rotation"), [Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md)
("producer"), [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md)
("retention"). Identity values stay in [`web/src/attest-pin.ts`](../web/src/attest-pin.ts).

## 1. Purpose and current state

Use this page when production should move to a newer block and the operator
has the external Bitcoin volume (`/Volumes/Bitcoin`) with the Core node and the
retained snapshots; until then production stays on its current generation. It
never rebuilds the `940611 -> 948454` lineage, an accepted mixed-provenance
exception ([retention](DATABASE_ARTIFACT_RETENTION.md#accepted-exception-and-forward-rule)).

Current state is queried: Read — `scripts/production-status.sh`. The served
generation is each host's `databases.toml` plus the pins in `attest-pin.ts`;
the line above the backend tabs in `web/index.html` names its block and date.
Separate gates inside the campaign: renting the builder (Human); booting the
producer UKI ([its own authorization](ATTESTED_BUILDER_TIER3_UKI.md#boot-and-recover));
the Direct ORAM runtime UKI switch (Flow E); the server-1 MacBook node, run by
the operator ([Flow I](PRODUCTION_OPERATIONS.md#i-pir2-macbook-node--local-then-auth));
Pages (Flow C).

## 2. Prerequisites

### 2.1 External Bitcoin volume and Core node

| Item ([inventory](data-retention/production-940611-948454.inventory.tsv)) | Role in a rebuild |
| --- | --- |
| `txoutset_940611.dat` (volume and Hetzner) | Irreplaceable. Not an input; keep. |
| `txoutset_948454.dat` (volume and Hetzner) | Irreplaceable. `FROM_SNAPSHOT` of the new delta. |
| 948454 checkpoint, delta mirror, Direct inputs, V2 evidence | Rollback and debug baseline. |
| Bitcoin Core datadir (path not in these docs) | Syncs past the target height. |

Read — `shasum -a 256 -c SHA256SUMS` in
`/Volumes/Bitcoin/data/archive/production-940611-948454/`
([handoff README](data-retention/external-handoff-README.md)).

The producer takes one Core `dumptxoutset` v2 file plus `gettxoutsetinfo
muhash` of the same chain state (attested-builder README). The accepted V2
evidence used Bitcoin Core `v31.0.0` ([retention §A](DATABASE_ARTIFACT_RETENTION.md#a-irreplaceable-source-inputs));
the version string goes into `CORE_VERSION` and the evidence.

### 2.2 SEV-SNP builder host

- The producer UKI is a one-shot VPSBG measured-boot image: it mounts only the
  root filesystem, runs one job under `/home/pir/data`, writes SEV-SNP evidence
  and powers off. It needs `/dev/sev-guest` and has no SSH.
- None exists: the VPSBG pir2 host was retired on 2026-10-02, and the Direct
  ORAM host (server 26939) is an 8 GB guest that keeps serving.
- The browser checks builder and BHTM reports against the AMD Turin ARK
  (`web/src/oram-source-proof.ts`, `web/src/trust-chain-proof.ts`). A Milan
  builder needs those verifiers changed first.
- Disk (estimate): two snapshots of about 9.4 GB (the delta reads both); a
  snapshot run of roughly 60–80 GB (a ~40 GB server tree plus 10–20 GB of
  intermediates in the development pipeline, [scripts/README.md](../scripts/README.md));
  a delta run that grows with its range. A second disk is unused unless the
  rootfs spans it. `MIN_FREE_KB=50000000` is a floor; size runs with `df`/`du`.
- RAM: not recorded. Serving the current generation peaked near 31 GB
  before #362 streamed the startup hash
  ([MacBook runbook §0](runbooks/pir2-macbook-replacement.md)). The operator's
  earlier plan: VPSBG "RAM-Optimized VDS 64 GB 2x SSD" (4 vCPU, 64 GB, 200 GB).

### 2.3 Changes to land first — Local (Flow B) unless marked

1. Builder access: `scripts/vpsbg-data-disk.sh` takes `--server-id`, but its
   SSH host is fixed to the Direct ORAM host, also the only host in
   `deploy/vpsbg_known_hosts`. A separate builder needs a host override.
2. Human — DPF/HarmonyPIR proof transport. The producer emits no v1 sidecar;
   live DPF/HarmonyPIR clients read the v1 opcode from `proof_dir`, and
   `stage_vpsbg_tier3_generation.sh` and the Direct ORAM run script require v1
   files ([producer boundary](DATABASE_ROOT_ROTATION_RUNBOOK.md#prospective-producer-boundary-decision-4a)).
3. Runtime UKI inputs (§8.2) and web names (§8.1), once the build has values.

### 2.4 Time and money (estimates)

| Work | Estimate | Basis |
| --- | --- | --- |
| Builder host | €290/month list; €232 with a promo last time | operator's earlier plan |
| Core catch-up sync | hours | the node's last height |
| Producer UKI, runtime UKI | 5–15 min each | [workload table](PRODUCTION_OPERATIONS.md#workload-estimates) |
| Native V2 snapshot run, delta run | hours each; no wall-clock recorded | workload table |
| BHTM run, ~55k blocks | about 40 min last time | `stats.json` of the 954,920 chunk |
| Direct ORAM reconstruct; Pages | ≤15 min; 20–60 min | workload table |

### 2.5 Human-only

Renting and cancelling the builder; VPSBG image delete (the quota is 5 and this
campaign uploads two UKIs); the freeze (§3); the transport decision (§2.3); pin
values (Flow H step 5); deleting any retained snapshot, Direct input or
evidence ([list](PRODUCTION_OPERATIONS.md#human-only--do-not-start-from-this-page)).
No new keys are expected ([key management](KEY_MANAGEMENT.md)).

## 3. Choose and freeze the generation — Human

1. Target height N, with the reason: a block several confirmations deep (the
   last BHTM chunk ended at tip minus 6).
2. Catalog. The tooling assumes db0 full plus db1 delta (stage script, ORAM run
   script, `oramSourceProofManifestPathForDbId`). Default: db0 = full at N, db1
   = delta 948454 -> N, so clients at 948454 sync incrementally and clients at
   940611 resync; another shape is a [query-plan migration](ATTESTED_BUILDER_TIER3_UKI.md#native-delta-path).
3. Limits. BHTM: the browser needs both delta endpoints in one attested tree,
   and the current tree covers 899,999–954,920, so a later N needs a BHTM run
   (§6). Direct ORAM host: 480 s for db0, 180 s for db1, 900 s in total on
   8 GB (`unified-server-run.sh`), sized for today; a longer delta grows db1.
4. Freeze record ([rotation §1](DATABASE_ROOT_ROTATION_RUNBOOK.md#1-freeze-and-identify-the-new-generation)):
   producer review and exact commit; builder binary and producer UKI hashes;
   reserved SNP fields; N and its block hash from an independent source; both
   delta endpoints; Core MuHash at N; network magic `f9beb4d9`; database names
   and order; directory and generation names. No build before this record.

## 4. Produce the raw UTXO snapshot — Local

1. Local — sync Core past N; take `dumptxoutset` at exactly N and
   `gettxoutsetinfo muhash` of the same state. How to hold the node at N while
   the tip moves is not written in this repo.
2. Local — name it `txoutset_<N>.dat`; put size, SHA-256, Core version, MuHash
   and block hash in the freeze record. Copy it beside the others (volume
   `data/archive/`, Hetzner `/home/pir/data/snapshots/`). Once used it is
   irreplaceable: a later snapshot plus a delta cannot rebuild an earlier MuHash.
3. Read — check `txoutset_948454.dat` against its inventory SHA-256 first.

## 5. Attested build — Auth (Flow H steps 2–3)

Each run is one boot of the producer UKI. Files move with Flow F
(`scripts/vpsbg-data-disk.sh`); the image boots with Flow E commands
(`scripts/vpsbg-measured-boot.sh upload|switch`).

1. Auth — Flow F `open` on the builder. Its `/home/pir/bitcoin-pir/attested-builder`
   checkout must be at the frozen commit; `build_uki_attested_builder_tier3.sh`
   refuses any commit but its `ATTESTED_BUILDER_REQUIRED_GIT_COMMIT`. A new
   commit needs its own review, that default and the ORAM pin identity.
2. Auth — build the producer UKI with the Hetzner archive mirror
   ([build](ATTESTED_BUILDER_TIER3_UKI.md#build-the-producer-uki)); keep
   `.efi`, `.sha256`, `.meta`. Reuse an archived one only if the commit is
   unchanged and it boots on this host.
3. Auth — `put` both snapshots into `/home/pir/data/attested-builder/inputs/`
   and the snapshot `config.env`
   ([provision](ATTESTED_BUILDER_TIER3_UKI.md#provision-a-native-full-build-v2-generation)),
   with `ANCHOR_HASH` set (the runner then checks it) and `MIN_FREE_KB` raised.
4. Auth — `upload --uki FILE`, then `switch --server-id <builder> --image-id
   <producer>`. The guest builds and powers off; `vpsbg-production-status.sh
   --server-id <builder>` shows power state only. Stop and report if it runs
   far past the expected hours.
5. Auth — Flow F `open`; read `attested-builder-runs/builder-tier3-<RUN_ID>.status`
   (`status=ok`, `direct_oram_eligible=yes`; `latest/` appears only after the
   V2 gate) and run `pir-attested-builder verify-build-evidence` with the
   frozen values ([verify](ATTESTED_BUILDER_TIER3_UKI.md#verify-after-boot)).
6. Auth — `put` the delta `config.env` (`MODE=native-full-build-v2-delta`,
   `FROM_SNAPSHOT` 948454, `TO_SNAPSHOT` N, `TO_ANCHOR_HASH`), boot the
   producer again (`close --image-id <producer>`), repeat step 5.
7. Auth — collect both complete outputs (`server-db/`, `oram-direct-inputs/`,
   evidence, manifests, summaries, status, logs) to pir1 and the volume; check
   `all-artifacts.manifest.sha256` after each copy. Keep the builder in stock
   mode until §9.

Never fill a stage with `MODE=reattest-existing-v2`, a local `build_*` wrapper
or `tools/db-builder` (development-only); never edit a file under a producer
`server-db/`. The server checks the tree against `MANIFEST.toml` at startup and
refuses to load on a mismatch (`crates/protocol/runtime/src/table.rs`), which
systemd, launchd or runit turn into a restart loop; regenerating the manifest
(`scripts/build_db_manifest.sh`) loads but breaks the evidence binding.

## 6. BHTM extension and the Bitcoin anchor proof

The browser's anchor check proves both delta endpoints as leaves of one
SEV-SNP-attested BHTM tree and the latest MuHash against the DB proof
(`web/src/trust-chain-proof.ts`). The Direct ORAM runtime checks only the
delta's start, against a leaf proof and tree root baked into its UKI. The BHTM
producer, leaf-proof tool, stream exporter and proof-runner UKI are in
[`Bitcoin-PIR/bhtm`](https://github.com/Bitcoin-PIR/bhtm), not this repo.

1. Read — N ≤ 954,920: leaf proofs for 948,454 and N from that chunk's archived
   stream; no BHTM run.
2. Auth — otherwise one BHTM job whose tree holds 948,454 and N (for example
   from the 899,999 anchor), per the bhtm repo, using the Core node and an
   SEV-SNP host (the builder can serve).
3. Local — assemble, shaped like the current ones, the trust-chain manifest
   (`web/public/proofs/trust-chain/<id>/`) and `oram-source/current.json` (db0)
   and `current-db1.json` (db1) from the V2 outputs, the builder chip's
   ARK/ASK/VCEK and the MEASUREMENT in its SNP report.

## 7. Verify before deployment — Local (Flow H step 4)

1. Local — per database, `bpir-admin db-proof verify --proof-dir <V2 output>`
   with explicit `--expect-*` values; a delta adds `--expect-from-height` and
   `--expect-from-block-hash` ([rotation §2](DATABASE_ROOT_ROTATION_RUNBOOK.md#2-build-and-verify-before-deployment)).
   Values come from the freeze record and producer identity, never from a live
   server or the proof itself. Any error rejects the build.
2. Local — a local catalog with the proposed sync plan and exact trees: fresh
   and delta sync on DPF, HarmonyPIR and OnionPIR; found, absent, whale.
3. Local — Direct ORAM reconstruction from the exact producer inputs: 3 min
   without a stage → stop, target 10 min, hard stop 15 min.

## 8. Roll out (Flow H steps 5–10)

### 8.1 Pin and web change set — Human, then Local

One PR ([rotation §3](DATABASE_ROOT_ROTATION_RUNBOOK.md#3-prepare-the-matching-frontend-pins)):
`PRODUCTION_DB_PROOF_PINS` (per §2.3), `PRODUCTION_ONION_DB_PROOF_V2_PINS`,
`PRODUCTION_ORAM_DB_PROOF_V2_PINS` (own builder identity) and `PIR2_TIER3_PIN`
(§8.2) in `attest-pin.ts`; the names that carry the old generation
(`DELTA_940611_948454_DB_PROOF_PIN`, `MAINNET_948454_*`,
`DEFAULT_TRUST_CHAIN_MANIFEST_PATH`, the trust-chain link and delta check in
`web/index.html`); `web/public/proofs/` (§6); `web/reproduce.html`; the
snapshot line in `web/index.html` (block height and the date it was mined);
the `web/src/__tests__/` cases that read the old fixtures. Local —
`cd web && npm run build && npm test && npm run build-web` ([Testing](TESTING.md)).
Merge after review; §8.4 publishes.

### 8.2 Direct ORAM runtime UKI — Local, then Auth (Flow E)

The runtime image bakes the generation into its measurement: expected MuHash,
Direct input SHA-256s, the delta's start height, hash and MuHash, BHTM tree root
and from-leaf proof, ORAM directory names and time budgets
(`scripts/dracut/97bpir-tier3-init/unified-server-run.sh`; the leaf-proof name
also in `scripts/dracut/96bpir-unified-server/module-setup.sh` and
`scripts/build_uki_tier3.sh`). A new generation needs a new runtime UKI.

1. Local — change those inputs (Flow B); build with `scripts/build_uki_tier3.sh`
   ([UKI build](runbooks/uki-build.md)), `BHTM_FROM_LEAF_PROOF` = the 948,454
   leaf proof of §6.
2. Auth — `vpsbg-measured-boot.sh images`, then `upload --uki FILE`; record the
   id. Do not switch yet: neither image starts on the other's catalog.

### 8.3 Stage without activating — Auth ([rotation §4](DATABASE_ROOT_ROTATION_RUNBOOK.md#4-stage-both-hosts-without-activating-them))

- pir1: copy both complete outputs to new immutable paths under
  `/home/pir/data/`, verify hashes, write a candidate `databases.toml`, keep a
  timestamped copy of the active one. Check `pir1_disk_used` first.
- Direct ORAM host: Flow F `open`, `scripts/stage_vpsbg_tier3_generation.sh`,
  `close --image-id` with the id `open` printed. With `--oram-only` it reads
  `MANIFEST.toml`, proof sidecars and `oram-direct-inputs/`, not the tables;
  check its free space.
- Server 1: the operator copies the new directories from pir1 over the read-only
  rsync ([runbook step 3](runbooks/pir2-macbook-replacement.md)), checks hashes,
  writes a new `databases.toml` beside the old one; ~50 GB per generation.

### 8.4 Activate and publish — Auth ([rotation §5](DATABASE_ROOT_ROTATION_RUNBOOK.md#5-activate-in-a-maintenance-window))

1. Auth — stop the pir1 services that read `/home/pir/data/databases.toml`
   (`pir-primary`; `pir-secondary` too if enabled, see `deploy/systemd/`);
   Flow F `open` on the Direct ORAM host; atomically replace each host's
   `databases.toml` with its candidate.
2. Auth — start them (persisted hint-pool entries carry the database
   fingerprint and are dropped). On the Direct ORAM host,
   `close --image-id <new runtime image>`: the Flow E switch, its own gate.
3. Auth (MacBook) — restart the node on the new catalog, or keep it offline
   until it can; never serve a different generation from pir1. Server 1 is
   best-effort, so DPF and HarmonyPIR stay down until it matches.
4. Read — `db-proof verify-live` per database on pir1 and server 1 (v1 opcode
   only); `scripts/oram-host-check.sh` (it reads the local checkout's pins, so
   use the §8.1 branch); `scripts/production-status.sh`.
5. Auth — Flow C: merge the §8.1 PR, wait for `web-build.yml`, dispatch
   `deploy-web.yml` with `confirm_production_deploy=true`.
6. Read — browser acceptance in a new session
   ([rotation §6](DATABASE_ROOT_ROTATION_RUNBOOK.md#6-post-deployment-acceptance));
   record it under `docs/data-retention/`.
7. Auth — re-vendor (`npm run sync-vendor`) and redeploy [`Bitcoin-PIR/playground`](https://github.com/Bitcoin-PIR/playground).
8. Auth — publish the generation's data bundle
   ([Data bundle](runbooks/data-bundle.md)): hash on pir1, commit
   `deploy/data-bundles/<generation>/`, upload, verify. Other operators fetch
   it ([Operator guide §3](OPERATOR_GUIDE.md#3-data)); keep the previous
   generation's bundle until §8.5's rollback window closes.

### 8.5 Rollback — Auth ([rotation §7](DATABASE_ROOT_ROTATION_RUNBOOK.md#7-rollback))

As a unit: stop the pir1 services, Flow F `open`, restore every host's prior
`databases.toml` (server 1 included), start the services, `close --image-id`
with the previous runtime image (it bakes the previous generation), run
`verify-live`, publish the prior pins with Flow C, repeat the acceptance. Keep
the prior generation, configs, frontend commit and Pages artifact until the
rollback window closes.

## 9. Retention and cleanup

Before old active paths become eligible for cleanup, keep on both the volume
and the Hetzner archive host ([retention](DATABASE_ARTIFACT_RETENTION.md#keep-these-three-layers)):
all three Core snapshots (940611, 948454, N; N is the next delta's base); both
complete producer outputs with the producer review reference, producer UKI
`.efi`/`.sha256`/`.meta`, `build-evidence.verify.txt`, status files, staged
catalogs and both acceptance transcripts; the BHTM job, proofs, leaf proofs and
their stream; the previous runtime UKI; every layer A–C item of the
`940611 -> 948454` lineage. Add a handoff directory (README, `inventory.tsv`,
`SHA256SUMS`) for the new lineage on both hosts, copy it to
`docs/data-retention/`, and update `DATABASE_ARTIFACT_RETENTION.md`.

After the rollback window, once those copies are checked, failed bulk outputs
(keep their small status and evidence files and one representative failure),
derived Direct ORAM payload and the MacBook's old copy may go. Then cancel the
builder (Human). Deleting a snapshot, Direct input or evidence is Human-only.

## 10. Checklist

- [ ] Volume verified; Core past N; builder rented (Turin, or verifiers changed); Flow F reaches it.
- [ ] Transport decided; quota checked; freeze record done; `txoutset_<N>.dat` on volume and Hetzner.
- [ ] Producer UKI archived; both runs `status=ok`; evidence and `db-proof verify` pass; outputs copied.
- [ ] BHTM tree covers both endpoints; manifests built; local end-to-end and ORAM reconstruction pass.
- [ ] Pin/web PR green; runtime UKI uploaded; pir1, ORAM host and server 1 staged.
- [ ] Window: catalogs swapped, new runtime image attached, server 1 switched or offline.
- [ ] `verify-live`, `oram-host-check.sh`, `production-status.sh` pass; Flow C deployed.
- [ ] Acceptance recorded; playground re-vendored; retention done; builder cancelled.
