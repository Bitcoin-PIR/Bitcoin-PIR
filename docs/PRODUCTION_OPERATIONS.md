# Production operations

Start here for any authorized production change. Query live state first —
never infer it from documents. Classify the ask as **one campaign**: a
named release (for example R5.1) or one flow A–I. One explicit
authorization covers that whole campaign. Run the campaign's numbered
steps in order. Do not invent a second campaign, and do not re-ask
between steps of the same campaign.

Live status:

```sh
scripts/production-status.sh
```

That prints pir1 SSH health, a public attest of the pir2 MacBook node
against `PIR2_MACBOOK_PIN`, and the Direct ORAM TEE host's VPSBG status
plus an attest against `PIR2_TIER3_PIN` (MEASUREMENT, binary, AMD chain).
Each script has `--help`.

The VPSBG pir2 host was retired on 2026-10-02. The pir2 slot (DPF server 1
and the HarmonyPIR query server) runs on a MacBook without a TEE (Flow I).
Direct ORAM runs on a separate VPSBG TEE host since 2026-10-03: server
26939 (212.73.134.61, AMD EPYC 7713P Milan, `wss://weikeng2.bitcoinpir.org`).
It serves Direct ORAM only (`unified_server --oram-only`), so its data disk
needs each database's `MANIFEST.toml`, proof sidecars and
`oram-direct-inputs/`, not the DPF or OnionPIR table files. Flows E–F and the
VPSBG scripts target this host. The live image still runs the retired
sealed-identity profile; a runtime UKI built from this tree has no server
identity (a fresh channel key every boot, bound by the attestation report)
and serves Direct ORAM free on a best-effort lane. Leave
`/home/pir/data/pir2-sealed/` in place while a rollback to a sealed image is
possible.

Identity values (hashes, measurements, image IDs) stay in
[`web/src/attest-pin.ts`](../web/src/attest-pin.ts) or in live command
output. Do not copy them into prose.

## How an agent should use this page

1. Classify the ask against the flow table, or as a named release that
   already lists its flows. If it matches none, stop and ask; do not
   improvise.
2. State the campaign, the remaining steps, the expected duration, and
   the hard stop **before** a long build, upload, or reboot.
3. Run only scripted commands shown here. Human-only work (keys, funds,
   image delete) still needs a separate decision. Pin edits and Pages
   dispatch are part of a release campaign when the user authorized that
   release, not a second ask.
4. When a step succeeds, continue if the next step is still in the
   authorized campaign. Stop on failure, a hard stop with no progress,
   or a step that belongs to a different campaign.

### Step types

| Type | Meaning | Agent may run? |
| --- | --- | --- |
| Read | No host, image, pin, or fund change | Yes, without extra authorization |
| Local | Laptop or CI check; no production mutation | Yes for the matching change class in [Testing](TESTING.md) |
| Auth | Changes a remote host, image, service, Pages site, or identity | Yes for every remaining step of the authorized campaign |
| Human | Key generation, funds, image delete | Do not start; ask and wait |

Each command does one thing: `upload` does not switch, `put` does not
close, and `close`/`switch` take the caller-supplied `--image-id`. The
agent issues those commands in campaign order without a new ask between
them. Recoverable API stalls in the same campaign (for example a 423
during `open`, then `start`) are in-campaign, not a new authorization.

### Workload estimates

Use these before starting. Missing progress before the hard stop means
stop and report.

| Work | Expected | Hard stop | Progress signal |
| --- | --- | --- | --- |
| `production-status.sh` | ~30 s | 20 s per SSH/API call | pir1, pir2 and ORAM host output, exit 0 |
| Local web check (`tsc` + vitest + `build-web`) | 2–10 min | 15 min | npm scripts exit 0 |
| PR `web-build.yml` | 10–25 min | 30 min job | wasm-pack, tsc, vitest, `build-web` |
| Pages `deploy-web.yml` | 20–60 min | 75 min build | `build-web`, then deploy job |
| pir1 `cargo build --release -p runtime` | 2–5 min | 15 min | compiler output, then systemd active |
| Tier 3 **runtime** UKI (`build_uki_tier3.sh`) | 5–15 min | 15 min | dracut, inventory, `ukify`, archive |
| Attested-builder **producer** UKI | 5–15 min | 15 min | archive `.efi` + `.meta` |
| Native full-build V2 snapshot/delta | hours; no wall-clock is written here | no progress for 3 min → stop | `build-summary.txt`, then `latest/` only after the V2 gate |
| Direct ORAM release reconstruct | target 10 min | 15 min (3 min without a stage) | build stages in `status.json` |
| VPSBG `images` / `upload` | seconds / a few min | 10 min upload | `image_id=` lines |
| VPSBG `switch` / `close` attachment | seconds; starting is separate | 15 min | `boot_mode=measured`, expected image id; read `running` separately |
| Data-disk `open` | 2–10 min | 15 min | `boot_mode=stock`, then `stock rootfs reachable over SSH` |
| `oram-host-check.sh` | 5–20 min | 15 min wait, then attest + queries | attest, channel-test and ORAM query output |

## Flow catalog

| Id | When to use | First command |
| --- | --- | --- |
| A | Diagnose live hosts | `scripts/production-status.sh` |
| B | Source / PR; no production mutation | [Testing](TESTING.md) |
| C | Publish the browser client to GitHub Pages | Flow C below |
| D | Change the pir1 Hetzner binary or unit | Flow D below |
| E | Build, upload, switch, or roll back the Direct ORAM host's **runtime** UKI | [UKI build](runbooks/uki-build.md) then [VPSBG image](runbooks/vpsbg-image.md) |
| F | Edit `/home/pir/data/` on VPSBG | [Key management](KEY_MANAGEMENT.md) |
| H | Produce or rotate DPF / Harmony / Onion v2 / ORAM proofs | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |
| I | Rebuild, restart, or re-pin the pir2 MacBook node (no TEE) | Flow I below |

Payment issuer deploy, mainnet Lightning, key generation, funds, and
image deletion are **not** flows.

## A. Diagnose — Read

1. Read — `scripts/production-status.sh`.
2. Read — if only the Direct ORAM host matters:
   `scripts/vpsbg-measured-boot.sh status --server-id 26939`.
3. Read — before a UKI upload:
   `scripts/vpsbg-measured-boot.sh images`.
4. Stop. `image_id=unavailable` is a valid observation, not a selection.

Success: the commands exit 0.

## B. Source change and CI — Local

Green CI is not a deploy. Merges are manual; there is no required
aggregate check on `main`.

1. Local — pick the narrowest row in [Testing](TESTING.md).
2. Local — open a `codex/` branch; do not mix a production mutation with
   a docs or CI cleanup in the same commit.
3. Local — open a PR against `main`. Path-filtered workflows run on
   that PR.
4. Human — inspect the PR's checks, then merge only if the user asked.

Usual PR workflows, when their paths match:

| Workflow | What it proves | Not a deploy of |
| --- | --- | --- |
| `web-build.yml` | wasm-pack, `tsc`, vitest, `build-web` | GitHub Pages |
| `pir-sdk-integration.yml` | deterministic SDK jobs | live servers (live jobs are schedule/dispatch) |
| `rust-ci.yml` | Rust test/clippy lanes, including pir-core build reproducibility | production hosts, databases |

## C. Web / GitHub Pages — Local then Auth

The site is `https://www.bitcoinpir.org/`. A push to `main` does **not**
publish. `.github/workflows/deploy-web.yml` deploys only on
`workflow_dispatch` from `main` with `confirm_production_deploy=true`.
The build job has contents-read only; Pages write/OIDC is confined to
the deploy job.

1. Local — land the web or pin change through Flow B. Pin edits must
   keep `web/src/attest-pin.ts` and the duplicate pins in
   `crates/sdk/client/tests/integration_test.rs` consistent
   ([rotation runbook](DATABASE_ROOT_ROTATION_RUNBOOK.md) §3).
2. Local — wait for `web-build.yml` on that `main` commit.
3. Auth — dispatch `deploy-web.yml` on `main` with
   `confirm_production_deploy=true`. Expected 20–60 min, hard stop
   75 min. Progress: wasm-pack, tsc, vitest, `npm run build-web`, then the
   deploy job.
4. Read — optional live browser check, only if the user asks.

Success: the dispatch run's deploy job is green and the live site
serves that commit. Updating pins is a separate Human step if the
check fails.

## D. pir1 Hetzner binary — Auth

pir1 is `root@65.21.91.217`, public `wss://weikeng1.bitcoinpir.org`.
It serves DPF-0, OnionPIR, and Harmony hints. There is no Hetzner
script; pin SSH against [`deploy/known_hosts`](../deploy/known_hosts).

1. Local — Flow B for the runtime change. Production binary is
   `cargo build --locked --release -p runtime --bin unified_server`
   plus `strip --strip-debug`. Nix is not the authority.
2. Auth — on the host, fast-forward the reviewed commit, build the
   same command, restart `pir-primary`. Restart `cloudflared` only if
   the tunnel itself is broken. Build 2–5 min, hard stop 15 min.
   `unified_server --version` prints the crate version, git revision,
   and binary sha256 of an installed binary without starting a server;
   `--help` prints the flag reference. So that clients do not report a pir1
   binary mismatch meanwhile, first deploy `PIR1_PIN` with the running build
   as `transitionBinarySha256Hex` (as in Flow I), then drop it afterwards.
3. Read — `scripts/production-status.sh` and confirm `:8091` /
   `pir-primary` are active. Do not treat `pir-secondary` as the
   public peer. This step is systemd/SSH health only; it does not
   compare the live binary to `PIR1_PIN`. That pin is checked by the
   browser client after Flow C.

Database swaps on pir1 stay inside Flow H. Do not restart during a
partial database write.

## E. Direct ORAM host **runtime** UKI and measured boot — Local then Auth

This flow builds and switches the **serving** UKI
(`scripts/build_uki_tier3.sh`). The attested-builder **producer** UKI
(`scripts/build_uki_attested_builder_tier3.sh`) is Flow H. They share
the VPSBG measured-boot slot and must not be substituted.

Details: [UKI build](runbooks/uki-build.md),
[VPSBG image](runbooks/vpsbg-image.md). Token default is
`.secrets/vpsbg-api-token`.

1. Read — Flow A. Record the live `image_id` as the rollback target.
2. Read — `scripts/vpsbg-measured-boot.sh images`. If VPSBG's image
   quota (5) is full, stop; deleting an image is Human.
3. Local — on the approved Linux build host, set every UKI input
   explicitly and run `scripts/build_uki_tier3.sh`. Nix and the
   attested-builder UKI are not this runtime UKI.
4. Auth — `scripts/vpsbg-measured-boot.sh upload --uki FILE`.
   Record the returned image id.
5. Auth — `switch --server-id ID --image-id NEW` only after a separate
   authorization. This reboots immediately.
6. Read — `scripts/oram-host-check.sh`. It attests against the pins in
   `web/src/attest-pin.ts` (update them for the new image first) and
   sends one ORAM query per database. Mismatch is a hard stop.
7. Auth — rollback is `switch` with the **previous** image id, then
   step 6 again.

A data/proof-only rotation does not need a new UKI (Flow H).

## F. VPSBG data-disk window — Auth

Use [`scripts/vpsbg-data-disk.sh`](../scripts/vpsbg-data-disk.sh).
Never build a provisioner UKI. Detach body is
`{"kernel_image_id":null}`. SSH only when `boot_mode=stock`. The stock
rootfs rate-limits new SSH connections (6 per 30 s per source); the wrapper
therefore multiplexes every `put`/`get`/`ssh` of a window over one
ControlMaster connection (socket under `VPSBG_SSH_CONTROL_DIR`, default
`/tmp/bpir-vpsbg-ssh-<uid>`), torn down by `open` and `close`. Do not add
your own `ssh`/`scp` calls beside it during a window.

1. Read — Flow A.
2. Auth — `open`. It prints `close_image_id`, the live image to
   reattach. Hard stop 15 min: `boot_mode=stock` and SSH.
3. Auth — `put` (writes), or Read `get` / `ssh`.
4. Auth — `close --image-id ID` with the id `open` printed, unless the
   user named a different one.
5. Read — confirm the expected image is attached. `close` does not start a
   stopped guest; starting it requires its own explicit authorization. Run
   Flow E step 6 only when the guest should be serving again.

## H. Database, proofs, and pins — Auth

Follow [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) and
read [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md)
before touching artifacts. Producer UKI details:
[Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md).

One generation is **one** `server-db` tree plus its evidence. DPF and
Harmony share INDEX/CHUNK + `bucket_super_root` with that V2 evidence.
Live DPF/Harmony clients still fetch the **v1** opcode from `proof_dir`
(retained mixed-provenance sidecars on the current lineage). OnionPIR
(pir1) and Direct ORAM (the VPSBG host) consume the same tree's Onion half plus
**v2** `proof_v2_dir`. The producer UKI does not emit a parallel v1
sidecar. Do not pair a serving tree from one run with a proof directory
from another.

Production databases come from the locked external
`Bitcoin-PIR/attested-builder` native full-build V2 pipeline at an
exact reviewed commit. That repo's README is the producer scope:
one run emits DPF/Harmony, Onion v2, and Direct ORAM inputs together.
`scripts/build_full.sh` and `tools/db-builder` are development-only.
`MODE=reattest-existing-v2` is a proof-migration tool and is
ineligible for production TEE-ORAM.

The live `940611 -> 948454` lineage is an accepted mixed-provenance
exception. Do not rebuild or relabel it. The two Core snapshots are
irreplaceable; a later snapshot plus a delta cannot reconstruct the
earlier MuHash.

VPSBG file placement is Flow F, not the portal and not a provisioner
UKI. Pin publication is Flow C. A new runtime binary/UKI, if the
schema requires one, is Flow D or E as a **separate** gate.

### H.0 Classify the proof family — Read

Identity values stay in [`web/src/attest-pin.ts`](../web/src/attest-pin.ts).
Do not copy them into prose.

| Family | Serves | Pin / lock | Verifier an agent may run |
| --- | --- | --- | --- |
| DB proof v1 | DPF + Harmony live opcode | `PRODUCTION_DB_PROOF_PINS` | `verify-live` (v1 opcode only). Roots are already in the V2 evidence; the UKI does not emit a second v1 sidecar |
| Onion v2 | pir1 OnionPIR | `PRODUCTION_ONION_DB_PROOF_V2_PINS` | local `db-proof verify`; **not** `verify-live` |
| ORAM v2 | Direct ORAM host | `PRODUCTION_ORAM_DB_PROOF_V2_PINS` | same local v2 verifiers; **not** `verify-live` |
| Builder SNP | attested-builder run | ORAM source manifests under `web/public/proofs/oram-source/` | `pir-attested-builder verify-build-evidence` |
| Runtime SNP | serving Direct ORAM UKI | `PIR2_TIER3_PIN` | Flow E step 6; `bpir-admin attest` |
| pir1 binary | serving pir1 | `PIR1_PIN` | browser after Flow C; Flow D step 3 is host health only |
| BHTM / trust-chain | height + block hash + MuHash | `web/public/proofs/trust-chain/` | browser tests; UKI consumes `BHTM_FROM_LEAF_PROOF` |

`server-info.super_root` is diagnostic. Never copy it into a pin.
`--expect-*` values come from the independently accepted proof record,
never from a live server or from the proof printing itself.

### Numbered rotation steps

1. Human — freeze the generation (rotation §1): producer review,
   exact builder commit, reserved SNP fields, height/hash, Core
   MuHash, magic, params hash, db ids, directory names. Independent
   block-hash check. Do not start a build.
2. Auth — if a new producer UKI is required, build
   `scripts/build_uki_attested_builder_tier3.sh` (not
   `build_uki_tier3.sh`). Place `config.env` with Flow F. Switch that
   builder image with Flow E-style `upload` / `switch` as its own
   authorization. The guest powers off when the run ends.
3. Auth — Flow F `open` to collect the complete output
   (`server-db/`, `oram-direct-inputs/`, V2 evidence, manifests,
   `build-summary.txt`). `latest/` exists only after the V2
   `full_build` gate. Then `close` to the recorded **runtime** image.
4. Local — `bpir-admin db-proof verify` with explicit `--expect-*`; it
   also prints the typed Onion layout.
   Direct ORAM reconstruct: 3 min without a stage → stop; 15 min hard
   stop. Missing progress is a failed build, not a reason to delete
   Core snapshots.
5. Human — edit pins in the same change set (rotation §3):
   `PRODUCTION_DB_PROOF_PINS`, `PRODUCTION_ONION_DB_PROOF_V2_PINS`,
   `PRODUCTION_ORAM_DB_PROOF_V2_PINS`,
   `crates/sdk/client/tests/integration_test.rs`, and
   `web/public/proofs/`. Do not recreate
   `PRODUCTION_ONION_QUERY_LAYOUT_PINS`.
6. Local — Flow B tests for that pin/lock change.
7. Auth — stage both hosts without activating. VPSBG:
   Flow F + `scripts/stage_vpsbg_tier3_generation.sh` (candidate
   catalog only). Keep `path` = V2 `server-db`, `proof_dir` = locked
   V1 sidecars, `proof_v2_dir` = complete V2 output.
8. Auth — activate in a fail-closed window (rotation §5): Flow F
   `open`, atomic `databases.toml` replace, Hetzner restart, `close`
   with the known-good **runtime** image id.
9. Read — `db-proof verify-live` on both hosts covers **v1 /
   DPF+Harmony only**. Onion/ORAM v2 live check is the browser/WASM
   path after Flow C, or `oram-host-check.sh` for the runtime
   SNP + ORAM smoke. Do not invent a unified “verify all proofs”
   command.
10. Auth — publish pins with Flow C.

Rollback is rotation §7: restore both hosts to the last generation
proven on both, then Flow C for the prior pins. If one host fails,
do not leave a mixed fleet.

## I. pir2 MacBook node — Local then Auth

The node has no TEE: clients check it against `PIR2_MACBOOK_PIN` and its
operator-signed identity. Bring-up, data layout, and the launchd unit
are the [MacBook node runbook](runbooks/pir2-macbook-replacement.md). The
work runs on the MacBook; this repository's hosts have no SSH to it.

1. Read — Flow A. Record the live `binary_sha256`.
2. Local (MacBook) — build the approved commit with runbook step 4 into a
   new `bin/<SHA>/` directory. Leave the running binary in place. Any
   rebuild changes the hash, because `git_rev` is compiled in.
3. Auth — Flow B, then Flow C: a PR that sets
   `PIR2_MACBOOK_PIN.binarySha256Hex` to the new `shasum -a 256
   unified_server` and `transitionBinarySha256Hex` to the build the node
   runs now. After the deploy, clients accept both builds.
4. Auth (MacBook) — switch the node with the runbook's switch procedure
   (after step 9), whenever the operator gets to it. The procedure waits
   for launchd to unregister the old service and rolls back on its own if
   the new binary does not listen; the web keeps working either way.
5. Read — Flow A prints `✓ binary_sha256 matches PIR2_MACBOOK_PIN` once
   the node runs the new build (`…the transition build…` while it still
   runs the old one).
6. Auth — Flow B, then Flow C: a PR that removes
   `transitionBinarySha256Hex`.

Never deploy a pin that leaves out the running build. On 2026-10-02 a pin
naming only the new build went out before a switch that then failed, and
the slot was down for about 3 h.

Rollback: before step 6, point the plist back at the previous `bin/<SHA>/`
and restart; the transition pin still accepts it. After step 6, roll back
the same way as an upgrade, through a new transition.

## Human-only — do not start from this page

- Key generation and writing `.keys/` from scratch.
- Funds, channels, or issuer deploy.
- VPSBG image delete.
- Generating new keys. Updating `web/src/attest-pin.ts` from a completed
  post-switch check is part of a release campaign when that release was
  authorized; it is not a second Human gate.
- Filling `--expect-*` from a live server or `server-info.super_root`.
- Rebuilding or deleting retained Core snapshots / ORAM inputs.
- Substituting `build_uki_attested_builder_tier3.sh` for the runtime
  UKI, or the reverse.

## Command index

| Operation | Runbook | Command | Successful handoff |
| --- | --- | --- | --- |
| Read pir1, pir2 and ORAM host status | this page, Flow A | `scripts/production-status.sh` | exit 0 |
| Rebuild or re-pin the pir2 MacBook node | this page, Flow I | runbook step 4, transition pin, switch, then drop the transition | Flow A prints `✓ binary_sha256 matches PIR2_MACBOOK_PIN` |
| Build the **runtime** UKI | [UKI build](runbooks/uki-build.md) | `scripts/build_uki_tier3.sh` | archived `.efi` + `.meta` |
| Build the **producer** UKI | [Attested-builder UKI](ATTESTED_BUILDER_TIER3_UKI.md) | `scripts/build_uki_attested_builder_tier3.sh` | archived `.efi` + `.meta` |
| Verify a local DB proof | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) | `bpir-admin db-proof verify` | verifier exit 0 |
| Stage a VPSBG generation | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) | `scripts/stage_vpsbg_tier3_generation.sh` | candidate catalog only |
| List, upload, switch, or roll back a VPSBG image | [VPSBG image](runbooks/vpsbg-image.md) | `scripts/vpsbg-measured-boot.sh` | exit 0 |
| Open or close a VPSBG data-disk window | [Key management](KEY_MANAGEMENT.md) | `scripts/vpsbg-data-disk.sh` | exit 0 |
| Check the Direct ORAM host after a switch | [VPSBG image](runbooks/vpsbg-image.md) | `scripts/oram-host-check.sh` | exit 0 |
| Publish the web client | this page, Flow C | `deploy-web.yml` dispatch | deploy job green |
| Check the issuer and mint on pir1 | [Issuer and mint](runbooks/issuer-and-mint.md) | `curl https://issuer.bitcoinpir.org/v2/info`; `bpir-issuer balance` | both units active, `/v2/info` lists the credit pack |

Paid access (credits verified at the issuer, outside the measured image) is
described in [`CREDITS.md`](CREDITS.md) and operated per
[Issuer and mint](runbooks/issuer-and-mint.md).
