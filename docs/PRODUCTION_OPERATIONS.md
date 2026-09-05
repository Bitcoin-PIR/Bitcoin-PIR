# Production operations

Start here for any authorized production change. Query live state first —
never infer it from documents. Classify the ask as **one campaign**: a
named release (for example R5.1) or one flow A–H. One explicit
authorization covers that whole campaign. Run the campaign's numbered
steps in order. Do not invent a second campaign, and do not re-ask
between steps of the same campaign.

Live status:

```sh
scripts/production-status.sh
```

That prints pir1 SSH health and the pir2 VPSBG snapshot. For pir2 only,
use `scripts/vpsbg-production-status.sh` or
`scripts/vpsbg-measured-boot.sh status`. Each mutation script also has
`--help` and, where it can change a host, `--dry-run`.

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
4. When a step prints `PASS` and `NEXT_STEP`, continue if that next step
   is still in the authorized campaign. Stop on failure, a hard stop
   with no progress, or a step that belongs to a different campaign.

### Step types

| Type | Meaning | Agent may run? |
| --- | --- | --- |
| Read | No host, image, pin, or fund change | Yes, without extra authorization |
| Local | Laptop or CI check; no production mutation | Yes for the matching change class in [Testing](TESTING.md) |
| Auth | Changes a remote host, image, service, Pages site, or identity | Yes for every remaining step of the authorized campaign |
| Human | Key generation, funds, image delete | Do not start; ask and wait |

`--apply` is still **per command**: `upload` does not switch, `put` does
not close, `close`/`switch` take the caller-supplied `--image-id`. The
agent issues those commands in campaign order without a new ask between
them. Recoverable API stalls in the same campaign (for example a 423
during `open`, then `start`) are in-campaign, not a new authorization.

### Workload estimates

Use these before starting. Missing progress before the hard stop means
stop and report.

| Work | Expected | Hard stop | Progress signal |
| --- | --- | --- | --- |
| `production-status.sh` | ~30 s | 20 s per SSH/API call | `PASS production_status` |
| Local web check (`tsc` + vitest + `build-web`) | 2–10 min | 15 min | npm scripts exit 0 |
| PR `web-build.yml` | 10–25 min | 30 min job | wasm-pack, tsc, vitest, `build-web` |
| PR `ci-summary.yml` | waits for siblings | 75 min | one green/red advisory status |
| Pages `deploy-web.yml` | 20–60 min | 75 min build | `build-web`, then deploy job |
| pir1 `cargo build --release -p runtime` | 2–5 min | 15 min | compiler output, then systemd active |
| Tier 3 **runtime** UKI (`build_uki_tier3.sh`) | 5–15 min | 15 min | dracut, inventory, `ukify`, `PASS uki_build` |
| Attested-builder **producer** UKI | 5–15 min | 15 min | archive `.efi` + `.meta` |
| Native full-build V2 snapshot/delta | hours; no wall-clock is written here | no progress for 3 min → stop | `build-summary.txt`, then `latest/` only after the V2 gate |
| Direct ORAM release reconstruct | target 10 min | 15 min (3 min without a stage) | ORAM debug runbook stages |
| VPSBG `images` / `upload` | seconds / a few min | 10 min upload | `PASS action=images\|upload` |
| VPSBG `switch` / `close` attachment | seconds; starting is separate | 15 min | `boot_mode=measured`, expected image id; read `running` separately |
| Data-disk `open` | 2–10 min | 15 min | `boot_mode=stock`, `ssh_ready=true` |
| `pir2-post-switch-check.sh` | 5–20 min | 15 min wait + attest | `PASS action=post_switch_check` |

## Flow catalog

| Id | When to use | First command |
| --- | --- | --- |
| A | Diagnose live hosts | `scripts/production-status.sh` |
| B | Source / PR; no production mutation | [Testing](TESTING.md) |
| C | Publish the browser client to GitHub Pages | Flow C below |
| D | Change the pir1 Hetzner binary or unit | Flow D below |
| E | Build, upload, switch, or roll back the **runtime** pir2 UKI | [UKI build](runbooks/uki-build.md) then [VPSBG image](runbooks/vpsbg-image.md) |
| F | Edit `/home/pir/data/` on VPSBG, including `startup.env` | [Key management](KEY_MANAGEMENT.md) |
| G | pir2 sealed Observe / Enroll / Probe / Ready | [Sealed release](runbooks/pir2-sealed-release.md) |
| H | Produce or rotate DPF / Harmony / Onion v2 / ORAM proofs | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) |

Payment issuer deploy, mainnet Lightning, key generation, funds, and
image deletion are **not** flows. The retired Payment V1 material lives
only in git history.

## A. Diagnose — Read

1. Read — `scripts/production-status.sh` (`--dry-run` lists paths only).
2. Read — if only pir2 matters:
   `scripts/vpsbg-measured-boot.sh status --server-id ID`.
3. Read — before a UKI upload:
   `scripts/vpsbg-measured-boot.sh images`.
4. Stop. `image_id=unavailable` is a valid observation, not a selection.

Success: `PASS production_status` and/or `PASS action=status|images`.

## B. Source change and CI — Local

Green CI is not a deploy. Merges are manual; there is no required
aggregate check on `main`.

1. Local — pick the narrowest row in [Testing](TESTING.md).
2. Local — open a `codex/` branch; do not mix a production mutation with
   a docs or CI cleanup in the same commit.
3. Local — open a PR against `main`. Path-filtered workflows run on
   that PR. Two run on every PR: `formal-proof.yml` and advisory
   `ci-summary.yml` (waits for sibling runs on the head SHA).
4. Human — inspect the CI summary, then merge only if the user asked.

Usual PR workflows, when their paths match:

| Workflow | What it proves | Not a deploy of |
| --- | --- | --- |
| `web-build.yml` | wasm-pack, `tsc`, vitest, `build-web` | GitHub Pages |
| `pir-sdk-integration.yml` | deterministic SDK jobs | live servers (live jobs are schedule/dispatch) |
| `rust-ci.yml` | Rust test/clippy lanes and the wasm32 check | production hosts |
| `build-determinism.yml` | pir-core reproducibility | databases |
| `workflow-supply-chain.yml` | workflow/UKI contract scripts | a UKI |
| `generated-proof-lock.yml` | lock files | live proofs |
| `formal-proof.yml` | locked EasyCrypt / contract | production hosts |

Do not add workflows or required checks from this page.

## C. Web / GitHub Pages — Local then Auth

The site is `https://www.bitcoinpir.org/`. A push to `main` does **not**
publish. `.github/workflows/deploy-web.yml` deploys only on
`workflow_dispatch` from `main` with `confirm_production_deploy=true`.
The build job has contents-read only; Pages write/OIDC is confined to
the deploy job. `scripts/pages-deploy-gate.mjs` enforces that
shape.

1. Local — land the web or pin change through Flow B. Pin edits must
   keep `web/src/attest-pin.ts`, `verification/locks/`, and the
   duplicate pins in `crates/sdk/client/tests/integration_test.rs`
   consistent ([rotation runbook](DATABASE_ROOT_ROTATION_RUNBOOK.md) §3).
2. Local — wait for `web-build.yml` on that `main` commit.
3. Auth — dispatch `deploy-web.yml` on `main` with
   `confirm_production_deploy=true`. Expected 20–60 min, hard stop
   75 min. Progress: wasm-pack, tsc, vitest, `npm run build-web`, then the
   deploy job.
4. Read — optional live browser check, only if the user asks:
   dispatch `web-strict-production-canary.yml` (45 min timeout) or the
   [production-test skill](../.claude/skills/production-test/SKILL.md).

Success: the dispatch run's deploy job is green and the live site
serves that commit. Updating pins is a separate Human step if the
check fails.

## D. pir1 Hetzner binary — Auth

pir1 is `root@65.21.91.217`, public `wss://weikeng1.bitcoinpir.org`.
It serves DPF-0, OnionPIR, and Harmony hints. There is no Hetzner
script; pin SSH against [`deploy/known_hosts`](../deploy/known_hosts).
The [hetzner skill](../.claude/skills/hetzner-pir/SKILL.md) still
contains a stale single-host caveat — ignore that; pir2 is VPSBG.

1. Local — Flow B for the runtime change. Production binary is
   `cargo build --locked --release -p runtime --bin unified_server`
   plus `strip --strip-debug`. Nix is not the authority.
2. Auth — on the host, fast-forward the reviewed commit, build the
   same command, restart `pir-primary`. Restart `cloudflared` only if
   the tunnel itself is broken. Build 2–5 min, hard stop 15 min.
3. Read — `scripts/production-status.sh` and confirm `:8091` /
   `pir-primary` are active. Do not treat `pir-secondary` as the
   public peer. This step is systemd/SSH health only; it does not
   compare the live binary to `PIR1_PIN`. That pin is checked by the
   browser client after Flow C.

Database swaps on pir1 stay inside Flow H. Do not restart during a
partial database write.

## E. pir2 **runtime** UKI and measured boot — Local then Auth

This flow builds and switches the **serving** UKI
(`scripts/build_uki_tier3.sh`). The attested-builder **producer** UKI
(`scripts/build_uki_attested_builder_tier3.sh`) is Flow H. They share
the VPSBG measured-boot slot and must not be substituted.

Details: [UKI build](runbooks/uki-build.md),
[VPSBG image](runbooks/vpsbg-image.md). Token default is
`.secrets/vpsbg-api-token`.

1. Read — Flow A. Record the live `image_id` as the rollback target.
2. Read — `scripts/vpsbg-measured-boot.sh images`. If count is 5/5,
   stop; deleting an image is Human.
3. Local — on the approved Linux build host, set every UKI input
   explicitly and run `scripts/build_uki_tier3.sh --dry-run`, then the
   live build. Nix and the attested-builder UKI are not this runtime
   UKI.
4. Auth — `scripts/vpsbg-measured-boot.sh upload --uki FILE --apply`.
   Record the returned image id. Do not switch in the same command.
5. Auth — `switch --server-id ID --image-id NEW --apply` only after
   a separate authorization. This reboots immediately.
6. Read — `scripts/pir2-post-switch-check.sh`. It reads pins from
   `web/src/attest-pin.ts` and must not edit that file. Mismatch is a
   hard stop.
7. Auth — rollback is `scripts/vpsbg-measured-boot.sh rollback` with
   the **previous** image id, then step 6 again.

A data/proof-only rotation does not need a new UKI (Flow H).

## F. VPSBG data-disk window — Auth

Use [`scripts/vpsbg-data-disk.sh`](../scripts/vpsbg-data-disk.sh).
Never build a provisioner UKI. Detach body is
`{"kernel_image_id":null}`. SSH only when `boot_mode=stock`.

1. Read — Flow A. The `--image-id` passed to `open` and `close` is
   the UKI to reattach, usually the current live image.
2. Auth — `open --server-id 25285 --image-id CURRENT --apply`.
   Hard stop 15 min: `boot_mode=stock` and SSH.
3. Auth — `put` (writes), or Read `get` / `ssh`. Remote paths must
   stay under `/home/pir/data/`. A ceremony `startup.env` must land at
   `/home/pir/data/pir2-sealed/startup.env`.
4. Auth — `close --server-id 25285 --image-id CURRENT --apply`. Same
   image id as step 1 unless the user named a different one.
5. Read — confirm the expected image is attached. `close` does not start a
   stopped guest; starting it requires its own explicit authorization. Run
   Flow E step 6 only when the guest should be serving again.

## G. pir2 sealed ceremony — Local then Auth

Details: [Sealed release](runbooks/pir2-sealed-release.md).

1. Local — `scripts/pir2-sealed-ceremony.sh phase --phase observe ...`
   (`--dry-run` first). Inputs (ordinal, nonce) are
   supplied by the operator; do not invent them.
2. Auth — Flow F to place that exact file at
   `/home/pir/data/pir2-sealed/startup.env`, then boot the measured UKI.
3. Local — after the Observe receipt exists,
   `scripts/pir2-sealed-ceremony.sh release` (`--dry-run` first).
4. Repeat steps 1–2 for `enroll`, `probe`, and `ready` with fresh
   output files, in that order.
5. Read — Flow E step 6 when Ready is serving.

Success: `PASS sealed_phase_config=<phase>` or `PASS sealed_release`.

## H. Database, proofs, and pins — Auth

Follow [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) and
read [Database artifact retention](DATABASE_ARTIFACT_RETENTION.md)
before touching artifacts. Producer UKI details:
[Attested-builder Tier 3 UKI](ATTESTED_BUILDER_TIER3_UKI.md).

One generation is **one** `server-db` tree plus its evidence. DPF and
Harmony share INDEX/CHUNK + `bucket_super_root` with that V2 evidence.
Live DPF/Harmony clients still fetch the **v1** opcode from `proof_dir`
(retained mixed-provenance sidecars on the current lineage). OnionPIR
(pir1) and Direct ORAM (pir2) consume the same tree's Onion half plus
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

Identity values stay in [`web/src/attest-pin.ts`](../web/src/attest-pin.ts)
or `verification/locks/`. Do not copy them into prose. EasyCrypt /
wire-shape locks in [Verification overview](VERIFICATION_OVERVIEW.md)
are Flow B, not this flow.

| Family | Serves | Pin / lock | Verifier an agent may run |
| --- | --- | --- | --- |
| DB proof v1 | DPF + Harmony live opcode | `PRODUCTION_DB_PROOF_PINS` | `verify-live` (v1 opcode only). Roots are already in the V2 evidence; the UKI does not emit a second v1 sidecar |
| Onion v2 | pir1 OnionPIR | `PRODUCTION_ONION_DB_PROOF_V2_PINS` | local `db-proof verify` / `verify-proof-directory`; **not** `verify-live` |
| ORAM v2 | pir2 Direct ORAM | `PRODUCTION_ORAM_DB_PROOF_V2_PINS` + `verification/locks/generated-proofs.json` | same local v2 verifiers; **not** `verify-live` |
| Builder SNP | attested-builder run | ORAM source manifests under `web/public/proofs/oram-source/` | `pir-attested-builder verify-build-evidence` |
| Runtime SNP | serving pir2 UKI | `PIR2_TIER3_PIN` | Flow E step 6; `bpir-admin attest` |
| pir1 binary | serving pir1 | `PIR1_PIN` | browser after Flow C; Flow D step 3 is host health only |
| BHTM / trust-chain | height + block hash + MuHash | `web/public/proofs/trust-chain/` | browser tests; UKI consumes `BHTM_FROM_LEAF_PROOF` |
| Formal / EasyCrypt | protocol source | `verification/locks/formal-proofs.json` | Flow B only |

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
4. Local — `bpir-admin db-proof verify` with explicit `--expect-*`.
   For typed Onion/ORAM layout also run `verify-proof-directory`.
   Direct ORAM reconstruct: 3 min without a stage → stop; 15 min hard
   stop. Missing progress is a failed build, not a reason to delete
   Core snapshots.
5. Human — edit pins in the same change set (rotation §3):
   `PRODUCTION_DB_PROOF_PINS`, `PRODUCTION_ONION_DB_PROOF_V2_PINS`,
   `PRODUCTION_ORAM_DB_PROOF_V2_PINS`,
   `verification/locks/generated-proofs.json` (ORAM table),
   `crates/sdk/client/tests/integration_test.rs`, and
   `web/public/proofs/`. Do not recreate
   `PRODUCTION_ONION_QUERY_LAYOUT_PINS`.
6. Local — Flow B tests for that pin/lock change.
7. Auth — stage both hosts without activating. VPSBG:
   Flow F + `scripts/stage_vpsbg_tier3_generation.sh` (candidate
   catalog only). Keep `path` = V2 `server-db`, `proof_dir` = locked
   V1 sidecars, `proof_v2_dir` = complete V2 output. Do not use
   `bpir-admin upload --no-activate` for attested evidence (it
   rewrites `MANIFEST.toml`).
8. Auth — activate in a fail-closed window (rotation §5): Flow F
   `open`, atomic `databases.toml` replace, Hetzner restart, `close`
   with the known-good **runtime** image id.
9. Read — `db-proof verify-live` on both hosts covers **v1 /
   DPF+Harmony only**. Onion/ORAM v2 live check is the browser/WASM
   path after Flow C, or `pir2-post-switch-check.sh` for the runtime
   SNP + ORAM smoke. Do not invent a unified “verify all proofs”
   command.
10. Auth — publish pins with Flow C. Write the release record with
    `scripts/generate-release-record.sh` (unique `--out`; never
    `--force` over an earlier record).

Rollback is rotation §7: restore both hosts to the last generation
proven on both, then Flow C for the prior pins. If one host fails,
do not leave a mixed fleet.

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
| Read pir1 and pir2 status | this page, Flow A | `scripts/production-status.sh` | `PASS production_status` |
| Build the **runtime** UKI | [UKI build](runbooks/uki-build.md) | `scripts/build_uki_tier3.sh` | `PASS uki_build` |
| Build the **producer** UKI | [Attested-builder UKI](ATTESTED_BUILDER_TIER3_UKI.md) | `scripts/build_uki_attested_builder_tier3.sh` | archived `.efi` + `.meta` |
| Verify a local DB proof | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) | `bpir-admin db-proof verify` | verifier exit 0 |
| Stage a VPSBG generation | [Database root rotation](DATABASE_ROOT_ROTATION_RUNBOOK.md) | `scripts/stage_vpsbg_tier3_generation.sh` | candidate catalog only |
| List, upload, switch, or roll back a VPSBG image | [VPSBG image](runbooks/vpsbg-image.md) | `scripts/vpsbg-measured-boot.sh` | `PASS action=...` |
| Open or close a VPSBG data-disk window | [Key management](KEY_MANAGEMENT.md) | `scripts/vpsbg-data-disk.sh` | `PASS action=open\|put\|get\|ssh\|close` |
| Check pir2 after a switch | [VPSBG image](runbooks/vpsbg-image.md) | `scripts/pir2-post-switch-check.sh` | `PASS action=post_switch_check` |
| Publish the web client | this page, Flow C | `deploy-web.yml` dispatch | deploy job green |
| Run the pir2 sealed release | [Sealed release](runbooks/pir2-sealed-release.md) | `scripts/pir2-sealed-ceremony.sh` | `PASS sealed_release` or `PASS sealed_phase_config=...` |
| Accept an Enroll, Probe, or Ready receipt | [Sealed release](runbooks/pir2-sealed-release.md) | `scripts/pir2-sealed-ceremony.sh receipt` | `PASS pir2_sealed_receipt_verify` |

Paid access (cashier-signed session grants, outside the measured image) is
described in [`SESSION_GRANTS.md`](SESSION_GRANTS.md); the retired Payment V1
material lives only in git history.
