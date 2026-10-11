# Release checklist

A release moves production to one reviewed `main` commit, the release
commit, as one campaign of [Production operations](PRODUCTION_OPERATIONS.md).
This page orders the flows a release needs. Commands, limits and recovery
details stay in the flows and runbooks that each step links. Identity values
stay in [`web/src/attest-pin.ts`](../web/src/attest-pin.ts) and
[`web/src/production-providers.ts`](../web/src/production-providers.ts).

## What counts as a release

- A named campaign (`r12`, …) that moves one or more of: the pir1 binary
  (Flow D, `PIR1_PIN`), the server-1 MacBook node (Flow I,
  `PIR2_MACBOOK_PIN`), the Direct ORAM host's runtime UKI (Flow E,
  `PIR2_TIER3_PIN`), the web pins and site (Flow C), and the database
  generation (Flow H). Re-vendoring the playground and republishing the
  service directory follow from those.
- One authorization covers every Auth step of the release
  ([step types](PRODUCTION_OPERATIONS.md#step-types)). Human steps (keys,
  funds, image delete) need their own decision.
- A merge is not a release. Production changes only when a host is rebuilt
  or switched, or when Flow C runs.
- A host that is offline or left out keeps its build and its pin. The release
  says which hosts it moves.
- Not part of this checklist: the issuer and the mint
  ([Issuer and mint](runbooks/issuer-and-mint.md); a change to
  `pir_credit::issuer` needs an issuer upgrade as well), and the directory
  relay binary ([Directory relay](runbooks/directory-relay.md), "Upgrade the
  relay").

## Preflight

`scripts/release-preflight.sh [--live] [COMMIT]` (default `origin/main`)
prints one line per check and blocks nothing: whether the commit is on
`main`; its `web-build.yml` and `rust-ci.yml` runs (for a path-filtered
commit, the newest run on an ancestor); the pins in its `attest-pin.ts` that
still carry `transitionBinarySha256Hex`; the commit GitHub Pages serves; the
commit the playground vendors (`vendor/SOURCE_COMMIT.txt` in
Bitcoin-PIR/playground); and, with `--live`, `scripts/production-status.sh`
against this checkout's pins. Run it at step 1, after each Flow C, and at
step 13.

## Why this order

- A no-TEE host (pir1, the MacBook) never meets a pin that leaves out the
  build it runs. Flow C first publishes its new build together with the
  running one as `transitionBinarySha256Hex`; then the host switches; then a
  later Flow C drops the transition. The MacBook is switched by its operator
  with no time bound (Flow I says what went wrong without this).
- The ORAM host has no transition: its MEASUREMENT changes with every image.
  It switches first and is checked against the new pins in a local checkout;
  Flow C follows. Browsers report its mismatch in between, so the pin PR is
  green before the switch.
- A database generation has no transition either: its pins and catalogs move
  together in the [maintenance window](DATABASE_ROOT_ROTATION_RUNBOOK.md#5-activate-in-a-maintenance-window).
- A unit or plist that passes a flag the new build no longer has does not
  start (#413 and #418 removed flags), so step 4 runs before any switch.
- Flow C publishes `main`'s tip at dispatch time, not a chosen commit.

## What changed → which steps

Compare the release commit with what each host runs: the comment above each
pin names its source commit, and step 1 reads the running binaries. Step
numbers refer to the checklist below.

| What changed | Steps |
| --- | --- |
| Server code: what `unified_server` builds from (`apps/server`, `crates/protocol`, `crates/trust`, `vendor/`, `Cargo.lock`) | All, for each host that should run the release commit: pir1 3a and 8, the MacBook 3b and 9, the ORAM host 3c and 6. Any rebuild changes the binary hash (the git revision is compiled in). Step 12 only if a role or access lane changes. |
| Unit or plist flags only (access policy, limits) | pir1: edit the unit on the host, then 8. MacBook: a `plist.new` with the same binary, through 9. Neither changes a pin. The ORAM host's flags live in its measured image (next row). Step 12 if an access lane changes. |
| ORAM run script or UKI inputs (`scripts/build_uki_tier3.sh`, `scripts/dracut/`, the kernel, the cloudflared pin, `oramctl`, the BHTM leaf proof) | 1–2, 3c, 5 (`PIR2_TIER3_PIN` only), 6–7, 10 (record and `reproduce.html`), 11, 13 |
| Web only (`web/`, the wasm crates) | 1–2, 7, 11 when `web/src/*.ts` or the wasm inputs changed, 13 |
| Pins only (`attest-pin.ts`, `production-providers.ts`) | 1–2, 5, 7, 11, 13; 12 when an endpoint, role, attestation or access lane changes |
| Database generation | [Database rebuild](DATABASE_REBUILD.md) §8 (Flow H) in place of 3–11: one pin PR, a new runtime UKI, all three hosts staged, a maintenance window, Flow C and the playground. Then 12–13. |

## Checklist

Each step gives its type, command, expected time and hard stop, success
signal and rollback. Skip the steps of hosts the release leaves out.

### 1. Preflight — Read

`scripts/release-preflight.sh --live COMMIT`. Record the rollback targets:
the binary each no-TEE host runs (`binary_sha256` from Flow A for the
MacBook, from `bpir-admin attest wss://weikeng1.bitcoinpir.org` for pir1)
and the ORAM host's `image_id` (Flow A). About 30 s, plus a `bpir-admin`
build unless `BPIR_ADMIN` is set. Success: `main:` on main; CI lines
`success`. Rollback: none.

### 2. Release commit — Local ([Flow B](PRODUCTION_OPERATIONS.md#b-source-change-and-ci--local))

The release commit is on `main` with its checks green; [Testing](TESTING.md)
picks the local checks. `web-build.yml` takes 10–25 min (stop 30 min).
Success: the preflight's `web-build:` and `rust-ci:` lines say `success`.
Rollback: none, nothing is deployed.

### 3. Builds — nothing that serves changes yet

- **a. pir1 — Auth** ([Flow D](PRODUCTION_OPERATIONS.md#d-pir1-hetzner-binary--auth)
  steps 1–2): on the host, fast-forward to the release commit, build and
  strip; do not restart. `unified_server --version` prints the git revision
  and `binary_sha256`. 2–5 min, stop 15 min.
- **b. MacBook — Local, by its operator**
  ([runbook step 4](runbooks/pir2-macbook-replacement.md#4-build-in-parallel-with-step-3)):
  build into a new `bin/<SHA>/` beside the running build and report the SHA.
- **c. ORAM host — Local, then Auth** ([Flow E](PRODUCTION_OPERATIONS.md#e-direct-oram-host-runtime-uki-and-measured-boot--local-then-auth)
  steps 2–4): `scripts/vpsbg-measured-boot.sh images` (5 images at most;
  deleting one is Human); the runtime UKI ([UKI build](runbooks/uki-build.md),
  5–15 min, stop 15 min); its MEASUREMENT predicted offline with
  `sev-snp-measure` (`web/reproduce.html`, "Predict the MEASUREMENT"); then
  `upload --uki FILE` (a few minutes, stop 10 min). Record the `image_id`.

Success: a hash per binary, the predicted MEASUREMENT, an `image_id`.
Rollback: none; an uploaded image only takes a slot.

### 4. Flags — Read

For pir1 and the MacBook, list the flags the unit or plist passes that the
new build does not know:

```sh
flags() { grep -o -- '--[a-z][a-z0-9-]*' | sort -u; }
comm -23 <(systemctl cat pir-primary | flags) <(NEW_BINARY --help | flags)  # pir1
comm -23 <(flags < "$NODE/plist.new") <(NEW_BINARY --help | flags)         # MacBook
```

Seconds. Success: no output. Otherwise fix the unit or `plist.new` before
the switch. The ORAM host's flags are in
`scripts/dracut/97bpir-tier3-init/unified-server-run.sh` at the release
commit.

### 5. Pin PR — Local (Flow B)

One PR against `main` that edits `web/src/attest-pin.ts`:

- each no-TEE host that will switch: `binarySha256Hex` is its new build and
  `transitionBinarySha256Hex` the build step 1 saw it running (not the old
  pin value);
- `PIR2_TIER3_PIN`: the predicted MEASUREMENT and the new binary;
- the comment above each changed pin: source commit and build.

Local checks: the `web/` row of [Testing](TESTING.md). Success:
`web-build.yml` green on the PR. With an ORAM pin in it, merge only after
step 6 passes. Rollback: close the PR.

### 6. ORAM switch — Auth, then Read ([Flow E](PRODUCTION_OPERATIONS.md#e-direct-oram-host-runtime-uki-and-measured-boot--local-then-auth) steps 5–6)

With the step-5 branch checked out (`oram-host-check.sh` reads this
checkout's pins), switch, which reboots at once, then check:
`scripts/vpsbg-measured-boot.sh switch --server-id 26939 --image-id NEW`,
then `scripts/oram-host-check.sh`. 5–20 min; stop after 15 min without
`boot_mode=measured`. Success: exit 0 (attest with the predicted
MEASUREMENT, channel, one ORAM query per database). Rollback: `switch` to the
recorded `image_id`, run `oram-host-check.sh` on `main`'s pins, and drop
`PIR2_TIER3_PIN` from the PR.

### 7. Publish — Auth ([Flow C](PRODUCTION_OPERATIONS.md#c-web--github-pages--local-then-auth))

Merge the PR. Once `web-build.yml` on that `main` commit is green:
`gh workflow run deploy-web.yml --ref main -f confirm_production_deploy=true`.
20–60 min, stop 75 min. Success: the deploy job is green and the preflight's
`pages:` line shows the commit. Rollback: revert the PR (Flow B), then Flow
C again.

### 8. pir1 switch — Auth (Flow D steps 2–3)

`systemctl restart pir-primary` (restart `cloudflared` only if the tunnel
itself is broken). About 2 min 20 s to `Listening` (manifest hashing); do not
call it failed before 3 min. Success: `scripts/production-status.sh` shows
`pir1_primary=active` and `pir1_port_8091=listening`, and
`bpir-admin attest wss://weikeng1.bitcoinpir.org --expect-binary NEW` passes.
Rollback: restart on the previous build (rebuild its commit if the build
replaced it); the transition still accepts it.

### 9. MacBook switch — Auth, by its operator ([Flow I](PRODUCTION_OPERATIONS.md#i-pir2-macbook-node--local-then-auth) step 4)

Whenever the operator gets to it: the switch procedure after
[runbook step 9](runbooks/pir2-macbook-replacement.md#9-launchd-service),
with `plist.new`. It waits until `launchctl print` no longer finds the old
service before `bootstrap`. Startup hashes about 34 GB, a few minutes; the
procedure rolls back on its own after 8 min without `Listening on`. Success:
Flow A prints `✓ binary_sha256 matches PIR2_MACBOOK_PIN`. Rollback: point the
plist back at the previous `bin/<SHA>/`; the transition still accepts it.

### 10. Closing pin PR — Local, then Auth

A PR that removes `transitionBinarySha256Hex` from each pin whose host now
runs the new build (pir1 after step 8; the MacBook only after step 9, in a
later PR if it has not switched yet), updates `web/reproduce.html` (it repeats
the ORAM UKI name, hashes and source revision, and the pir1 binary), and adds
the release record (below). Merge, then step 7. Success: the preflight's
`transition:` line names only hosts still waiting to switch. Rollback: from
here on, a host rolls back through a new transition (Flow I, "Rollback").

### 11. Playground — Auth

After the Flow C of step 7 and again after step 10; until then the
playground checks hosts against its old pins. In a checkout at the `main`
commit Flow C published:
`wasm-pack build crates/sdk/wasm --target web --out-dir pkg`. In a
[playground](https://github.com/Bitcoin-PIR/playground) checkout:
`BITCOINPIR_REPO=<that checkout> npm run sync-vendor`. Open a PR with
`vendor/` and `vendor/SOURCE_COMMIT.txt` and merge it; the playground's
`pages.yml` publishes on push to `main`. Minutes. Success: the preflight's
`playground:` line shows the commit. Rollback: revert the playground PR.

### 12. Directory — Auth

Only when the release changes a listed provider's endpoint, role,
attestation or access lanes:
[Directory relay](runbooks/directory-relay.md#publish-or-update-entries),
"Publish or update entries". Minutes. Success: the readback returns the new
heads. Rollback: publish the previous values at the next sequence.

### 13. Close — Read

`scripts/release-preflight.sh --live`: on main, CI green, a transition only
for a host still waiting, Pages and the playground on the last release
commit, `production-status.sh` exit 0. Live integration tests (a
`pir-sdk-integration.yml` dispatch) and browser checks run only when the
operator asks for them.

## Record the release

- The pin PRs: release name, release commit, what each host runs after it,
  and the checks that passed. Add the step-13 preflight output as a comment
  on the closing PR.
- A new ORAM image: `docs/data-retention/production-release-image-<image_id>.env`,
  with the keys of the previous record (`browser_acceptance` names the checks
  that passed), in the closing PR.
- pir1 and the MacBook: the comment above each pin names its source commit
  and build.
- A database generation:
  [rotation §6](DATABASE_ROOT_ROTATION_RUNBOOK.md#6-post-deployment-acceptance)
  and [Database rebuild](DATABASE_REBUILD.md) §9, under `docs/data-retention/`.
- The release's tracking issue, if it has one.
