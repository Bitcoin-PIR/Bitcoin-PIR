# Run the pir2 sealed release

This is Flow G in [Production operations](../PRODUCTION_OPERATIONS.md).
Placing `startup.env` is Flow F, not a provisioner UKI.

Use [`scripts/pir2-sealed-ceremony.sh`](../../scripts/pir2-sealed-ceremony.sh)
to advance the prepared pir2 release through Observe, sealed release, Enroll,
Probe, and Ready.

## Inputs

- An unused output path for each phase's `startup.env`.
- The phase ordinal and a fresh verifier nonce.
- The exact measured UKI/OVMF values and Observe receipt required by the
  sealed-release command.

## Campaign

[`scripts/pir2-sealed-campaign.sh`](../../scripts/pir2-sealed-campaign.sh) runs
one release as five reviewed windows over the scripts below; every action has
`--dry-run`, which prints each external command as a `PLAN:` line and touches
nothing. Inputs come from an env file of `KEY=VALUE` lines (allowlisted keys,
plain values) and an evidence directory (mode 0700) holding one
`<phase>-ordinal<N>.startup.env` per phase, written with the `phase` action:

```
REV=<release commit>            TAG=r8-<sha8>          GEN=8
ROLLBACK_IMAGE=307              ROLLBACK_LABEL=image307-YYYYMMDD
EVIDENCE_DIR=/absolute/.keys/pir2-ceremony/epoch9
ORD_OBSERVE=61 ORD_ENROLL=62 ORD_PROBE1=63 ORD_PROBE2=64 ORD_READY=65
INPUTS_FROM=/home/pir/data/production-builds/<previous tag>
ORAMCTL_SHA256=<from the previous sidecar>  BHTM_SHA256=<from the previous sidecar>
BPIR_ADMIN=/absolute/target/release/bpir-admin
OPERATOR_PUBKEY_HEX=<pin in web/src/production-providers.ts>
ARK_SHA256=<AMD ARK pin>        PROVIDER_ID_HEX=<pir2 provider id>
HETZNER_ARCHIVE=pir-hetzner:/home/pir/uki-archive/tier3
```

```sh
scripts/pir2-sealed-campaign.sh plan   --env campaign.env
scripts/pir2-sealed-campaign.sh build  --env campaign.env --dry-run   # then without --dry-run
scripts/pir2-sealed-campaign.sh enroll --env campaign.env
scripts/pir2-sealed-campaign.sh probe  --env campaign.env --ordinal 63 --with-cert
scripts/pir2-sealed-campaign.sh probe  --env campaign.env --ordinal 64
scripts/pir2-sealed-campaign.sh ready  --env campaign.env
```

`build` preserves the previous image's rollback set, builds the runtime and
UKI on the stock rootfs (`scripts/pir2-sealed-remote/`, pinned cloudflared
placed first), archives the trio locally and on Hetzner, places the Observe
startup, uploads the UKI (the returned image id is appended to the env file as
`IMAGE`), boots Observe, fetches its receipt from the recovery root, and signs
the release. `enroll` detaches the old envelope, places release + startup,
accepts the Enroll receipt, and signs the runtime identity cert. `probe` runs
one Probe and requires the enrolled identity. `ready` boots Ready, waits for
the live attestation, runs the post-switch check against a candidate pin built
from the evidence, the channel test, fetches and accepts both Ready receipts
over the WebSocket, and drafts the release record from the attestation. The
pin update (`web/src/attest-pin.ts`) stays a reviewed code change made from
the two `pin_*` values the `ready` action prints.

## Run (individual steps)

```sh
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64 --dry-run
scripts/pir2-sealed-ceremony.sh phase \
  --phase observe --out /absolute/observe.startup.env --ordinal ORDINAL \
  --verifier-nonce-hex HEX64
scripts/pir2-sealed-ceremony.sh release [existing release arguments]
```

After `PASS sealed_phase_config=observe`, place that exact file with
[`scripts/vpsbg-data-disk.sh`](../../scripts/vpsbg-data-disk.sh):

```sh
scripts/vpsbg-data-disk.sh open --server-id 25285 --image-id CURRENT --apply
scripts/vpsbg-data-disk.sh put --local /absolute/observe.startup.env \
  --remote /home/pir/data/pir2-sealed/startup.env --apply
scripts/vpsbg-data-disk.sh close --server-id 25285 --image-id CURRENT --apply
```

`release`, `receipt`, and `fetch` run `cargo run --locked --offline -p bpir-admin`,
which rebuilds the debug binary whenever the tree changed; inside a maintenance
window that has cost more than ten minutes. Build once before the ceremony and
point the wrapper at the result (`--dry-run` previews show it in `COMMAND=`):

```sh
cargo build --locked --offline --release -p bpir-admin
export BPIR_ADMIN="$PWD/target/release/bpir-admin"
```

## Rollback set

Before the previous image's `startup.env` is replaced by the new image's Observe
file (that is, in the build window, before `put`), preserve the four files a
rollback to that image needs — `credentials.envelope.bin`, `release.bin`,
`identity.cert`, and its Ready `startup.env` — with the reviewed guest-side
script, run over `scripts/vpsbg-data-disk.sh ssh` on the stock rootfs:

```sh
scripts/pir2-sealed-rollback-set.sh preserve --label imagePREV-YYYYMMDD
```

`preserve` refuses a `startup.env` that is not a Ready file (pass
`--startup-from` for an explicit previous Ready startup), never overwrites a
label, and writes `rollback/LABEL/MANIFEST.sha256`. In the Enroll window run
`detach-envelope --label LABEL --apply`: it re-verifies the set, requires the
canonical envelope to equal the preserved copy, and only then removes it so
Enroll on the new image mints a fresh one. A rollback is `restore --label LABEL
--apply` in a Flow F window followed by `close` onto that image and Flow E
step 6; `verify --label LABEL` checks a set at any time. Every action has a
`--dry-run` plan and ends with `PASS action=...`.

Do not build a provisioner UKI. Run the release after the Observe receipt is
available. Generate new startup files for `enroll`, `probe`, and `ready`, and
boot each in that order. A completed release prints `PASS sealed_release`;
every phase file prints `PASS sealed_phase_config=<phase>` and `NEXT_STEP`.

## Receipt acceptance

A phase status marker proves only that the guest persisted a receipt. The
recovery HTTP root is served through Cloudflare with
`Cache-Control: max-age=14400`, and a phase's receipt URL can return a cached
receipt from an earlier phase (observed in the field: an Enroll fetch returned
the previous Observe receipt with `CF-Cache-Status: HIT`). Before trusting any
downloaded receipt, require its hash to equal the receipt hash declared by the
phase's status response; if the two disagree, treat the download as rejecting
evidence, rename it out of the way, and retrieve the persisted receipt through
the Flow F data-disk window instead of retrying the public URL.
[`scripts/pir2-sealed-recovery-receipt.sh`](../../scripts/pir2-sealed-recovery-receipt.sh)
implements exactly this (cache-busted polling for the expected phase and
ordinal, hash check, quarantine of mismatches, at most three attempts), and
`bpir-admin pir2-sealed-observe-fields --receipt FILE` prints an Observe
receipt's public claim fields for the release command and the pin update
without verifying anything.

Before a later authority signs or activates anything derived from an Enroll,
Probe, or Ready receipt, an offline verifier must accept all of the following
together:

- the AMD ARK pin, ARK-to-ASK-to-VCEK chain, and SNP report signature;
- the receipt digest duplicated in the signed SNP `REPORT_DATA`;
- the exact signed release digest, measurement, guest policy, and TCB floor;
- the expected phase, ordinal, fresh verifier nonce, and current boot ID; and
- for non-Observe phases, a valid Ed25519 service identity public key, its
  fingerprint, and the identity generation.

The pre-release Observe receipt is verified inside `bpir-admin
pir2-sealed-release`. Every later receipt is accepted with the reviewed
repository command, which runs exactly the checks above and prints the
enrolled service identity public key:

```sh
scripts/pir2-sealed-ceremony.sh receipt \
  --receipt /absolute/enroll.receipt.bin --release /absolute/release.bin \
  --operator-pubkey-hex HEX64 \
  --expected-phase enroll --expected-ordinal ORDINAL \
  --expected-verifier-nonce-hex HEX64 --expected-boot-id-hex HEX32 \
  --expected-receipt-sha256-hex HEX64 \
  --ark ark.pem --ask ask.pem --vcek vcek.pem --expected-ark-sha256-hex HEX64
```

Take the ordinal and nonce from the phase's own `startup.env`, the boot ID
and receipt hash from its status JSON or persisted marker, and the operator
key from the source pin. A successful run prints `PASS
pir2_sealed_receipt_verify` and `NEXT_STEP`; anything else is rejecting
evidence. Do not treat a hex/field parser, the status JSON, or a file hash
as a substitute for this command.

Ready writes two receipts for the same boot: `ready-preflight-BOOT.bin` before
ORAM access and `ready-runtime-BOOT.bin` when the final server opens the sealed
keys, plus the preflight marker `ready-preflight-BOOT.env`. Unlike Observe,
Enroll, and Probe, a successful Ready boot does not expose them through the
finite recovery HTTP root. Instead, the serving guest answers the read-only
opcode `REQ_PIR2_SEALED_RECEIPT_GET` with the persisted bytes verbatim (images
built from the revision that added it onward). Once attestation and the
channel check pass, copy them out without a Flow F window:

```sh
scripts/pir2-sealed-ceremony.sh fetch wss://weikeng2.bitcoinpir.org \
  --out-dir /absolute/evidence-dir --dry-run
scripts/pir2-sealed-ceremony.sh fetch wss://weikeng2.bitcoinpir.org \
  --out-dir /absolute/evidence-dir
```

`PASS pir2_sealed_receipt_fetch boot_id_hex=BOOT` names the boot all three
replies agree on; the command trusts nothing it downloads. Accept
`ready-preflight-BOOT.bin` and `ready-runtime-BOOT.bin` with the `receipt`
action (`--expected-phase ready --expected-boot-id-hex BOOT`) before treating
the Ready boot as accepted. A `RESP_ERROR` reply means the guest predates the
opcode; retrieve the files in a separately authorized Flow F maintenance
window instead, using the exact boot ID from the persisted ORAM published
marker. Either way a later boot must use a new ordinal and fresh nonce.

After the ORAM progress API releases port 8091, the final server still loads the
large database mappings before it listens. During that interval the public
origin can return HTTP 502 even though the control plane is healthy. Once the
server is listening it is WebSocket-only, so an ordinary HTTPS request to
`/status.json` is not a Ready health check. Use the repository attestation and
encrypted-channel checks instead.

Free queries are open, so the ORAM smoke query in
`scripts/verify_oram_tier3_deploy.sh` (run by `pir2-post-switch-check.sh`)
is a valid Ready canary together with attestation, channel verification, and
strict Ready receipt acceptance. The measured image carries no admission
policy or payment artifact; paid access is handled outside it.

The incident that motivated the receipt-transport and acceptance rules in this
section is recorded in
[History: epoch-5 entitlement rotation](../history/EPOCH5_ENTITLEMENT_ROTATION.md).
