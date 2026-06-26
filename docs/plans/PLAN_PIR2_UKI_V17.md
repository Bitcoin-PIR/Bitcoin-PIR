# PLAN: pir2 (VPSBG) UKI v17 — realign to the current server binary

**Status:** PLAN ONLY — not executed. Drafted 2026-05-18.
**Goal:** bring pir2 (weikeng2, VPSBG, SEV-SNP) from its pre-3b binary
(`f63b3535…`, commit `49db31da`, Tier 3 UKI v16) up to the current
production server, so pir1 and pir2 run the same `unified_server`.

**Not urgent / not functional.** pir2 does **not** serve OnionPIR
(`[HUMAN]` confirmed) — it runs `--serve-queries` for DPF + Harmony,
and the per-group OnionPIR Merkle redesign never touched the
DPF/Harmony wire protocol, so pir2@`49db31da` ↔ pir1@`121ea5c3` are
already compatible. This is a fleet-hygiene realignment, not a fix.

---

## Target version

Build pir2 from commit **`121ea5c3`** — the exact commit pir1's live
binary (`0cc87a8c…`) is built from. `unified_server`@`121ea5c3` links
`onionpir@aa7710d` and produces a binary byte-identical to pir1's, so
after this `PIR1_PIN` and `PIR2_TIER3_PIN` share a `binarySha256Hex`
again (fleet uniform).

> Alternative: build from current `main` HEAD. `runtime/` is identical
> to `121ea5c3` (nothing touched it since 3b), but Phase 4 removed a
> dead `pub const` from `pir-core` — the resulting binary may hash
> differently from `0cc87a8c`. If you go this route, also redeploy
> pir1 from HEAD to keep the fleet uniform. Not recommended — more
> churn for no functional gain.

---

## Stage 0 — Pre-flight verification  `[do before building anything]`

0.1 **Boot pir2 into Slice 2 for SSH.** If pir2 is in Tier 3 (UKI, no
    sshd), toggle in the VPSBG portal → Measured Boot → UKI → "None"
    → Save & Reboot. Confirm `ssh vpsbg-pir` works.

0.2 **Confirm pir2 does NOT load OnionPIR data.** `ssh vpsbg-pir`,
    inspect `databases.toml` + the `pir-vpsbg` service flags.
    Expected: DPF + Harmony DBs only, `--serve-queries`, no
    `--pool-size`. **If pir2 loads any OnionPIR data** → that data
    must be `onionpir@aa7710d`-rebuilt AND every file listed in
    `MANIFEST.toml`, or the 3b binary panics at load (3b-deploy
    incidents #1/#2, PLAN_MERKLE_CODING.md §E). The whole upgrade
    balloons. Expected to be a non-issue — but VERIFY, do not assume.

0.3 Record the current state for rollback: v16 UKI file, current
    `databases.toml`, the running binary hash (`f63b3535…`).

0.4 Confirm the Hetzner build host is healthy (it builds the UKI):
    dracut 110, kernel 7.0.0-15, kmod 34.2 present (CLAUDE.md
    "Hetzner — UKI build host").

## Stage 1 — Build the binary  `[Hetzner build host — I can do this]`

1.1 `ssh pir-hetzner`, `cd /home/pir/BitcoinPIR`, `git fetch`,
    `git checkout 121ea5c3`.
1.2 `export PATH="/home/pir/.cargo/bin:$PATH" && ./scripts/build_unified_server.sh`
    (the deterministic wrapper).
1.3 `sha256sum target/release/unified_server` → expect
    `0cc87a8c8530a7830e78ed172af2c5c666c62ccde5d00dbca36321c577dcdeba`
    (== pir1). If it differs, STOP and investigate before continuing.

## Stage 2 — Build the Tier 3 UKI v17  `[Hetzner — I can do this]`

2.1 `sudo KERNEL=/boot/vmlinuz-7.0.0-15-generic ./scripts/build_uki_tier3.sh`
    — bakes the binary into a zstd initramfs, builds the Tier 3 UKI
    `.efi`. The script validates the SEV module set (ccp, sev-guest,
    tsm_report) pre/post-build.
2.2 Output `/tmp/bpir-tier3.efi`. `scp pir-hetzner:/tmp/bpir-tier3.efi
    deploy/uki/bpir-tier3-v17.efi`.

## Stage 3 — Deploy the UKI to pir2  `[VPSBG portal — operator]`

3.1 VPSBG portal → upload `bpir-tier3-v17.efi` → Measured Boot → UKI
    → Save & Reboot. pir2 reboots into the v17 UKI (Tier 3, no sshd).
3.2 ⚠️ Brief **pir2 downtime** during the reboot → DPF (2-server) and
    HarmonyPIR are unavailable for that window. Schedule it.

## Stage 4 — Capture the new attestation pins  `[operator]`

4.1 `./target/release/bpir-admin attest wss://weikeng2.bitcoinpir.org`.
4.2 Record the **new MEASUREMENT** (v17 — differs from v16's
    `59e276f3…`; the initramfs/binary changed) and the binary
    sha256 (expect `0cc87a8c…`).

## Stage 5 — Update web pins + redeploy  `[I can do this]`

5.1 `web/src/attest-pin.ts` → `PIR2_TIER3_PIN.measurementHex` = new
    v17 measurement; `binarySha256Hex` = `0cc87a8c…`. Restore the
    "PIR1_PIN and PIR2_TIER3_PIN share a binarySha256Hex" comment
    (true again once pir2 == pir1).
5.2 Update the CLAUDE.md "Attestation pins" quick-reference.
5.3 Commit + push → `deploy-web.yml` redeploys the web client with
    the v17 pins.
5.4 ⚠️ **Sequencing window:** between the Stage 3 reboot and this web
    redeploy, the live site's old `PIR2_TIER3_PIN` mismatches pir2's
    new measurement → pir2 shows "attestation mismatch". Keep Stage 5
    tight after Stage 3, or accept a short pir2-red window.

## Stage 6 — Verify

6.1 Web attestation panel for pir2 → VCEK chain ✓, MEASUREMENT
    matches v17, binary matches, `reportDataMatch`.
6.2 `wss://weikeng2.bitcoinpir.org` real WS handshake OK.
6.3 Run the `production-test` DPF + Harmony suites (pir2's roles) —
    confirm no regression.

## Rollback

- Keep `deploy/uki/bpir-tier3-v16.efi`. If v17 misbehaves: VPSBG
  portal → upload v16 → Save & Reboot.
- Emergency: portal → UKI → "None" → Save & Reboot → boots the
  Slice 2 rootfs with sshd for debugging.
- `attest-pin.ts` rollback = `git revert` the Stage 5 commit.

## Risk register

- **Measurement-change attestation window** (Stage 5.4) — the one
  real UX gotcha; sequence tightly.
- **pir2 reboot downtime** — DPF + Harmony briefly unavailable.
- **SEV chain** — the v17 UKI must preserve the SEV module set +
  measured-boot chain; `build_uki_tier3.sh` validates it.
- **dracut version** — dracut 060 cannot build a working initramfs
  for kernel 7.0; dracut 110 required (already on the Hetzner host).
- **OnionPIR-data landmine** (Stage 0.2) — only if pir2 unexpectedly
  loads OnionPIR data. Verify first.

## Division of labour

- Stages 1–2 (Hetzner binary + UKI build) and Stage 5 (web pins) — I
  can execute on request.
- Stages 0.1 / 3 / 4 (VPSBG portal, boot-mode toggles, `bpir-admin
  attest`) — operator-driven.
