# Phase 3 (Attested Lockdown) — Roadmap

Snapshot of the remaining work after the 2026-05-02 / 2026-05-03
deployment that landed:
- Slices 1–4 of the dynamic attestation surface (DB manifests,
  `/attest`, ed25519 admin auth, DB upload protocol, `bpir-admin` CLI)
- VPSBG as the second non-collusion server + `pir2.chenweikeng.com`
  Cloudflare tunnel
- Phase 3 Slice 1 (UKI builder + `--expect-measurement` verifier flag)
- Phase 3 Slice 2 (dracut hook enforces the binary pin at pre-pivot
  — operator tamper-tested end-to-end on VPSBG 2026-05-02)
- Encrypted channel (Slices A–C, deployed 2026-05-03): X25519 long-
  lived server keypair generated inside the SEV-SNP guest at boot,
  bound into REPORT_DATA via the V2 layout. Per-session ECDH +
  ChaCha20-Poly1305 AEAD frame wrapping. cloudflared sees only
  ciphertext for any client that runs the handshake. End-to-end
  verified via `bpir-admin channel-test wss://pir2.chenweikeng.com`.

This document is the canonical to-do for the next sessions on this
work. Pick up by re-reading the "Current state" summary, then jumping
to whichever slice you want to start on.

---

## Current state (as of 2026-05-02 commit `e68df9b`)

### Production deployment

| | |
|---|---|
| `pir1.chenweikeng.com` | Hetzner i7-8700, role=primary, DPF + OnionPIR + HarmonyPIR query, 125 GB RAM, 944 GB disk. Cloudflared tunnel terminates here. **Not** SEV-attested (Intel chip). |
| `pir2.chenweikeng.com` | VPSBG EPYC 9745 (Zen 5), role=secondary, DPF + HarmonyPIR hint, **SEV-SNP active** at VMPL0, custom UKI loaded. 48 GB disk, 22 GB used. |
| Cloudflare tunnels | Two: Hetzner (existing) for pir1, VPSBG (new) for pir2. Both healthy. |
| DBs in production | `main` (height 940611), `delta_940611_944000`. Both have `MANIFEST.toml`. |
| Hetzner `pir-secondary.service` | Stopped + disabled (port 8092 free). Unit file kept for hot-spare revival via `systemctl start pir-secondary`. |

### Attested values published (operator: weikengchen)

These are live values from the running pir2 — anyone can verify with `bpir-admin attest`.

```
Server: wss://pir2.chenweikeng.com

Launch MEASUREMENT (covers OVMF + UKI bytes — UKI contains the
bpir-verify dracut hook + the new V2-aware unified_server's hash in
cmdline, so this digest authenticates that the box boots into a kernel
that enforces binary integrity at pre-pivot AND that the running
binary speaks the encrypted-channel protocol):
  e522983f0d595b99157c9612cb623522044110c5154807df8b5f700da33c09932f14137c8afef2e53127b61b6402ce0a

UKI bytes sha256 (built by scripts/build_uki.sh on vpsbg-pir;
deterministic for back-to-back local builds, fresh git clones produce
different bytes due to source mtimes leaking into the cpio):
  8449585e863397dadf7ee55a3af88e9fb52494466ac61bd7edd69bb9e72e1cef

unified_server binary sha256 (pinned in cmdline, enforced at boot by
the bpir-verify dracut hook — tamper test passed 2026-05-02 against
the predecessor binary, hook unchanged):
  3f1f7722f5ca4cb44d9eb240306a5bab47022a665624af12c5e90ad97cd6e993

Server X25519 channel pubkey (V2-bound to REPORT_DATA — bpir-admin
attest cross-checks the binding; encrypted-channel handshakes ECDH
against this key, so cloudflared can't substitute its own):
  615ed2699569fdb0a28b848a16a0155a27b445cfb8617c25d538d5b4ad541f42

DB manifest roots (db_id order):
  main (940611):              8911588dde20282726b5f2ae8e2c3152c673d636dc6a10295d9b9037e36fba11
  delta_940611_944000:        b1822802cfb193b80c57974e43388d2389c11715eb7b3d56fcd062c348f03f3a

Server git rev (per /attest, captured at unified_server build time):
  93ec886ca14cb5b6782a33bd5131b6bc1358054f
```

Verifiers can cross-check end-to-end with:
```bash
# Static checks: report binding + binary + measurement
bpir-admin attest wss://pir2.chenweikeng.com \
    --expect-measurement e522983f0d595b99157c9612cb623522044110c5154807df8b5f700da33c09932f14137c8afef2e53127b61b6402ce0a \
    --expect-binary 3f1f7722f5ca4cb44d9eb240306a5bab47022a665624af12c5e90ad97cd6e993

# Live encrypted channel: handshake + encrypted REQ_PING + REQ_GET_INFO
bpir-admin channel-test wss://pir2.chenweikeng.com
```

### Slices 1–4 of the dynamic attestation work

All landed and deployed. See commits `2858f54`, `c167579`, `ab9c0dc`,
`dcbcd2b`, `f2fafcd`. Tooling in `bpir-admin/`.

### Phase 3 Slice 1 (UKI builder)

Landed (`f7a308b`). `scripts/build_uki.sh` produces a UKI that bakes
the binary's SHA-256 into the kernel cmdline. `bpir-admin attest
--expect-measurement` cross-checks the chip-signed launch digest.

### Phase 3 Slice 2 (dracut hook — landed + tamper-tested)

Landed in code (`e81ad56`) plus the determinism follow-up (`d8cb85c`).
Tamper-tested live on vpsbg-pir 2026-05-02:

- Tampered `/home/pir/BitcoinPIR/target/release/unified_server`
  (`b338434f…` → `0abacfa4…`) and rebooted.
- Dracut bpir-verify hook fired at pre-pivot, detected hash mismatch
  vs cmdline pin, dropped to `emergency_shell`.
- Both probes confirmed boot was halted before any systemd service
  started: `ssh vpsbg-pir` → connection timeout (sshd never started),
  `bpir-admin attest` → cloudflare 530 (cloudflared never started).
- Recovery via VPSBG portal "None" UKI fallback → cp .bak back →
  re-upload Slice 2 UKI → clean reboot. New MEASUREMENT
  `8d60b7dc…` published above.

`scripts/dracut/95bpir-verify/{module-setup.sh, bpir-verify.sh}`
defines the pre-pivot hook. `scripts/build_uki.sh` installs the
module to `/usr/lib/dracut/modules.d/95bpir-verify/` and pulls it
into a freshly-generated `/tmp/bpir-initrd.img` via `dracut --force
--no-hostonly --reproducible --add bpir-verify` (with
`SOURCE_DATE_EPOCH=0`). The custom initrd is the one packed into
the UKI by ukify.

The module is opt-in via `--add bpir-verify` only — there is no entry
in `/etc/dracut.conf.d/`, so future kernel-update autogenerated initrds
(triggered by `apt install linux-image-*`) will not pick up the hook.
Only build_uki.sh does.

---

## Operational reference (Slice 2 in production)

### Binary update flow

Every time `unified_server` is rebuilt, the cmdline pin no longer
matches and the dracut hook will block boot. So binary updates require
a coordinated UKI rebuild:

```bash
# 1. Build the new binary (already done if you just `cargo build --release`).
ssh vpsbg-pir 'sudo -u pir bash -lc "
    source ~/.cargo/env && cd /home/pir/BitcoinPIR &&
    git fetch origin && git reset --hard origin/main &&
    CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release -p runtime --bin unified_server
"'
# 2. Snapshot the current (good) binary as a recovery backup.
ssh vpsbg-pir 'cp /home/pir/BitcoinPIR/target/release/unified_server{,.bak}'
# 3. Re-bake UKI with new binary's hash baked into cmdline.
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki.sh'
scp vpsbg-pir:/tmp/bpir.efi ./bpir.efi
# 4. Upload via VPSBG portal → Measured Boot → UKI → Save & Reboot.
# 5. After reboot, capture + republish the new MEASUREMENT.
./target/release/bpir-admin attest wss://pir2.chenweikeng.com
```

### Recovery — UKI bricks the box

If a future UKI fails to boot (hook bug, kernel update breaks the
initrd, wrong cmdline pin, etc.) and SSH is dead:

1. **VPSBG portal → Measured Boot → UKI dropdown → "None"** →
   Save & Reboot. Falls back to stock Ubuntu boot, no enforcement.
2. SSH back in, `cp .bak unified_server` if the binary is the
   problem.
3. Re-bake + re-upload a fresh UKI.

VNC may not work for SEV-SNP guests with measured boot enabled
(framebuffer often disabled). The "None" UKI fallback is the
reliable recovery path.

---

## Slice 3 — Tier 3 lockdown: bake binary into initramfs, drop sshd

**Goal**: the UKI itself contains everything needed to run
`unified_server` — kernel + initramfs (with binary, libs, configs) +
cmdline (admin pubkey, listen port). No rootfs needed for the service
to start. Drop sshd entirely.

### What changes from Slice 2

| | Slice 2 (Hybrid) | Slice 3 (Lockdown) |
|---|---|---|
| Binary location | rootfs `/home/pir/...`, verified by initramfs | initramfs `/usr/local/bin/unified_server`, runs from there |
| MEASUREMENT covers binary | Transitively (cmdline pins hash) | Directly (binary bytes are in UKI) |
| sshd | available | **gone** — no rootfs, no sshd |
| Operator access | SSH to box | `bpir-admin` over WSS only |
| DB upload | `bpir-admin upload` (already wired) | unchanged |
| Binary update | Rebuild → upload UKI → reboot | unchanged |

### Architectural decisions to make before coding

- **Networking**: dhcp via dhclient in initramfs, or static IP from
  cmdline? Recommend dhcp (dynamic IP from VPSBG). Need
  `dracut --add-drivers " virtio_net "` and dhcp client in initramfs.
- **Persistent storage**: where do the DBs live? Two options:
  - (a) Separate ext4 partition on `/dev/sda2` mounted at `/data` in initramfs.
  - (b) Reuse the existing rootfs partition for `/data/` only — initramfs
    mounts the existing rootfs read-only-except-/data.
  Recommend (a) for clean isolation, but (b) if disk repartitioning
  is operationally painful on VPSBG.
- **Logs**: where do they go? Without a rootfs, `journalctl` storage
  is gone. Options:
  - (a) Send to console only (VNC visible).
  - (b) Set up a small writable volume just for `/var/log/journal`.
  - (c) Forward via a journal-remote sidecar to Hetzner.
  Recommend (a) for MVP.
- **DNS resolution**: needed for cloudflared if we keep that on VPSBG
  (which we do — pir2.chenweikeng.com routes through it). cloudflared
  resolves AMD's KDS endpoint and Cloudflare's edge. Bake systemd-resolved
  + /etc/resolv.conf pointing at 1.1.1.1 in the initramfs.
- **cloudflared in the UKI?**: yes, otherwise pir2.chenweikeng.com goes
  dark. Add cloudflared binary + token + supervisor (s6-overlay or
  similar) into initramfs.
- **Admin key rotation**: the admin pubkey lives in the UKI cmdline.
  Rotating means rebuilding + reuploading the UKI, then rebooting.
  Document this in the operator README.

### Tools/deps needed

- `mkosi` or rich `dracut` config (probably mkosi for the
  binary+supervisor packaging; dracut to build the initrd itself).
- A small runit/s6 supervisor to manage two long-running processes
  inside the initramfs (`unified_server` + `cloudflared`).
- `cloudflared` static binary (already shipped by Cloudflare).
- All `unified_server`'s dynamic deps: `ldd
  target/release/unified_server` to enumerate. Roughly: libssl,
  libcrypto, libpthread, libgcc_s, libstdc++ (from SEAL static link),
  libc, ld-linux.

### Acceptance criteria

1. After UKI upload and reboot, `bpir-admin attest
   wss://pir2.chenweikeng.com` returns ReportDataMatch with the new
   MEASUREMENT (different from Slice 1+2's value because the UKI
   bytes now include the binary).
2. `ssh vpsbg-pir 'echo hi'` fails (no sshd).
3. The VPSBG VNC console shows `unified_server` and `cloudflared`
   running supervised.
4. `bpir-admin upload <name> <dir> --target-path … --server
   wss://pir2.chenweikeng.com` still works.

### Estimate

~1.5 to 2 weeks. Significant new ground: initramfs as full OS,
supervised processes, in-initramfs networking, mkosi/dracut tuning,
testing rollback paths over VPSBG VNC.

### Risk: rollback complexity

If a Tier 3 UKI fails to boot, the operator's only fallback is the
VPSBG portal: re-upload a previous-known-good UKI (or the vanilla
"None" option to revert to stock Ubuntu boot). Make sure to keep at
least one known-good UKI checked in so this is one command:
```bash
scp known_good_bpir.efi vpsbg-pir:/tmp/...   # via... wait, no SSH after Slice 3.
# Actually: re-upload via the VPSBG portal from the laptop.
```

So the operator README must include a "if Tier 3 UKI bricks the box"
recovery checklist.

---

## Web frontend updates

The web client (`web/`) has two relevant concerns this work introduces:

### 1. Display attestation status in the UI

Right now the SDK has the attestation primitives
(`pir_sdk_client::attest::attest`) but the web wrapper doesn't expose
them. Add a small UI element to the existing client page (`web/src/`):

- Periodic background `/attest` against pir1 + pir2.
- For pir1 (Hetzner, no SEV): green badge "self-reported attestation
  (no hardware backing)" with binary_sha256 + git_rev visible.
- For pir2 (VPSBG, SEV-SNP): green badge "✓ Verified via SEV-SNP"
  showing the launch MEASUREMENT and a tooltip explaining what was
  attested. Cross-check against operator-published values baked into
  the page bundle at build time (so any divergence is immediately
  visible).

Implementation surface:
- New `web/src/attest-badge.ts` (or similar) — runs the attest call
  via the existing `WasmDpfClient` connection, parses the response,
  renders status.
- Add a build-time constant for expected MEASUREMENT (like
  `VITE_BPIR_EXPECTED_MEASUREMENT_PIR2=f568fc1f…`).
- Document the publication flow: when the operator uploads a new UKI
  to VPSBG, they:
  1. Re-bake UKI, capture new MEASUREMENT.
  2. Update `VITE_BPIR_EXPECTED_MEASUREMENT_PIR2` in `.env`.
  3. Rebuild + redeploy the web client.

### 2. AMD VCEK chain verification (optional, deferred)

Currently `bpir-admin attest` (and the analogous browser flow) trust
that the SEV-SNP report's signature is valid. To be truly
independent, the verifier should:
- Fetch AMD's ARK + ASK + VCEK for the chip from
  `https://kdsintf.amd.com/vcek/v1/Turin/<chip-id>?...`
- Verify the cert chain: ARK self-signed → ARK signs ASK → ASK signs VCEK.
- Verify the SEV report's ECDSA-P384 signature against the VCEK.

Doing this in browser context requires either:
- A WASM build of the verification code (cleanest; reuses
  `pir_core::attest` + ed25519/ECDSA crates compiled to wasm32).
- A Cloudflare Worker that does the verification and returns a
  signed assertion (more centralized, less ideal).

Recommend: WASM build, ship as part of the SDK. Estimate ~3 days.

### 3. Confirm `--role secondary` doesn't break existing client flows

The web client expects:
- pir1 (Hetzner primary) handles `REQ_HARMONY_QUERY` and `REQ_HARMONY_BATCH_QUERY` (online).
- pir2 (VPSBG, now also primary's-equivalent in topology) handles `REQ_HARMONY_HINTS` (offline).

This is the existing topology. `--role secondary` on VPSBG matches.

After today's `e68df9b` dual-stack bind fix, the connection should
succeed. **Open**: actually run the web client end-to-end with a real
HarmonyPIR query and confirm.

---

## Quick-reference command index

```bash
# Attest VPSBG
./target/release/bpir-admin attest wss://pir2.chenweikeng.com

# Upload a new DB
./target/release/bpir-admin upload main_944321 ./build/output/main_944321 \
    --target-path checkpoints/944321 \
    --server wss://pir2.chenweikeng.com
ssh vpsbg-pir 'systemctl restart pir-vpsbg'

# Build a fresh UKI on VPSBG (after binary rebuild; must run as root)
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki.sh'
scp vpsbg-pir:/tmp/bpir.efi ./bpir.efi
# then upload via VPSBG portal → reboot → re-attest → republish

# Hot-spare revival (Hetzner secondary)
ssh pir-hetzner 'systemctl start pir-secondary'

# Check live state
ssh vpsbg-pir 'systemctl status pir-vpsbg cloudflared --no-pager | head -20'
ssh vpsbg-pir 'journalctl -u pir-vpsbg -p err --no-pager -n 20'

# Re-deploy code change (VPSBG)
ssh vpsbg-pir 'sudo -u pir bash -lc "
    source ~/.cargo/env && cd /home/pir/BitcoinPIR &&
    git fetch origin && git reset --hard origin/main &&
    CMAKE_POLICY_VERSION_MINIMUM=3.5 cargo build --release -p runtime --bin unified_server
"'
ssh vpsbg-pir 'systemctl restart pir-vpsbg'
```

## Open questions worth pinging VPSBG support about

1. **OVMF blob**: ask for the exact bytes of the OVMF firmware their
   SEV-SNP guests boot with. Without it, `sev-snp-measure` can only
   produce launch digests that diverge from the chip-reported one
   (verified empirically: stock Ubuntu OVMF gives `2fe9ae9c…` but the
   chip reports `cc68b431…` for the no-UKI baseline).
2. **Tier of EPYC**: confirm the VM stays on the same physical chip
   across reboots (chip ID is in the report; if it changes, the VM
   was migrated). Currently chip ID = `00 36 42 73 5D DC 6E 02`.
3. **TCB updates**: SEV-SNP firmware version (FMC=1, SNP=4 in current
   report). When AMD publishes a new TCB, what's VPSBG's update
   cadence?
