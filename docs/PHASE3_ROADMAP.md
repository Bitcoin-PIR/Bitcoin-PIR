# Phase 3 (Attested Lockdown) — Roadmap

Snapshot of the remaining work after the 2026-05-02 deployment that
landed Slices 1–4 of the dynamic attestation surface (DB manifests,
`/attest`, ed25519 admin auth, DB upload protocol, `bpir-admin` CLI),
deployed VPSBG as the second non-collusion server, set up the
`pir2.chenweikeng.com` Cloudflare tunnel, and shipped Phase 3 Slice 1
(UKI builder + `--expect-measurement` verifier flag).

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

Launch MEASUREMENT (covers OVMF + UKI bytes):
  f568fc1f133eb4b74737ce75f4c71b3f31fca1003b39d6e60d537ca71d70f8fd4d568474e4e81e58a40425eea207699d

UKI bytes sha256 (the bpir.efi uploaded via VPSBG portal):
  5a0f0c08730de08398d86599332c2f0e987fe05eea7dcc10dfa45cc541532ad0

unified_server binary sha256:
  9df104eb6d3882d9b9c59765e3c7418d679e2473e6f46af5521b861d2a87ed16
  (was 6e805660... before the e68df9b dual-stack bind fix; rebuild
   shifted the binary hash. The cmdline-pinned hash in the live UKI
   still says 6e805660 — see "Action 0" below.)

DB manifest roots (db_id order):
  main (940611):              8911588dde20282726b5f2ae8e2c3152c673d636dc6a10295d9b9037e36fba11
  delta_940611_944000:        b1822802cfb193b80c57974e43388d2389c11715eb7b3d56fcd062c348f03f3a

Server git rev: e68df9b (post-fix), expected via `bpir-admin attest`
```

### Slices 1–4 of the dynamic attestation work

All landed and deployed. See commits `2858f54`, `c167579`, `ab9c0dc`,
`dcbcd2b`, `f2fafcd`. Tooling in `bpir-admin/`.

### Phase 3 Slice 1 (UKI builder)

Landed (`f7a308b`). `scripts/build_uki.sh` produces a UKI that bakes
the binary's SHA-256 into the kernel cmdline. `bpir-admin attest
--expect-measurement` cross-checks the chip-signed launch digest.

**What this does NOT yet enforce**: nothing on VPSBG reads
`bpir.expected_binary_sha256` from `/proc/cmdline` and refuses to
start `pir-vpsbg.service` if the disk binary's hash differs. Slice 2
closes this.

---

## Action 0 — operator follow-up needed before Slice 2

**Re-bake the UKI and re-upload via VPSBG portal.** The dual-stack fix
(`e68df9b`) changed the binary hash from `6e805660…` to `9df104eb…`.
The currently-loaded UKI's cmdline still pins `6e805660…`, which is
fine while Slice 2 doesn't enforce — but if Slice 2 lands without
re-baking, the dracut hook will refuse to start the service.

```bash
# Must run as root — /boot/vmlinuz-* is mode 0600.
ssh vpsbg-pir '/home/pir/BitcoinPIR/scripts/build_uki.sh'
scp vpsbg-pir:/tmp/bpir.efi ./bpir.efi
# then upload bpir.efi via VPSBG portal → Confidentiality &
# Protection → Advanced: Measured Boot → UKI → Save & Reboot.
# After reboot, capture and republish:
./target/release/bpir-admin attest wss://pir2.chenweikeng.com
# new MEASUREMENT replaces f568fc1f… in the published values above.
```

This re-bake is also a useful operational drill — every binary update
will follow the same flow.

---

## Slice 2 — dracut hook: enforce cmdline-pinned binary hash at boot

**Goal**: a small initramfs hook that runs after rootfs mount but
before systemd starts `pir-vpsbg.service`. It hashes the on-disk
binary and refuses to chain to systemd if the hash doesn't match
what's pinned in `/proc/cmdline`.

This converts the cmdline pin from "operator promise" to "boot-blocking
enforcement". Combined with MEASUREMENT covering the cmdline (already
done), an attacker who tampers with the binary on disk causes the
next boot to halt visibly instead of running silently with stale data.

### Design

A dracut module at `/usr/lib/dracut/modules.d/95bpir-verify/`:

```
95bpir-verify/
├── module-setup.sh       — declares dependencies, copies our hook
└── bpir-verify.sh        — the actual hook script (runs in initramfs)
```

`module-setup.sh`:
```sh
#!/bin/bash
check() { return 0; }
depends() { echo "systemd"; return 0; }
install() {
    inst_hook pre-pivot 90 "$moddir/bpir-verify.sh"
    inst_multiple sha256sum grep awk
}
```

`bpir-verify.sh`:
```sh
#!/bin/sh
# Read expected hash from cmdline.
EXPECTED=$(grep -oE 'bpir\.expected_binary_sha256=[0-9a-f]+' /proc/cmdline | cut -d= -f2)
if [ -z "$EXPECTED" ]; then
    echo "[bpir-verify] no bpir.expected_binary_sha256 in cmdline; skipping"
    exit 0
fi

# /sysroot is the rootfs at the pre-pivot hook point.
BINARY=/sysroot/home/pir/BitcoinPIR/target/release/unified_server
if [ ! -r "$BINARY" ]; then
    echo "[bpir-verify] FATAL: $BINARY not readable" >&2
    emergency_shell "binary missing"
fi

ACTUAL=$(sha256sum "$BINARY" | awk '{print $1}')
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "[bpir-verify] FATAL: binary hash mismatch" >&2
    echo "[bpir-verify]   expected: $EXPECTED" >&2
    echo "[bpir-verify]   got:      $ACTUAL" >&2
    emergency_shell "binary tamper detected"
fi
echo "[bpir-verify] binary hash verified: $ACTUAL"
```

### Build flow update

`scripts/build_uki.sh` needs a new step before `ukify build`:
1. Install the dracut module to `/etc/dracut.conf.d/bpir.conf`:
   `add_dracutmodules+=" bpir-verify "`
2. Regenerate the initrd with the module included:
   `dracut --force /tmp/bpir-initrd.img 7.0.0-15-generic`
3. Use that custom initrd instead of `/boot/initrd.img-*` in the
   ukify call.

### Acceptance test

After uploading the new UKI and rebooting:
1. Tamper test: `ssh vpsbg-pir 'sudo dd if=/dev/urandom
   bs=1 count=1 conv=notrunc seek=1000 of=/home/pir/BitcoinPIR/target/release/unified_server'`
2. Reboot: `ssh vpsbg-pir 'reboot'`
3. Watch console via VPSBG VNC — should see `[bpir-verify] FATAL:
   binary hash mismatch` and drop to emergency shell.
4. Restore binary: `ssh vpsbg-pir`'s VNC shell → `cp
   /home/pir/BitcoinPIR/target/release/unified_server.bak
   /home/pir/BitcoinPIR/target/release/unified_server`. Reboot. Should
   boot cleanly.

### Estimate

~1 day. Bulk of the work is testing the dracut module — easy to get
wrong because it runs in initramfs context (no normal env, sparse
toolset).

### Rollback plan

If the dracut module breaks boot, the operator boots into VPSBG
console (VNC), removes the dracut config (`rm
/etc/dracut.conf.d/bpir.conf`), and rebuilds the standard initrd
(`dracut --force`), then re-uploads a vanilla UKI via the portal.

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
