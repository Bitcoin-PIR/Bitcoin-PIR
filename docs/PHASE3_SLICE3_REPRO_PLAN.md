# Phase 3 Slice 3 — UKI Reproducible-Build Plan (L4 polish)

**Status (2026-05-03)**: not started. Slice 3 is shipped and Layer 3
reproducibility is achieved (verifiers can compute MEASUREMENT given
operator-published UKI bytes + VPSBG's custom OVMF — see
[PHASE3_ROADMAP.md::Full Layer 3 reproducibility — verified 2026-05-03](PHASE3_ROADMAP.md)).

This plan covers the L4 sub-gap: making the **UKI binary itself
bit-deterministic from source**, so that any verifier with the
git tree can rebuild byte-identical UKI bytes (and therefore the
same MEASUREMENT) without trusting the operator's published .efi.

The OVMF reproducibility sub-gap (asking VPSBG for their custom EDK2
build commit + flags) is **out of scope** for this plan — it's a
separate single-email task.

---

## Goal

Two operators on different machines, both starting from a fresh
`git clone` of the same commit + identical Cargo.lock + Ubuntu/Proxmox
package versions, produce **byte-identical** Tier 3 UKI bytes:

```bash
# Operator A:
git clone <repo> && cd <repo> && git checkout <commit>
sudo scripts/build_uki_tier3.sh
shasum -a 256 /tmp/bpir-tier3.efi

# Operator B (different machine, same inputs):
git clone <repo> && cd <repo> && git checkout <commit>
sudo scripts/build_uki_tier3.sh
shasum -a 256 /tmp/bpir-tier3.efi

# These two sha256 values must match.
```

When this works, MEASUREMENT can be predicted purely from source +
declared dependency versions. No "trust the operator's UKI bytes"
step in the verification chain.

---

## Current state — known divergence sources

The existing builds are **not** bit-deterministic. Empirically, two
back-to-back builds on the SAME machine produce identical UKI bytes
(thanks to `--reproducible` + `SOURCE_DATE_EPOCH=0` already passed to
dracut), but two builds on DIFFERENT machines or fresh clones
diverge. The known divergence sources, in rough order of impact:

1. **Dracut cpio mtimes leak in.** dracut reads our module-setup
   scripts from `scripts/dracut/96bpir-cloudflared/` etc.; their
   mtimes (set by `git clone` to the clone time) end up in the cpio
   archive. Two fresh clones at different times → different mtimes
   → different cpio bytes → different initrd → different UKI sha →
   different MEASUREMENT.

2. **`cargo build --release` is not bit-deterministic.** Stock cargo
   embeds the build path (`/home/pir/BitcoinPIR/target/...`),
   timestamps in dependency metadata, and parallel-compilation
   ordering quirks. Two builds on different hosts, even with
   identical Cargo.lock, produce different `unified_server` binaries.

3. **`TUNNEL_TOKEN` is baked into the initramfs.** Each operator has
   their own Cloudflare tunnel token; the token bytes live at
   `/etc/cloudflared/tunnel.env` inside the cpio. Even two operators
   running the same source produce different UKIs because the tokens
   differ. Beyond reproducibility, this also means the token is
   committed to MEASUREMENT — minor secrecy concern.

4. **Build-host package versions.** The build pulls binaries from
   `/usr/lib/`: kernel image, modules, busybox, runit, libstdc++,
   libgomp, libgcc_s, libm, libc, ld-linux. Two operators on
   different Ubuntu versions (or even the same version with
   different package update windows) produce different cpio
   contents.

5. **Dependency drift in cargo.** `Cargo.lock` pins versions but
   `cargo build` may re-fetch from crates.io with potentially
   different bytes (rare but possible if the mirror diverged).
   Vendored deps eliminate this.

---

## Sub-tasks (ordered by ROI: easy + high-impact first)

### 1. `touch -d @0` pre-pass on dracut module sources

**Effort**: 1 line.
**Impact**: closes the most common divergence (mtime leakage).

In `scripts/build_uki_tier3.sh`, before invoking dracut, force all
module-setup files to epoch 0:

```bash
find "$DRACUT_MODULE_DIR" -type f -exec touch -d @0 {} \;
# OR if cp -fp also propagates mtimes from elsewhere:
find /usr/lib/dracut/modules.d/96bpir-* /usr/lib/dracut/modules.d/97bpir-* \
    -type f -exec touch -d @0 {} \; 2>/dev/null
```

Same change in `scripts/build_uki.sh` (Slice 2 build) for revert
artifact reproducibility.

**Acceptance**: two consecutive builds on the same machine, with the
build dir wiped between runs (`rm -rf /usr/lib/dracut/modules.d/96bpir-*
/usr/lib/dracut/modules.d/97bpir-* /tmp/bpir-tier3-initrd.img
/tmp/bpir-tier3.efi`), produce identical UKI sha.

---

### 2. `cargo build --release` bit-determinism

**Effort**: medium (1-2 days, mostly testing).
**Impact**: the binary is the most observable divergence. Without
this fix, the operator-published `binary_sha256` only matches builds
on operator's specific machine.

Recipe (canonical Rust reproducibility):

```bash
# Set in the build environment OR add to .cargo/config.toml [build]:
RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/build/repo"

# Lock toolchain to a specific stable version via rust-toolchain.toml:
echo '[toolchain]
channel = "1.84.0"
components = ["rustfmt", "clippy"]
' > rust-toolchain.toml

# Set SOURCE_DATE_EPOCH for any timestamp embedding:
export SOURCE_DATE_EPOCH=0

# Build with single-codegen-unit + frozen deps:
cargo build --release --frozen -p runtime --bin unified_server \
    --config 'build.codegen-units=1'

# Strip debug info + reproducibly:
strip --strip-debug -g target/release/unified_server
```

Test by cloning into two different paths on the same machine, building
both, comparing sha. Then test on a different machine.

If pure cargo flags aren't enough (some deps have non-deterministic
build.rs), the next step is vendoring + a hermetic build container —
see sub-task 4 + 5.

**Acceptance**: two operators on different machines (same Ubuntu
version + same Rust toolchain) produce byte-identical
`unified_server` binaries.

---

### 3. Move `TUNNEL_TOKEN` out of the initramfs

**Effort**: medium-high (architectural decision required).
**Impact**: removes per-operator divergence + tightens the secrecy
of the token.

Currently the token sits in `/etc/cloudflared/tunnel.env` baked into
the cpio. The takeover init's runit service sources it. Options:

(a) **Pass via cmdline parameter.** Read from `/proc/cmdline` in the
    cloudflared service. Token IS still in MEASUREMENT (cmdline is
    measured), but moves out of the initramfs cpio bytes —
    operator-specific divergence shifts to the cmdline only, which
    can be templated cleanly.

(b) **Load from a runtime-mounted partition.** The runit service
    reads the token from `/data/cloudflared/tunnel.env` (on the
    bind-mounted rootfs partition, NOT in measured memory). Token
    is no longer in MEASUREMENT — UKI is operator-agnostic, anyone
    with the same git commit can rebuild byte-identical bytes.
    Trade-off: cloudflared no longer covered by MEASUREMENT in any
    sense (the token is data, not code, so this is mostly fine).

(c) **External cloudflared (separate service).** Run cloudflared
    on the host or a sidecar VM, not inside the SEV-SNP guest at all.
    Maximum reproducibility for the guest; loses the property that
    cloudflared sees only ciphertext (which is preserved by the
    Slice C encrypted channel anyway).

**Recommendation**: (a) for minimum churn. (b) is cleanest but means
re-thinking the runit service. (c) is a Slice 4 conversation.

**Acceptance**: the same git commit produces byte-identical UKI bytes
for two different operators with two different cloudflared tokens.

---

### 4. Vendor cargo dependencies

**Effort**: low (~1 hour).
**Impact**: removes dependency-fetch drift; required for fully
hermetic builds in sub-task 5.

```bash
# In the repo root:
cargo vendor vendor
cat >> .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "vendor"
EOF
git add vendor .cargo/config.toml
```

The `vendor/` dir adds ~50-200 MB to the repo. Consider Git LFS if
size matters.

**Acceptance**: `cargo build --release --offline` succeeds without
network access.

---

### 5. Hermetic build environment

**Effort**: medium-high (3-5 days).
**Impact**: closes the build-host divergence (kernel, packages,
toolchain). Required for full third-party reproducibility.

Two paths:

(a) **Nix flake**: `flake.nix` declares pinned nixpkgs + Rust
    toolchain + all build deps (dracut, ukify, runit, busybox,
    cloudflared). Operator runs `nix develop` then
    `scripts/build_uki_tier3.sh`. Anyone with Nix gets bit-identical
    binaries.

(b) **Pinned distroless container**: `Dockerfile.build` based on a
    fixed Ubuntu image (or distroless), with all deps installed at
    pinned versions. Operator runs
    `docker run --rm -v $PWD:/repo build-image
    /repo/scripts/build_uki_tier3.sh`.

(a) is the gold standard for reproducibility but requires Nix
proficiency. (b) is more accessible but Ubuntu's apt repo can drift
silently — would need to also pin via `apt-get install
package=version` and snapshot the package mirror.

**Acceptance**: two operators with no shared build infrastructure
(different OS, different Rust install) but same git commit produce
byte-identical UKI bytes.

---

## Validation strategy

For each sub-task, the test is: two builds, different machines/clones,
bit-identical output. The test SUITE for the whole plan:

```bash
# Operator A
git clone <repo> /tmp/repo-A && cd /tmp/repo-A
git checkout <commit>
<set up reproducible build env per sub-tasks 4+5>
sudo scripts/build_uki_tier3.sh
SHA_A=$(shasum -a 256 /tmp/bpir-tier3.efi | cut -d' ' -f1)

# Operator B (different host)
... same recipe ...
SHA_B=$(shasum -a 256 /tmp/bpir-tier3.efi | cut -d' ' -f1)

[ "$SHA_A" = "$SHA_B" ] && echo "✓ reproducible" || echo "✗ diverged"

# Cross-check against chip:
sev-snp-measure --mode snp --vcpus 2 --vcpu-sig 0x00B10F10 \
    --ovmf OVMF_SEV_MEASUREDBOOT_4M.fd \
    --kernel /tmp/bpir-tier3.efi \
    --guest-features 0x1
# matches what bpir-admin attest reports from pir2?
```

Sub-tasks land incrementally; each one closes a divergence source.
Sub-task 1 alone may already make 2 builds on the same machine
identical. Sub-tasks 1+2 may close most cases. Sub-task 5 is the
"belt and suspenders" final layer.

---

## Out of scope

- VPSBG OVMF source build commit + flags. One-line email to VPSBG
  support; not part of this plan.
- IGVM-based reproducibility. Proxmox uses `-kernel` not IGVM for
  the UKI case (per VPSBG response 2026-05-03), so IGVM tooling
  isn't needed.
- L5 ("trust no one including AMD"). AMD ARK fingerprint pinning
  is the trust anchor; this plan stays under that anchor.
- TCB / microcode reproducibility. SEV-SNP firmware version is
  AMD's responsibility; we pin via the published REPORTED_TCB in
  bpir-admin attest.

---

## Estimate

| Sub-task | Effort | Cumulative | What it unlocks |
|---|---|---|---|
| 1. dracut mtime fix | 1 line | 5 min | Same-machine determinism |
| 2. cargo reproducibility | 1-2 days | 1-2 days | Same-OS, different-machine binary determinism |
| 3. TUNNEL_TOKEN extraction | medium-high | 3-5 days | Different-operator UKI determinism |
| 4. cargo vendor | 1 hour | ~1-2 days | Offline-buildable deps |
| 5. hermetic build env | 3-5 days | ~1-2 weeks | Different-OS, different-distro full L4 |

Realistic full timeline: ~2 weeks of focused work. Sub-tasks 1+4 are
quick wins regardless of whether the whole plan ships.

---

## Quick-start for a new session

A self-contained prompt to spawn a new session is provided at the
bottom of this doc. Copy-paste it into `claude --new-session` (or
similar) when ready.

(See `Session-starter prompt` below.)
