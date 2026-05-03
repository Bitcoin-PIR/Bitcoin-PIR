{
  description = "BitcoinPIR — hermetic build environment for Tier 3 UKI reproducibility (sub-task 5 of docs/PHASE3_SLICE3_REPRO_PLAN.md)";

  # Pin nixpkgs + rust-overlay to specific revisions so two operators on
  # different machines get bit-identical toolchains. The flake.lock file
  # commits the resolved revisions; running `nix flake update` is an
  # explicit, audit-able operation.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ rust-overlay.overlays.default ];
    };

    # Match rust-toolchain.toml's pinned channel (1.94.1 stable).
    # Both operators end up with byte-identical rustc binaries.
    rustToolchain = pkgs.rust-bin.stable."1.94.1".default;

  in {
    devShells.${system}.default = pkgs.mkShell {
      packages = [
        rustToolchain
      ] ++ (with pkgs; [

        # ─── Rust / Cargo ──────────────────────────────────────────────
        # rustToolchain provides cargo + rustc + rustfmt + clippy.

        # ─── C/C++ build chain (for OnionPIR's CMake-built SEAL) ───────
        # OnionPIR's HEXL submodule has cmake_minimum_required(VERSION) below
        # 3.5, which CMake 4.x rejects. nixpkgs's `cmake` tracks latest
        # upstream; we'd need to either patch OnionPIR upstream or pin
        # CMake to a 3.x branch here. For now use the current default and
        # let `nix develop` surface the version; upgrade plan TBD.
        cmake
        gnumake
        gcc
        pkg-config

        # ─── UKI build chain ──────────────────────────────────────────
        # `ukify` ships inside the systemd package on nixpkgs (no separate
        # systemd-ukify derivation). dracut handles initramfs cpio.
        dracut
        systemd       # provides ukify
        binutils      # strip, objcopy

        # ─── runit (PID 1 takeover supervisor inside Tier 3) ──────────
        # Provides runsvdir, runsv, sv, chpst — invoked by
        # /sbin/bpir-tier3-init via /etc/sv/<service>/run.
        runit

        # ─── busybox (statically linked, baked into Tier 3 initramfs) ─
        # Provides udhcpc, ip, mount, modprobe, sleep, ln, mkdir, cat, sh.
        busybox

        # ─── cloudflared (tunnel binary baked into initramfs) ─────────
        cloudflared

        # ─── Misc ─────────────────────────────────────────────────────
        coreutils  # sha256sum, find, touch, etc.
        gnused
        gawk
        git
        which
      ]);

      shellHook = ''
        echo "──────────────────────────────────────────────────────────────"
        echo "  BitcoinPIR — hermetic build env (Nix flake, sub-task 5)"
        echo "──────────────────────────────────────────────────────────────"
        echo "  rustc:       $(rustc --version 2>/dev/null || echo MISSING)"
        echo "  cargo:       $(cargo --version 2>/dev/null || echo MISSING)"
        echo "  cmake:       $(cmake --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  ukify:       $(ukify --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  dracut:      $(dracut --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  cloudflared: $(cloudflared --version 2>/dev/null | head -1 || echo MISSING)"
        echo "  runsv:       $(which runsv 2>/dev/null || echo MISSING)"
        echo "  busybox:     $(which busybox 2>/dev/null || echo MISSING)"
        echo
        echo "  Build:"
        echo "    ./scripts/build_unified_server.sh"
        echo "    sudo ./scripts/build_uki_tier3.sh   # needs root for /boot/vmlinuz"
        echo
        echo "  This is Phase 1 of sub-task 5: pinned toolchain via dev shell."
        echo "  Phase 2 (full nix build derivation, content-addressed source"
        echo "  paths → cross-path determinism) is a follow-up — see"
        echo "  docs/PHASE3_SLICE3_REPRO_PLAN.md."
      '';
    };
  };
}
