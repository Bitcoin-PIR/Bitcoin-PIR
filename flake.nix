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

    # SEAL submodule used to be fetched separately + copied into the
    # vendored onionpir at postPatch — that was needed when SEAL lived
    # at OnionPIRv2-fork/extern/SEAL, OUTSIDE the rust/onionpir/ subcrate
    # that cargo vendor would extract. The OnionPIR fork's restructure
    # (rev ac7082eb...) now bundles SEAL at rust/onionpir/extern/SEAL,
    # so cargo's git fetcher pulls it as part of the onionpir crate's
    # own submodules. No separate seal-src needed.

  in {
    # ─── packages.unified-server ───────────────────────────────────────
    # Phase 2 of sub-task 5: build inside Nix's sandbox so the source
    # gets content-addressed into /nix/store/<hash>-source/. Two operators
    # cloning to different host paths converge to the same /nix/store
    # path → C++ __FILE__ macros in OnionPIR's CMake-built libonionpir.a
    # + libseal-4.1.a embed identical strings → cross-path determinism
    # closes (the gap the convention-based recipe couldn't reach).
    #
    # Use: `nix build .#unified-server` → ./result/bin/unified_server
    packages.${system} = {
      unified-server = pkgs.rustPlatform.buildRustPackage {
        pname = "unified-server";
        version = "0.1.0";
        src = ./.;

        # Cargo.lock is the source of truth for crate versions; outputHashes
        # provide content hashes for git deps (cargo vendor's git fetch is
        # non-deterministic without these). Initial values are lib.fakeHash;
        # first `nix build` will fail with the actual hash to substitute.
        cargoLock = {
          lockFile = ./Cargo.lock;
          # Captured via lib.fakeSha256 → first-build error → real value.
          # Re-capture whenever Cargo.lock's git rev for any dep changes.
          # Note: onionpir's hash includes the SEAL submodule contents
          # (cargo follows submodules during git dep fetch).
          outputHashes = {
            "alf-nt-0.1.0"     = "sha256-XfS1MTBqRJpAjvEE352J8vqSTwYOuXFJvrpXDmT8HmA=";
            "fastprp-0.1.0"    = "sha256-GVTeA1yBdpOj0GHcKTqQZz+1+AvV+tBkvUewTnNSlAo=";
            "harmonypir-0.1.0" = "sha256-uBflflGcvtQLcZJtekCwc5oB4IoyNhtrQmahav5KiR0=";
            "libdpf-0.1.0"     = "sha256-Hu4yEsxiNugk0dZe02Fz70DzOGKf9v52fhRgXtV8Vnw=";
            # onionpir hash bumped after the upstream restructure (rev
            # ac7082eb...) — now includes the bundled SEAL submodule.
            "onionpir-0.1.0"   = "sha256-hRX15/D5rUlFAnVdeTWBB31hDgG9h3BfrtO6GG+K0oA=";
          };
        };

        # Match the build_unified_server.sh wrapper's invocation.
        # rustPlatform.buildRustPackage already adds `--profile release`
        # by default, so we omit `--release` here to avoid the
        # "argument can't be used with `--release`" conflict.
        cargoBuildFlags = [ "-p" "runtime" "--bin" "unified_server" ];

        # The repo's .cargo/config.toml declares [source."git+..."] +
        # [source.crates-io] replace-with = "vendored-sources" entries
        # for sub-task 4's offline-build path. rustPlatform.buildRustPackage
        # ALSO writes its own [source.crates-io] / git source overrides
        # into the sandbox config, which collides with ours ("Sources are
        # not allowed to be defined multiple times"). Strip the in-repo
        # source replacements during patchPhase so only the Nix-managed
        # vendor dir is visible to cargo inside the sandbox.
        postPatch = ''
          # Remove every line from the first [source.crates-io] header to
          # end of file (the source-replacement block lives at the bottom
          # of .cargo/config.toml after the AES-NI rustflags + vendor doc).
          # rustPlatform.buildRustPackage writes its own [source.*]
          # entries, and cargo errors on duplicate source definitions.
          sed -i '/^\[source\.crates-io\]/,$d' .cargo/config.toml

          # Force USE_HEXL=OFF in the vendored OnionPIR build.rs.
          # HEXL's FetchContent_Declare hits the network at CMake configure
          # time, which the strict Nix sandbox blocks. SEAL falls back to
          # its scalar paths — slower but functionally correct, suitable
          # for the Phase 2 spike. Re-enable later by pre-fetching HEXL
          # via fetchFromGitHub and patching SEAL's FetchContent_Declare
          # (override-by-first-declared rule).
          sed -i 's|let use_hexl = .*$|let use_hexl = false;|' \
              "$NIX_BUILD_TOP/cargo-vendor-dir/onionpir-0.1.0/build.rs"
        '';
        # Skip cargo test inside the build (live-server integration tests
        # require network + a running pir2; not appropriate for sandbox).
        doCheck = false;

        nativeBuildInputs = with pkgs; [
          rustToolchain
          cmake
          gcc
          pkg-config
          gnumake
          # OnionPIR's build.rs uses git submodule for SEAL. Since cargo
          # already fetched the git dep with its submodules into the
          # source store path, no separate fetch should be needed at
          # build time.
          git
        ];

        # libgomp is linked by SEAL (OpenMP); libstdc++ comes from gcc.
        buildInputs = [ ];

        # Strip debug info reproducibly. cargo's release default already
        # omits debug; this is defense-in-depth.
        dontStrip = false;

        # __noChroot DROPPED: it allowed network for HEXL FetchContent but
        # also let CMake see /usr/bin/gcc, which references impure
        # /usr/libexec/ paths the Nix ld-wrapper rejects. With strict
        # sandbox, the only gcc visible is the Nix-provided one in PATH,
        # but HEXL FetchContent will fail from no-network. Open Phase 2
        # follow-up: pre-fetch HEXL via fetchFromGitHub and patch SEAL's
        # FetchContent_Declare to use it (override-by-first-declared rule).
      };
    };

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
