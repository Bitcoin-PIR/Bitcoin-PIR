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

    # cpu_features — google's runtime CPU-detection library. HEXL's
    # cmake/third-party/cpu-features/CMakeLists.txt uses ExternalProject_Add
    # to fetch this at configure time, which the strict Nix sandbox blocks.
    # We pre-fetch via Nix and rewrite HEXL's CMakeLists (in hexl-src
    # below) to file(COPY) from this store path instead. Rev pin matches
    # HEXL v1.2.5's CMakeLists.txt.in: GIT_TAG 32b49eb5...
    cpu-features-src = pkgs.fetchFromGitHub {
      owner = "google";
      repo = "cpu_features";
      rev = "32b49eb5e7809052a28422cfde2f2745fbb0eb76";
      hash = "sha256-PGvk5x0MUZojmL3+zpoo0D2t4H5pfcBvMiCPx1Qbs/s=";
    };

    # HEXL is fetched at CMake configure time by SEAL's FetchContent
    # (or by OnionPIR's superseding declaration in CMakeLists.txt). We
    # pre-fetch via Nix + apply two patches:
    #   1. Drop AVX-512 probes from HEXL's root CMakeLists (matches the
    #      OnionPIR fork's PATCH_COMMAND — needed on AVX-512-capable
    #      build hosts to prevent SIGILL on AVX-2-only runtime CPUs).
    #   2. Replace cpu_features ExternalProject_Add with file(COPY) from
    #      the Nix-fetched cpu-features-src above (closes the network
    #      requirement that ExternalProject lacks a SOURCE_DIR override).
    hexl-src = pkgs.applyPatches {
      name = "hexl-source-patched";
      src = pkgs.fetchFromGitHub {
        owner = "intel";
        repo = "hexl";
        rev = "f95acf1";
        hash = "sha256-AZAQ0l//WHHZW4rqyukldHjFLkm28e0zUfHFEGFy2h4=";
      };
      postPatch = ''
        # 1. AVX-512 probe removal (same as OnionPIR's PATCH_COMMAND)
        sed -i.bak "/hexl_check_compile_flag.*test-avx512/d" CMakeLists.txt
        rm -f CMakeLists.txt.bak

        # 2. Replace cpu-features download with file(COPY) from Nix-fetched
        # source. Quoted heredoc to prevent bash from expanding the
        # CMake variable references; sed substitutes the Nix store path
        # for the placeholder.
        cat > cmake/third-party/cpu-features/CMakeLists.txt <<'NIX_EOF'
        # Patched by BitcoinPIR's flake.nix: cpu-features pre-fetched.
        file(COPY @CPU_FEATURES_SRC@/ DESTINATION ''${CMAKE_CURRENT_BINARY_DIR}/cpu-features-src)

        hexl_cache_variable(BUILD_SHARED_LIBS)
        hexl_cache_variable(BUILD_PIC)
        hexl_cache_variable(BUILD_TESTING)

        set(BUILD_PIC ON CACHE BOOL "" FORCE)
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

        add_subdirectory(''${CMAKE_CURRENT_BINARY_DIR}/cpu-features-src
                         ''${CMAKE_CURRENT_BINARY_DIR}/cpu-features-build
                         EXCLUDE_FROM_ALL)

        unset(BUILD_PIC CACHE)
        unset(BUILD_SHARED_LIBS CACHE)
        unset(BUILD_TESTING CACHE)

        hexl_uncache_variable(BUILD_SHARED_LIBS)
        hexl_uncache_variable(BUILD_PIC)
        hexl_uncache_variable(BUILD_TESTING)
        NIX_EOF

        sed -i "s|@CPU_FEATURES_SRC@|${cpu-features-src}|g" \
            cmake/third-party/cpu-features/CMakeLists.txt
      '';
    };

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
      # ─── packages.tier3-uki — NOT YET WIRED UP ─────────────────────
      # Phase 2 extension to produce the full Tier 3 UKI (kernel +
      # initramfs + cmdline as a single PE/EFI) was attempted but hit a
      # dracut/Nix integration gap that needs more design than this
      # session's scope. Sketch + findings:
      #
      # - dracut has no `--modules-dir` flag; modules must live inside
      #   `dracutbasedir/modules.d/`. Workable: build a writable basedir
      #   under $NIX_BUILD_TOP, copy Nix's dracut tree + our patched
      #   bpir-* modules in, point dracut at it via `--conf` with
      #   `dracutbasedir="..."`. This part works.
      #
      # - dracut's auto-included default modules (`base`, `udev-rules`,
      #   `qemu`, network, etc.) walk PATH and try to install ~hundreds
      #   of binaries via `inst_multiple` / `inst_simple`. For each, it
      #   creates symlinks INSIDE the initramfs at the binary's full
      #   path (`/initramfs/nix/store/<hash>-busybox/bin/wc` →
      #   `/nix/store/<hash>-busybox/bin/wc`). The symlink target paths
      #   are absolute Nix-store paths that don't exist at the relative
      #   target dirs dracut expects. Hundreds of `ln: failed to create
      #   symbolic link` errors, then `Cannot find [systemd-]udevd
      #   binary` aborts the build. Restricting modules with
      #   `-m "base bpir-cloudflared bpir-unified-server bpir-tier3-init"`
      #   reduces but doesn't eliminate the issue (dracut still
      #   auto-includes udev-rules under any base config).
      #
      # - Closing this requires either:
      #     (a) Replace dracut entirely with NixOS's `make-initrd-ng` or
      #         `lib/build-support/initrd.nix`, which natively handles
      #         /nix/store paths (it copies binaries into the initramfs
      #         root, doesn't try to symlink them via host paths). Big
      #         architectural change; means rewriting the bpir-*
      #         module-setup.sh logic as Nix expressions.
      #     (b) Patch dracut (or write a wrapper) that translates Nix
      #         store paths to relative initramfs paths during inst_simple.
      #         Requires deep dracut knowledge.
      #     (c) Keep the existing scripts/build_uki_tier3.sh path for UKI
      #         building; use the Nix flake only for unified_server.
      #         Operator runs both inside `nix develop` shell. Pragmatic
      #         middle ground; sacrifices the cross-path sandbox property
      #         for the UKI bytes specifically.
      #
      # Phase 2 ships unified-server as the deterministic deliverable;
      # tier3-uki is tracked as the next major Phase 2 follow-up.

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

          # Copy HEXL to a writable location: HEXL's CMakeLists writes
          # .tmp files next to source during configure_package_config_file,
          # which fails when the source is in read-only /nix/store.
          HEXL_RW=$NIX_BUILD_TOP/hexl-rw
          cp -r ${hexl-src} $HEXL_RW
          chmod -R u+w $HEXL_RW

          # Inject -DFETCHCONTENT_SOURCE_DIR_HEXL=<writable-hexl-path> into
          # the vendored onionpir build.rs's CMake configure call, so
          # SEAL's FetchContent for HEXL skips the network git clone
          # and uses our pre-fetched + AVX-512-probe-patched +
          # cpu_features-patched source instead. Must be a CMake
          # variable (-D...), not env var — CMake's FetchContent.cmake
          # reads it via if(DEFINED FETCHCONTENT_SOURCE_DIR_<UCNAME>),
          # not if(DEFINED ENV{...}).
          sed -i "s|.args(\[\"-DCMAKE_BUILD_TYPE=Release\"\])|.args([\"-DCMAKE_BUILD_TYPE=Release\"])\n        .arg(\"-DFETCHCONTENT_SOURCE_DIR_HEXL=$HEXL_RW\")|" \
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
