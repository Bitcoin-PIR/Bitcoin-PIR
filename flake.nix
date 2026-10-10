{
  description = "BitcoinPIR — hermetic build environment for Tier 3 UKI reproducibility (sub-task 5 of docs/history/PHASE3_SLICE3_REPRO_PLAN.md)";

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

    # Intel HEXL — x86_64 NTT/eltwise acceleration for the onionpir C++
    # engine (linked when ONIONPIR_USE_HEXL is defined, i.e. USE_HEXL=ON —
    # the crate's x86_64 default since rev 7ea020a). nixpkgs has no `hexl`
    # package, so build it here. HEXL 1.2.6 does `find_package(CpuFeatures
    # CONFIG)` and only FetchContent-downloads google/cpu_features if that
    # misses — passing nixpkgs' cpu_features makes the HEXL build fully
    # hermetic (no network). HEXL_BENCHMARK/HEXL_TESTING OFF likewise skip
    # the google-benchmark / gtest FetchContent. The result ships
    # lib/cmake/hexl-1.2.6/HEXLConfig.cmake, so the onionpir build's
    # `find_package(HEXL CONFIG)` resolves it (see buildInputs + postPatch).
    hexl = pkgs.stdenv.mkDerivation {
      pname = "hexl";
      version = "1.2.6";
      src = pkgs.fetchFromGitHub {
        owner = "intel";
        repo = "hexl";
        rev = "v1.2.6";
        hash = "sha256-9DWQMmbvwl/UVyllNoixjJJsd7ksFztwKZ8gFlIBg+U=";
      };
      nativeBuildInputs = [ pkgs.cmake ];
      # cpu_features ships its CMake config package in the `dev` output;
      # buildInputs propagation puts it on CMAKE_PREFIX_PATH so HEXL's
      # `find_package(CpuFeatures CONFIG)` resolves it instead of fetching.
      buildInputs = [ pkgs.cpu_features ];
      cmakeFlags = [
        # nixpkgs' cmake hook sets CMAKE_INSTALL_INCLUDEDIR to an absolute
        # path; HEXL's header install does
        #   install(DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
        # which then double-prefixes ($out/nix/store/...-hexl/include) and
        # leaves HEXL::hexl's INTERFACE_INCLUDE_DIRECTORIES pointing at a
        # non-existent $out/include. A relative includedir lands the
        # headers at $out/include, where the exported config expects them.
        "-DCMAKE_INSTALL_INCLUDEDIR=include"
        "-DHEXL_BENCHMARK=OFF"
        "-DHEXL_TESTING=OFF"
        "-DHEXL_SHARED_LIB=OFF"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
      ];
    };

  in {
    # ─── packages.unified-server ───────────────────────────────────────
    # Phase 2 of sub-task 5: build inside Nix's sandbox so the source
    # gets content-addressed into /nix/store/<hash>-source/. Two operators
    # cloning to different host paths converge to the same /nix/store
    # path → C++ __FILE__ macros in OnionPIR's CMake-built libonionpir.a
    # embed identical strings → cross-path determinism closes (the gap
    # the convention-based recipe couldn't reach).
    #
    # Use: `nix build .#unified-server` → ./result/bin/unified_server
    packages.${system} = {
      # Hermetic, bit-reproducible build — development/reproducibility
      # use only (and it lacks the `cuckoo-oram` feature the Direct ORAM
      # host's production binary requires).
      # Production binaries are bare-Cargo builds per CLAUDE.md; do not
      # pin this derivation's sha256 as a production release identity.
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
          # Content hashes for the git deps in Cargo.lock. The keys MUST
          # be exactly the set of git dependencies in Cargo.lock — a
          # stale key ("a hash was specified for X, but there is no
          # corresponding git dependency") and a missing one both fail
          # evaluation. Re-capture whenever a git rev or the dep set
          # changes: set the entry to the all-A fake hash, run
          # `nix build`, substitute the hash from the mismatch error.
          # Note: the onionpir crate is SEAL-free and submodule-free —
          # its hash covers just the rust/onionpir/ crate tree (Rust src
          # + the bundled cpp/ C++ engine + CMakeLists.txt).
          #
          # 2026-05-18 re-sync: dropped `alf-nt` (HarmonyPIR's PRP
          # backend no longer depends on the ALF crate); added `arc`
          # (new git dep); `onionpir-0.1.0` → `onionpir-0.2.0`.
          # 2026-05-19 re-pin: onionpir aa7710d → c7ed905 → 7ea020a — the
          # self-contained-crate restructure, then the HEXL / -march
          # detection fix.
          # 2026-05-20 re-pin: 7ea020a → 3f815ba — build.rs now emits
          # HEXL + cpu_features link directives natively (via the
          # package's *Targets*.cmake IMPORTED_LOCATION, split-output
          # safe), so the flake postPatch HEXL-link sed below is dropped.
          # New rev → new content hash (fake-hash cycle).
          outputHashes = {
            "arc-0.1.0"        = "sha256-tUyvnyJoNTlrXpudIZ3Er6Mqj8zmltBtY06kF9P6hp0=";
            "fastprp-0.1.0"    = "sha256-GVTeA1yBdpOj0GHcKTqQZz+1+AvV+tBkvUewTnNSlAo=";
            "harmonypir-0.1.0" = "sha256-E7moHaQUhR4NUIdKsOluOGHFOkZE6bJrj26tc0f3IGQ=";
            "libdpf-0.1.0"     = "sha256-Hu4yEsxiNugk0dZe02Fz70DzOGKf9v52fhRgXtV8Vnw=";
            "onionpir-0.2.0"   = "sha256-0xqftjQya0180F+xSOhcTnKKqj4nMHzEiSwQTtlZpJQ=";
          };
        };

        # Same package and binary as the bare-Cargo production build.
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

          # Point the onionpir C++ build's CMake at the HEXL + cpu_features
          # CMake-config packages. Since rev 7ea020a the onionpir CMakeLists
          # defaults USE_HEXL=ON on x86_64 and does `find_package(HEXL
          # CONFIG)`; HEXL's own config in turn does `find_package(
          # CpuFeatures CONFIG)`. nixpkgs' cmake hook already exports both
          # on CMAKE_PREFIX_PATH via buildInputs, but the `cmake` crate
          # (cmake-rs) spawns its own cmake — inject the prefixes into its
          # Config chain explicitly so resolution can't depend on env
          # propagation. Fully hermetic: HEXL is the Nix derivation above.
          sed -i 's|\.define("ONIONPIR_BUILD_FFI", "ON")|&\n        .define("CMAKE_PREFIX_PATH", "${hexl};${pkgs.cpu_features.dev}")|' \
              "$NIX_BUILD_TOP/cargo-vendor-dir/onionpir-0.2.0/build.rs"

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
          # git: available to the sandbox build for any build script
          # that shells out to it. The onionpir crate is SEAL-free and
          # submodule-free, so it needs no git fetch of its own.
          git
        ];

        # Intel HEXL (Nix-built, above) + its cpu_features dependency —
        # for the onionpir C++ engine's find_package(HEXL CONFIG) /
        # find_package(CpuFeatures CONFIG) and the final link. cpu_features
        # is a shared lib, so it stays a runtime dep of unified_server in
        # the Nix closure.
        buildInputs = [ hexl pkgs.cpu_features ];

        # Strip debug info reproducibly. cargo's release default already
        # omits debug; this is defense-in-depth.
        dontStrip = false;

        # Strict sandbox (no __noChroot): the build needs no network. HEXL
        # is the Nix-built derivation above and the onionpir C++ build
        # resolves it via find_package(CONFIG) — no FetchContent; every
        # git dep is pre-fetched by Nix via cargoLock. The only gcc
        # visible is the Nix-provided one.
      };
    };

    devShells.${system}.default = pkgs.mkShell {
      packages = [
        rustToolchain
      ] ++ (with pkgs; [

        # ─── Rust / Cargo ──────────────────────────────────────────────
        # rustToolchain provides cargo + rustc + rustfmt + clippy.

        # ─── C/C++ build chain (for OnionPIR's CMake-built C++ engine) ─
        # The onionpir crate's CMakeLists sets CMAKE_POLICY_VERSION_MINIMUM,
        # so it configures cleanly under CMake 4.x — nixpkgs's `cmake`
        # (latest upstream) works as-is.
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
        echo "    cargo build --locked --release -p runtime --bin unified_server"
        echo "    sudo ./scripts/build_uki_tier3.sh   # needs root for /boot/vmlinuz"
      '';
    };
  };
}
