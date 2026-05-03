use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("../..").canonicalize().unwrap();

    // --- Step 0: Ensure the SEAL submodule is checked out ---
    // Fresh `git clone` (without --recurse-submodules) leaves extern/SEAL
    // empty; CMake then fails at add_subdirectory(extern/SEAL) with
    // "does not contain a CMakeLists.txt file". Cargo consumers don't
    // typically know to pass --recurse-submodules, so we self-heal here.
    // Idempotent: skip the git call entirely once the submodule has a
    // populated tree (cheap stat instead of forking git on every build).
    let seal_cmakelists = repo_root.join("extern/SEAL/CMakeLists.txt");
    if !seal_cmakelists.exists() {
        eprintln!(
            "onionpir build.rs: extern/SEAL is empty; running `git submodule update --init --recursive`"
        );
        let status = Command::new("git")
            .current_dir(&repo_root)
            .args(["submodule", "update", "--init", "--recursive"])
            .status()
            .expect("Failed to spawn git for submodule init (is git on PATH?)");
        assert!(
            status.success(),
            "git submodule update failed; clone the repo with --recurse-submodules \
             or initialize manually: git submodule update --init --recursive"
        );
        assert!(
            seal_cmakelists.exists(),
            "extern/SEAL/CMakeLists.txt still missing after submodule init at {}",
            repo_root.display()
        );
    }

    // The `cmake` crate injects Clang-specific flags (--target=arm64-apple-macosx)
    // that GCC doesn't understand. Instead, drive CMake directly via Command.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out_dir.join("build");
    std::fs::create_dir_all(&build_dir).unwrap();

    // --- Step 1: Find GCC on macOS ---
    let (gcc, gxx) = if cfg!(target_os = "macos") {
        find_homebrew_gcc().expect("Could not find Homebrew GCC (g++-13..15). Install with: brew install gcc")
    } else {
        ("gcc".to_string(), "g++".to_string())
    };

    // --- Step 2: CMake configure ---
    // Intel HEXL is x86_64-only (AVX2 / AVX-512-IFMA paths). Enable it on
    // x86_64 Linux/Windows; leave it off on Apple Silicon and any other
    // non-x86 target. SEAL's runtime CPU dispatch handles AVX2-only vs
    // AVX-512-IFMA hosts at runtime, so a single binary is portable.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let use_hexl = target_arch == "x86_64" && (target_os == "linux" || target_os == "windows");
    let hexl_flag = if use_hexl { "-DUSE_HEXL=ON" } else { "-DUSE_HEXL=OFF" };

    // Clear environment variables that Cargo sets which inject Clang-specific
    // flags (--target=arm64-apple-macosx) that GCC doesn't understand.
    let configure_status = Command::new("cmake")
        .current_dir(&build_dir)
        .env_remove("CFLAGS")
        .env_remove("CXXFLAGS")
        .env_remove("ASMFLAGS")
        .env_remove("CC")
        .env_remove("CXX")
        .env_remove("TARGET")
        .env_remove("HOST")
        .arg(&repo_root)
        // Use Release (not the project's custom "Benchmark" type): when
        // USE_HEXL=ON, SEAL forwards CMAKE_BUILD_TYPE to HEXL via
        // FetchContent, and HEXL only accepts Debug/Release/RelWithDebInfo/
        // MinSizeRel — "Benchmark" hard-errors. The library is fine in
        // Release; logging.h has a no-op DEBUG_PRINT fallback for builds
        // that don't define _DEBUG or _BENCHMARK.
        .args(["-DCMAKE_BUILD_TYPE=Release"])
        .args([hexl_flag])
        .arg(format!("-DCMAKE_C_COMPILER={}", gcc))
        .arg(format!("-DCMAKE_CXX_COMPILER={}", gxx))
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", out_dir.display()))
        .status()
        .expect("Failed to run cmake configure");
    assert!(configure_status.success(), "CMake configure failed");

    // --- Step 3: CMake build ---
    let nproc = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let build_status = Command::new("cmake")
        .current_dir(&build_dir)
        .args(["--build", "."])
        .args(["--target", "onionpir"])
        .args(["-j", &nproc.to_string()])
        .status()
        .expect("Failed to run cmake build");
    assert!(build_status.success(), "CMake build failed");

    // --- Step 4: Emit linker directives ---
    // libonionpir.a is in the cmake build root
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=onionpir");

    // libseal-4.1.a is under extern/SEAL/lib/ in the cmake build tree
    println!(
        "cargo:rustc-link-search=native={}/extern/SEAL/lib",
        build_dir.display()
    );
    println!("cargo:rustc-link-lib=static=seal-4.1");

    // Link OpenMP (libgomp) and C++ standard library
    if cfg!(target_os = "macos") {
        if let Some(gcc_lib) = find_gcc_lib_dir() {
            println!("cargo:rustc-link-search=native={}", gcc_lib);
        }
        println!("cargo:rustc-link-lib=dylib=gomp");
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else {
        println!("cargo:rustc-link-lib=dylib=gomp");
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // --- Step 5: Rerun triggers ---
    for path in &[
        "src/ffi.cpp",
        "src/ffi_c.cpp",
        "src/includes/ffi.h",
        "src/includes/ffi_c.h",
        "CMakeLists.txt",
    ] {
        println!("cargo:rerun-if-changed={}/{}", repo_root.display(), path);
    }
}

/// Find Homebrew GCC (g++-15, g++-14, g++-13)
fn find_homebrew_gcc() -> Option<(String, String)> {
    for ver in &["15", "14", "13"] {
        let gxx = format!("/opt/homebrew/bin/g++-{}", ver);
        let gcc = format!("/opt/homebrew/bin/gcc-{}", ver);
        if std::path::Path::new(&gxx).exists() {
            return Some((gcc, gxx));
        }
    }
    None
}

/// Find the GCC runtime library directory (for libgomp)
fn find_gcc_lib_dir() -> Option<String> {
    for ver in &["15", "14", "13"] {
        for minor in &["2.0", "1.0"] {
            let dir = format!(
                "/opt/homebrew/Cellar/gcc/{}.{}/lib/gcc/current",
                ver, minor
            );
            if std::path::Path::new(&dir).exists() {
                return Some(dir);
            }
        }
    }
    None
}
