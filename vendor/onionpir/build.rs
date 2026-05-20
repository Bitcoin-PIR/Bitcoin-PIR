// Build script for the `onionpir` Rust crate.
//
// Runs the crate-local CMake project (rust/onionpir/CMakeLists.txt) with
// `-DONIONPIR_BUILD_FFI=ON` to produce `libonionpir.a`, then links it (plus
// the C++ runtime, and Intel HEXL when the engine was built against it) into
// the crate. The FFI surface itself is declared in `src/lib.rs`.
//
// The CMake project, the cpp/ engine sources and this script all live inside
// the crate dir — no path here reaches outside CARGO_MANIFEST_DIR — so
// `cargo vendor` ships a self-contained, buildable crate.
//
// HEXL note: `libonionpir.a` is a *static* archive, and a static archive does
// not carry its own link dependencies. When CMake resolves Intel HEXL
// (`USE_HEXL=ON` and a HEXL package is found) the archive is left with
// unresolved `intel::hexl::*` and `cpu_features` symbols — so any Rust
// consumer would fail to link. This script reads the generated CMake cache to
// learn whether HEXL was resolved, locates each library's on-disk path via
// the exported `<Pkg>Targets*.cmake` (so split-output package layouts like
// nixpkgs — CMake config in a `dev` store path, library in `out` — are
// handled correctly), and emits matching `-l`/`-L` directives so a consumer
// links cleanly with no manual flag injection. With HEXL inactive the
// in-crate scalar/SIMD shim (cpp/hexl_shim.cpp) is compiled into
// `libonionpir.a` instead, leaving nothing extra to link.
//
// Re-runs when the C ABI header, any C++ source, or the CMake cache changes.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    // The crate is self-contained: CMakeLists.txt + cpp/ both live inside the
    // crate dir, so the CMake source dir IS the manifest dir. The previous
    // layout used manifest_dir.parent().parent() to reach a repo-root CMake
    // project, which broke any cargo-vendored consumer — cargo flattens a git
    // dep down to just the consumed subcrate, dropping everything above it.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Upstream gates the debug/benchmark print macros (DEBUG_PRINT,
    // PRINT_INT_ARRAY) on _BENCHMARK or _DEBUG. Plain Release leaves them
    // undefined → compile errors. Build type "Benchmark" defines _BENCHMARK
    // and uses the same -O3 -march flags.
    let dst = cmake::Config::new(&manifest_dir)
        .define("ONIONPIR_BUILD_FFI", "ON")
        .define("CMAKE_BUILD_TYPE", "Benchmark")
        .profile("Benchmark")  // tell cmake-rs not to override CMAKE_BUILD_TYPE
        .build_target("onionpir")
        .build();

    // cmake-rs runs the build in <dst>/build; the onionpir target pins its
    // ARCHIVE_OUTPUT_DIRECTORY to CMAKE_BINARY_DIR, which is exactly that dir.
    let build_dir = dst.join("build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=onionpir");

    // If the engine was built with Intel HEXL active, libonionpir.a needs the
    // HEXL + cpu_features archives linked *after* it. Emitted here — between
    // `onionpir` and the C++ runtime below — so the final link order is
    // onionpir → hexl → cpu_features → c++, with each archive's unresolved
    // symbols satisfied by the libraries to its right. A no-op when HEXL is
    // inactive (the shim is baked into libonionpir.a).
    let cmake_cache = build_dir.join("CMakeCache.txt");
    emit_hexl_link_flags(&cmake_cache);

    // C++ runtime: libc++ on Apple (clang default), libstdc++ on Linux GCC.
    // MUST come last — both libonionpir.a and libhexl.a are C++ static
    // archives carrying unresolved std::/operator-new symbols.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // Re-run triggers.
    let watch = [
        manifest_dir.join("cpp/includes/onion_ffi.h"),
        manifest_dir.join("cpp/onion_ffi.cpp"),
        manifest_dir.join("CMakeLists.txt"),
        // The cache records which HEXL (if any) CMake resolved, hence which
        // link flags we emit above. cmake-rs rewrites it mid-run, before this
        // script finishes, so it is always older than the script's recorded
        // output — tracking it does not create a rebuild loop.
        cmake_cache,
    ];
    for p in &watch {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    // Also rerun if anything under cpp/ changes — broader than ideal but
    // catches edits to the engine that affect the FFI's behavior.
    println!("cargo:rerun-if-changed={}", manifest_dir.join("cpp").display());
}

/// Read the CMake cache and, when it shows Intel HEXL was resolved, emit the
/// `cargo:rustc-link-{search,lib}` directives the static `libonionpir.a`
/// needs: `hexl` and its `cpu_features` CPU-dispatch dependency.
///
/// No-op when HEXL is inactive — either `USE_HEXL=OFF` (the cache has no
/// `HEXL_DIR` at all) or `USE_HEXL=ON` but no package was found (`HEXL_DIR`
/// is the `…-NOTFOUND` sentinel). Both compile the in-crate shim into
/// `libonionpir.a`, so there is nothing extra to link.
fn emit_hexl_link_flags(cmake_cache: &Path) {
    let cache = match fs::read_to_string(cmake_cache) {
        Ok(text) => text,
        // A missing cache after a successful build would be very surprising;
        // treat it as "no HEXL" rather than failing the build outright.
        Err(_) => return,
    };

    // `HEXL_DIR` is created by find_package(HEXL): it points at the directory
    // holding HEXLConfig.cmake when HEXL is found, and is absent or
    // `HEXL_DIR-NOTFOUND` otherwise. A real path here mirrors CMake's
    // resolved ONIONPIR_HEXL_ACTIVE=TRUE decision.
    let hexl_dir = match cmake_cache_value(&cache, "HEXL_DIR") {
        Some(dir) if is_resolved(&dir) => dir,
        _ => return, // HEXL inactive → the shim is baked into libonionpir.a
    };
    let hexl_cmake_dir = PathBuf::from(&hexl_dir);

    if !emit_package_lib(&hexl_cmake_dir, "hexl") {
        println!(
            "cargo:warning=onionpir: HEXL is active but libhexl could not be \
             located from HEXL_DIR={} — the link will likely fail",
            hexl_dir,
        );
    }

    // cpu_features is HEXL's runtime CPU-feature-detection dependency. HEXL's
    // package config pulls it in via find_dependency(CpuFeatures), which
    // leaves `CpuFeatures_DIR` in the cache. When that entry is missing,
    // fall back to HEXL's CMake dir — the two are typically co-installed,
    // and emit_package_lib's libdir-scan fallback finds them side by side.
    let cpu_cmake_dir = cmake_cache_value(&cache, "CpuFeatures_DIR")
        .filter(|d| is_resolved(d))
        .map(PathBuf::from)
        .unwrap_or_else(|| hexl_cmake_dir.clone());

    if !emit_package_lib(&cpu_cmake_dir, "cpu_features") {
        // Not necessarily an error: some HEXL builds fold cpu_features
        // straight into libhexl.a, leaving nothing separate to link.
        println!(
            "cargo:warning=onionpir: HEXL is active but no separate \
             cpu_features library was located from {} — assuming it is \
             bundled into libhexl.a",
            cpu_cmake_dir.display(),
        );
    }
}

/// Emit `cargo:rustc-link-{search,lib}` directives for native library `name`
/// belonging to the CMake package whose config directory is `cmake_dir`. Two
/// strategies, tried in order:
///
/// 1. **Targets file (primary).** `<Pkg>Targets*.cmake` files next to the
///    package config record each imported target's on-disk location as an
///    `IMPORTED_LOCATION[_<CONFIG>]` property. The value is either absolute
///    (nixpkgs and similar patch absolute store paths in directly) or
///    `${_IMPORT_PREFIX}/…` (standard CMake export, where `_IMPORT_PREFIX`
///    is computed at config-load time by walking up from the dispatch
///    `<Pkg>Targets.cmake`). Both forms are handled, and the resolved
///    absolute path yields both the `-L` directory (its parent) and the
///    static/shared kind (its extension) with no extra filesystem probing.
/// 2. **Lib dir scan (fallback).** Derive `<prefix>/lib` from `cmake_dir`
///    under the conventional `<prefix>/lib/cmake/<pkg>` layout and scan it
///    for `lib<name>.{a,so,dylib}`. Used when the Targets scan finds
///    nothing — e.g., an export referencing a CMake variable we don't
///    expand, or no Targets file at all.
///
/// The Targets-file path is essential for split-output package layouts
/// (most notably nixpkgs): the CMake config sits under a `dev` store path
/// while the library lives in `out`, so the libdir-from-config-dir
/// heuristic lands in `dev/lib`, which holds only `cmake/` and no library.
fn emit_package_lib(cmake_dir: &Path, name: &str) -> bool {
    if let Some(libpath) = library_path_from_targets(cmake_dir, name) {
        if let Some(libdir) = libpath.parent() {
            let kind = match libpath.extension().and_then(|s| s.to_str()) {
                Some("a") => "static",
                _ => "dylib",
            };
            println!("cargo:rustc-link-search=native={}", libdir.display());
            println!("cargo:rustc-link-lib={}={}", kind, name);
            return true;
        }
    }
    match libdir_from_cmake_dir(cmake_dir) {
        Some(libdir) => emit_native_lib(&libdir, name),
        None => false,
    }
}

/// Walk `<Pkg>Targets*.cmake` files in `cmake_dir` for an
/// `IMPORTED_LOCATION[_<CONFIG>]` property whose value resolves to
/// `lib<name>.{a,so,dylib}` on disk. Returns the first such absolute path,
/// preferring a static (`.a`) match over a shared one (a self-contained
/// link is preferable).
///
/// Both the standard CMake export form (`${_IMPORT_PREFIX}/…`, resolved
/// against the prefix recovered from the dispatch `<Pkg>Targets.cmake`) and
/// absolute paths patched in by build systems like nixpkgs are handled.
/// Values that remain unresolved after substitution, or that resolve to
/// non-existent files, are skipped so the caller's fallback can try.
fn library_path_from_targets(cmake_dir: &Path, name: &str) -> Option<PathBuf> {
    let prefix = import_prefix_for(cmake_dir);

    let want_a = format!("lib{}.a", name);
    let want_so = format!("lib{}.so", name);
    let want_dylib = format!("lib{}.dylib", name);

    let mut shared: Option<PathBuf> = None;
    for entry in fs::read_dir(cmake_dir).ok()?.flatten() {
        let path = entry.path();
        let fname = match path.file_name().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        // `<Pkg>Targets.cmake` (the dispatch) and `<Pkg>Targets-<config>.cmake`
        // (per-config) are the only files that carry IMPORTED_LOCATION; skip
        // Config.cmake, ConfigVersion.cmake, …
        if !fname.contains("Targets") || !fname.ends_with(".cmake") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for line in text.lines() {
            let line = line.trim_start();
            // Accepts IMPORTED_LOCATION, IMPORTED_LOCATION_RELEASE,
            // _DEBUG, _NOCONFIG, … — any config suffix or none.
            if !line.starts_with("IMPORTED_LOCATION") {
                continue;
            }
            let quoted = match extract_quoted(line) {
                Some(q) => q,
                None => continue,
            };
            let resolved = match &prefix {
                Some(p) => quoted.replace("${_IMPORT_PREFIX}", &p.to_string_lossy()),
                None => quoted.to_string(),
            };
            let libpath = PathBuf::from(&resolved);
            // Reject values that didn't fully resolve (a `${VAR}` we don't
            // know how to expand survived) or that don't point to a real
            // file — the libdir-scan fallback may still find the library.
            if !libpath.is_absolute() || !libpath.exists() {
                continue;
            }
            let basename = match libpath.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => continue,
            };
            if basename == want_a {
                return Some(libpath); // static preferred — short-circuit
            }
            if (basename == want_so || basename == want_dylib) && shared.is_none() {
                shared = Some(libpath);
            }
        }
    }
    shared
}

/// Recover the absolute install prefix that `${_IMPORT_PREFIX}` references
/// inside per-config Targets files. The dispatch `<Pkg>Targets.cmake`
/// computes it with a chain of `get_filename_component(_IMPORT_PREFIX …
/// PATH)` calls: the first walks from the file path to its containing
/// directory (= `cmake_dir`), each subsequent one walks a directory up. So
/// the prefix sits `walks - 1` ancestors above `cmake_dir`.
///
/// Returns `None` when no dispatch file is found, or when its body has no
/// walk chain (the in-build-tree export form, which records absolute paths
/// directly and needs no substitution).
fn import_prefix_for(cmake_dir: &Path) -> Option<PathBuf> {
    let dispatch = fs::read_dir(cmake_dir).ok()?.flatten()
        .map(|e| e.path())
        .find(|p| {
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // `<Pkg>Targets.cmake` — no `-<config>` suffix.
            n.ends_with("Targets.cmake") && !n.contains("Targets-")
        })?;
    let text = fs::read_to_string(&dispatch).ok()?;
    let walks = text
        .lines()
        .filter(|l| l.trim_start().starts_with("get_filename_component(_IMPORT_PREFIX"))
        .count();
    if walks == 0 {
        return None;
    }
    let mut p = cmake_dir.to_path_buf();
    for _ in 0..(walks - 1) {
        p = p.parent()?.to_path_buf();
    }
    Some(p)
}

/// Return the text between the first pair of double-quotes in `line`, or
/// `None` if fewer than two quotes are present.
fn extract_quoted(line: &str) -> Option<&str> {
    let start = line.find('"')? + 1;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// True unless the cache value is empty or a CMake `…-NOTFOUND` sentinel.
fn is_resolved(value: &str) -> bool {
    !value.is_empty() && !value.ends_with("-NOTFOUND")
}

/// Look up a `KEY:TYPE=VALUE` entry in CMakeCache.txt text. Comment lines
/// (`//` and `#`) are skipped; the trimmed value of the first matching key is
/// returned.
fn cmake_cache_value(cache: &str, key: &str) -> Option<String> {
    for line in cache.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        // A cache entry is `KEY:TYPE=VALUE`; the type annotation sits between
        // the key and the first '='.
        let (lhs, value) = match line.split_once('=') {
            Some(parts) => parts,
            None => continue,
        };
        let name = lhs.split(':').next().unwrap_or(lhs);
        if name == key {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Map a package's CMake-config directory to the library directory beside it:
/// `<prefix>/lib/cmake/<pkg>` → `<prefix>/lib`. Locates the `cmake` path
/// component and returns its parent, so a `lib` vs `lib64` root and an
/// optional version-suffixed package subdir are both handled.
fn libdir_from_cmake_dir(cmake_dir: &Path) -> Option<PathBuf> {
    for ancestor in cmake_dir.ancestors() {
        if ancestor.file_name().map_or(false, |n| n == "cmake") {
            return ancestor.parent().map(Path::to_path_buf);
        }
    }
    // No `cmake` component (unusual layout): fall back to the grandparent,
    // matching the documented <…>/lib/cmake/<pkg> shape.
    cmake_dir.parent().and_then(Path::parent).map(Path::to_path_buf)
}

/// Emit `cargo:rustc-link-search` + `cargo:rustc-link-lib` for native library
/// `name` in `libdir`, picking the `static`/`dylib` kind from whichever
/// library file is actually present (static is preferred — it keeps the link
/// self-contained, with no runtime .so lookup). Returns `false`, emitting
/// nothing, when no `lib<name>.*` exists in `libdir`.
fn emit_native_lib(libdir: &Path, name: &str) -> bool {
    let has_static = libdir.join(format!("lib{}.a", name)).exists();
    let has_shared = libdir.join(format!("lib{}.so", name)).exists()
        || libdir.join(format!("lib{}.dylib", name)).exists();

    if !has_static && !has_shared {
        return false;
    }
    println!("cargo:rustc-link-search=native={}", libdir.display());
    let kind = if has_static { "static" } else { "dylib" };
    println!("cargo:rustc-link-lib={}={}", kind, name);
    true
}
