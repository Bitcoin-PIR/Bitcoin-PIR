cmake_minimum_required(VERSION 3.13)

# CMake 4.x compat: an installed HEXL package config (or another find_package'd
# dependency) may still declare 3.5-era policy defaults. Allow them under a
# newer cmake.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# Set build type to Benchmark if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Benchmark)
endif()

# Compiler picked up from PATH. Load the desired toolchain before running
# cmake (e.g. `module load gcc/13.3.0`). Override with -DCMAKE_CXX_COMPILER=...
# if you want to pin a specific binary.

# Ask every target in this project to compile as C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)   # fail if the compiler can't do C++20
set(CMAKE_CXX_EXTENSIONS  OFF)        # use -std=c++20, not gnu++20

# Arch-independent optimisation flags. The microarchitecture flag (-march) is
# appended after project() below — it depends on CMAKE_SYSTEM_PROCESSOR, which
# CMake only populates as part of project().
if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(CMAKE_CXX_FLAGS "-O2 -MD -pg")   # -pg: profiling build
else()
    set(CMAKE_CXX_FLAGS "-O3 -MD")
endif()
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG")

set(IS_BENCHMARK_BUILD CMAKE_BUILD_TYPE STREQUAL "Benchmark")
if (${IS_BENCHMARK_BUILD})
    add_compile_definitions(_BENCHMARK)
endif ()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(Onion-PIR)

# ============================================================================
# The blocks below read CMAKE_SYSTEM_PROCESSOR, which CMake only populates as
# part of project(). They MUST stay after project(): evaluated earlier,
# CMAKE_SYSTEM_PROCESSOR is empty, the arch regex silently fails, and the
# -march / HEXL / AVX detection all quietly take their non-x86 fallback —
# disabling HEXL on x86_64 even when explicitly requested. (Past regression.)
# ============================================================================

# ---- Microarchitecture target ----------------------------------------------
# -march=native bakes in the *build host's* instruction set: not reproducible,
# and a latent SIGILL when the deploy CPU is older than the builder. Default to
# a portable baseline instead. Override with -DONIONPIR_MARCH=<value> (e.g.
# native, x86-64-v4, znver4, …); set it empty to omit -march entirely.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    set(_ONIONPIR_MARCH_DEFAULT "x86-64-v3")   # AVX2 + FMA + BMI; runs on any
                                               # Haswell-or-newer Intel / Zen
else()
    set(_ONIONPIR_MARCH_DEFAULT "native")      # ARM/other: host tuning is fine
endif()
set(ONIONPIR_MARCH "${_ONIONPIR_MARCH_DEFAULT}" CACHE STRING
    "Microarchitecture passed to -march (empty = omit the flag)")
if (ONIONPIR_MARCH)
    message(STATUS "Codegen target: -march=${ONIONPIR_MARCH}")
    string(APPEND CMAKE_CXX_FLAGS " -march=${ONIONPIR_MARCH}")
endif()

# ---- Intel HEXL -------------------------------------------------------------
# HEXL is x86_64-only. USE_HEXL defaults ON on x86_64, OFF elsewhere (ARM,
# WASM). When HEXL is unavailable the build uses the scalar/SIMD shim under
# cpp/hexl_compat/ (cpp/hexl_shim.cpp), which reimplements the subset of HEXL's
# API the engine needs (NTT, Eltwise*, MinimalPrimitiveRoot).
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    set(_USE_HEXL_DEFAULT ON)
else()
    set(_USE_HEXL_DEFAULT OFF)
endif()
option(USE_HEXL "Enable Intel HEXL acceleration (x86_64 only)" ${_USE_HEXL_DEFAULT})

# ONIONPIR_HEXL_ACTIVE is the resolved decision — true only when HEXL is both
# requested AND actually found. Everything downstream keys off this, so a
# requested-but-missing HEXL degrades cleanly to the shim.
set(ONIONPIR_HEXL_ACTIVE FALSE)
if (USE_HEXL)
    # Locate an installed HEXL: pass -DHEXL_DIR=<dir with HEXLConfig.cmake> or
    # -DCMAKE_PREFIX_PATH=<prefix>. Deliberately NOT REQUIRED — a missing HEXL
    # must not break the build (e.g. cargo-vendored consumers that don't ship
    # it); we fall back to the shim instead.
    find_package(HEXL CONFIG)
    if (HEXL_FOUND)
        set(ONIONPIR_HEXL_ACTIVE TRUE)
        message(STATUS "HEXL found (${HEXL_DIR}) — Intel HEXL acceleration enabled.")
    else()
        message(WARNING
            "USE_HEXL=ON but no HEXL package was found — pass -DHEXL_DIR=<dir> "
            "or -DCMAKE_PREFIX_PATH=<prefix>. Falling back to the scalar/SIMD "
            "shim at cpp/hexl_compat/.")
    endif()
else()
    message(STATUS "HEXL disabled — using scalar/SIMD shim at cpp/hexl_compat/.")
endif()
if (ONIONPIR_HEXL_ACTIVE)
    add_compile_definitions(ONIONPIR_USE_HEXL)
endif()

# ---- AVX-512 / AVX2 escape hatches ------------------------------------------
# For hosts where -march pulls in instructions the deploy CPU lacks. With the
# default ONIONPIR_MARCH=x86-64-v3 there is no AVX-512 to disable; NOAVX512
# matters only when ONIONPIR_MARCH is bumped to an AVX-512 level.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    option(NOAVX512 "Disable AVX-512" OFF)
else()
    option(NOAVX512 "Disable AVX-512" ON)
endif()
option(NOAVX2 "Disable AVX2" OFF)
if (NOAVX512 AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    message(STATUS "Disabling AVX-512 (-mno-avx512f)")
    add_compile_options(-mno-avx512f)
endif()
if (NOAVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|amd64|AMD64)")
    message(STATUS "Disabling AVX2 (-mno-avx2)")
    add_compile_options(-mno-avx2)
endif()

# Build-time selector for the parameter set.
# Override on the cmake line:
#   cmake -DACTIVE_CONFIG=CONFIG_N2048_K1_COMP ..
# Default is picked up from cpp/includes/database_constants.h when unset.
if (DEFINED ACTIVE_CONFIG)
    message(STATUS "ACTIVE_CONFIG = ${ACTIVE_CONFIG}")
    add_compile_definitions(ACTIVE_CONFIG=${ACTIVE_CONFIG})
endif()


# Source layout split for the two build targets:
#   ONIONPIR_CORE_SRC  = library-eligible sources (PIR engine + scalar/SIMD HEXL
#                        shim if applicable). Excludes main.cpp / test scaffolding.
#   ONIONPIR_FFI_SRC   = C-ABI wrapper for Rust / Java consumers.
#   ONIONPIR_BIN_SRC   = additional sources for the Onion-PIR executable
#                        (main.cpp and the in-tree test harness under cpp/tests/).
file(GLOB ONIONPIR_CORE_SRC
    cpp/bv_keyswitch.cpp cpp/client.cpp cpp/gsw.cpp cpp/logging.cpp
    cpp/matrix.cpp cpp/pir.cpp cpp/query_queue.cpp cpp/rlwe.cpp cpp/server.cpp
    cpp/shared_key_store.cpp cpp/utils.cpp
)
if (NOT ONIONPIR_HEXL_ACTIVE)
    list(APPEND ONIONPIR_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/cpp/hexl_shim.cpp")
endif()

file(GLOB ONIONPIR_BIN_SRC cpp/main.cpp cpp/tests/*.cpp)
set(ONIONPIR_FFI_SRC "${CMAKE_CURRENT_SOURCE_DIR}/cpp/onion_ffi.cpp")

# Common include dirs reused by all targets below.
set(ONIONPIR_PUBLIC_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/cpp/includes")
if (NOT ONIONPIR_HEXL_ACTIVE)
    list(APPEND ONIONPIR_PUBLIC_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/cpp/hexl_compat")
endif()

# Executable target (Onion-PIR): core engine + test harness + main.
add_executable(Onion-PIR ${ONIONPIR_CORE_SRC} ${ONIONPIR_BIN_SRC})
target_include_directories(Onion-PIR PUBLIC ${ONIONPIR_PUBLIC_INCLUDES})
if (ONIONPIR_HEXL_ACTIVE)
    target_link_libraries(Onion-PIR PUBLIC HEXL::hexl)
endif()
# Land the executable in the top-level build dir (e.g. build/Onion-PIR) so
# run.py and scripts/ find it at the same path as before this crate became a
# CMake subdirectory of the repo-root wrapper. CMAKE_BINARY_DIR is the top of
# the build tree whether configured here directly or via the wrapper.
set_target_properties(Onion-PIR PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Library target (onionpir): core engine + C ABI, for Rust / Java / native
# consumers. Disabled by default since the headline executable doesn't need it.
#   ONIONPIR_BUILD_FFI=ON       — build the library (Rust crate flips this on)
#   ONIONPIR_BUILD_SHARED=ON    — build as a .dylib / .so instead of .a
#                                  (Java JNA loads a shared library by name)
option(ONIONPIR_BUILD_FFI    "Build the onionpir library with C ABI" OFF)
option(ONIONPIR_BUILD_SHARED "Build onionpir as a shared library (default: static)" OFF)
if (ONIONPIR_BUILD_FFI)
    if (ONIONPIR_BUILD_SHARED)
        add_library(onionpir SHARED ${ONIONPIR_CORE_SRC} ${ONIONPIR_FFI_SRC})
    else()
        add_library(onionpir STATIC ${ONIONPIR_CORE_SRC} ${ONIONPIR_FFI_SRC})
    endif()
    target_include_directories(onionpir PUBLIC ${ONIONPIR_PUBLIC_INCLUDES})
    if (ONIONPIR_HEXL_ACTIVE)
        target_link_libraries(onionpir PUBLIC HEXL::hexl)
    endif()
    # PIC so the static lib can be linked into shared libraries downstream
    # (Java JNA's .so/.dylib; Rust crates also commonly do).
    set_property(TARGET onionpir PROPERTY POSITION_INDEPENDENT_CODE ON)
    # Land the library in the top-level build dir (build-ffi/libonionpir.a,
    # build-shared/libonionpir.{so,dylib}) so build.rs, java/build.sh and the
    # tests/ffi_smoke.cpp recipe find it at the pre-restructure path.
    set_target_properties(onionpir PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
endif()
