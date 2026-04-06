//! Build N-ary Merkle tree for DPF backend (arity=8, slots_per_bin=4).
//!
//! Usage: gen_4_build_merkle_dpf [--data-dir <dir>]

mod merkle_builder;

fn main() {
    // DPF: arity=8 → sibling slot = 4 + 7*32 = 228B
    // cuckoo slots_per_bin=4 (same as INDEX/CHUNK tables)
    // Produces files with "_dpf" suffix
    merkle_builder::build_merkle_n(8, 4, "_dpf");
}
