pub mod bitstring;
pub mod cache;
pub mod fastprp;

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod aes_wasm_simd;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use cache::{CounterCache, PartitionCache};
pub use fastprp::FastPrp;
