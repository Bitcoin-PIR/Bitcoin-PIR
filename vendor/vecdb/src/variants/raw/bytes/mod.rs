use crate::{Format, ReadOnlyRawVec, impl_vec_wrapper};

use super::ReadWriteRawVec;

mod strategy;
mod r#trait;
mod value;

pub use strategy::*;
pub use r#trait::*;
pub use value::*;

/// Raw storage vector using explicit byte serialization in little-endian format.
///
/// Uses the `Bytes` trait to serialize values with `to_bytes()/from_bytes()` in
/// **LITTLE-ENDIAN** format, ensuring **portability across different endianness systems**.
///
/// Like `ZeroCopyVec`, this wraps `ReadWriteRawVec` and supports:
/// - Holes (deleted indices)
/// - Updated values (modifications to stored data)
/// - Push/rollback operations
///
/// The only difference from `ZeroCopyVec` is the serialization strategy:
/// - `BytesVec`: Explicit little-endian, portable across architectures
/// - `ZeroCopyVec`: Native byte order, faster but not portable
///
/// Use `BytesVec` when:
/// - Sharing data between systems with different endianness
/// - Cross-platform compatibility is required
/// - Custom serialization logic is needed
///
/// Use `ZeroCopyVec` when:
/// - Maximum performance is critical
/// - Data stays on the same architecture
#[derive(Debug)]
#[must_use = "Vector should be stored to keep data accessible"]
pub struct BytesVec<I, T>(pub(crate) ReadWriteRawVec<I, T, BytesStrategy<T>>);

pub type BytesVecReader<I, T> = super::VecReader<I, T, BytesStrategy<T>>;

impl_vec_wrapper!(
    BytesVec,
    ReadWriteRawVec<I, T, BytesStrategy<T>>,
    BytesVecValue,
    Format::Bytes,
    ReadOnlyRawVec<I, T, BytesStrategy<T>>
);
