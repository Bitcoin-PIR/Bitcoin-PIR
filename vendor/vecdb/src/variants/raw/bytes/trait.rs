use crate::{Error, Result};

/// Trait for types that can be serialized to/from bytes with explicit byte order.
///
/// This trait uses **LITTLE-ENDIAN** byte order for all numeric types, making the data
/// **portable across different endianness systems** (x86, ARM, etc.). This is the key
/// difference from `ZeroCopyVec`, which uses native byte order and is not portable.
///
/// Use this trait when:
/// - You need cross-platform compatibility
/// - You're sharing data between systems with different endianness
/// - You need custom serialization logic
///
/// For maximum performance on a single system, use `ZeroCopyVec` instead.
pub trait Bytes: Sized {
    /// The byte array type returned by `to_bytes`.
    /// For fixed-size types, this is `[u8; N]` where N is the size of the type.
    type Array: AsRef<[u8]>;

    /// Whether the byte representation from `to_bytes` is identical to the
    /// in-memory representation of Self. When true, bulk operations can use
    /// memcpy instead of per-element deserialization.
    ///
    /// For numeric types, this is true on little-endian platforms (since
    /// `to_bytes`/`from_bytes` use little-endian format which matches native).
    const IS_NATIVE_LAYOUT: bool = false;

    /// Serializes this value to bytes.
    ///
    /// For numeric types, this uses little-endian byte order (via `to_le_bytes`).
    fn to_bytes(&self) -> Self::Array;

    /// Deserializes a value from bytes.
    ///
    /// For numeric types, this uses little-endian byte order (via `from_le_bytes`).
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

// Implement Bytes for common numeric types
macro_rules! impl_bytes_for_numeric {
    ($($t:ty),*) => {
        $(
            impl Bytes for $t {
                type Array = [u8; std::mem::size_of::<$t>()];
                const IS_NATIVE_LAYOUT: bool = cfg!(target_endian = "little");

                #[inline]
                fn to_bytes(&self) -> Self::Array {
                    self.to_le_bytes()
                }

                #[inline]
                fn from_bytes(bytes: &[u8]) -> Result<Self> {
                    let arr: [u8; std::mem::size_of::<$t>()] = bytes
                        .try_into()
                        .map_err(|_| Error::WrongLength {
                            expected: std::mem::size_of::<$t>(),
                            received: bytes.len(),
                        })?;
                    Ok(<$t>::from_le_bytes(arr))
                }
            }
        )*
    };
}

impl_bytes_for_numeric!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64
);

// Implement Bytes for fixed-size byte arrays
macro_rules! impl_bytes_for_array {
    ($($n:expr),*) => {
        $(
            impl Bytes for [u8; $n] {
                type Array = [u8; $n];
                const IS_NATIVE_LAYOUT: bool = true;

                #[inline]
                fn to_bytes(&self) -> Self::Array {
                    *self
                }

                #[inline]
                fn from_bytes(bytes: &[u8]) -> Result<Self> {
                    bytes.try_into().map_err(|_| Error::WrongLength {
                        expected: $n,
                        received: bytes.len(),
                    })
                }
            }
        )*
    };
}

impl_bytes_for_array!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 64, 65
);
