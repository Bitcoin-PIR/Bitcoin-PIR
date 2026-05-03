use crate::{Bytes, Error, Result};

/// Storage format selection for stored vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Format {
    /// Explicit byte serialization with little-endian byte order.
    /// **PORTABLE** across different endianness systems. Uses custom Bytes trait.
    Bytes,
    /// Direct memory mapping with native byte order via zerocopy.
    /// **NOT PORTABLE** - fastest but endianness-dependent. Best for random access.
    ZeroCopy,
    /// Pcodec compression optimized for numeric sequences (best compression for numbers).
    Pco = 64,
    /// LZ4 compression (fastest compression/decompression, moderate ratio).
    LZ4 = 65,
    /// Zstd compression (highest compression ratio, slower).
    Zstd = 66,
}

impl Format {
    #[inline]
    pub fn is_raw(&self) -> bool {
        matches!(self, Self::ZeroCopy | Self::Bytes)
    }

    #[inline]
    pub fn is_compressed(&self) -> bool {
        matches!(self, Self::Pco | Self::LZ4 | Self::Zstd)
    }

    #[inline]
    pub fn is_zerocopy(&self) -> bool {
        *self == Self::ZeroCopy
    }

    #[inline]
    pub fn is_bytes(&self) -> bool {
        *self == Self::Bytes
    }

    #[inline]
    pub fn is_pcodec(&self) -> bool {
        *self == Self::Pco
    }

    #[inline]
    pub fn is_lz4(&self) -> bool {
        *self == Self::LZ4
    }

    #[inline]
    pub fn is_zstd(&self) -> bool {
        *self == Self::Zstd
    }
}

impl Bytes for Format {
    type Array = [u8; size_of::<Self>()];

    #[inline]
    fn to_bytes(&self) -> Self::Array {
        [*self as u8]
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let len = bytes.len();
        if len != size_of::<Self>() {
            return Err(Error::WrongLength {
                expected: size_of::<Self>(),
                received: len,
            });
        }

        match bytes[0] {
            0 => Ok(Self::Bytes),
            1 => Ok(Self::ZeroCopy),
            64 => Ok(Self::Pco),
            65 => Ok(Self::LZ4),
            66 => Ok(Self::Zstd),
            b => Err(Error::InvalidFormat(b)),
        }
    }
}
