use crate::{Bytes, Result};

/// Marker for tracking when data was last modified.
///
/// Used for change tracking, rollback support, and ETag generation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[must_use = "Stamp values should be used for tracking"]
pub struct Stamp(u64);

impl Stamp {
    pub fn new(stamp: u64) -> Self {
        Self(stamp)
    }
}

impl From<u64> for Stamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Stamp> for u64 {
    fn from(value: Stamp) -> Self {
        value.0
    }
}

impl Bytes for Stamp {
    type Array = [u8; size_of::<Self>()];

    #[inline]
    fn to_bytes(&self) -> Self::Array {
        self.0.to_bytes()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(u64::from_bytes(bytes)?))
    }
}
