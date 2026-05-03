use std::{
    fmt,
    fs,
    io::{self, Read},
    iter::Sum,
    ops::Add,
    path::Path,
};

use crate::{Bytes, Error, Result};

/// Version tracking for data schema and computed values.
///
/// Used to detect when stored data needs to be recomputed due to changes
/// in computation logic or source data versions. Supports validation
/// against persisted versions to ensure compatibility.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[must_use = "Version values should be used for compatibility checks"]
pub struct Version(u32);

impl Version {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);

    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    pub fn write(&self, path: &Path) -> Result<(), io::Error> {
        fs::write(path, self.to_bytes().as_ref())
    }

    pub fn swap_bytes(self) -> Self {
        Self(self.0.swap_bytes())
    }
}

impl Bytes for Version {
    type Array = [u8; size_of::<Self>()];

    #[inline]
    fn to_bytes(&self) -> Self::Array {
        self.0.to_bytes()
    }

    #[inline]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(u32::from_bytes(bytes)?))
    }
}

impl From<Version> for u32 {
    fn from(value: Version) -> u32 {
        value.0
    }
}

impl From<Version> for usize {
    fn from(value: Version) -> usize {
        value.0 as usize
    }
}

impl From<u32> for Version {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<usize> for Version {
    fn from(value: usize) -> Self {
        assert!(value <= u32::MAX as usize, "Version overflow: {value}");
        Self(value as u32)
    }
}

impl TryFrom<&Path> for Version {
    type Error = Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        let mut buf = [0u8; size_of::<Self>()];
        fs::read(value)?.as_slice().read_exact(&mut buf)?;
        Self::from_bytes(&buf)
    }
}

impl Add<Version> for Version {
    type Output = Self;
    fn add(self, rhs: Version) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sum for Version {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, Add::add)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
