use std::{fmt::Debug, ops::Add};

use crate::PrintableIndex;

/// Trait for types that can be used as vector indices.
///
/// This trait is automatically implemented for any type that satisfies the
/// required bounds. No manual implementation is needed.
pub trait VecIndex
where
    Self: Debug
        + Default
        + Copy
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + From<usize>
        + Into<usize>
        + Add<usize, Output = Self>
        + Send
        + Sync
        + PrintableIndex
        + 'static,
{
    /// Converts this index to a `usize`.
    #[inline]
    fn to_usize(self) -> usize {
        self.into()
    }

    /// Returns the previous index, or `None` if this is zero.
    #[inline]
    fn decremented(self) -> Option<Self> {
        self.to_usize().checked_sub(1).map(Self::from)
    }
}

impl<I> VecIndex for I where
    I: Debug
        + Default
        + Copy
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + From<usize>
        + Into<usize>
        + Add<usize, Output = Self>
        + Send
        + Sync
        + PrintableIndex
        + 'static
{
}
