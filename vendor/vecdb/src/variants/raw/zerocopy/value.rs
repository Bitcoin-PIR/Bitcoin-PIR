use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::VecValue;

/// Value trait for ZeroCopyVec.
/// Extends RawVecValue with zerocopy bounds for direct memory mapping.
pub trait ZeroCopyVecValue
where
    Self: VecValue + FromBytes + IntoBytes + Immutable + KnownLayout,
{
}

impl<T> ZeroCopyVecValue for T where T: VecValue + FromBytes + IntoBytes + Immutable + KnownLayout {}
