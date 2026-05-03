use crate::VecValue;

use super::Bytes;

/// Value trait for BytesVec.
/// Extends RawVecValue with Bytes trait for custom serialization.
pub trait BytesVecValue
where
    Self: VecValue + Bytes,
{
}

impl<T> BytesVecValue for T where T: VecValue + Bytes {}
