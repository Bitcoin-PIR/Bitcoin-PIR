use crate::{Bytes, VecValue};

/// Value trait for ZstdVec.
/// Extends VecValue with Bytes trait for byte serialization.
pub trait ZstdVecValue
where
    Self: VecValue + Bytes,
{
}

impl<T> ZstdVecValue for T where T: VecValue + Bytes {}
