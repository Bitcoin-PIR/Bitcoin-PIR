use crate::{Bytes, VecValue};

/// Value trait for LZ4Vec.
/// Extends VecValue with Bytes trait for byte serialization.
pub trait LZ4VecValue
where
    Self: VecValue + Bytes,
{
}

impl<T> LZ4VecValue for T where T: VecValue + Bytes {}
