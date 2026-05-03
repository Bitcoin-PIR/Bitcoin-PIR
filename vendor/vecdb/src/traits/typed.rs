use crate::{AnyVec, VecIndex, VecValue};

/// A vector with statically-known index and value types.
///
/// This trait extends [`AnyVec`] by providing associated types for the index (`I`)
/// and value (`T`) types, enabling type-safe operations at compile time.
///
/// # Type Parameters
/// - `I`: The index type, must implement [`VecIndex`]
/// - `T`: The value type, must implement [`VecValue`]
pub trait TypedVec: AnyVec {
    /// The index type used to address elements in this vector.
    type I: VecIndex;
    /// The value type stored in this vector.
    type T: VecValue;
}
