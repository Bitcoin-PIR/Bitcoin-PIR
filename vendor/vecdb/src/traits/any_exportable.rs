use super::{AnySerializableVec, AnyVecWithWriter};

/// Type-erased trait for vectors that are both writable and serializable.
/// This trait is automatically implemented for any type that implements both
/// `AnyVecWithWriter` and `AnySerializableVec`.
pub trait AnyExportableVec: AnyVecWithWriter + AnySerializableVec {}

/// Blanket implementation for all types that implement both traits.
impl<V> AnyExportableVec for V where V: AnyVecWithWriter + AnySerializableVec {}
