use crate::{AnyVec, ReadableVec, TypedVec, i64_to_usize};

/// Type-erased trait for collectable vectors.
pub trait AnyReadableVec: AnyVec {
    /// Returns the number of items in the specified range.
    fn range_count(&self, from: Option<i64>, to: Option<i64>) -> usize {
        let len = self.len();
        let from = from.map(|i| i64_to_usize(i, len)).unwrap_or_default();
        let to = to.map(|i| i64_to_usize(i, len)).unwrap_or(len);
        to.saturating_sub(from)
    }

    /// Returns the total size in bytes of items in the specified range.
    fn range_weight(&self, from: Option<i64>, to: Option<i64>) -> usize {
        self.range_count(from, to) * self.value_type_to_size_of()
    }
}

impl<V> AnyReadableVec for V
where
    V: TypedVec,
    V: ReadableVec<V::I, V::T>,
{
}
