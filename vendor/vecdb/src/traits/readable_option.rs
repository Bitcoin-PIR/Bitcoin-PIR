use crate::{ReadableVec, VecIndex, VecValue};

/// Extension methods for `ReadableVec<I, Option<T>>`.
pub trait ReadableOptionVec<I: VecIndex, T: VecValue + Default> {
    /// Collect all values, replacing `None` with `T::default()`.
    fn collect_or_default(&self) -> Vec<T>;

    /// Flattens `Option<Option<T>>` → `Option<T>`.
    fn collect_one_flat(&self, index: I) -> Option<T>;
}

impl<V, I, T> ReadableOptionVec<I, T> for V
where
    V: ReadableVec<I, Option<T>> + Sized,
    I: VecIndex,
    T: VecValue + Default,
{
    fn collect_or_default(&self) -> Vec<T> {
        self.fold(Vec::with_capacity(self.len()), |mut v, opt| {
            v.push(opt.unwrap_or_default());
            v
        })
    }

    fn collect_one_flat(&self, index: I) -> Option<T> {
        self.collect_one(index).flatten()
    }
}
