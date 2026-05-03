use std::sync::Arc;

use crate::{
    AnyVec, ReadOnlyClone, ReadableBoxedVec, ReadableVec, TypedVec, VecIndex, VecValue, Version,
    short_type_name,
};

mod transform;

pub use transform::*;

pub type ComputeFrom1<I, T, S1T> = fn(I, S1T) -> T;

/// Lazily computed vector deriving values on-the-fly from one source vector.
///
/// Unlike `EagerVec`, no data is stored on disk. Values are computed during
/// iteration by applying a function to the source vector's elements. Use when:
/// - Storage space is limited
/// - Computation is cheap relative to disk I/O
/// - Values are only accessed once or infrequently
///
/// For frequently accessed derived data, prefer `EagerVec` for better performance.
#[derive(Clone)]
pub struct LazyVecFrom1<I, T, S1I, S1T>
where
    S1I: VecIndex,
    S1T: VecValue,
{
    name: Arc<str>,
    base_version: Version,
    source: ReadableBoxedVec<S1I, S1T>,
    compute: ComputeFrom1<I, T, S1T>,
}

impl<I, T, S1I, S1T> LazyVecFrom1<I, T, S1I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
{
    pub fn init(
        name: &str,
        version: Version,
        source: ReadableBoxedVec<S1I, S1T>,
        compute: ComputeFrom1<I, T, S1T>,
    ) -> Self {
        assert_eq!(
            I::to_string(),
            S1I::to_string(),
            "LazyVecFrom1 index type mismatch: expected {}, got {}",
            I::to_string(),
            S1I::to_string()
        );

        Self {
            name: Arc::from(name),
            base_version: version,
            source,
            compute,
        }
    }
}

impl<I, T, S1I, S1T> ReadOnlyClone for LazyVecFrom1<I, T, S1I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
{
    type ReadOnly = Self;

    fn read_only_clone(&self) -> Self {
        self.clone()
    }
}

impl<I, T, S1I, S1T> AnyVec for LazyVecFrom1<I, T, S1I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
{
    fn version(&self) -> Version {
        self.base_version + self.source.version()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn index_type_to_string(&self) -> &'static str {
        I::to_string()
    }

    fn len(&self) -> usize {
        self.source.len()
    }

    #[inline]
    fn value_type_to_size_of(&self) -> usize {
        size_of::<T>()
    }

    #[inline]
    fn value_type_to_string(&self) -> &'static str {
        short_type_name::<T>()
    }

    #[inline]
    fn region_names(&self) -> Vec<String> {
        Vec::new()
    }
}

impl<I, T, S1I, S1T> ReadableVec<I, T> for LazyVecFrom1<I, T, S1I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
{
    #[inline]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<T>) {
        let to = to.min(self.len());
        buf.reserve(to.saturating_sub(from));
        self.for_each_range_dyn_at(from, to, &mut |v| buf.push(v));
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(T)) {
        let compute = self.compute;
        let to = to.min(self.len());
        let mut pos = from;
        self.source.for_each_range_dyn_at(from, to, &mut |v| {
            f(compute(I::from(pos), v));
            pos += 1;
        });
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, mut f: F) -> B
    where
        Self: Sized,
    {
        self.try_fold_range_at(from, to, init, |acc, v| {
            Ok::<_, std::convert::Infallible>(f(acc, v))
        })
        .unwrap_or_else(|e: std::convert::Infallible| match e {})
    }

    #[inline]
    fn try_fold_range_at<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> std::result::Result<B, E>
    where
        Self: Sized,
    {
        let to = to.min(self.len());
        if from >= to {
            return Ok(init);
        }
        let compute = self.compute;
        let buf = self.source.collect_range_dyn(from, to);
        buf.into_iter().enumerate().try_fold(init, |acc, (local, v)| {
            f(acc, compute(I::from(from + local), v))
        })
    }

    #[inline]
    fn collect_one_at(&self, index: usize) -> Option<T> {
        let v = self.source.collect_one_at(index)?;
        Some((self.compute)(I::from(index), v))
    }

    fn read_sorted_into_at(&self, indices: &[usize], out: &mut Vec<T>) {
        let compute = self.compute;
        let source_vals = self.source.read_sorted_at(indices);
        out.reserve(source_vals.len());
        indices
            .iter()
            .zip(source_vals)
            .for_each(|(&i, v)| out.push(compute(I::from(i), v)));
    }
}

impl<I, T, S1I, S1T> TypedVec for LazyVecFrom1<I, T, S1I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
{
    type I = I;
    type T = T;
}

impl<I, T, S1T> LazyVecFrom1<I, T, I, S1T>
where
    I: VecIndex,
    T: VecValue,
    S1T: VecValue,
{
    /// Create a lazy vec with a generic transform.
    /// Usage: `LazyVecFrom1::transformed::<Negate>(name, v, source)`
    pub fn transformed<F: UnaryTransform<S1T, T>>(
        name: &str,
        version: Version,
        source: ReadableBoxedVec<I, S1T>,
    ) -> Self {
        Self::init(name, version, source, |_, v| F::apply(v))
    }
}
