use std::sync::Arc;

use crate::{
    AnyVec, ReadableBoxedVec, ReadableVec, TypedVec, VecIndex, VecValue, Version, short_type_name,
};

pub type ComputeFrom3<I, T, S1T, S2T, S3T> = fn(I, S1T, S2T, S3T) -> T;

/// Lazily computed vector deriving values from three source vectors.
///
/// Values are computed on-the-fly during iteration using a provided function.
/// Nothing is stored on disk - all values are recomputed each time they're accessed.
#[derive(Clone)]
pub struct LazyVecFrom3<I, T, S1I, S1T, S2I, S2T, S3I, S3T>
where
    S1I: VecIndex,
    S1T: VecValue,
    S2I: VecIndex,
    S2T: VecValue,
    S3I: VecIndex,
    S3T: VecValue,
{
    name: Arc<str>,
    base_version: Version,
    source1: ReadableBoxedVec<S1I, S1T>,
    source2: ReadableBoxedVec<S2I, S2T>,
    source3: ReadableBoxedVec<S3I, S3T>,
    compute: ComputeFrom3<I, T, S1T, S2T, S3T>,
    s1_counts: bool,
    s2_counts: bool,
    s3_counts: bool,
}

impl<I, T, S1I, S1T, S2I, S2T, S3I, S3T> LazyVecFrom3<I, T, S1I, S1T, S2I, S2T, S3I, S3T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
    S2I: VecIndex,
    S2T: VecValue,
    S3I: VecIndex,
    S3T: VecValue,
{
    pub fn init(
        name: &str,
        version: Version,
        source1: ReadableBoxedVec<S1I, S1T>,
        source2: ReadableBoxedVec<S2I, S2T>,
        source3: ReadableBoxedVec<S3I, S3T>,
        compute: ComputeFrom3<I, T, S1T, S2T, S3T>,
    ) -> Self {
        let target = I::to_string();
        let s1 = source1.index_type_to_string();
        let s2 = source2.index_type_to_string();
        let s3 = source3.index_type_to_string();

        assert!(
            s1 == target || s2 == target || s3 == target,
            "LazyVecFrom3: at least one source must have index type {}, got {}, {}, and {}",
            target,
            s1,
            s2,
            s3
        );

        let s1_counts = s1 == target;
        let s2_counts = s2 == target;
        let s3_counts = s3 == target;

        Self {
            name: Arc::from(name),
            base_version: version,
            source1,
            source2,
            source3,
            compute,
            s1_counts,
            s2_counts,
            s3_counts,
        }
    }
}

impl<I, T, S1I, S1T, S2I, S2T, S3I, S3T> AnyVec for LazyVecFrom3<I, T, S1I, S1T, S2I, S2T, S3I, S3T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
    S2I: VecIndex,
    S2T: VecValue,
    S3I: VecIndex,
    S3T: VecValue,
{
    fn version(&self) -> Version {
        self.base_version + self.source1.version() + self.source2.version() + self.source3.version()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn index_type_to_string(&self) -> &'static str {
        I::to_string()
    }

    fn len(&self) -> usize {
        let len1 = if self.s1_counts {
            self.source1.len()
        } else {
            usize::MAX
        };
        let len2 = if self.s2_counts {
            self.source2.len()
        } else {
            usize::MAX
        };
        let len3 = if self.s3_counts {
            self.source3.len()
        } else {
            usize::MAX
        };
        len1.min(len2).min(len3)
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

impl<I, T, S1I, S1T, S2I, S2T, S3I, S3T> ReadableVec<I, T>
    for LazyVecFrom3<I, T, S1I, S1T, S2I, S2T, S3I, S3T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
    S2I: VecIndex,
    S2T: VecValue,
    S3I: VecIndex,
    S3T: VecValue,
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
        let buf1 = self.source1.collect_range_dyn(from, to);
        let buf2 = self.source2.collect_range_dyn(from, to);
        let buf3 = self.source3.collect_range_dyn(from, to);
        buf1.into_iter()
            .zip(buf2)
            .zip(buf3)
            .enumerate()
            .for_each(|(local, ((v1, v2), v3))| {
                f(compute(I::from(from + local), v1, v2, v3));
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
        let buf1 = self.source1.collect_range_dyn(from, to);
        let buf2 = self.source2.collect_range_dyn(from, to);
        let buf3 = self.source3.collect_range_dyn(from, to);
        buf1.into_iter()
            .zip(buf2)
            .zip(buf3)
            .enumerate()
            .try_fold(init, |acc, (local, ((v1, v2), v3))| {
                f(acc, compute(I::from(from + local), v1, v2, v3))
            })
    }

    #[inline]
    fn collect_one_at(&self, index: usize) -> Option<T> {
        if index >= self.len() {
            return None;
        }
        let v1 = self.source1.collect_one_at(index)?;
        let v2 = self.source2.collect_one_at(index)?;
        let v3 = self.source3.collect_one_at(index)?;
        Some((self.compute)(I::from(index), v1, v2, v3))
    }

    fn read_sorted_into_at(&self, indices: &[usize], out: &mut Vec<T>) {
        let compute = self.compute;
        let vals1 = self.source1.read_sorted_at(indices);
        let vals2 = self.source2.read_sorted_at(indices);
        let vals3 = self.source3.read_sorted_at(indices);
        out.reserve(vals1.len().min(vals2.len()).min(vals3.len()));
        indices
            .iter()
            .zip(vals1.into_iter().zip(vals2).zip(vals3))
            .for_each(|(&i, ((v1, v2), v3))| out.push(compute(I::from(i), v1, v2, v3)));
    }
}

impl<I, T, S1I, S1T, S2I, S2T, S3I, S3T> TypedVec
    for LazyVecFrom3<I, T, S1I, S1T, S2I, S2T, S3I, S3T>
where
    I: VecIndex,
    T: VecValue,
    S1I: VecIndex,
    S1T: VecValue,
    S2I: VecIndex,
    S2T: VecValue,
    S3I: VecIndex,
    S3T: VecValue,
{
    type I = I;
    type T = T;
}
