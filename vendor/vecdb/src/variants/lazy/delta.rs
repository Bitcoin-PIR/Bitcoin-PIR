use std::{marker::PhantomData, sync::Arc};

use crate::{
    AnyVec, CheckedSub, ReadableBoxedVec, ReadableVec, TypedVec, VecIndex, VecValue, Version,
    short_type_name,
};

/// Trait defining how to combine a current value with an earlier value.
///
/// `S` is the source type read from the vec, `T` is the output type produced.
/// When `S = T` (e.g., rolling sums), the operation is same-type.
/// When `S != T` (e.g., delta change/rate), the operation converts between types.
pub trait DeltaOp<S, T>: Send + Sync + 'static {
    /// Source index for the `ago` value given a window start.
    /// Returns `None` when there is no preceding element (cumulative ops at start = 0).
    #[inline]
    fn ago_index(start: usize) -> Option<usize> {
        Some(start)
    }

    /// Fallback `ago` value when `ago_index` returns `None`.
    #[inline]
    fn ago_default() -> S
    where
        S: Sized,
    {
        unreachable!()
    }

    /// Window element count from current index `h` and window start.
    #[inline]
    fn count(h: usize, start: usize) -> usize {
        h - start
    }

    fn combine(current: S, ago: S, count: usize) -> T;
}

/// Rolling sum from cumulative: `cum[h] - cum[start - 1]`
#[derive(Clone, Copy)]
pub struct DeltaSub;

impl<T> DeltaOp<T, T> for DeltaSub
where
    T: CheckedSub + Default,
{
    #[inline]
    fn ago_index(start: usize) -> Option<usize> {
        start.checked_sub(1)
    }

    #[inline]
    fn ago_default() -> T {
        T::default()
    }

    #[inline]
    fn count(h: usize, start: usize) -> usize {
        h - start + 1
    }

    #[inline]
    fn combine(current: T, ago: T, _count: usize) -> T {
        current.checked_sub(ago).unwrap_or_default()
    }
}

/// Rolling average from cumulative: `(cum[h] - cum[start - 1]) / (h - start + 1)`
#[derive(Clone, Copy)]
pub struct DeltaAvg;

impl<S, T> DeltaOp<S, T> for DeltaAvg
where
    S: Into<f64> + Default,
    T: From<f64>,
{
    #[inline]
    fn ago_index(start: usize) -> Option<usize> {
        start.checked_sub(1)
    }

    #[inline]
    fn ago_default() -> S {
        S::default()
    }

    #[inline]
    fn count(h: usize, start: usize) -> usize {
        h - start + 1
    }

    #[inline]
    fn combine(current: S, ago: S, count: usize) -> T {
        if count == 0 {
            T::from(0.0)
        } else {
            T::from((current.into() - ago.into()) / count as f64)
        }
    }
}

/// Delta change: `source[h] - source[start]` via f64, allowing cross-type (unsigned → signed).
#[derive(Clone, Copy)]
pub struct DeltaChange;

impl<S, C> DeltaOp<S, C> for DeltaChange
where
    S: Into<f64>,
    C: From<f64>,
{
    #[inline]
    fn combine(current: S, ago: S, _count: usize) -> C {
        C::from(Into::<f64>::into(current) - Into::<f64>::into(ago))
    }
}

/// Delta rate (growth): `(source[h] - source[start]) / source[start]` via f64.
#[derive(Clone, Copy)]
pub struct DeltaRate;

impl<S, B> DeltaOp<S, B> for DeltaRate
where
    S: Into<f64>,
    B: From<f64>,
{
    #[inline]
    fn combine(current: S, ago: S, _count: usize) -> B {
        let current_f: f64 = current.into();
        let ago_f: f64 = ago.into();
        if ago_f == 0.0 {
            B::from(0.0)
        } else {
            B::from((current_f - ago_f) / ago_f)
        }
    }
}

/// Lazily computed vector that combines a source value with a lookback value.
///
/// For each index `h` with `start = window_starts[h]`:
/// - `INCLUSIVE` ops (cumulative source): reads `source[h]` and `source[start - 1]`,
///   count = `h - start + 1`. Used for rolling sums/averages from prefix sums.
/// - Non-inclusive ops (raw source): reads `source[h]` and `source[start]`,
///   count = `h - start`. Used for point-to-point deltas (change, rate).
///
/// Nothing is stored on disk — values are computed on-the-fly during iteration.
pub struct LazyDeltaVec<I, S, T, Op> {
    name: Arc<str>,
    base_version: Version,
    source: ReadableBoxedVec<I, S>,
    window_starts_version: Version,
    #[allow(clippy::type_complexity)]
    window_starts: Arc<dyn Fn() -> Arc<[I]> + Send + Sync>,
    _op: PhantomData<(Op, T)>,
}

impl<I, S, T, Op> LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
    T: VecValue,
    Op: DeltaOp<S, T>,
{
    pub fn new(
        name: &str,
        version: Version,
        source: ReadableBoxedVec<I, S>,
        window_starts_version: Version,
        window_starts: impl Fn() -> Arc<[I]> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: Arc::from(name),
            base_version: version,
            source,
            window_starts_version,
            window_starts: Arc::new(window_starts),
            _op: PhantomData,
        }
    }
}

impl<I, S, T, Op> Clone for LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
{
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            base_version: self.base_version,
            source: self.source.clone(),
            window_starts_version: self.window_starts_version,
            window_starts: self.window_starts.clone(),
            _op: PhantomData,
        }
    }
}

impl<I, S, T, Op> AnyVec for LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
    T: VecValue,
    Op: DeltaOp<S, T>,
{
    fn version(&self) -> Version {
        self.base_version + self.source.version() + self.window_starts_version
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

impl<I, S, T, Op> LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
    T: VecValue,
    Op: DeltaOp<S, T>,
{
    /// Core bulk iteration with fold + early exit support: collect source range
    /// covering both current and ago positions in a single sequential read,
    /// then apply Op per element.
    #[inline]
    fn bulk_try_fold<B, E>(
        &self,
        from: usize,
        to: usize,
        starts: &[I],
        init: B,
        mut f: impl FnMut(B, T) -> std::result::Result<B, E>,
    ) -> std::result::Result<B, E> {
        if from >= to {
            return Ok(init);
        }

        // Starts are monotonically non-decreasing, so the earliest ago is from starts[from].
        let read_from = Op::ago_index(starts[from].to_usize())
            .unwrap_or(0)
            .min(from);

        let source_data = self.source.collect_range_dyn(read_from, to);

        let mut acc = init;
        for i in from..to {
            let start = starts[i].to_usize();
            let current = source_data[i - read_from].clone();
            let ago = match Op::ago_index(start) {
                Some(idx) => source_data[idx - read_from].clone(),
                None => Op::ago_default(),
            };
            acc = f(acc, Op::combine(current, ago, Op::count(i, start)))?;
        }
        Ok(acc)
    }

    #[inline]
    fn bulk_for_each(&self, from: usize, to: usize, starts: &[I], mut each: impl FnMut(T)) {
        self.bulk_try_fold(from, to, starts, (), |(), v| {
            each(v);
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap_or_else(|e: std::convert::Infallible| match e {})
    }
}

impl<I, S, T, Op> ReadableVec<I, T> for LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
    T: VecValue,
    Op: DeltaOp<S, T>,
{
    #[inline]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<T>) {
        let starts = (self.window_starts)();
        let to = to.min(self.len()).min(starts.len());
        if from >= to {
            return;
        }
        buf.reserve(to - from);
        self.bulk_for_each(from, to, &starts, |v| buf.push(v));
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(T)) {
        let starts = (self.window_starts)();
        let to = to.min(self.len()).min(starts.len());
        if from >= to {
            return;
        }
        self.bulk_for_each(from, to, &starts, f);
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, mut f: F) -> B
    where
        Self: Sized,
    {
        let starts = (self.window_starts)();
        let to = to.min(self.len()).min(starts.len());
        if from >= to {
            return init;
        }
        self.bulk_try_fold(from, to, &starts, init, |acc, v| {
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
        f: F,
    ) -> std::result::Result<B, E>
    where
        Self: Sized,
    {
        let starts = (self.window_starts)();
        let to = to.min(self.len()).min(starts.len());
        if from >= to {
            return Ok(init);
        }
        self.bulk_try_fold(from, to, &starts, init, f)
    }

    #[inline]
    fn collect_one_at(&self, index: usize) -> Option<T> {
        if index >= self.len() {
            return None;
        }
        let starts = (self.window_starts)();
        if index >= starts.len() {
            return None;
        }
        let start = starts[index].to_usize();
        let current = self.source.collect_one_at(index)?;
        let ago = match Op::ago_index(start) {
            Some(idx) => self.source.collect_one_at(idx)?,
            None => Op::ago_default(),
        };
        Some(Op::combine(current, ago, Op::count(index, start)))
    }

    fn read_sorted_into_at(&self, indices: &[usize], out: &mut Vec<T>) {
        if indices.is_empty() {
            return;
        }

        let starts = (self.window_starts)();
        let len = self.len().min(starts.len());
        let count = indices.len();

        let mut reads: Vec<(usize, u32, bool)> = Vec::with_capacity(count * 2);
        indices.iter().enumerate().for_each(|(slot, &h)| {
            if h < len {
                reads.push((h, slot as u32, true));
                if let Some(ago_idx) = Op::ago_index(starts[h].to_usize()) {
                    reads.push((ago_idx, slot as u32, false));
                }
            }
        });
        reads.sort_unstable_by_key(|r| r.0);

        let mut positions: Vec<usize> = Vec::with_capacity(reads.len());
        let mut val_indices: Vec<u32> = Vec::with_capacity(reads.len());
        reads.iter().for_each(|&(pos, _, _)| {
            if positions.last() != Some(&pos) {
                positions.push(pos);
            }
            val_indices.push((positions.len() - 1) as u32);
        });

        let vals = self.source.read_sorted_at(&positions);

        let mut current_vi = vec![0u32; count];
        let mut ago_vi = vec![0u32; count];
        reads.iter().enumerate().for_each(|(i, &(_, slot, is_current))| {
            let vi = val_indices[i];
            if is_current {
                current_vi[slot as usize] = vi;
            } else {
                ago_vi[slot as usize] = vi;
            }
        });

        out.reserve(count);
        indices.iter().enumerate().for_each(|(slot, &h)| {
            if h >= len {
                return;
            }
            let start = starts[h].to_usize();
            let current = vals[current_vi[slot] as usize].clone();
            let ago = match Op::ago_index(start) {
                Some(_) => vals[ago_vi[slot] as usize].clone(),
                None => Op::ago_default(),
            };
            out.push(Op::combine(current, ago, Op::count(h, start)));
        });
    }
}

impl<I, S, T, Op> TypedVec for LazyDeltaVec<I, S, T, Op>
where
    I: VecIndex,
    S: VecValue,
    T: VecValue,
    Op: DeltaOp<S, T>,
{
    type I = I;
    type T = T;
}
