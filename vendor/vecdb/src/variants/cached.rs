use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

use parking_lot::RwLock;

use crate::{
    AnyVec, ReadableBoxedVec, ReadableCloneableVec, ReadableVec, VecIndex, VecValue, Version,
    short_type_name,
};

/// Budget gate for [`CachedVec`] materialization.
///
/// When the budget is exhausted, reads fall through to the source without caching.
pub trait CachedVecBudget: Send + Sync {
    /// Attempts to reserve one cache slot given the entry's access count.
    /// Implementations may enforce a minimum access threshold or evict entries.
    fn try_reserve(&self, access_count: u64) -> bool;
}

impl CachedVecBudget for AtomicUsize {
    #[inline]
    fn try_reserve(&self, _: u64) -> bool {
        self.fetch_update(Relaxed, Relaxed, |n| if n > 0 { Some(n - 1) } else { None })
            .is_ok()
    }
}

/// Budget that always allows materialization (used by [`CachedVec::new`]).
struct NoBudget;

impl CachedVecBudget for NoBudget {
    #[inline]
    fn try_reserve(&self, _: u64) -> bool {
        true
    }
}

static NO_BUDGET: NoBudget = NoBudget;

/// Cached snapshot of a readable vec, refreshed when len or version changes.
///
/// Cloning is cheap (Arc). All clones share the same cache.
///
/// When constructed with a budget, materialization is gated: if the budget
/// is exhausted, reads fall through to the source without caching.
#[derive(Clone)]
pub struct CachedVec<I: VecIndex, T: VecValue> {
    source: ReadableBoxedVec<I, T>,
    #[allow(clippy::type_complexity)]
    cache: Arc<RwLock<(usize, Version, Arc<[T]>)>>,
    budget: &'static dyn CachedVecBudget,
    access_count: Option<Arc<AtomicU64>>,
}

impl<I: VecIndex, T: VecValue> CachedVec<I, T> {
    fn empty() -> (usize, Version, Arc<[T]>) {
        (0, Version::ZERO, Arc::from(&[] as &[T]))
    }

    pub fn new(source: &(impl ReadableCloneableVec<I, T> + 'static)) -> Self {
        Self {
            source: source.read_only_boxed_clone(),
            cache: Arc::new(RwLock::new(Self::empty())),
            budget: &NO_BUDGET,
            access_count: None,
        }
    }

    pub fn new_budgeted(
        source: ReadableBoxedVec<I, T>,
        budget: &'static dyn CachedVecBudget,
        access_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            source,
            cache: Arc::new(RwLock::new(Self::empty())),
            budget,
            access_count: Some(access_count),
        }
    }

    pub fn version(&self) -> Version {
        self.source.version()
    }

    pub fn clear(&self) {
        *self.cache.write() = Self::empty();
        if let Some(c) = &self.access_count {
            c.store(0, Relaxed);
        }
    }

    /// Always materializes on miss (ignores budget).
    pub fn get(&self) -> Arc<[T]> {
        self.materialize(false).unwrap()
    }

    /// Returns `None` when budget is exhausted or below min access threshold.
    #[inline]
    fn try_cached(&self) -> Option<Arc<[T]>> {
        self.materialize(true)
    }

    fn materialize(&self, check_budget: bool) -> Option<Arc<[T]>> {
        let len = self.source.len();
        let version = self.source.version();

        let count = self
            .access_count
            .as_ref()
            .map(|c| c.fetch_add(1, Relaxed) + 1)
            .unwrap_or(0);

        let cache = self.cache.read();
        if cache.0 == len && cache.1 == version {
            return Some(cache.2.clone());
        }
        drop(cache);

        if check_budget && !self.budget.try_reserve(count) {
            return None;
        }

        let data: Arc<[T]> = self.source.collect_range_dyn(0, len).into();
        let mut cache = self.cache.write();
        if cache.0 == len && cache.1 == version {
            return Some(cache.2.clone());
        }
        *cache = (len, version, data.clone());

        Some(data)
    }
}

impl<I: VecIndex, T: VecValue> AnyVec for CachedVec<I, T> {
    fn version(&self) -> Version {
        self.source.version()
    }

    fn name(&self) -> &str {
        self.source.name()
    }

    fn len(&self) -> usize {
        self.source.len()
    }

    fn index_type_to_string(&self) -> &'static str {
        self.source.index_type_to_string()
    }

    fn region_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn value_type_to_size_of(&self) -> usize {
        size_of::<T>()
    }

    fn value_type_to_string(&self) -> &'static str {
        short_type_name::<T>()
    }
}

impl<I: VecIndex, T: VecValue> ReadableVec<I, T> for CachedVec<I, T> {
    #[inline]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<T>) {
        if let Some(data) = self.try_cached() {
            let to = to.min(data.len());
            if from < to {
                buf.extend_from_slice(&data[from..to]);
            }
        } else {
            self.source.read_into_at(from, to, buf);
        }
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(T)) {
        if let Some(data) = self.try_cached() {
            let to = to.min(data.len());
            let from = from.min(to);
            for v in &data[from..to] {
                f(v.clone());
            }
        } else {
            self.source.for_each_range_dyn_at(from, to, f);
        }
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, mut f: F) -> B
    where
        Self: Sized,
    {
        if let Some(data) = self.try_cached() {
            let to = to.min(data.len());
            let from = from.min(to);
            let mut acc = init;
            for v in &data[from..to] {
                acc = f(acc, v.clone());
            }
            acc
        } else {
            // Can't call source.fold_range_at (Sized), collect then fold.
            self.source
                .collect_range_dyn(from, to)
                .into_iter()
                .fold(init, f)
        }
    }

    #[inline]
    fn try_fold_range_at<B, E, F: FnMut(B, T) -> Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> Result<B, E>
    where
        Self: Sized,
    {
        if let Some(data) = self.try_cached() {
            let to = to.min(data.len());
            let from = from.min(to);
            let mut acc = init;
            for v in &data[from..to] {
                acc = f(acc, v.clone())?;
            }
            Ok(acc)
        } else {
            self.source
                .collect_range_dyn(from, to)
                .into_iter()
                .try_fold(init, f)
        }
    }

    #[inline]
    fn collect_one_at(&self, index: usize) -> Option<T> {
        if let Some(data) = self.try_cached() {
            data.get(index).cloned()
        } else {
            self.source.collect_one_at(index)
        }
    }

    #[inline]
    fn read_sorted_into_at(&self, indices: &[usize], out: &mut Vec<T>) {
        if let Some(data) = self.try_cached() {
            out.reserve(indices.len());
            for &i in indices {
                if let Some(v) = data.get(i) {
                    out.push(v.clone());
                }
            }
        } else {
            self.source.read_sorted_into_at(indices, out);
        }
    }
}
