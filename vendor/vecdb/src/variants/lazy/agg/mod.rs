use std::{marker::PhantomData, sync::Arc};

use crate::{
    AnyVec, ReadableBoxedVec, ReadableVec, TypedVec, VecIndex, VecValue, Version, short_type_name,
};

mod fold;
mod sparse;

pub use fold::*;
use sparse::*;

/// Lazy aggregation vector that maps coarser output indices to ranges in a finer source.
///
/// Values are computed on-the-fly using cursor-based sequential access.
/// The mapping is pulled via a caller-provided closure on each read.
pub struct LazyAggVec<I, O, S1I, S2T, S1T = O, Strat = Sparse>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
{
    name: Arc<str>,
    version: Version,
    mapping_version: Version,
    source: ReadableBoxedVec<S1I, S1T>,
    #[allow(clippy::type_complexity)]
    mapping: Arc<dyn Fn() -> Arc<[S2T]> + Send + Sync>,
    #[allow(clippy::type_complexity)]
    _phantom: PhantomData<fn() -> (I, O, Strat)>,
}

impl<I, O, S1I, S2T, S1T, Strat> LazyAggVec<I, O, S1I, S2T, S1T, Strat>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
{
    pub fn new(
        name: &str,
        version: Version,
        mapping_version: Version,
        source: ReadableBoxedVec<S1I, S1T>,
        mapping: impl Fn() -> Arc<[S2T]> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: Arc::from(name),
            version,
            mapping_version,
            source,
            mapping: Arc::new(mapping),
            _phantom: PhantomData,
        }
    }
}

impl<I, O, S1I, S2T, S1T, Strat> Clone for LazyAggVec<I, O, S1I, S2T, S1T, Strat>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
{
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            version: self.version,
            mapping_version: self.mapping_version,
            source: self.source.clone(),
            mapping: self.mapping.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<I, O, S1I, S2T, S1T, Strat> AnyVec for LazyAggVec<I, O, S1I, S2T, S1T, Strat>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
    Strat: 'static,
{
    fn version(&self) -> Version {
        self.version + self.source.version() + self.mapping_version
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn index_type_to_string(&self) -> &'static str {
        I::to_string()
    }

    fn len(&self) -> usize {
        (self.mapping)().len()
    }

    #[inline]
    fn value_type_to_size_of(&self) -> usize {
        size_of::<O>()
    }

    #[inline]
    fn value_type_to_string(&self) -> &'static str {
        short_type_name::<O>()
    }

    #[inline]
    fn region_names(&self) -> Vec<String> {
        vec![]
    }
}

impl<I, O, S1I, S2T, S1T, Strat> TypedVec for LazyAggVec<I, O, S1I, S2T, S1T, Strat>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
    Strat: 'static,
{
    type I = I;
    type T = O;
}

impl<I, O, S1I, S2T, S1T, Strat> ReadableVec<I, O>
    for LazyAggVec<I, O, S1I, S2T, S1T, Strat>
where
    I: VecIndex,
    O: VecValue,
    S1I: VecIndex,
    S2T: VecValue,
    S1T: VecValue,
    Strat: AggFold<O, S1I, S2T, S1T>,
{
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<O>) {
        let mapping = (self.mapping)();
        let to = to.min(mapping.len());
        if from >= to {
            return;
        }
        buf.reserve(to - from);
        Strat::fold(&*self.source, &mapping, from, to, (), |(), v| buf.push(v));
    }

    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(O)) {
        let mapping = (self.mapping)();
        let to = to.min(mapping.len());
        if from >= to {
            return;
        }
        Strat::fold(&*self.source, &mapping, from, to, (), |(), v| f(v));
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, O) -> B>(&self, from: usize, to: usize, init: B, f: F) -> B
    where
        Self: Sized,
    {
        let mapping = (self.mapping)();
        let to = to.min(mapping.len());
        if from >= to {
            return init;
        }
        Strat::fold(&*self.source, &mapping, from, to, init, f)
    }

    #[inline]
    fn try_fold_range_at<B, E, F: FnMut(B, O) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        f: F,
    ) -> std::result::Result<B, E>
    where
        Self: Sized,
    {
        let mapping = (self.mapping)();
        let to = to.min(mapping.len());
        if from >= to {
            return Ok(init);
        }
        Strat::try_fold(&*self.source, &mapping, from, to, init, f)
    }

    #[inline]
    fn collect_one_at(&self, index: usize) -> Option<O> {
        let mapping = (self.mapping)();
        if index >= mapping.len() {
            return None;
        }
        Strat::collect_one(&*self.source, &mapping, index)
    }
}
