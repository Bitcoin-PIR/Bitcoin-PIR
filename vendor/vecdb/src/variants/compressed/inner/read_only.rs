use std::{marker::PhantomData, sync::Arc};

use parking_lot::RwLock;

use crate::{
    AnyVec, CompressedIoSource, CompressedMmapSource, MMAP_CROSSOVER_BYTES, ReadOnlyBaseVec,
    ReadableVec, TypedVec, VecIndex, VecValue, Version, short_type_name, vec_region_name,
};

use super::{CompressionStrategy, Pages, ReadWriteCompressedVec};

/// Lean read-only view of a compressed vector (~48 bytes).
///
/// Carries only the fields needed for disk reads: region, shared length,
/// name/header metadata, and the pages index. No pushed buffer, no rollback state.
///
/// Created via [`ReadWriteCompressedVec::read_only_clone`].
#[derive(Debug, Clone)]
pub struct ReadOnlyCompressedVec<I, T, S> {
    base: ReadOnlyBaseVec<I, T>,
    pages: Arc<RwLock<Pages>>,
    _strategy: PhantomData<S>,
}

impl<I, T, S> ReadOnlyCompressedVec<I, T, S> {
    pub(crate) fn new(base: ReadOnlyBaseVec<I, T>, pages: Arc<RwLock<Pages>>) -> Self {
        Self {
            base,
            pages,
            _strategy: PhantomData,
        }
    }
}

impl<I, T, S> ReadOnlyCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    #[inline(always)]
    fn fold_source<B, F: FnMut(B, T) -> B>(
        &self,
        from: usize,
        to: usize,
        len: usize,
        init: B,
        f: F,
    ) -> B {
        let range_bytes = (to - from) * size_of::<T>();
        if range_bytes > MMAP_CROSSOVER_BYTES {
            CompressedIoSource::<I, T, S>::new_from_parts(
                self.base.region(),
                &self.pages,
                len,
                from,
                to,
            )
            .fold(init, f)
        } else {
            CompressedMmapSource::<I, T, S>::new_from_parts(
                self.base.region(),
                &self.pages,
                len,
                from,
                to,
            )
            .fold(init, f)
        }
    }

    #[inline(always)]
    fn try_fold_source<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        len: usize,
        init: B,
        f: F,
    ) -> std::result::Result<B, E> {
        let range_bytes = (to - from) * size_of::<T>();
        if range_bytes > MMAP_CROSSOVER_BYTES {
            CompressedIoSource::<I, T, S>::new_from_parts(
                self.base.region(),
                &self.pages,
                len,
                from,
                to,
            )
            .try_fold(init, f)
        } else {
            CompressedMmapSource::<I, T, S>::new_from_parts(
                self.base.region(),
                &self.pages,
                len,
                from,
                to,
            )
            .try_fold(init, f)
        }
    }
}

impl<I, T, S> AnyVec for ReadOnlyCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    #[inline]
    fn version(&self) -> Version {
        self.base.version()
    }

    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }

    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }

    #[inline]
    fn index_type_to_string(&self) -> &'static str {
        I::to_string()
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
        let base = vec_region_name(self.base.name(), I::to_string());
        let pages = format!("{base}_pages");
        vec![base, pages]
    }
}

impl<I, T, S> ReadableVec<I, T> for ReadOnlyCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    #[inline(always)]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<T>) {
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return;
        }
        buf.reserve(to - from);

        let reader = self.base.region().create_reader();
        let pages = self.pages.read();
        ReadWriteCompressedVec::<I, T, S>::read_stored_pages_into(
            &reader, &pages, from, to, buf,
        );
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(T)) {
        self.fold_range_at(from, to, (), |(), v| f(v));
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, f: F) -> B
    where
        Self: Sized,
    {
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return init;
        }
        self.fold_source(from, to, len, init, f)
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
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return Ok(init);
        }
        self.try_fold_source(from, to, len, init, f)
    }
}

impl<I, T, S> TypedVec for ReadOnlyCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    type I = I;
    type T = T;
}
