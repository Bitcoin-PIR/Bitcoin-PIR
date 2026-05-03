use std::marker::PhantomData;

use crate::{
    AnyVec, Error, HEADER_OFFSET, MMAP_CROSSOVER_BYTES, RawIoSource, RawMmapSource,
    ReadOnlyBaseVec, ReadableVec, Result, Stamp, TypedVec, VecIndex, VecReader, VecValue, Version,
    short_type_name, vec_region_name,
};

use super::RawStrategy;

/// Lean read-only view of a raw vector (~40 bytes).
///
/// Carries only the fields needed for disk reads: region, shared length,
/// name/header metadata. No holes, no updated map, no pushed buffer,
/// no rollback state.
///
/// Created via [`ReadWriteRawVec::read_only_clone`].
#[derive(Debug, Clone)]
pub struct ReadOnlyRawVec<I, T, S> {
    base: ReadOnlyBaseVec<I, T>,
    _strategy: PhantomData<S>,
}

impl<I, T, S> ReadOnlyRawVec<I, T, S> {
    pub(crate) fn new(base: ReadOnlyBaseVec<I, T>) -> Self {
        Self {
            base,
            _strategy: PhantomData,
        }
    }
}

impl<I, T, S> ReadOnlyRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    pub(crate) fn region(&self) -> &rawdb::Region {
        self.base.region()
    }

    pub(crate) fn stored_len(&self) -> usize {
        self.base.stored_len()
    }

    #[inline]
    pub fn stamp(&self) -> Stamp {
        self.base.header().stamp()
    }

    pub fn reader(&self) -> VecReader<I, T, S> {
        VecReader::from_read_only(self)
    }

    #[inline]
    pub fn read_at_once(&self, index: usize) -> Result<T> {
        self.reader()
            .try_get(index)
            .ok_or_else(|| Error::IndexTooHigh {
                index,
                len: self.base.len(),
                name: self.base.name().to_string(),
            })
    }

    #[inline]
    pub fn read_once(&self, index: I) -> Result<T> {
        self.read_at_once(index.to_usize())
    }

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
            RawIoSource::<I, T, S>::new_from_parts(self.base.region(), len, from, to).fold(init, f)
        } else {
            RawMmapSource::<I, T, S>::new_from_parts(self.base.region(), len, from, to)
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
            RawIoSource::<I, T, S>::new_from_parts(self.base.region(), len, from, to)
                .try_fold(init, f)
        } else {
            RawMmapSource::<I, T, S>::new_from_parts(self.base.region(), len, from, to)
                .try_fold(init, f)
        }
    }
}

impl<I, T, S> AnyVec for ReadOnlyRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
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
        vec![vec_region_name(self.base.name(), I::to_string())]
    }
}

impl<I, T, S> ReadableVec<I, T> for ReadOnlyRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    #[inline(always)]
    fn collect_one_at(&self, index: usize) -> Option<T> {
        let len = self.base.len();
        if index >= len {
            return None;
        }
        let reader = self.base.region().create_reader();
        Some(unsafe {
            S::read_from_ptr(
                reader.prefixed(HEADER_OFFSET).as_ptr(),
                index * size_of::<T>(),
            )
        })
    }

    #[inline(always)]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<T>) {
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return;
        }
        buf.reserve(to - from);
        if S::IS_NATIVE_LAYOUT {
            let reader = self.base.region().create_reader();
            let src = unsafe {
                std::slice::from_raw_parts(
                    reader
                        .prefixed(HEADER_OFFSET)
                        .as_ptr()
                        .add(from * size_of::<T>()) as *const T,
                    to - from,
                )
            };
            buf.extend_from_slice(src);
        } else {
            self.fold_source(from, to, len, (), |(), v| buf.push(v));
        }
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

impl<I, T, S> TypedVec for ReadOnlyRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    type I = I;
    type T = T;
}
