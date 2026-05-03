use std::{collections::BTreeMap, marker::PhantomData, mem, path::PathBuf, sync::Arc};

use log::info;
use parking_lot::RwLock;
use rawdb::{Database, Reader, Region};

use crate::{
    AnyStoredVec, AnyVec, CompressedIoSource, CompressedMmapSource, Error, Format, Header,
    ImportOptions, MMAP_CROSSOVER_BYTES, ReadWriteBaseVec, ReadableVec, Result, Stamp, TypedVec,
    VecIndex, VecValue, Version, WritableVec, likely, short_type_name, unlikely,
    vec_region_name_with,
};

use super::{CompressionStrategy, Page, Pages, ReadOnlyCompressedVec};

/// Maximum size in bytes of a single uncompressed page (16 KiB).
/// Smaller pages reduce memory overhead during decompression and improve
/// random access performance, while larger pages compress more efficiently.
/// 16 KiB balances these trade-offs for typical workloads.
pub const MAX_UNCOMPRESSED_PAGE_SIZE: usize = 16 * 1024;

const VERSION: Version = Version::new(3);

/// Inner implementation for compressed storage vectors.
/// Parameterized by compression strategy to support different compression algorithms.
#[derive(Debug)]
#[must_use = "Vector should be stored to keep data accessible"]
pub struct ReadWriteCompressedVec<I, T, S> {
    base: ReadWriteBaseVec<I, T>,
    pages: Arc<RwLock<Pages>>,
    _strategy: PhantomData<S>,
}

impl<I, T, S> ReadWriteCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    const PER_PAGE: usize = MAX_UNCOMPRESSED_PAGE_SIZE / Self::SIZE_OF_T;

    pub fn read_only_clone(&self) -> ReadOnlyCompressedVec<I, T, S> {
        ReadOnlyCompressedVec::new(self.base.read_only_base(), Arc::clone(&self.pages))
    }

    /// # Warning
    ///
    /// This will DELETE all existing data on format/version errors. Use with caution.
    pub fn forced_import_with(mut options: ImportOptions, format: Format) -> Result<Self> {
        options.version = options.version + VERSION;
        let res = Self::import_with(options, format);
        match res {
            Err(Error::WrongEndian)
            | Err(Error::WrongLength { .. })
            | Err(Error::DifferentFormat { .. })
            | Err(Error::DifferentVersion { .. }) => {
                info!("Resetting {}...", options.name);
                options
                    .db
                    .remove_region_if_exists(&vec_region_name_with::<I>(options.name))?;
                options
                    .db
                    .remove_region_if_exists(&Self::pages_region_name_with(options.name))?;
                Self::import_with(options, format)
            }
            _ => res,
        }
    }

    #[inline]
    pub fn import_with(mut options: ImportOptions, format: Format) -> Result<Self> {
        options.version = options.version + VERSION;
        let db = options.db;
        let name = options.name;

        let base = ReadWriteBaseVec::import(options, format)?;

        let pages = Pages::import(db, &Self::pages_region_name_with(name))?;

        let mut this = Self {
            base,
            pages: Arc::new(RwLock::new(pages)),
            _strategy: PhantomData,
        };

        let len = this.real_stored_len();
        *this.base.mut_prev_stored_len() = len;
        this.base.update_stored_len(len);

        Ok(this)
    }

    #[inline]
    pub fn decode_page(&self, page_index: usize, reader: &Reader) -> Result<Vec<T>> {
        Self::decode_page_with(self.stored_len(), page_index, reader, &self.pages.read())
    }

    #[inline]
    pub(crate) fn decode_page_with(
        stored_len: usize,
        page_index: usize,
        reader: &Reader,
        pages: &Pages,
    ) -> Result<Vec<T>> {
        let index = Self::page_index_to_index(page_index);

        if unlikely(index >= stored_len) {
            return Err(Error::IndexTooHigh {
                index,
                len: stored_len,
                name: "page".to_string(),
            });
        }
        if unlikely(page_index >= pages.len()) {
            return Err(Error::ExpectVecToHaveIndex);
        }

        // SAFETY: We checked page_index < pages.len() above
        let page = pages
            .get(page_index)
            .expect("page should exist after bounds check");
        let data = reader.unchecked_read(page.start as usize, page.bytes as usize);
        S::decode_page(data, page)
    }

    #[inline]
    fn compress_page(chunk: &[T]) -> Result<Vec<u8>> {
        debug_assert!(
            chunk.len() <= Self::PER_PAGE,
            "chunk length {} exceeds PER_PAGE {}",
            chunk.len(),
            Self::PER_PAGE
        );

        S::compress(chunk)
    }

    #[inline(always)]
    pub(crate) fn index_to_page_index(index: usize) -> usize {
        index / Self::PER_PAGE
    }

    #[inline(always)]
    pub(crate) fn page_index_to_index(page_index: usize) -> usize {
        page_index * Self::PER_PAGE
    }

    /// Reads stored page data into a buffer. Used by both ReadWrite and ReadOnly read_into_at.
    #[inline(always)]
    pub(crate) fn read_stored_pages_into(
        reader: &Reader,
        pages: &Pages,
        from: usize,
        to: usize,
        buf: &mut Vec<T>,
    ) {
        let start_page = Self::index_to_page_index(from);
        let end_page = Self::index_to_page_index(to - 1);
        for page_idx in start_page..=end_page {
            let page_start = Self::page_index_to_index(page_idx);
            let page = pages
                .get(page_idx)
                .expect("page should exist after bounds check");
            let data = reader.unchecked_read(page.start as usize, page.bytes as usize);
            let values_count = page.values_count() as usize;
            let local_from = from.saturating_sub(page_start);
            let local_to = (to - page_start).min(values_count);

            if !page.is_raw() && likely(local_from == 0) {
                let before = buf.len();
                S::decompress_append(data, values_count, buf)
                    .expect("decompression failed in read_into_at");
                buf.truncate(before + local_to);
            } else {
                let mut page_buf = Vec::with_capacity(values_count);
                S::decode_page_into(data, page, &mut page_buf)
                    .expect("page decode failed in read_into_at");
                buf.extend_from_slice(&page_buf[local_from..local_to]);
            }
        }
    }

    pub(crate) fn pages_region_name(&self) -> String {
        Self::pages_region_name_with(self.name())
    }
    fn pages_region_name_with(name: &str) -> String {
        format!("{}_pages", vec_region_name_with::<I>(name))
    }

    pub fn remove(self) -> Result<()> {
        self.base.remove()?;

        let pages = Arc::try_unwrap(self.pages).map_err(|_| Error::PagesStillReferenced)?;
        pages.into_inner().remove()?;

        Ok(())
    }

    #[inline]
    pub fn reserve_pushed(&mut self, additional: usize) {
        self.base.reserve_pushed(additional);
    }

    #[inline]
    pub(crate) fn create_reader(&self) -> Reader {
        self.base.region().create_reader()
    }

    #[inline]
    pub(crate) fn pages(&self) -> &Arc<RwLock<Pages>> {
        &self.pages
    }

    pub(crate) fn collect_stored_range(&self, from: usize, to: usize) -> Result<Vec<T>> {
        if from >= to {
            return Ok(vec![]);
        }

        let reader = self.create_reader();
        let pages = self.pages.read();
        let real_len = pages.stored_len(Self::PER_PAGE);
        let to = to.min(real_len);
        if from >= to {
            return Ok(vec![]);
        }

        let mut result = Vec::with_capacity(to - from);
        let start_page = Self::index_to_page_index(from);
        let end_page = Self::index_to_page_index(to - 1);

        for page_idx in start_page..=end_page {
            let page_start = Self::page_index_to_index(page_idx);
            let decoded = Self::decode_page_with(real_len, page_idx, &reader, &pages)?;
            let local_from = from.saturating_sub(page_start);
            let local_to = (to - page_start).min(decoded.len());
            result.extend_from_slice(&decoded[local_from..local_to]);
        }

        Ok(result)
    }

    fn deserialize_then_undo_changes(&mut self, bytes: &[u8]) -> Result<()> {
        let change =
            ReadWriteBaseVec::<I, T>::parse_change_data(bytes, Self::SIZE_OF_T, |b| S::read(b))?;

        let current_stored_len = self.stored_len();
        if change.prev_stored_len < current_stored_len {
            self.base.update_stored_len(change.prev_stored_len);
        }

        self.base.apply_rollback(&change);
        self.base.mut_pushed().extend(change.truncated_values);

        Ok(())
    }

    #[inline]
    pub fn fold_stored_io<B, F: FnMut(B, T) -> B>(
        &self,
        from: usize,
        to: usize,
        init: B,
        f: F,
    ) -> B {
        let stored_len = self.stored_len();
        let from = from.min(stored_len);
        let to = to.min(stored_len);
        if from >= to {
            return init;
        }
        CompressedIoSource::new(self, from, to).fold(init, f)
    }

    #[inline]
    pub fn fold_stored_mmap<B, F: FnMut(B, T) -> B>(
        &self,
        from: usize,
        to: usize,
        init: B,
        f: F,
    ) -> B {
        let stored_len = self.stored_len();
        let from = from.min(stored_len);
        let to = to.min(stored_len);
        if from >= to {
            return init;
        }
        CompressedMmapSource::new(self, from, to).fold(init, f)
    }

    #[inline(always)]
    fn fold_source<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, f: F) -> B {
        let range_bytes = (to - from) * Self::SIZE_OF_T;
        if range_bytes > MMAP_CROSSOVER_BYTES {
            CompressedIoSource::new(self, from, to).fold(init, f)
        } else {
            CompressedMmapSource::new(self, from, to).fold(init, f)
        }
    }

    #[inline(always)]
    fn try_fold_source<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        f: F,
    ) -> std::result::Result<B, E> {
        let range_bytes = (to - from) * Self::SIZE_OF_T;
        if range_bytes > MMAP_CROSSOVER_BYTES {
            CompressedIoSource::new(self, from, to).try_fold(init, f)
        } else {
            CompressedMmapSource::new(self, from, to).try_fold(init, f)
        }
    }
}

impl<I, T, S> AnyVec for ReadWriteCompressedVec<I, T, S>
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
        vec![self.base.index_to_name(), self.pages_region_name()]
    }
}

impl<I, T, S> AnyStoredVec for ReadWriteCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    #[inline]
    fn db_path(&self) -> PathBuf {
        self.base.db_path()
    }

    #[inline]
    fn region(&self) -> &Region {
        self.base.region()
    }

    #[inline]
    fn header(&self) -> &Header {
        self.base.header()
    }

    #[inline]
    fn mut_header(&mut self) -> &mut Header {
        self.base.mut_header()
    }

    #[inline]
    fn saved_stamped_changes(&self) -> u16 {
        self.base.saved_stamped_changes()
    }

    #[inline]
    fn stored_len(&self) -> usize {
        self.base.stored_len()
    }

    #[inline]
    fn real_stored_len(&self) -> usize {
        self.pages.read().stored_len(Self::PER_PAGE)
    }

    fn write(&mut self) -> Result<bool> {
        self.base.write_header_if_needed()?;

        let stored_len = self.stored_len();
        let pushed_len = self.base.pushed().len();

        // Phase 1a: Copy metadata snapshot (minimal lock scope)
        let (truncate_at, starting_page_index, partial_page) = {
            let pages = self.pages.read();

            let real_stored_len = pages.stored_len(Self::PER_PAGE);
            if stored_len > real_stored_len {
                return Err(Error::CorruptedRegion {
                    name: self.name().to_string(),
                    region_len: real_stored_len,
                });
            }

            if pushed_len == 0 && stored_len == real_stored_len {
                return Ok(false);
            }

            let starting_page_index = Self::index_to_page_index(stored_len);
            if starting_page_index > pages.len() {
                return Err(Error::CorruptedRegion {
                    name: self.name().to_string(),
                    region_len: pages.len(),
                });
            }

            if starting_page_index < pages.len() {
                let partial_len = stored_len % Self::PER_PAGE;
                let page = *pages
                    .get(starting_page_index)
                    .ok_or(Error::ExpectVecToHaveIndex)?;
                (
                    page.start,
                    starting_page_index,
                    if partial_len != 0 {
                        Some((page, partial_len))
                    } else {
                        None
                    },
                )
            } else {
                (pages.next_start(), starting_page_index, None)
            }
        };
        // Pages lock released — decompression happens without blocking readers

        // Fast path: append to existing raw page without reading it back.
        // When the last page is raw, not truncated, and won't overflow, just
        // write the new pushed bytes at the end of the existing page data.
        if let Some((page, partial_len)) = partial_page
            && page.is_raw()
            && partial_len == page.values_count() as usize
            && partial_len + pushed_len < Self::PER_PAGE
        {
            let taken = mem::take(self.base.mut_pushed());
            let raw = S::values_to_bytes(&taken);
            let append_at = page.end() as usize;
            self.region().truncate_write(append_at, &raw)?;

            let mut pages = self.pages.write();
            pages.truncate(starting_page_index);
            pages.checked_push(
                starting_page_index,
                Page::raw(
                    page.start,
                    page.bytes + raw.len() as u32,
                    (partial_len + pushed_len) as u32,
                ),
            )?;
            self.base.update_stored_len(stored_len + pushed_len);
            pages.flush()?;
            return Ok(true);
        }

        // Phase 1b: Read partial page (if needed) outside lock
        let mut values = if let Some((page, partial_len)) = partial_page {
            let reader = self.create_reader();
            let data = reader.unchecked_read(page.start as usize, page.bytes as usize);
            let mut page_values = S::decode_page(data, &page)?;
            page_values.truncate(partial_len);
            page_values
        } else {
            vec![]
        };

        // Phase 2: Encode pages (no locks held)
        // Full pages are compressed; the last partial page is stored raw.
        let taken = mem::take(self.base.mut_pushed());
        if values.is_empty() {
            values = taken;
        } else {
            values.extend_from_slice(&taken);
        }

        let num_pages = values.len().div_ceil(Self::PER_PAGE);
        let mut buf = Vec::with_capacity(values.len() * Self::SIZE_OF_T);
        let mut page_sizes: Vec<(usize, usize, bool)> = Vec::with_capacity(num_pages);
        for chunk in values.chunks(Self::PER_PAGE) {
            if chunk.len() == Self::PER_PAGE {
                let compressed = Self::compress_page(chunk)?;
                page_sizes.push((compressed.len(), chunk.len(), false));
                buf.extend_from_slice(&compressed);
            } else {
                let raw = S::values_to_bytes(chunk);
                page_sizes.push((raw.len(), chunk.len(), true));
                buf.extend_from_slice(&raw);
            }
        }

        // Phase 3: Write to region first (without holding pages lock to avoid deadlock)
        self.region().truncate_write(truncate_at as usize, &buf)?;

        let mut pages = self.pages.write();
        pages.truncate(starting_page_index);

        for (i, &(byte_len, values_len, is_raw)) in page_sizes.iter().enumerate() {
            let start = pages.next_start();
            let page = if is_raw {
                Page::raw(start, byte_len as u32, values_len as u32)
            } else {
                Page::compressed(start, byte_len as u32, values_len as u32)
            };
            pages.checked_push(starting_page_index + i, page)?;
        }

        self.base.update_stored_len(stored_len + pushed_len);
        pages.flush()?;

        Ok(true)
    }

    #[inline]
    fn serialize_changes(&self) -> Result<Vec<u8>> {
        self.base.serialize_changes(
            Self::SIZE_OF_T,
            |from, to| self.collect_stored_range(from, to),
            |vals, buf| {
                for v in vals {
                    S::write_to_vec(v, buf);
                }
            },
        )
    }

    #[inline]
    fn db(&self) -> Database {
        self.base.db()
    }

    fn any_stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()> {
        <Self as WritableVec<I, T>>::stamped_write_with_changes(self, stamp)
    }

    fn remove(self) -> Result<()> {
        Self::remove(self)
    }

    fn any_truncate_if_needed_at(&mut self, index: usize) -> Result<()> {
        <Self as WritableVec<I, T>>::truncate_if_needed_at(self, index)
    }

    fn any_reset(&mut self) -> Result<()> {
        <Self as WritableVec<I, T>>::reset(self)
    }
}

impl<I, T, S> WritableVec<I, T> for ReadWriteCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    #[inline]
    fn push(&mut self, value: T) {
        self.base.mut_pushed().push(value);
    }

    #[inline]
    fn pushed(&self) -> &[T] {
        self.base.pushed()
    }

    fn truncate_if_needed_at(&mut self, index: usize) -> Result<()> {
        if self.base.truncate_pushed(index) {
            self.base.update_stored_len(index);
        }
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.pages.write().reset();
        self.truncate_if_needed_at(0)?;
        self.base.reset_base()
    }

    fn reset_unsaved(&mut self) {
        self.base.reset_unsaved_base();
    }

    fn is_dirty(&self) -> bool {
        !self.base.pushed().is_empty()
    }

    fn stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()> {
        if self.base.saved_stamped_changes() == 0 {
            return self.stamped_write(stamp);
        }

        let data = self.serialize_changes()?;
        self.base.save_change_file(stamp, &data)?;
        self.stamped_write(stamp)?;
        self.base.save_prev();

        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        let bytes = self.base.read_current_change_file()?;
        self.deserialize_then_undo_changes(&bytes)
    }

    fn find_rollback_files(&self) -> Result<BTreeMap<Stamp, PathBuf>> {
        self.base.find_rollback_files()
    }

    fn save_rollback_state(&mut self) {
        self.base.save_prev_for_rollback();
    }
}

impl<I, T, S> ReadableVec<I, T> for ReadWriteCompressedVec<I, T, S>
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
        let stored_len = self.stored_len();

        if from < stored_len {
            let stored_to = to.min(stored_len);
            let reader = self.create_reader();
            let pages = self.pages.read();
            Self::read_stored_pages_into(&reader, &pages, from, stored_to, buf);
        }

        if to > stored_len {
            let push_from = from.max(stored_len);
            let pushed = self.base.pushed();
            let start = push_from - stored_len;
            let end = (to - stored_len).min(pushed.len());
            buf.extend_from_slice(&pushed[start..end]);
        }
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(T)) {
        self.fold_range_at(from, to, (), |(), v| f(v));
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, mut f: F) -> B
    where
        Self: Sized,
    {
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return init;
        }

        let stored_len = self.stored_len();

        if to <= stored_len {
            return self.fold_source(from, to, init, f);
        }

        let mut acc = init;
        if from < stored_len {
            acc = self.fold_source(from, stored_len, acc, &mut f);
        }
        self.base.fold_pushed(from, to, acc, f)
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
        let len = self.base.len();
        let from = from.min(len);
        let to = to.min(len);
        if from >= to {
            return Ok(init);
        }

        let stored_len = self.stored_len();

        if to <= stored_len {
            return self.try_fold_source(from, to, init, f);
        }

        let mut acc = init;
        if from < stored_len {
            acc = self.try_fold_source(from, stored_len, acc, &mut f)?;
        }
        self.base.try_fold_pushed(from, to, acc, f)
    }
}

impl<I, T, S> TypedVec for ReadWriteCompressedVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: CompressionStrategy<T>,
{
    type I = I;
    type T = T;
}
