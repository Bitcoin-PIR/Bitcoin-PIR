use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    mem,
    path::PathBuf,
};

use log::{debug, info};
use rawdb::{Database, Reader, Region, likely, unlikely};

use crate::{
    AnyStoredVec, AnyVec, Bytes, Error, Format, HEADER_OFFSET, Header, ImportOptions,
    MMAP_CROSSOVER_BYTES, RawIoSource, RawMmapSource, ReadWriteBaseVec, ReadableVec, Result,
    SIZE_OF_U64, Stamp, TypedVec, VecIndex, VecReader, VecValue, Version, WithPrev, WritableVec,
    check_bounds, short_type_name, vec_region_name_with,
};

use super::{RawStrategy, ReadOnlyRawVec};

const VERSION: Version = Version::ONE;

/// Core implementation for raw storage vectors shared by BytesVec and ZeroCopyVec.
///
/// Parameterized by serialization strategy `S` to support different serialization approaches:
/// - `BytesStrategy`: Explicit little-endian serialization (portable)
/// - `ZeroCopyStrategy`: Native byte order via zerocopy (fast but not portable)
///
/// Provides holes (deleted indices) and updated values tracking for both vec types.
#[derive(Debug)]
#[must_use = "Vector should be stored to keep data accessible"]
pub struct ReadWriteRawVec<I, T, S> {
    pub(crate) base: ReadWriteBaseVec<I, T>,
    holes: WithPrev<BTreeSet<usize>>,
    updated: WithPrev<BTreeMap<usize, T>>,
    has_stored_holes: bool,
    _strategy: PhantomData<S>,
}

impl<I, T, S> ReadWriteRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    pub const SIZE_OF_T: usize = size_of::<T>();

    pub fn read_only_clone(&self) -> ReadOnlyRawVec<I, T, S> {
        ReadOnlyRawVec::new(self.base.read_only_base())
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
                Self::import_with(options, format)
            }
            _ => res,
        }
    }

    pub fn import_with(mut options: ImportOptions, format: Format) -> Result<Self> {
        options.version = options.version + VERSION;

        let db = options.db;
        let name = options.name;

        let base = ReadWriteBaseVec::import(options, format)?;

        // Raw format requires data to be aligned to SIZE_OF_T
        let region_len = base.region().meta().len();
        if region_len > HEADER_OFFSET
            && !(region_len - HEADER_OFFSET).is_multiple_of(Self::SIZE_OF_T)
        {
            return Err(Error::CorruptedRegion {
                name: name.to_string(),
                region_len,
            });
        }

        let holes = db
            .get_region(&Self::holes_region_name_with(name))
            .map(|region| {
                region
                    .create_reader()
                    .read_all()
                    .chunks(size_of::<usize>())
                    .map(usize::from_bytes)
                    .collect::<Result<BTreeSet<usize>>>()
            })
            .transpose()?;

        let mut this = Self {
            base,
            has_stored_holes: holes.is_some(),
            holes: WithPrev::new(holes.unwrap_or_default()),
            updated: WithPrev::default(),
            _strategy: PhantomData,
        };

        let len = this.real_stored_len();
        *this.base.mut_prev_stored_len() = len;
        this.base.update_stored_len(len);

        Ok(this)
    }

    pub fn remove(self) -> Result<()> {
        let db = self.base.db();
        let holes_region_name = self.holes_region_name();
        let has_stored_holes = self.has_stored_holes;

        self.base.remove()?;

        if has_stored_holes {
            db.remove_region(&holes_region_name)?;
        }

        Ok(())
    }

    fn holes_region_name(&self) -> String {
        Self::holes_region_name_with(self.name())
    }
    fn holes_region_name_with(name: &str) -> String {
        format!("{}_holes", vec_region_name_with::<I>(name))
    }

    #[inline(always)]
    pub fn holes(&self) -> &BTreeSet<usize> {
        self.holes.current()
    }

    #[inline(always)]
    pub fn prev_holes(&self) -> &BTreeSet<usize> {
        self.holes.previous()
    }

    #[inline(always)]
    pub fn mut_holes(&mut self) -> &mut BTreeSet<usize> {
        self.holes.current_mut()
    }

    #[inline(always)]
    pub fn updated(&self) -> &BTreeMap<usize, T> {
        self.updated.current()
    }

    #[inline(always)]
    pub fn mut_updated(&mut self) -> &mut BTreeMap<usize, T> {
        self.updated.current_mut()
    }

    #[inline(always)]
    pub fn prev_updated(&self) -> &BTreeMap<usize, T> {
        self.updated.previous()
    }

    #[inline(always)]
    pub fn pushed(&self) -> &[T] {
        self.base.pushed()
    }

    #[inline(always)]
    pub fn mut_pushed(&mut self) -> &mut Vec<T> {
        self.base.mut_pushed()
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        self.base.mut_pushed().push(value);
    }

    #[inline]
    pub fn reserve_pushed(&mut self, additional: usize) {
        self.base.reserve_pushed(additional);
    }

    #[inline]
    pub fn create_reader(&self) -> Reader {
        self.base.region().create_reader()
    }

    #[inline]
    pub fn reader(&self) -> VecReader<I, T, S> {
        VecReader::from_read_write(self)
    }

    #[inline]
    pub fn index_to_name(&self) -> String {
        self.base.index_to_name()
    }

    #[inline(always)]
    pub fn unchecked_read_at(&self, index: usize, reader: &Reader) -> T {
        let ptr = reader.prefixed(HEADER_OFFSET).as_ptr();
        unsafe { S::read_from_ptr(ptr, index * Self::SIZE_OF_T) }
    }

    #[inline(always)]
    pub fn read_at(&self, index: usize, reader: &Reader) -> Result<T> {
        let len = self.base.len();
        if likely(index < len) {
            Ok(self.unchecked_read_at(index, reader))
        } else {
            Err(Error::IndexTooHigh {
                index,
                len,
                name: self.name().to_string(),
            })
        }
    }

    #[inline]
    pub fn read_at_once(&self, index: usize) -> Result<T> {
        self.read_at(index, &self.create_reader())
    }

    #[inline]
    pub fn read_once(&self, index: I) -> Result<T> {
        self.read_at_once(index.to_usize())
    }

    #[inline(always)]
    pub fn get_pushed_or_read(&self, index: I, reader: &VecReader<I, T, S>) -> Option<T> {
        self.get_pushed_or_read_at(index.to_usize(), reader)
    }

    #[inline(always)]
    pub fn get_pushed_or_read_at(&self, index: usize, reader: &VecReader<I, T, S>) -> Option<T> {
        let stored_len = self.stored_len();
        if index >= stored_len {
            return self.base.pushed().get(index - stored_len).cloned();
        }
        Some(reader.get(index))
    }

    #[inline]
    pub fn get_any_or_read(&self, index: I, reader: &Reader) -> Result<Option<T>> {
        self.get_any_or_read_at(index.to_usize(), reader)
    }

    #[inline]
    pub fn get_any_or_read_at(&self, index: usize, reader: &Reader) -> Result<Option<T>> {
        if unlikely(!self.holes().is_empty()) && self.holes().contains(&index) {
            return Ok(None);
        }

        let stored_len = self.stored_len();

        if index >= stored_len {
            return Ok(self.base.pushed().get(index - stored_len).cloned());
        }

        if unlikely(!self.updated().is_empty())
            && let Some(updated_value) = self.updated().get(&index)
        {
            return Ok(Some(updated_value.clone()));
        }

        Ok(Some(self.unchecked_read_at(index, reader)))
    }

    pub fn collect_holed(&self) -> Result<Vec<Option<T>>> {
        self.collect_holed_range(0, self.len())
    }

    pub fn collect_holed_range(&self, from: usize, to: usize) -> Result<Vec<Option<T>>> {
        let len = self.len();
        let from = from.min(len);
        let to = to.min(len);

        if from >= to {
            return Ok(vec![]);
        }

        let reader = self.create_reader();

        (from..to)
            .map(|i| self.get_any_or_read_at(i, &reader))
            .collect::<Result<Vec<_>>>()
    }

    #[inline]
    pub fn update(&mut self, index: I, value: T) -> Result<()> {
        self.update_at(index.to_usize(), value)
    }

    #[inline]
    pub fn update_at(&mut self, index: usize, value: T) -> Result<()> {
        let stored_len = self.stored_len();

        if index >= stored_len {
            let Some(slot) = self.base.mut_pushed().get_mut(index - stored_len) else {
                return Err(Error::IndexTooHigh {
                    index,
                    len: stored_len,
                    name: self.name().to_string(),
                });
            };
            *slot = value;
            return Ok(());
        }

        if !self.holes().is_empty() {
            self.mut_holes().remove(&index);
        }

        self.mut_updated().insert(index, value);

        Ok(())
    }

    #[inline]
    pub fn delete(&mut self, index: I) {
        self.delete_at(index.to_usize())
    }

    #[inline]
    pub fn delete_at(&mut self, index: usize) {
        if index < self.len() {
            self.unchecked_delete_at(index);
        }
    }

    #[inline]
    #[doc(hidden)]
    pub fn unchecked_delete(&mut self, index: I) {
        self.unchecked_delete_at(index.to_usize())
    }

    #[inline]
    #[doc(hidden)]
    pub fn unchecked_delete_at(&mut self, index: usize) {
        if !self.updated().is_empty() {
            self.mut_updated().remove(&index);
        }
        self.mut_holes().insert(index);
    }

    #[inline]
    pub fn get_first_empty_index(&self) -> I {
        self.holes()
            .first()
            .copied()
            .unwrap_or_else(|| self.base.len())
            .into()
    }

    #[inline]
    pub fn fill_first_hole_or_push(&mut self, value: T) -> Result<I> {
        if let Some(hole) = self.mut_holes().pop_first().map(I::from) {
            self.update(hole, value)?;
            return Ok(hole);
        }
        self.base.mut_pushed().push(value);
        Ok(I::from(self.len() - 1))
    }

    pub fn take(&mut self, index: I, reader: &Reader) -> Result<Option<T>> {
        self.take_at(index.to_usize(), reader)
    }

    pub fn take_at(&mut self, index: usize, reader: &Reader) -> Result<Option<T>> {
        let opt = self.get_any_or_read_at(index, reader)?;
        if opt.is_some() {
            self.unchecked_delete_at(index);
        }
        Ok(opt)
    }

    pub(crate) fn collect_stored_range(&self, from: usize, to: usize) -> Result<Vec<T>> {
        let reader = self.create_reader();
        Ok((from..to)
            .map(|i| {
                if let Some(val) = self.prev_updated().get(&i) {
                    val.clone()
                } else {
                    self.unchecked_read_at(i, &reader)
                }
            })
            .collect())
    }

    fn deserialize_then_undo_changes(&mut self, bytes: &[u8]) -> Result<()> {
        let change =
            ReadWriteBaseVec::<I, T>::parse_change_data(bytes, Self::SIZE_OF_T, |b| S::read(b))?;
        let mut pos = change.bytes_consumed;
        let mut len = SIZE_OF_U64;

        let current_stored_len = self.stored_len();
        if change.prev_stored_len < current_stored_len {
            self.truncate_dirty_at(change.prev_stored_len);
        }

        self.base.apply_rollback(&change);

        for (i, val) in change.truncated_values.into_iter().enumerate() {
            self.mut_updated().insert(change.truncated_start + i, val);
        }

        check_bounds(bytes, pos, len)?;
        let modified_len = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;

        len = SIZE_OF_U64
            .checked_mul(modified_len)
            .ok_or(Error::Overflow)?;
        check_bounds(bytes, pos, len)?;
        let indexes_start = pos;
        pos += len;

        len = Self::SIZE_OF_T
            .checked_mul(modified_len)
            .ok_or(Error::Overflow)?;
        check_bounds(bytes, pos, len)?;
        let mut idx_pos = indexes_start;
        let mut val_pos = pos;
        for _ in 0..modified_len {
            let idx = usize::from_bytes(&bytes[idx_pos..idx_pos + SIZE_OF_U64])?;
            let val = S::read(&bytes[val_pos..val_pos + Self::SIZE_OF_T])?;
            self.update_at(idx, val)?;
            idx_pos += SIZE_OF_U64;
            val_pos += Self::SIZE_OF_T;
        }
        pos += len;

        len = SIZE_OF_U64;
        check_bounds(bytes, pos, len)?;
        let prev_holes_len = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;
        len = SIZE_OF_U64
            .checked_mul(prev_holes_len)
            .ok_or(Error::Overflow)?;
        check_bounds(bytes, pos, len)?;

        if prev_holes_len > 0 || !self.holes().is_empty() || !self.prev_holes().is_empty() {
            let prev_holes = bytes[pos..pos + len]
                .chunks(SIZE_OF_U64)
                .map(usize::from_bytes)
                .collect::<Result<BTreeSet<_>>>()?;
            *self.holes.current_mut() = prev_holes;
            self.holes.save();
        }

        self.updated.save();

        Ok(())
    }

    #[inline]
    fn has_dirty_stored(&self) -> bool {
        !self.holes().is_empty() || !self.updated().is_empty()
    }

    fn truncate_dirty_at(&mut self, index: usize) {
        if self.holes().last().is_some_and(|&h| h >= index) {
            self.mut_holes().split_off(&index);
        }
        if self
            .updated()
            .last_key_value()
            .is_some_and(|(&k, _)| k >= index)
        {
            self.mut_updated().split_off(&index);
        }
    }

    #[inline(always)]
    fn fold_source<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, f: F) -> B {
        let range_bytes = (to - from) * Self::SIZE_OF_T;
        if range_bytes > MMAP_CROSSOVER_BYTES {
            RawIoSource::new(self, from, to).fold(init, f)
        } else {
            RawMmapSource::new(self, from, to).fold(init, f)
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
            RawIoSource::new(self, from, to).try_fold(init, f)
        } else {
            RawMmapSource::new(self, from, to).try_fold(init, f)
        }
    }

    /// Own implementation (not delegating to try_fold_dirty) so LLVM can vectorize without `?` penalty.
    fn fold_dirty<B, F: FnMut(B, T) -> B>(&self, from: usize, to: usize, init: B, mut f: F) -> B {
        let stored_len = self.stored_len();
        let reader = self.create_reader();
        let data_ptr = reader.prefixed(HEADER_OFFSET).as_ptr();
        let mut acc = init;

        let stored_to = to.min(stored_len);
        let mut hole_iter = self.holes().range(from..to).peekable();
        let mut update_iter = self.updated().range(from..stored_to).peekable();

        let mut byte_off = from * Self::SIZE_OF_T;
        for i in from..stored_to {
            if unlikely(hole_iter.peek() == Some(&&i)) {
                hole_iter.next();
                byte_off += Self::SIZE_OF_T;
                continue;
            }
            let val = if unlikely(update_iter.peek().is_some_and(|&(&k, _)| k == i)) {
                update_iter.next().unwrap().1.clone()
            } else {
                unsafe { S::read_from_ptr(data_ptr, byte_off) }
            };
            byte_off += Self::SIZE_OF_T;
            acc = f(acc, val);
        }

        let push_from = from.max(stored_len);
        if push_from < to {
            let pushed = self.base.pushed();
            for i in push_from..to {
                if unlikely(hole_iter.peek() == Some(&&i)) {
                    hole_iter.next();
                    continue;
                }
                if let Some(v) = pushed.get(i - stored_len) {
                    acc = f(acc, v.clone());
                }
            }
        }

        acc
    }

    fn try_fold_dirty<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> std::result::Result<B, E> {
        let stored_len = self.stored_len();
        let reader = self.create_reader();
        let data_ptr = reader.prefixed(HEADER_OFFSET).as_ptr();
        let mut acc = init;

        let stored_to = to.min(stored_len);
        let mut hole_iter = self.holes().range(from..to).peekable();
        let mut update_iter = self.updated().range(from..stored_to).peekable();

        let mut byte_off = from * Self::SIZE_OF_T;
        for i in from..stored_to {
            if unlikely(hole_iter.peek() == Some(&&i)) {
                hole_iter.next();
                byte_off += Self::SIZE_OF_T;
                continue;
            }
            let val = if unlikely(update_iter.peek().is_some_and(|&(&k, _)| k == i)) {
                update_iter.next().unwrap().1.clone()
            } else {
                // SAFETY: i < stored_len, reader holds mmap guard
                unsafe { S::read_from_ptr(data_ptr, byte_off) }
            };
            byte_off += Self::SIZE_OF_T;
            acc = f(acc, val)?;
        }

        let push_from = from.max(stored_len);
        if push_from < to {
            let pushed = self.base.pushed();
            for i in push_from..to {
                if unlikely(hole_iter.peek() == Some(&&i)) {
                    hole_iter.next();
                    continue;
                }
                if let Some(v) = pushed.get(i - stored_len) {
                    acc = f(acc, v.clone())?;
                }
            }
        }

        Ok(acc)
    }

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
        RawIoSource::new(self, from, to).fold(init, f)
    }

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
        RawMmapSource::new(self, from, to).fold(init, f)
    }
}

impl<I, T, S> AnyVec for ReadWriteRawVec<I, T, S>
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
        let mut names = vec![self.index_to_name()];
        if self.has_stored_holes {
            names.push(self.holes_region_name());
        }
        names
    }
}

impl<I, T, S> AnyStoredVec for ReadWriteRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    #[inline]
    fn db_path(&self) -> PathBuf {
        self.base.db_path()
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

    fn db(&self) -> Database {
        self.region().db()
    }

    #[inline]
    fn real_stored_len(&self) -> usize {
        (self.region().meta().len() - HEADER_OFFSET) / Self::SIZE_OF_T
    }

    #[inline]
    fn stored_len(&self) -> usize {
        self.base.stored_len()
    }

    fn write(&mut self) -> Result<bool> {
        self.base.write_header_if_needed()?;

        let stored_len = self.stored_len();
        let pushed_len = self.base.pushed().len();
        let real_stored_len = self.real_stored_len();
        // After rollback, stored_len can be > real_stored_len (missing items are in updated map)
        let truncated = stored_len < real_stored_len;
        let expanded = stored_len > real_stored_len;
        let has_new_data = pushed_len != 0;
        let has_updated_data = !self.updated().is_empty();
        let has_holes = !self.holes().is_empty();
        let had_holes = self.has_stored_holes;

        if !truncated && !expanded && !has_new_data && !has_updated_data && !has_holes && !had_holes
        {
            return Ok(false);
        }

        let from = stored_len * Self::SIZE_OF_T + HEADER_OFFSET;

        if has_new_data {
            // Take the pushed buffer to free its heap allocation after writing.
            let taken = mem::take(self.base.mut_pushed());
            if S::IS_NATIVE_LAYOUT {
                // Bulk write: memory layout matches serialized format, skip per-value
                // serialization entirely. Single memcpy from pushed buffer to mmap.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        taken.as_ptr() as *const u8,
                        taken.len() * Self::SIZE_OF_T,
                    )
                };
                self.region().truncate_write(from, bytes)?;
            } else {
                let mut bytes = Vec::with_capacity(pushed_len * Self::SIZE_OF_T);
                for v in &taken {
                    S::write_to_vec(v, &mut bytes);
                }
                self.region().truncate_write(from, &bytes)?;
            }
            self.base.update_stored_len(stored_len + pushed_len);
        } else if truncated {
            self.region().truncate(from)?;
        }

        if has_updated_data {
            let updated = self.updated.take_current();
            let region = self.region();

            if unlikely(expanded) {
                // After rollback, updates may extend beyond current disk length.
                // Use write_at which handles extension (slower but necessary).
                let mut bytes = Vec::with_capacity(Self::SIZE_OF_T);
                for (index, value) in updated {
                    let offset = index * Self::SIZE_OF_T + HEADER_OFFSET;
                    bytes.clear();
                    S::write_to_vec(&value, &mut bytes);
                    region.write_at(&bytes, offset)?;
                }
            } else {
                // Normal case: write directly to mmap, no intermediate allocations
                region.batch_write_each(
                    updated
                        .into_iter()
                        .map(|(index, value)| (index * Self::SIZE_OF_T + HEADER_OFFSET, value)),
                    Self::SIZE_OF_T,
                    S::write_to_slice,
                );
            }
        }

        if has_holes {
            self.has_stored_holes = true;
            let holes_region = self
                .region()
                .db()
                .create_region_if_needed(&self.holes_region_name())?;
            let holes = self.holes();
            let mut bytes = Vec::with_capacity(holes.len() * size_of::<usize>());
            for i in holes {
                bytes.extend(i.to_bytes());
            }
            holes_region.truncate_write(0, &bytes)?;
        } else if had_holes {
            self.has_stored_holes = false;
            let db = self.region().db();
            let holes_name = self.holes_region_name();
            debug!("{}: removing holes region '{}'", db, holes_name);
            db.remove_region(&holes_name)?;
        }

        Ok(true)
    }

    fn region(&self) -> &Region {
        self.base.region()
    }

    fn serialize_changes(&self) -> Result<Vec<u8>> {
        let mut bytes = self.base.serialize_changes(
            Self::SIZE_OF_T,
            |from, to| self.collect_stored_range(from, to),
            |vals, buf| {
                for v in vals {
                    S::write_to_vec(v, buf);
                }
            },
        )?;

        let reader = self.create_reader();
        let updated = self.updated();
        let prev_updated = self.prev_updated();

        // Collect all indices that need change tracking: entries currently modified
        // AND entries that were in prev_updated but removed (e.g., by delete_at).
        // Without the latter, rollback after rollback loses track of deleted entries.
        let all_keys: BTreeSet<usize> =
            updated.keys().chain(prev_updated.keys()).copied().collect();

        bytes.extend(all_keys.len().to_bytes());
        for &i in &all_keys {
            bytes.extend(i.to_bytes());
        }
        for &i in &all_keys {
            if let Some(v) = prev_updated.get(&i) {
                S::write_to_vec(v, &mut bytes);
            } else {
                S::write_to_vec(&self.unchecked_read_at(i, &reader), &mut bytes);
            }
        }

        let prev_holes = self.prev_holes();
        bytes.extend(prev_holes.len().to_bytes());
        for &hole in prev_holes {
            bytes.extend(hole.to_bytes());
        }

        Ok(bytes)
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

impl<I, T, S> WritableVec<I, T> for ReadWriteRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
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
        self.truncate_dirty_at(index);

        if self.base.truncate_pushed(index) {
            self.base.update_stored_len(index);
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.holes.clear();
        self.updated.clear();
        self.truncate_if_needed_at(0)?;
        self.base.reset_base()
    }

    fn reset_unsaved(&mut self) {
        self.base.reset_unsaved_base();
        self.holes.clear();
        self.updated.clear();
    }

    fn is_dirty(&self) -> bool {
        !self.base.pushed().is_empty() || !self.holes().is_empty() || !self.updated().is_empty()
    }

    fn stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()> {
        if self.base.saved_stamped_changes() == 0 {
            return self.stamped_write(stamp);
        }

        // serialize_changes() reads prev_holes, so must happen BEFORE holes.save()
        let data = self.serialize_changes()?;
        self.base.save_change_file(stamp, &data)?;
        self.stamped_write(stamp)?;
        self.base.save_prev();
        self.holes.save();
        self.updated.clear_previous();

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
        self.holes.save();
        self.updated.save();
    }
}

impl<I, T, S> ReadableVec<I, T> for ReadWriteRawVec<I, T, S>
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
        if self.has_dirty_stored() {
            return self
                .get_any_or_read_at(index, &self.create_reader())
                .ok()
                .flatten();
        }
        let stored_len = self.stored_len();
        if index >= stored_len {
            return self.base.pushed().get(index - stored_len).cloned();
        }
        Some(self.unchecked_read_at(index, &self.create_reader()))
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

        if self.has_dirty_stored() {
            self.fold_dirty(from, to, (), |(), v| buf.push(v));
            return;
        }

        let stored_len = self.stored_len();

        if from < stored_len {
            let stored_to = to.min(stored_len);
            if S::IS_NATIVE_LAYOUT {
                // Bulk read: memory layout matches T, single memcpy from mmap.
                let reader = self.create_reader();
                let src = unsafe {
                    std::slice::from_raw_parts(
                        reader
                            .prefixed(HEADER_OFFSET)
                            .as_ptr()
                            .add(from * Self::SIZE_OF_T) as *const T,
                        stored_to - from,
                    )
                };
                buf.extend_from_slice(src);
            } else {
                self.fold_source(from, stored_to, (), |(), v| buf.push(v));
            }
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

        if self.has_dirty_stored() {
            return self.fold_dirty(from, to, init, f);
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

        if self.has_dirty_stored() {
            return self.try_fold_dirty(from, to, init, f);
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

impl<I, T, S> TypedVec for ReadWriteRawVec<I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    type I = I;
    type T = T;
}
