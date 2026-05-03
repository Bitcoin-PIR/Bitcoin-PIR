use std::{collections::BTreeMap, fs, marker::PhantomData, ops::Deref, path::PathBuf, sync::Arc};

use rawdb::Database;

use crate::{Bytes, Error, Result, SIZE_OF_U64, Stamp, VecIndex, VecValue};

use super::{Format, HEADER_OFFSET, Header, ImportOptions, ReadOnlyBaseVec, SharedLen, WithPrev};

/// Base storage vector with fields common to all stored vector implementations.
///
/// Derefs to [`ReadOnlyBaseVec`] for read-only access to region, header, name,
/// stored_len, and version. Write state (pushed, rollback) lives here.
#[derive(Debug)]
pub(crate) struct ReadWriteBaseVec<I, T> {
    pub(crate) read_only: ReadOnlyBaseVec<I, T>,
    pushed: WithPrev<Vec<T>>,
    previous_stored_len: usize,
    saved_stamped_changes: u16,
}

impl<I, T> Deref for ReadWriteBaseVec<I, T> {
    type Target = ReadOnlyBaseVec<I, T>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.read_only
    }
}

impl<I, T> ReadWriteBaseVec<I, T>
where
    I: VecIndex,
    T: VecValue,
{
    pub fn import(options: ImportOptions, format: Format) -> Result<Self> {
        let region = options
            .db
            .create_region_if_needed(&vec_region_name_with::<I>(options.name))?;

        let region_len = region.meta().len();
        if region_len > 0 && region_len < HEADER_OFFSET {
            return Err(Error::CorruptedRegion {
                name: region.meta().id().to_string(),
                region_len,
            });
        }

        let header = if region_len == 0 {
            Header::create_and_write(&region, options.version, format)?
        } else {
            Header::import_and_verify(&region, options.version, format)?
        };

        Ok(Self {
            read_only: ReadOnlyBaseVec {
                region,
                header,
                name: Arc::from(options.name),
                stored_len: SharedLen::default(),
                phantom: PhantomData,
            },
            pushed: WithPrev::default(),
            previous_stored_len: 0,
            saved_stamped_changes: options.saved_stamped_changes,
        })
    }

    #[inline]
    pub fn read_only_base(&self) -> ReadOnlyBaseVec<I, T> {
        self.read_only.clone()
    }

    #[inline]
    pub fn pushed(&self) -> &[T] {
        self.pushed.current()
    }

    #[inline]
    pub fn mut_pushed(&mut self) -> &mut Vec<T> {
        self.pushed.current_mut()
    }

    #[inline]
    pub fn reserve_pushed(&mut self, additional: usize) {
        self.pushed.current_mut().reserve(additional);
    }

    #[inline]
    pub fn prev_pushed(&self) -> &[T] {
        self.pushed.previous()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.stored_len() + self.pushed().len()
    }

    #[inline]
    pub fn update_stored_len(&self, val: usize) {
        self.read_only.stored_len.set(val);
    }

    #[inline]
    pub fn prev_stored_len(&self) -> usize {
        self.previous_stored_len
    }

    #[inline(always)]
    pub fn mut_prev_stored_len(&mut self) -> &mut usize {
        &mut self.previous_stored_len
    }

    #[inline(always)]
    pub fn saved_stamped_changes(&self) -> u16 {
        self.saved_stamped_changes
    }

    #[inline]
    pub fn mut_header(&mut self) -> &mut Header {
        &mut self.read_only.header
    }

    #[inline]
    pub fn db(&self) -> Database {
        self.region.db()
    }

    #[inline]
    pub fn db_path(&self) -> PathBuf {
        self.db().path().to_path_buf()
    }

    pub fn write_header_if_needed(&mut self) -> Result<()> {
        if self.read_only.header.modified() {
            self.read_only.header.write(&self.read_only.region)?;
        }
        Ok(())
    }

    pub fn index_to_name(&self) -> String {
        vec_region_name(&self.name, I::to_string())
    }

    pub fn remove(self) -> Result<()> {
        self.read_only.region.remove()?;
        Ok(())
    }

    /// Tight pointer loop for LLVM vectorization.
    #[inline]
    pub fn fold_pushed<B, F: FnMut(B, T) -> B>(
        &self,
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> B {
        let stored_len = self.stored_len();
        let start = from.max(stored_len);
        if start >= to {
            return init;
        }
        let pushed = self.pushed();
        let slice_from = start - stored_len;
        let slice_to = (to - stored_len).min(pushed.len());
        let ptr = pushed.as_ptr();
        let mut acc = init;
        let mut i = slice_from;
        while i < slice_to {
            acc = f(acc, unsafe { ptr.add(i).read() });
            i += 1;
        }
        acc
    }

    #[inline]
    pub fn try_fold_pushed<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        mut f: F,
    ) -> std::result::Result<B, E> {
        let stored_len = self.stored_len();
        let start = from.max(stored_len);
        if start >= to {
            return Ok(init);
        }
        let pushed = self.pushed();
        let mut acc = init;
        for v in &pushed[(start - stored_len)..(to - stored_len).min(pushed.len())] {
            acc = f(acc, v.clone())?;
        }
        Ok(acc)
    }

    /// Returns true if stored_len needs updating to `index`.
    pub fn truncate_pushed(&mut self, index: usize) -> bool {
        let stored_len = self.stored_len();
        let len = stored_len + self.pushed().len();

        if index >= len {
            return false;
        }

        if index <= stored_len {
            self.pushed.current_mut().clear();
        } else {
            self.pushed.current_mut().truncate(index - stored_len);
        }

        index < stored_len
    }

    pub fn reset_base(&mut self) -> Result<()> {
        self.pushed.clear();
        self.read_only.stored_len.set(0);
        self.previous_stored_len = 0;
        self.read_only.header.update_stamp(Stamp::default());

        let changes_path = self.changes_path();
        if changes_path.exists() {
            fs::remove_dir_all(&changes_path)?;
        }

        Ok(())
    }

    pub fn reset_unsaved_base(&mut self) {
        self.pushed.current_mut().clear();
    }

    pub fn changes_path(&self) -> PathBuf {
        self.db_path()
            .join("changes")
            .join(vec_region_name(&self.name, I::to_string()))
    }

    pub fn serialize_changes(
        &self,
        size_of_t: usize,
        collect_stored: impl FnOnce(usize, usize) -> Result<Vec<T>>,
        write_values: impl Fn(&[T], &mut Vec<u8>),
    ) -> Result<Vec<u8>> {
        let prev_stored_len = self.prev_stored_len();
        let stored_len = self.stored_len();
        let truncated = prev_stored_len.saturating_sub(stored_len);

        let value_count = truncated + self.prev_pushed().len() + self.pushed().len();
        let mut bytes = Vec::with_capacity(6 * SIZE_OF_U64 + value_count * size_of_t);

        bytes.extend(self.header.stamp().to_bytes());
        bytes.extend(prev_stored_len.to_bytes());
        bytes.extend(stored_len.to_bytes());
        bytes.extend(truncated.to_bytes());

        if truncated > 0 {
            let truncated_vals = collect_stored(stored_len, prev_stored_len)?;
            write_values(&truncated_vals, &mut bytes);
        }

        bytes.extend(self.prev_pushed().len().to_bytes());
        write_values(self.prev_pushed(), &mut bytes);

        bytes.extend(self.pushed().len().to_bytes());
        write_values(self.pushed(), &mut bytes);

        Ok(bytes)
    }

    /// Caller must check `saved_stamped_changes > 0` before calling.
    pub fn save_change_file(&self, stamp: Stamp, data: &[u8]) -> Result<()> {
        debug_assert!(self.saved_stamped_changes > 0);
        let path = self.changes_path();
        fs::create_dir_all(&path)?;

        let files: BTreeMap<Stamp, PathBuf> = fs::read_dir(&path)?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let s = Stamp::from(path.file_name()?.to_str()?.parse::<u64>().ok()?);
                if s < stamp {
                    Some((s, path))
                } else {
                    let _ = fs::remove_file(&path);
                    None
                }
            })
            .collect();

        let excess = files
            .len()
            .saturating_sub(self.saved_stamped_changes as usize - 1);
        for (_, path) in files.iter().take(excess) {
            fs::remove_file(path)?;
        }

        fs::write(path.join(u64::from(stamp).to_string()), data)?;
        Ok(())
    }

    pub fn save_prev(&mut self) {
        self.previous_stored_len = self.stored_len();
        self.pushed.previous_mut().clear();
    }

    pub fn save_prev_for_rollback(&mut self) {
        self.previous_stored_len = self.stored_len();
        self.pushed.save();
    }

    pub fn read_current_change_file(&self) -> Result<Vec<u8>> {
        let path = self
            .changes_path()
            .join(u64::from(self.header.stamp()).to_string());
        Ok(fs::read(path)?)
    }

    pub fn find_rollback_files(&self) -> Result<BTreeMap<Stamp, PathBuf>> {
        Ok(fs::read_dir(self.changes_path())?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                let stamp = Stamp::from(path.file_name()?.to_str()?.parse::<u64>().ok()?);
                Some((stamp, path))
            })
            .collect())
    }

    /// Returns `Error::Overflow` on arithmetic overflow,
    /// `Error::WrongLength` if the data is truncated.
    pub fn parse_change_data(
        bytes: &[u8],
        size_of_t: usize,
        read_value: impl Fn(&[u8]) -> Result<T>,
    ) -> Result<ChangeData<T>> {
        let mut pos = 0;
        let mut len = SIZE_OF_U64;

        check_bounds(bytes, pos, len)?;
        let prev_stamp = Stamp::from_bytes(&bytes[pos..pos + len])?;
        pos += len;

        check_bounds(bytes, pos, len)?;
        let prev_stored_len = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;

        // stored_len (skip, not needed for rollback)
        check_bounds(bytes, pos, len)?;
        pos += len;

        check_bounds(bytes, pos, len)?;
        let truncated_count = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;

        let truncated_start = prev_stored_len
            .checked_sub(truncated_count)
            .ok_or(Error::Underflow)?;

        let truncated_values = if truncated_count > 0 {
            len = size_of_t
                .checked_mul(truncated_count)
                .ok_or(Error::Overflow)?;
            check_bounds(bytes, pos, len)?;
            let vals = bytes[pos..pos + len]
                .chunks(size_of_t)
                .map(&read_value)
                .collect::<Result<Vec<_>>>()?;
            pos += len;
            vals
        } else {
            vec![]
        };

        len = SIZE_OF_U64;
        check_bounds(bytes, pos, len)?;
        let prev_pushed_len = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;
        len = size_of_t
            .checked_mul(prev_pushed_len)
            .ok_or(Error::Overflow)?;
        check_bounds(bytes, pos, len)?;
        let prev_pushed = bytes[pos..pos + len]
            .chunks(size_of_t)
            .map(&read_value)
            .collect::<Result<Vec<_>>>()?;
        pos += len;

        len = SIZE_OF_U64;
        check_bounds(bytes, pos, len)?;
        let pushed_len = usize::from_bytes(&bytes[pos..pos + len])?;
        pos += len;
        // Skip current pushed values (we already have prev_pushed)
        let skip = size_of_t.checked_mul(pushed_len).ok_or(Error::Overflow)?;
        check_bounds(bytes, pos, skip)?;
        pos += skip;

        Ok(ChangeData {
            prev_stamp,
            prev_stored_len,
            truncated_start,
            truncated_values,
            prev_pushed,
            bytes_consumed: pos,
        })
    }

    /// Caller handles type-specific truncation BEFORE calling this.
    pub fn apply_rollback(&mut self, data: &ChangeData<T>) {
        self.read_only.header.update_stamp(data.prev_stamp);
        self.read_only.stored_len.set(data.prev_stored_len);

        // Clone into current, then save() copies current→previous (reuses both allocations)
        self.pushed.current_mut().clone_from(&data.prev_pushed);
        self.pushed.save();
    }
}

/// Parsed change data returned by parse_change_data, consumed by apply_rollback.
#[derive(Debug)]
pub(crate) struct ChangeData<T> {
    pub prev_stamp: Stamp,
    pub prev_stored_len: usize,
    pub truncated_start: usize,
    pub truncated_values: Vec<T>,
    pub prev_pushed: Vec<T>,
    pub bytes_consumed: usize,
}

pub(crate) fn check_bounds(bytes: &[u8], pos: usize, len: usize) -> Result<()> {
    let end = pos.checked_add(len).ok_or(Error::Overflow)?;
    if end > bytes.len() {
        return Err(Error::WrongLength {
            received: bytes.len(),
            expected: end,
        });
    }
    Ok(())
}

pub fn vec_region_name_with<I: VecIndex>(name: &str) -> String {
    vec_region_name(name, I::to_string())
}

pub fn vec_region_name(name: &str, index: &str) -> String {
    format!("{name}/{index}")
}
