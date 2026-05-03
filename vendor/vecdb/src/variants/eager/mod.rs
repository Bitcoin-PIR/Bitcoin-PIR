use std::{collections::BTreeMap, fmt::Debug, path::PathBuf};

use log::info;
use rawdb::{Database, Region};

mod aggregates;
mod arithmetic;
mod checked_sub;
mod cumulative;
mod lookback;
mod saturating_add;
mod statistics;
mod transforms;

pub use checked_sub::*;
pub use saturating_add::*;

use crate::{
    AnyStoredVec, AnyVec, Exit, Header, ImportOptions, ImportableVec, ReadableBoxedVec,
    ReadableCloneableVec, ReadableVec, Result, Stamp, StoredVec, TypedVec, Version, WritableVec,
    traits::writable::MAX_CACHE_SIZE,
};

/// Wrapper for computing and storing derived values from source vectors.
///
/// `EagerVec` wraps any `StoredVec` and provides computation methods to derive and persist
/// calculated values. Results are stored on disk and automatically recomputed when:
/// - Source data versions change
/// - The vector's computation logic version changes
///
/// # Key Features
/// - **Incremental Updates**: Only computes missing values, not the entire dataset
/// - **Automatic Versioning**: Detects stale data and recomputes automatically
/// - **Batched Writes**: Flushes periodically to prevent excessive memory usage
///
/// # Common Operations
/// - Transformations: `compute_transform()`, `compute_range()`
/// - Arithmetic: `compute_add()`, `compute_subtract()`, `compute_multiply()`, `compute_divide()`
/// - Moving statistics: `compute_sma()`, `compute_ema()`, `compute_sum()`, `compute_max()`, `compute_min()`
/// - Lookback calculations: `compute_change()`, `compute_percentage_change()`
#[derive(Debug)]
#[must_use = "Vector should be stored to keep data accessible"]
pub struct EagerVec<V>(V);

impl<V: ImportableVec> ImportableVec for EagerVec<V> {
    fn import(db: &Database, name: &str, version: Version) -> Result<Self> {
        Ok(Self(V::import(db, name, version)?))
    }

    fn import_with(options: ImportOptions) -> Result<Self> {
        Ok(Self(V::import_with(options)?))
    }

    fn forced_import(db: &Database, name: &str, version: Version) -> Result<Self> {
        Ok(Self(V::forced_import(db, name, version)?))
    }

    fn forced_import_with(options: ImportOptions) -> Result<Self> {
        Ok(Self(V::forced_import_with(options)?))
    }
}

impl<V> EagerVec<V>
where
    V: StoredVec,
{
    /// Validates version, truncates to `max_from`, then runs `f` in batched writes.
    fn compute_init<F>(&mut self, version: Version, max_from: V::I, exit: &Exit, f: F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()>,
    {
        self.validate_computed_version_or_reset(version)?;
        self.truncate_if_needed(max_from)?;
        self.repeat_until_complete(exit, f)
    }

    /// Max end index for one batch, capped at `max_end`.
    /// Ensures `pushed_len * SIZE_OF_T >= MAX_CACHE_SIZE` so `batch_limit_reached()` fires.
    #[inline]
    pub fn batch_end(&self, max_end: usize) -> usize {
        let size = size_of::<V::T>().max(1);
        let cap = MAX_CACHE_SIZE.div_ceil(size);
        (self.len() + cap).min(max_end)
    }

    /// Helper that repeatedly calls a compute function until it completes.
    /// Writes between iterations when batch limit is hit.
    pub fn repeat_until_complete<F>(&mut self, exit: &Exit, mut f: F) -> Result<()>
    where
        F: FnMut(&mut Self) -> Result<()>,
    {
        loop {
            f(self)?;
            let batch_limit_reached = self.batch_limit_reached();
            if batch_limit_reached {
                info!("Batch limit reached, saving to disk...");
            }
            if self.is_dirty() {
                let _lock = exit.lock();
                self.write()?;
            }
            if !batch_limit_reached {
                break;
            }
        }

        Ok(())
    }

    /// Removes this vector and all its associated regions from the database
    pub fn remove(self) -> Result<()> {
        self.0.remove()
    }
}

impl<V> AnyVec for EagerVec<V>
where
    V: StoredVec,
{
    #[inline]
    fn version(&self) -> Version {
        self.0.header().computed_version()
    }

    #[inline]
    fn name(&self) -> &str {
        self.0.name()
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn index_type_to_string(&self) -> &'static str {
        self.0.index_type_to_string()
    }

    #[inline]
    fn value_type_to_size_of(&self) -> usize {
        self.0.value_type_to_size_of()
    }

    #[inline]
    fn value_type_to_string(&self) -> &'static str {
        self.0.value_type_to_string()
    }

    #[inline]
    fn region_names(&self) -> Vec<String> {
        self.0.region_names()
    }
}

impl<V> AnyStoredVec for EagerVec<V>
where
    V: StoredVec,
{
    #[inline]
    fn db_path(&self) -> PathBuf {
        self.0.db_path()
    }

    #[inline]
    fn region(&self) -> &Region {
        self.0.region()
    }

    #[inline]
    fn header(&self) -> &Header {
        self.0.header()
    }

    #[inline]
    fn mut_header(&mut self) -> &mut Header {
        self.0.mut_header()
    }

    #[inline]
    fn saved_stamped_changes(&self) -> u16 {
        self.0.saved_stamped_changes()
    }

    #[inline]
    fn write(&mut self) -> Result<bool> {
        self.0.write()
    }

    #[inline]
    fn stored_len(&self) -> usize {
        self.0.stored_len()
    }

    #[inline]
    fn real_stored_len(&self) -> usize {
        self.0.real_stored_len()
    }

    #[inline]
    fn serialize_changes(&self) -> Result<Vec<u8>> {
        self.0.serialize_changes()
    }

    #[inline]
    fn db(&self) -> Database {
        self.0.db()
    }

    fn any_stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()> {
        self.0.stamped_write_with_changes(stamp)
    }

    fn remove(self) -> Result<()> {
        self.0.remove()
    }

    fn any_truncate_if_needed_at(&mut self, index: usize) -> Result<()> {
        self.truncate_if_needed_at(index)
    }

    fn any_reset(&mut self) -> Result<()> {
        self.reset()
    }
}

impl<V> WritableVec<V::I, V::T> for EagerVec<V>
where
    V: StoredVec,
{
    #[inline]
    fn push(&mut self, value: V::T) {
        self.0.push(value);
    }

    #[inline]
    fn pushed(&self) -> &[V::T] {
        self.0.pushed()
    }

    #[inline]
    fn truncate_if_needed_at(&mut self, index: usize) -> Result<()> {
        self.0.truncate_if_needed_at(index)
    }

    #[inline]
    fn reset(&mut self) -> Result<()> {
        self.0.reset()
    }

    #[inline]
    fn reset_unsaved(&mut self) {
        self.0.reset_unsaved()
    }

    #[inline]
    fn is_dirty(&self) -> bool {
        self.0.is_dirty()
    }

    #[inline]
    fn stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()> {
        self.0.stamped_write_with_changes(stamp)
    }

    #[inline]
    fn rollback(&mut self) -> Result<()> {
        self.0.rollback()
    }

    fn find_rollback_files(&self) -> Result<BTreeMap<Stamp, PathBuf>> {
        self.0.find_rollback_files()
    }

    fn save_rollback_state(&mut self) {
        self.0.save_rollback_state()
    }
}

impl<V> ReadableVec<V::I, V::T> for EagerVec<V>
where
    V: StoredVec,
{
    #[inline(always)]
    fn collect_one_at(&self, index: usize) -> Option<V::T> {
        self.0.collect_one_at(index)
    }

    #[inline(always)]
    fn read_into_at(&self, from: usize, to: usize, buf: &mut Vec<V::T>) {
        self.0.read_into_at(from, to, buf)
    }

    #[inline]
    fn for_each_range_dyn_at(&self, from: usize, to: usize, f: &mut dyn FnMut(V::T)) {
        self.0.for_each_range_dyn_at(from, to, f)
    }

    #[inline]
    fn fold_range_at<B, F: FnMut(B, V::T) -> B>(&self, from: usize, to: usize, init: B, f: F) -> B
    where
        Self: Sized,
    {
        self.0.fold_range_at(from, to, init, f)
    }

    #[inline]
    fn try_fold_range_at<B, E, F: FnMut(B, V::T) -> std::result::Result<B, E>>(
        &self,
        from: usize,
        to: usize,
        init: B,
        f: F,
    ) -> std::result::Result<B, E>
    where
        Self: Sized,
    {
        self.0.try_fold_range_at(from, to, init, f)
    }
}

impl<V> ReadableCloneableVec<V::I, V::T> for EagerVec<V>
where
    V: StoredVec,
{
    #[inline]
    fn read_only_boxed_clone(&self) -> ReadableBoxedVec<V::I, V::T> {
        self.0.read_only_boxed_clone()
    }
}

impl<V> StoredVec for EagerVec<V>
where
    V: StoredVec,
{
    type ReadOnly = V::ReadOnly;

    #[inline]
    fn read_only_clone(&self) -> Self::ReadOnly {
        self.0.read_only_clone()
    }
}

impl<V> TypedVec for EagerVec<V>
where
    V: StoredVec,
{
    type I = V::I;
    type T = V::T;
}
