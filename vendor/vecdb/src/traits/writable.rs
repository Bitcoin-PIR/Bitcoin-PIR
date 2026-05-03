use std::{collections::BTreeMap, path::PathBuf};

use log::info;
use rawdb::unlikely;

use crate::{AnyStoredVec, Error, Result, Stamp, VecIndex, VecValue, Version};

/// Maximum in-memory cache size before forcing a flush (1 GiB).
/// Prevents unbounded memory growth when pushing many values without flushing.
pub(crate) const MAX_CACHE_SIZE: usize = 1024 * 1024 * 1024;

/// Typed interface for stored vectors (push, truncate, rollback).
///
/// Provides the core write operations for all stored vec types.
/// For reading, use [`ReadableVec`] (`collect_range`, `fold_range`, etc.).
/// Raw vecs (`BytesVec`, `ZeroCopyVec`) additionally provide
/// `VecReader` for O(1) random access.
///
/// [`ReadableVec`]: crate::ReadableVec
pub trait WritableVec<I, T>: AnyStoredVec
where
    I: VecIndex,
    T: VecValue,
{
    const SIZE_OF_T: usize = size_of::<T>();

    fn push(&mut self, value: T);

    /// Returns the current pushed (uncommitted) values.
    fn pushed(&self) -> &[T];

    /// Truncates the vector to the given usize index if the current length exceeds it.
    fn truncate_if_needed_at(&mut self, index: usize) -> Result<()>;

    /// Resets the vector state.
    fn reset(&mut self) -> Result<()>;

    /// Resets uncommitted changes.
    fn reset_unsaved(&mut self);

    /// Returns true if there are uncommitted changes.
    fn is_dirty(&self) -> bool;

    /// Flushes with the given stamp, saving changes to enable rollback.
    fn stamped_write_with_changes(&mut self, stamp: Stamp) -> Result<()>;

    /// Rolls back the most recent change set.
    fn rollback(&mut self) -> Result<()>;

    /// Returns available rollback change files.
    #[doc(hidden)]
    fn find_rollback_files(&self) -> Result<BTreeMap<Stamp, PathBuf>>;

    /// Saves type-specific rollback state after the rollback loop completes.
    #[doc(hidden)]
    fn save_rollback_state(&mut self);

    /// Rolls back changes to before the given stamp.
    fn rollback_before(&mut self, stamp: Stamp) -> Result<Stamp> {
        let mut current = self.stamp();
        if current < stamp {
            return Ok(current);
        }

        let files = self.find_rollback_files()?;
        let mut iter = files.range(..=current);

        while let Some((&s, _)) = iter.next_back() {
            current = self.stamp();
            if current < stamp {
                break;
            }
            if s != current {
                return Err(Error::StampMismatch {
                    file: s,
                    vec: current,
                });
            }
            self.rollback()?;
        }

        self.save_rollback_state();

        Ok(self.stamp())
    }

    /// Number of pushed (uncommitted) values in the memory buffer.
    #[inline]
    fn pushed_len(&self) -> usize {
        self.pushed().len()
    }

    /// Returns true if there are no pushed (uncommitted) values.
    #[inline]
    fn is_pushed_empty(&self) -> bool {
        self.pushed_len() == 0
    }

    /// Returns true if the typed index is within bounds.
    #[inline]
    fn has(&self, index: I) -> bool {
        self.has_at(index.to_usize())
    }

    /// Returns true if the usize index is within bounds.
    #[inline]
    fn has_at(&self, index: usize) -> bool {
        index < self.len()
    }

    /// Pushes a value at the given index, erroring if index != current length.
    /// Use this when you expect to always append in order.
    #[inline]
    fn checked_push(&mut self, index: I, value: T) -> Result<()> {
        self.checked_push_at(index.to_usize(), value)
    }

    /// Pushes a value at the given usize index, erroring if index != current length.
    /// Use this when you expect to always append in order.
    #[inline]
    fn checked_push_at(&mut self, index: usize, value: T) -> Result<()> {
        let len = self.len();

        if unlikely(index != len) {
            return Err(Error::UnexpectedIndex {
                expected: len,
                got: index,
                name: self.name().to_string(),
            });
        }

        self.push(value);
        Ok(())
    }

    /// Truncates the vector to the given index if the current length exceeds it.
    fn truncate_if_needed(&mut self, index: I) -> Result<()> {
        self.truncate_if_needed_at(index.to_usize())
    }

    /// Truncates the vector to the given index if needed, updating the stamp.
    #[inline]
    fn truncate_if_needed_with_stamp(&mut self, index: I, stamp: Stamp) -> Result<()> {
        self.update_stamp(stamp);
        self.truncate_if_needed(index)
    }

    /// Clears all values from the vector.
    #[inline]
    fn clear(&mut self) -> Result<()> {
        self.truncate_if_needed_at(0)
    }

    /// Returns true if the pushed cache has reached the batch limit (~1GiB).
    ///
    /// When this limit is reached, the caller should flush to disk before continuing.
    /// This prevents excessive memory usage during bulk operations.
    #[inline]
    fn batch_limit_reached(&self) -> bool {
        self.pushed_len() * Self::SIZE_OF_T >= MAX_CACHE_SIZE
    }

    /// Extends the vector to `target_len`, filling with `value`.
    /// Batches writes in ~1GB chunks to avoid memory explosion.
    fn fill_to(&mut self, target_len: usize, value: T) -> Result<()>
    where
        T: Copy,
    {
        let batch_count = MAX_CACHE_SIZE / Self::SIZE_OF_T.max(1);

        while self.len() < target_len {
            let count = (target_len - self.len()).min(batch_count);
            for _ in 0..count {
                self.push(value);
            }
            if self.batch_limit_reached() {
                self.write()?;
            }
        }
        Ok(())
    }

    /// Flushes with the given stamp, optionally saving changes for rollback.
    #[inline]
    fn stamped_write_maybe_with_changes(&mut self, stamp: Stamp, with_changes: bool) -> Result<()> {
        if with_changes {
            self.stamped_write_with_changes(stamp)
        } else {
            self.stamped_write(stamp)
        }
    }

    /// Validates the computed version against the stored version, resetting if they don't match.
    /// Automatically includes the vec's own version - only pass dependency versions.
    fn validate_computed_version_or_reset(&mut self, dep_version: Version) -> Result<()> {
        let version = self.header().vec_version() + dep_version;
        if version != self.header().computed_version() {
            self.mut_header().update_computed_version(version);
            if !self.is_empty() {
                self.reset()?;
            }
        }

        if self.is_empty() {
            info!(
                "Computing {}_to_{}...",
                self.index_type_to_string(),
                self.name()
            )
        }

        Ok(())
    }

    /// Validates computed version and truncates to `max_from` in one call.
    ///
    /// Equivalent to:
    /// ```ignore
    /// vec.validate_computed_version_or_reset(dep_version)?;
    /// vec.truncate_if_needed(max_from)?;
    /// ```
    fn validate_and_truncate(&mut self, dep_version: Version, max_from: I) -> Result<()> {
        self.validate_computed_version_or_reset(dep_version)?;
        self.truncate_if_needed(max_from)
    }
}
