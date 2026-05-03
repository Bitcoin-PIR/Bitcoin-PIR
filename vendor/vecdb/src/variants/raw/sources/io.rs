use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
};

use parking_lot::RwLockReadGuard;
use rawdb::{Region, RegionMetadata};

use crate::{AnyStoredVec, BUFFER_SIZE, HEADER_OFFSET, VecIndex, VecValue, likely};

use super::super::{RawStrategy, ReadWriteRawVec};

/// Buffer size aligned to SIZE_OF_T for raw I/O reads.
const fn aligned_buffer_size<T>() -> usize {
    let size_of_t = size_of::<T>();
    (BUFFER_SIZE / size_of_t) * size_of_t
}

/// Buffered file I/O source for reading stored data sequentially.
///
/// Better than mmap for very large sequential scans (>4 GiB). Uses a dedicated
/// file handle with OS readahead. Only sees stored (persisted) values.
pub struct RawIoSource<'a, I, T, S> {
    file: File,
    buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_len: usize,
    file_offset: usize,
    end_offset: usize,
    _lock: RwLockReadGuard<'a, RegionMetadata>,
    _marker: PhantomData<(I, T, S)>,
}

impl<'a, I, T, S> RawIoSource<'a, I, T, S>
where
    I: VecIndex,
    T: VecValue,
    S: RawStrategy<T>,
{
    const SIZE_OF_T: usize = size_of::<T>();
    const NORMAL_BUFFER_SIZE: usize = aligned_buffer_size::<T>();

    pub(crate) fn new(vec: &'a ReadWriteRawVec<I, T, S>, from: usize, to: usize) -> Self {
        Self::new_from_parts(vec.region(), vec.stored_len(), from, to)
    }

    pub(crate) fn new_from_parts(
        region: &'a Region,
        stored_len: usize,
        from: usize,
        to: usize,
    ) -> Self {
        let file = region.open_db_read_only_file().expect("open file");
        let region_meta = region.meta();
        let region_start = region_meta.start();
        let start_offset = region_start + HEADER_OFFSET;
        let from = from.min(stored_len);
        let to = to.min(stored_len);

        let from_offset = start_offset + from * Self::SIZE_OF_T;
        let end_offset = start_offset + to * Self::SIZE_OF_T;

        let mut this = Self {
            file,
            buffer: vec![0; Self::NORMAL_BUFFER_SIZE],
            buffer_pos: 0,
            buffer_len: 0,
            file_offset: from_offset,
            end_offset,
            _lock: region_meta,
            _marker: PhantomData,
        };

        if likely(this.can_read_file()) {
            this.file
                .seek(SeekFrom::Start(from_offset as u64))
                .expect("Failed to seek");
        }

        this
    }

    #[inline(always)]
    fn can_read_file(&self) -> bool {
        self.file_offset < self.end_offset
    }

    #[inline(always)]
    fn cant_read_file(&self) -> bool {
        self.file_offset >= self.end_offset
    }

    #[inline(always)]
    fn remaining_file_bytes(&self) -> usize {
        self.end_offset - self.file_offset
    }

    #[inline(always)]
    fn refill_buffer(&mut self) {
        let buffer_len = self.remaining_file_bytes().min(Self::NORMAL_BUFFER_SIZE);
        self.file
            .read_exact(&mut self.buffer[..buffer_len])
            .expect("Failed to read file buffer");
        self.file_offset += buffer_len;
        self.buffer_len = buffer_len;
        self.buffer_pos = 0;
    }

    /// Fold all remaining elements — own implementation so LLVM can vectorize the inner loop.
    #[inline(always)]
    pub(crate) fn fold<B, F: FnMut(B, T) -> B>(mut self, init: B, mut f: F) -> B {
        let mut accum = init;
        loop {
            let ptr = self.buffer.as_ptr();
            let mut pos = self.buffer_pos;
            let end = self.buffer_len;
            while pos + Self::SIZE_OF_T <= end {
                accum = f(accum, unsafe { S::read_from_ptr(ptr, pos) });
                pos += Self::SIZE_OF_T;
            }
            self.buffer_pos = end;

            if self.cant_read_file() {
                break;
            }
            self.refill_buffer();
        }
        accum
    }

    /// Fallible fold with early exit on error.
    #[inline(always)]
    pub(crate) fn try_fold<B, E, F: FnMut(B, T) -> std::result::Result<B, E>>(
        mut self,
        init: B,
        mut f: F,
    ) -> std::result::Result<B, E> {
        let mut accum = init;
        loop {
            let ptr = self.buffer.as_ptr();
            let mut pos = self.buffer_pos;
            let end = self.buffer_len;
            while pos + Self::SIZE_OF_T <= end {
                accum = f(accum, unsafe { S::read_from_ptr(ptr, pos) })?;
                pos += Self::SIZE_OF_T;
            }
            self.buffer_pos = end;

            if self.cant_read_file() {
                break;
            }
            self.refill_buffer();
        }
        Ok(accum)
    }
}
