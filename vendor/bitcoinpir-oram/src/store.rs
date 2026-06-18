use crate::{Error, Result, TieredMerkleState};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

/// Fixed-size page storage used by the ORAM bucket layer.
pub trait PageStore {
    /// Size in bytes of one page.
    fn page_size(&self) -> usize;

    /// Number of pages.
    fn page_count(&self) -> usize;

    /// Read a page into `out`.
    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()>;

    /// Write a page from `input`.
    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()>;

    /// Flush durable storage. In-memory implementations may no-op.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Return trusted authentication state for wrappers that maintain one.
    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        None
    }
}

impl<T: PageStore + ?Sized> PageStore for Box<T> {
    fn page_size(&self) -> usize {
        (**self).page_size()
    }

    fn page_count(&self) -> usize {
        (**self).page_count()
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        (**self).read_page(page_idx, out)
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        (**self).write_page(page_idx, input)
    }

    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }

    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        (**self).tiered_merkle_state()
    }
}

/// In-memory page store for tests and microbenchmarks.
#[derive(Debug)]
pub struct MemPageStore {
    page_size: usize,
    pages: Vec<u8>,
}

impl MemPageStore {
    /// Create a zero-filled in-memory store.
    pub fn new(page_count: usize, page_size: usize) -> Result<Self> {
        if page_count == 0 || page_size == 0 {
            return Err(Error::InvalidInput(
                "page_count and page_size must be > 0".into(),
            ));
        }
        Ok(Self {
            page_size,
            pages: vec![0; page_count * page_size],
        })
    }
}

impl PageStore for MemPageStore {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn page_count(&self) -> usize {
        self.pages.len() / self.page_size
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        check_page(self, page_idx, out.len())?;
        let start = page_idx * self.page_size;
        out.copy_from_slice(&self.pages[start..start + self.page_size]);
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        check_page(self, page_idx, input.len())?;
        let start = page_idx * self.page_size;
        self.pages[start..start + self.page_size].copy_from_slice(input);
        Ok(())
    }
}

/// File-backed fixed-size page store.
#[derive(Debug)]
pub struct FilePageStore {
    page_size: usize,
    page_count: usize,
    file: File,
}

impl FilePageStore {
    /// Open or create a fixed-size page file.
    ///
    /// Existing contents are preserved if the file already has the requested
    /// length. Otherwise the file is resized and newly allocated bytes are zero.
    pub fn open(path: impl AsRef<Path>, page_count: usize, page_size: usize) -> Result<Self> {
        if page_count == 0 || page_size == 0 {
            return Err(Error::InvalidInput(
                "page_count and page_size must be > 0".into(),
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.set_len((page_count * page_size) as u64)?;
        Ok(Self {
            page_size,
            page_count,
            file,
        })
    }

    fn offset(&self, page_idx: usize) -> Result<u64> {
        if page_idx >= self.page_count {
            return Err(Error::InvalidInput(format!(
                "page_idx {} out of range {}",
                page_idx, self.page_count
            )));
        }
        Ok((page_idx * self.page_size) as u64)
    }
}

impl PageStore for FilePageStore {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn page_count(&self) -> usize {
        self.page_count
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        check_page(self, page_idx, out.len())?;
        self.file.seek(SeekFrom::Start(self.offset(page_idx)?))?;
        self.file.read_exact(out)?;
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        check_page(self, page_idx, input.len())?;
        self.file.seek(SeekFrom::Start(self.offset(page_idx)?))?;
        self.file.write_all(input)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

/// Fixed-prefix page cache for keeping public top tree levels in trusted RAM.
///
/// This cache is intentionally simple: it caches pages `[0, cached_pages)`.
/// For heap-array ORAM bucket layouts those are the root-adjacent tree levels.
/// Because the cached set is a public fixed prefix, cache hits are not
/// secret-dependent.
#[derive(Debug)]
pub struct FrontCachedPageStore<S> {
    inner: S,
    cached_pages: usize,
    page_size: usize,
    cached: Vec<u8>,
    dirty: Vec<bool>,
}

impl<S: PageStore> FrontCachedPageStore<S> {
    /// Load the first `cached_pages` pages into memory.
    pub fn new(mut inner: S, cached_pages: usize) -> Result<Self> {
        if cached_pages > inner.page_count() {
            return Err(Error::InvalidInput(format!(
                "cached_pages {} > page_count {}",
                cached_pages,
                inner.page_count()
            )));
        }
        let page_size = inner.page_size();
        let mut cached = vec![0u8; cached_pages * page_size];
        for page_idx in 0..cached_pages {
            let start = page_idx * page_size;
            inner.read_page(page_idx, &mut cached[start..start + page_size])?;
        }
        Ok(Self {
            inner,
            cached_pages,
            page_size,
            cached,
            dirty: vec![false; cached_pages],
        })
    }

    /// Create a zero-filled front cache without reading from the inner store.
    ///
    /// Use this only when the caller is about to initialize every cached page
    /// before any read. This is useful for creating a fresh encrypted image,
    /// where reading all-zero physical pages would fail authentication.
    pub fn new_zeroed(inner: S, cached_pages: usize) -> Result<Self> {
        if cached_pages > inner.page_count() {
            return Err(Error::InvalidInput(format!(
                "cached_pages {} > page_count {}",
                cached_pages,
                inner.page_count()
            )));
        }
        let page_size = inner.page_size();
        Ok(Self {
            inner,
            cached_pages,
            page_size,
            cached: vec![0u8; cached_pages * page_size],
            dirty: vec![false; cached_pages],
        })
    }

    /// Number of cached front pages.
    pub fn cached_pages(&self) -> usize {
        self.cached_pages
    }

    /// Consume the wrapper.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn cached_range(&self, page_idx: usize) -> std::ops::Range<usize> {
        let start = page_idx * self.page_size;
        start..start + self.page_size
    }
}

impl<S: PageStore> PageStore for FrontCachedPageStore<S> {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn page_count(&self) -> usize {
        self.inner.page_count()
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        check_page(self, page_idx, out.len())?;
        if page_idx < self.cached_pages {
            out.copy_from_slice(&self.cached[self.cached_range(page_idx)]);
            Ok(())
        } else {
            self.inner.read_page(page_idx, out)
        }
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        check_page(self, page_idx, input.len())?;
        if page_idx < self.cached_pages {
            let range = self.cached_range(page_idx);
            self.cached[range].copy_from_slice(input);
            self.dirty[page_idx] = true;
            Ok(())
        } else {
            self.inner.write_page(page_idx, input)
        }
    }

    fn flush(&mut self) -> Result<()> {
        for page_idx in 0..self.cached_pages {
            if self.dirty[page_idx] {
                let range = self.cached_range(page_idx);
                self.inner.write_page(page_idx, &self.cached[range])?;
                self.dirty[page_idx] = false;
            }
        }
        self.inner.flush()
    }
}

/// A wrapper that records page access traces for tests.
#[derive(Debug)]
pub struct TracingStore<S> {
    inner: S,
    trace: RefCell<Vec<TraceEvent>>,
}

/// One page access observed by the storage layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceEvent {
    /// Page read.
    Read(usize),
    /// Page write.
    Write(usize),
}

impl<S> TracingStore<S> {
    /// Wrap a page store.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            trace: RefCell::new(Vec::new()),
        }
    }

    /// Return and clear the trace.
    pub fn take_trace(&self) -> Vec<TraceEvent> {
        std::mem::take(&mut *self.trace.borrow_mut())
    }

    /// Consume the wrapper.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: PageStore> PageStore for TracingStore<S> {
    fn page_size(&self) -> usize {
        self.inner.page_size()
    }

    fn page_count(&self) -> usize {
        self.inner.page_count()
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        self.trace.borrow_mut().push(TraceEvent::Read(page_idx));
        self.inner.read_page(page_idx, out)
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        self.trace.borrow_mut().push(TraceEvent::Write(page_idx));
        self.inner.write_page(page_idx, input)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

fn check_page(store: &impl PageStore, page_idx: usize, len: usize) -> Result<()> {
    if page_idx >= store.page_count() {
        return Err(Error::InvalidInput(format!(
            "page_idx {} out of range {}",
            page_idx,
            store.page_count()
        )));
    }
    if len != store.page_size() {
        return Err(Error::InvalidInput(format!(
            "page buffer len {} != page_size {}",
            len,
            store.page_size()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn front_cache_serves_cached_prefix_and_flushes() {
        let mut inner = MemPageStore::new(4, 8).unwrap();
        inner.write_page(0, &[1; 8]).unwrap();
        inner.write_page(1, &[2; 8]).unwrap();
        inner.write_page(2, &[3; 8]).unwrap();

        let mut cached = FrontCachedPageStore::new(inner, 2).unwrap();
        assert_eq!(cached.cached_pages(), 2);

        cached.write_page(0, &[9; 8]).unwrap();
        cached.write_page(2, &[7; 8]).unwrap();

        let mut out = [0u8; 8];
        cached.read_page(0, &mut out).unwrap();
        assert_eq!(out, [9; 8]);
        cached.read_page(2, &mut out).unwrap();
        assert_eq!(out, [7; 8]);

        cached.flush().unwrap();
        let mut inner = cached.into_inner();
        inner.read_page(0, &mut out).unwrap();
        assert_eq!(out, [9; 8]);
        inner.read_page(2, &mut out).unwrap();
        assert_eq!(out, [7; 8]);
    }

    #[test]
    fn zeroed_front_cache_does_not_read_inner_on_create() {
        let inner = MemPageStore::new(2, 8).unwrap();
        let mut cached = FrontCachedPageStore::new_zeroed(inner, 1).unwrap();

        let mut out = [99u8; 8];
        cached.read_page(0, &mut out).unwrap();
        assert_eq!(out, [0; 8]);
    }
}
