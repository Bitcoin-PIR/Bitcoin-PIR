use crate::{EmbeddedTreeState, Error, Result, TieredMerkleState};
use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::FileExt,
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

    /// Read multiple pages, returning them in the caller's requested order.
    fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
        let page_size = self.page_size();
        let mut pages = Vec::with_capacity(page_indices.len());
        for &page_idx in page_indices {
            let mut page = vec![0u8; page_size];
            self.read_page(page_idx, &mut page)?;
            pages.push(page);
        }
        Ok(pages)
    }

    /// Write multiple pages from caller-provided page bytes.
    fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        if page_indices.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "page index count {} != page count {}",
                page_indices.len(),
                pages.len()
            )));
        }
        let page_size = self.page_size();
        for (&page_idx, page) in page_indices.iter().zip(pages) {
            if page.len() != page_size {
                return Err(Error::InvalidInput(format!(
                    "page len {} != page_size {}",
                    page.len(),
                    page_size
                )));
            }
            self.write_page(page_idx, page)?;
        }
        Ok(())
    }

    /// Flush durable storage. In-memory implementations may no-op.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Return trusted authentication state for wrappers that maintain one.
    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        None
    }
}

/// Path-level page storage used by Circuit ORAM access/eviction.
///
/// The fallback implementation for ordinary [`PageStore`] values loops over
/// individual pages. Authenticated tree layouts can implement this directly to
/// verify and update whole root-to-leaf paths without separate sibling-hash IO.
pub trait PathPageStore {
    /// Logical page size exposed to the ORAM controller.
    fn page_size(&self) -> usize;

    /// Number of logical pages.
    fn page_count(&self) -> usize;

    /// Read a public root-to-leaf path as logical page bytes.
    fn read_path_pages(&mut self, path: &[usize]) -> Result<Vec<Vec<u8>>>;

    /// Write a public root-to-leaf path from logical page bytes.
    fn write_path_pages(&mut self, path: &[usize], pages: &[Vec<u8>]) -> Result<()>;

    /// Read multiple public paths, preserving caller path/page order.
    fn read_paths_pages(&mut self, paths: &[Vec<usize>]) -> Result<Vec<Vec<Vec<u8>>>> {
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            out.push(self.read_path_pages(path)?);
        }
        Ok(out)
    }

    /// Write multiple public paths, preserving caller path/page order.
    fn write_paths_pages(&mut self, paths: &[Vec<usize>], pages: &[Vec<Vec<u8>>]) -> Result<()> {
        if paths.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "path count {} != page-path count {}",
                paths.len(),
                pages.len()
            )));
        }
        for (path, path_pages) in paths.iter().zip(pages) {
            self.write_path_pages(path, path_pages)?;
        }
        Ok(())
    }

    /// Flush durable storage. In-memory implementations may no-op.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    /// Return trusted authentication state for wrappers that maintain one.
    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        None
    }

    /// Return trusted embedded-tree state for wrappers that maintain one.
    fn embedded_tree_state(&self) -> Option<EmbeddedTreeState> {
        None
    }
}

impl<T: PageStore + ?Sized> PathPageStore for T {
    fn page_size(&self) -> usize {
        PageStore::page_size(self)
    }

    fn page_count(&self) -> usize {
        PageStore::page_count(self)
    }

    fn read_path_pages(&mut self, path: &[usize]) -> Result<Vec<Vec<u8>>> {
        PageStore::read_pages(self, path)
    }

    fn write_path_pages(&mut self, path: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        PageStore::write_pages(self, path, pages)
    }

    fn read_paths_pages(&mut self, paths: &[Vec<usize>]) -> Result<Vec<Vec<Vec<u8>>>> {
        let total_pages = paths.iter().map(Vec::len).sum();
        let mut flat_path = Vec::with_capacity(total_pages);
        for path in paths {
            flat_path.extend_from_slice(path);
        }
        let flat_pages = PageStore::read_pages(self, &flat_path)?;
        let mut iter = flat_pages.into_iter();
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let mut path_pages = Vec::with_capacity(path.len());
            for _ in path {
                path_pages.push(iter.next().expect("flat page count matches path lengths"));
            }
            out.push(path_pages);
        }
        Ok(out)
    }

    fn write_paths_pages(&mut self, paths: &[Vec<usize>], pages: &[Vec<Vec<u8>>]) -> Result<()> {
        if paths.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "path count {} != page-path count {}",
                paths.len(),
                pages.len()
            )));
        }
        let total_pages = paths.iter().map(Vec::len).sum();
        let mut flat_path = Vec::with_capacity(total_pages);
        let mut flat_pages = Vec::with_capacity(total_pages);
        for (path, path_pages) in paths.iter().zip(pages) {
            if path.len() != path_pages.len() {
                return Err(Error::InvalidInput(format!(
                    "path length {} != page count {}",
                    path.len(),
                    path_pages.len()
                )));
            }
            flat_path.extend_from_slice(path);
            flat_pages.extend(path_pages.iter().cloned());
        }
        PageStore::write_pages(self, &flat_path, &flat_pages)
    }

    fn flush(&mut self) -> Result<()> {
        PageStore::flush(self)
    }

    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        PageStore::tiered_merkle_state(self)
    }

    fn embedded_tree_state(&self) -> Option<EmbeddedTreeState> {
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

    fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
        (**self).read_pages(page_indices)
    }

    fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        (**self).write_pages(page_indices, pages)
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
        read_exact_at(&self.file, out, self.offset(page_idx)?)?;
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        check_page(self, page_idx, input.len())?;
        write_all_at(&self.file, input, self.offset(page_idx)?)?;
        Ok(())
    }

    fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
        let page_size = self.page_size;
        let mut pages = vec![vec![0u8; page_size]; page_indices.len()];
        let mut order = page_order(page_indices);
        order.sort_by_key(|&pos| page_indices[pos]);

        let mut run_start = 0;
        while run_start < order.len() {
            let first_page = page_indices[order[run_start]];
            self.offset(first_page)?;
            let mut run_end = run_start + 1;
            while run_end < order.len() {
                let prev_page = page_indices[order[run_end - 1]];
                let next_page = page_indices[order[run_end]];
                if next_page != prev_page + 1 {
                    break;
                }
                self.offset(next_page)?;
                run_end += 1;
            }

            let run_pages = run_end - run_start;
            let mut run_buf = vec![0u8; run_pages * page_size];
            read_exact_at(&self.file, &mut run_buf, self.offset(first_page)?)?;
            for (run_pos, &original_pos) in order[run_start..run_end].iter().enumerate() {
                let start = run_pos * page_size;
                pages[original_pos].copy_from_slice(&run_buf[start..start + page_size]);
            }
            run_start = run_end;
        }

        Ok(pages)
    }

    fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        if page_indices.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "page index count {} != page count {}",
                page_indices.len(),
                pages.len()
            )));
        }
        for page in pages {
            if page.len() != self.page_size {
                return Err(Error::InvalidInput(format!(
                    "page len {} != page_size {}",
                    page.len(),
                    self.page_size
                )));
            }
        }

        let mut order = page_order(page_indices);
        order.sort_by_key(|&pos| page_indices[pos]);
        if has_duplicate_pages(page_indices, &order) {
            for (&page_idx, page) in page_indices.iter().zip(pages) {
                self.write_page(page_idx, page)?;
            }
            return Ok(());
        }

        let mut run_start = 0;
        while run_start < order.len() {
            let first_page = page_indices[order[run_start]];
            self.offset(first_page)?;
            let mut run_end = run_start + 1;
            while run_end < order.len() {
                let prev_page = page_indices[order[run_end - 1]];
                let next_page = page_indices[order[run_end]];
                if next_page != prev_page + 1 {
                    break;
                }
                self.offset(next_page)?;
                run_end += 1;
            }

            let mut run_buf = Vec::with_capacity((run_end - run_start) * self.page_size);
            for &original_pos in &order[run_start..run_end] {
                run_buf.extend_from_slice(&pages[original_pos]);
            }
            write_all_at(&self.file, &run_buf, self.offset(first_page)?)?;
            run_start = run_end;
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
}

fn page_order(page_indices: &[usize]) -> Vec<usize> {
    (0..page_indices.len()).collect()
}

fn has_duplicate_pages(page_indices: &[usize], sorted_order: &[usize]) -> bool {
    sorted_order
        .windows(2)
        .any(|window| page_indices[window[0]] == page_indices[window[1]])
}

fn read_exact_at(file: &File, mut out: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !out.is_empty() {
        let read = file.read_at(out, offset)?;
        if read == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "failed to fill whole page",
            ));
        }
        offset += read as u64;
        out = &mut out[read..];
    }
    Ok(())
}

fn write_all_at(file: &File, mut input: &[u8], mut offset: u64) -> io::Result<()> {
    while !input.is_empty() {
        let written = file.write_at(input, offset)?;
        if written == 0 {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "failed to write whole page",
            ));
        }
        offset += written as u64;
        input = &input[written..];
    }
    Ok(())
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
        if cached_pages > PageStore::page_count(&inner) {
            return Err(Error::InvalidInput(format!(
                "cached_pages {} > page_count {}",
                cached_pages,
                PageStore::page_count(&inner)
            )));
        }
        let page_size = PageStore::page_size(&inner);
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
        if cached_pages > PageStore::page_count(&inner) {
            return Err(Error::InvalidInput(format!(
                "cached_pages {} > page_count {}",
                cached_pages,
                PageStore::page_count(&inner)
            )));
        }
        let page_size = PageStore::page_size(&inner);
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
        PageStore::page_count(&self.inner)
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

    fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
        let mut pages = vec![vec![0u8; self.page_size]; page_indices.len()];
        let mut inner_positions = Vec::new();
        let mut inner_indices = Vec::new();
        let page_count = PageStore::page_count(self);

        for (pos, &page_idx) in page_indices.iter().enumerate() {
            if page_idx >= page_count {
                return Err(Error::InvalidInput(format!(
                    "page_idx {} out of range {}",
                    page_idx, page_count
                )));
            }
            if page_idx < self.cached_pages {
                pages[pos].copy_from_slice(&self.cached[self.cached_range(page_idx)]);
            } else {
                inner_positions.push(pos);
                inner_indices.push(page_idx);
            }
        }

        if !inner_indices.is_empty() {
            let inner_pages = self.inner.read_pages(&inner_indices)?;
            for (pos, page) in inner_positions.into_iter().zip(inner_pages) {
                pages[pos] = page;
            }
        }
        Ok(pages)
    }

    fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        if page_indices.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "page index count {} != page count {}",
                page_indices.len(),
                pages.len()
            )));
        }

        let mut inner_indices = Vec::new();
        let mut inner_pages = Vec::new();
        let page_count = PageStore::page_count(self);
        for (&page_idx, page) in page_indices.iter().zip(pages) {
            if page_idx >= page_count {
                return Err(Error::InvalidInput(format!(
                    "page_idx {} out of range {}",
                    page_idx, page_count
                )));
            }
            if page.len() != self.page_size {
                return Err(Error::InvalidInput(format!(
                    "page len {} != page_size {}",
                    page.len(),
                    self.page_size
                )));
            }
            if page_idx < self.cached_pages {
                let range = self.cached_range(page_idx);
                self.cached[range].copy_from_slice(page);
                self.dirty[page_idx] = true;
            } else {
                inner_indices.push(page_idx);
                inner_pages.push(page.clone());
            }
        }

        if !inner_indices.is_empty() {
            self.inner.write_pages(&inner_indices, &inner_pages)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        for page_idx in 0..self.cached_pages {
            if self.dirty[page_idx] {
                let range = self.cached_range(page_idx);
                self.inner.write_page(page_idx, &self.cached[range])?;
                self.dirty[page_idx] = false;
            }
        }
        PageStore::flush(&mut self.inner)
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
        PageStore::page_size(&self.inner)
    }

    fn page_count(&self) -> usize {
        PageStore::page_count(&self.inner)
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
        PageStore::flush(&mut self.inner)
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

    #[derive(Debug)]
    struct BulkCountingStore {
        inner: MemPageStore,
        read_page_calls: usize,
        write_page_calls: usize,
        read_pages_calls: usize,
        write_pages_calls: usize,
        last_read_pages: Vec<usize>,
        last_write_pages: Vec<usize>,
    }

    impl BulkCountingStore {
        fn new(inner: MemPageStore) -> Self {
            Self {
                inner,
                read_page_calls: 0,
                write_page_calls: 0,
                read_pages_calls: 0,
                write_pages_calls: 0,
                last_read_pages: Vec::new(),
                last_write_pages: Vec::new(),
            }
        }
    }

    impl PageStore for BulkCountingStore {
        fn page_size(&self) -> usize {
            PageStore::page_size(&self.inner)
        }

        fn page_count(&self) -> usize {
            PageStore::page_count(&self.inner)
        }

        fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
            self.read_page_calls += 1;
            self.inner.read_page(page_idx, out)
        }

        fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
            self.write_page_calls += 1;
            self.inner.write_page(page_idx, input)
        }

        fn read_pages(&mut self, page_indices: &[usize]) -> Result<Vec<Vec<u8>>> {
            self.read_pages_calls += 1;
            self.last_read_pages = page_indices.to_vec();
            self.inner.read_pages(page_indices)
        }

        fn write_pages(&mut self, page_indices: &[usize], pages: &[Vec<u8>]) -> Result<()> {
            self.write_pages_calls += 1;
            self.last_write_pages = page_indices.to_vec();
            self.inner.write_pages(page_indices, pages)
        }
    }

    #[test]
    fn file_store_bulk_pages_preserve_requested_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pages.bin");
        let mut store = FilePageStore::open(&path, 6, 4).unwrap();
        for page_idx in 0..6 {
            store.write_page(page_idx, &[page_idx as u8; 4]).unwrap();
        }

        let pages = store.read_pages(&[4, 2, 3]).unwrap();
        assert_eq!(pages, vec![vec![4; 4], vec![2; 4], vec![3; 4]]);

        store
            .write_pages(&[3, 1, 2], &[vec![30; 4], vec![10; 4], vec![20; 4]])
            .unwrap();
        let pages = store.read_pages(&[1, 2, 3]).unwrap();
        assert_eq!(pages, vec![vec![10; 4], vec![20; 4], vec![30; 4]]);
    }

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

        PageStore::flush(&mut cached).unwrap();
        let mut inner = cached.into_inner();
        inner.read_page(0, &mut out).unwrap();
        assert_eq!(out, [9; 8]);
        inner.read_page(2, &mut out).unwrap();
        assert_eq!(out, [7; 8]);
    }

    #[test]
    fn front_cache_bulk_pages_keep_cached_hits_in_memory() {
        let mut mem = MemPageStore::new(6, 4).unwrap();
        for page_idx in 0..6 {
            mem.write_page(page_idx, &[page_idx as u8; 4]).unwrap();
        }
        let inner = BulkCountingStore::new(mem);
        let mut cached = FrontCachedPageStore::new(inner, 2).unwrap();

        let pages = cached.read_pages(&[0, 3, 1, 4]).unwrap();
        assert_eq!(pages, vec![vec![0; 4], vec![3; 4], vec![1; 4], vec![4; 4]]);

        cached
            .write_pages(&[1, 4, 5], &[vec![11; 4], vec![44; 4], vec![55; 4]])
            .unwrap();

        let inner = cached.into_inner();
        assert_eq!(inner.read_page_calls, 2);
        assert_eq!(inner.write_page_calls, 0);
        assert_eq!(inner.read_pages_calls, 1);
        assert_eq!(inner.write_pages_calls, 1);
        assert_eq!(inner.last_read_pages, vec![3, 4]);
        assert_eq!(inner.last_write_pages, vec![4, 5]);
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
