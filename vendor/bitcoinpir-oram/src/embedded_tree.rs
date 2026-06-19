//! Path-level authenticated ORAM tree with child hashes embedded in bucket pages.
//!
//! This is not a transparent [`PageStore`] wrapper. Authentication is efficient
//! only when callers operate on whole root-to-leaf paths: parent pages carry the
//! child subtree hashes needed to authenticate the next page on that same path.

use crate::{Error, PageStore, PathPageStore, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PAGE_DOMAIN: &[u8] = b"bpir-oram-embedded-page-v1";
const CHILD_HASH_BYTES: usize = 32;

/// Bytes appended to every physical bucket page for embedded child hashes.
pub const EMBEDDED_TREE_AUTH_BYTES_PER_PAGE: usize = CHILD_HASH_BYTES * 2;

/// Trusted state for reopening an embedded authenticated ORAM tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmbeddedTreeState {
    /// Logical store domain separating metadata/payload and index/chunk roots.
    pub store_id: [u8; 16],
    /// Number of physical ORAM bucket pages.
    pub page_count: usize,
    /// Logical bucket bytes before the embedded child-hash trailer.
    pub logical_page_size: usize,
    /// Trusted root hash for the whole embedded tree.
    pub root_hash: [u8; 32],
}

/// Path-level authenticated store with two child hashes embedded per page.
#[derive(Debug)]
pub struct EmbeddedTreePageStore<S> {
    inner: S,
    store_id: [u8; 16],
    page_count: usize,
    logical_page_size: usize,
    physical_page_size: usize,
    root_hash: [u8; 32],
    verified_batch_cache: Option<VerifiedBatchCache>,
}

#[derive(Clone, Debug)]
struct EmbeddedPage {
    logical: Vec<u8>,
    left_hash: [u8; 32],
    right_hash: [u8; 32],
}

#[derive(Clone, Debug)]
struct VerifiedBatchCache {
    root_hash: [u8; 32],
    pages: BTreeMap<usize, EmbeddedPage>,
}

impl<S: PageStore> EmbeddedTreePageStore<S> {
    /// Physical page bytes for a logical bucket payload size.
    pub const fn physical_page_size_for(logical_page_size: usize) -> usize {
        logical_page_size + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE
    }

    /// Build embedded child hashes over the current logical page contents.
    ///
    /// The underlying store must already have physical pages of
    /// `logical_page_size + 64` bytes. Existing trailer bytes are ignored and
    /// replaced with freshly computed child hashes.
    pub fn build(mut inner: S, store_id: [u8; 16], logical_page_size: usize) -> Result<Self> {
        let page_count = inner.page_count();
        let physical_page_size = Self::physical_page_size_for(logical_page_size);
        validate_dimensions(&inner, page_count, logical_page_size, physical_page_size)?;

        let mut physical = vec![0u8; physical_page_size];
        let mut pages = Vec::with_capacity(page_count);
        for page_idx in 0..page_count {
            inner.read_page(page_idx, &mut physical)?;
            pages.push(EmbeddedPage::decode(&physical, logical_page_size)?);
        }

        let mut hashes = vec![[0u8; 32]; page_count];
        for page_idx in (0..page_count).rev() {
            pages[page_idx].left_hash = child_hash(&hashes, left_child(page_idx));
            pages[page_idx].right_hash = child_hash(&hashes, right_child(page_idx));
            hashes[page_idx] = pages[page_idx].hash(store_id, page_idx);
        }

        for (page_idx, page) in pages.iter().enumerate() {
            page.encode(&mut physical, logical_page_size)?;
            inner.write_page(page_idx, &physical)?;
        }

        Ok(Self {
            inner,
            store_id,
            page_count,
            logical_page_size,
            physical_page_size,
            root_hash: hashes[0],
            verified_batch_cache: None,
        })
    }

    /// Reopen from trusted state.
    pub fn from_state(inner: S, state: EmbeddedTreeState) -> Result<Self> {
        let physical_page_size = Self::physical_page_size_for(state.logical_page_size);
        validate_dimensions(
            &inner,
            state.page_count,
            state.logical_page_size,
            physical_page_size,
        )?;
        Ok(Self {
            inner,
            store_id: state.store_id,
            page_count: state.page_count,
            logical_page_size: state.logical_page_size,
            physical_page_size,
            root_hash: state.root_hash,
            verified_batch_cache: None,
        })
    }

    /// Snapshot trusted root state.
    pub const fn state(&self) -> EmbeddedTreeState {
        EmbeddedTreeState {
            store_id: self.store_id,
            page_count: self.page_count,
            logical_page_size: self.logical_page_size,
            root_hash: self.root_hash,
        }
    }

    /// Current trusted root hash.
    pub const fn root_hash(&self) -> [u8; 32] {
        self.root_hash
    }

    /// Logical bucket page bytes exposed to the ORAM controller.
    pub const fn logical_page_size(&self) -> usize {
        self.logical_page_size
    }

    /// Physical page bytes stored on disk.
    pub const fn physical_page_size(&self) -> usize {
        self.physical_page_size
    }

    /// Number of physical bucket pages.
    pub const fn page_count(&self) -> usize {
        self.page_count
    }

    /// Borrow the underlying store.
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Consume the wrapper and return the underlying physical store.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Read and verify a root-to-descendant path, returning logical page bytes.
    pub fn read_path(&mut self, path: &[usize]) -> Result<Vec<Vec<u8>>> {
        let paths = vec![path.to_vec()];
        Ok(self
            .read_paths(&paths)?
            .pop()
            .expect("single requested path yields one path"))
    }

    /// Verify the existing path, replace logical bytes, update embedded child
    /// hashes bottom-up, and write the path pages back.
    pub fn write_path(&mut self, path: &[usize], logical_pages: &[Vec<u8>]) -> Result<()> {
        let paths = vec![path.to_vec()];
        let pages = vec![logical_pages.to_vec()];
        self.write_paths(&paths, &pages)
    }

    /// Read and verify multiple root-to-descendant paths in one physical batch.
    pub fn read_paths(&mut self, paths: &[Vec<usize>]) -> Result<Vec<Vec<Vec<u8>>>> {
        let pages = self.read_verified_paths(paths)?;
        let mut logical_paths = Vec::with_capacity(paths.len());
        for path in paths {
            let mut logical_pages = Vec::with_capacity(path.len());
            for page_idx in path {
                logical_pages.push(
                    pages
                        .get(page_idx)
                        .expect("verified path pages include every requested page")
                        .logical
                        .clone(),
                );
            }
            logical_paths.push(logical_pages);
        }
        self.verified_batch_cache = Some(VerifiedBatchCache {
            root_hash: self.root_hash,
            pages,
        });
        Ok(logical_paths)
    }

    /// Update multiple previously verified paths and write dirty physical pages.
    ///
    /// `logical_paths` must already account for overlapping logical pages across
    /// paths. The method maintains embedded child hashes in an overlay so hash
    /// updates from earlier paths in the batch are preserved by later paths.
    pub fn write_paths(
        &mut self,
        paths: &[Vec<usize>],
        logical_paths: &[Vec<Vec<u8>>],
    ) -> Result<()> {
        if paths.len() != logical_paths.len() {
            return Err(Error::InvalidInput(format!(
                "path count {} != logical path count {}",
                paths.len(),
                logical_paths.len()
            )));
        }
        if paths.is_empty() {
            return Ok(());
        }

        let mut pages = match self.verified_batch_cache.take() {
            Some(cache)
                if cache.root_hash == self.root_hash && cache_covers_paths(&cache.pages, paths) =>
            {
                cache.pages
            }
            _ => self.read_verified_paths(paths)?,
        };
        let mut dirty_pages = BTreeSet::new();

        for (path, logical_pages) in paths.iter().zip(logical_paths) {
            if path.len() != logical_pages.len() {
                return Err(Error::InvalidInput(format!(
                    "path length {} != logical page count {}",
                    path.len(),
                    logical_pages.len()
                )));
            }
            validate_path(path, self.page_count)?;
            for (page_idx, logical) in path.iter().zip(logical_pages) {
                if logical.len() != self.logical_page_size {
                    return Err(Error::InvalidInput(format!(
                        "logical page len {} != expected {}",
                        logical.len(),
                        self.logical_page_size
                    )));
                }
                pages
                    .get_mut(page_idx)
                    .expect("verified path pages include every requested page")
                    .logical
                    .copy_from_slice(logical);
                dirty_pages.insert(*page_idx);
            }

            let mut current_child = None::<(usize, [u8; 32])>;
            for depth in (0..path.len()).rev() {
                let page_idx = path[depth];
                let page = pages
                    .get_mut(&page_idx)
                    .expect("verified path pages include every requested page");
                if let Some((child_idx, hash)) = current_child {
                    page.set_child_hash(page_idx, child_idx, hash)?;
                }
                let page_hash = page.hash(self.store_id, page_idx);
                current_child = Some((page_idx, page_hash));
                dirty_pages.insert(page_idx);
            }
            self.root_hash = current_child.expect("non-empty path").1;
        }

        let page_indices = dirty_pages.into_iter().collect::<Vec<_>>();
        let mut physical_pages = Vec::with_capacity(page_indices.len());
        for page_idx in &page_indices {
            let mut physical = vec![0u8; self.physical_page_size];
            pages
                .get(page_idx)
                .expect("dirty page exists in overlay")
                .encode(&mut physical, self.logical_page_size)?;
            physical_pages.push(physical);
        }
        self.inner.write_pages(&page_indices, &physical_pages)
    }

    fn read_verified_paths(
        &mut self,
        paths: &[Vec<usize>],
    ) -> Result<BTreeMap<usize, EmbeddedPage>> {
        if paths.is_empty() {
            return Ok(BTreeMap::new());
        }
        let mut page_indices = BTreeSet::new();
        for path in paths {
            validate_path(path, self.page_count)?;
            page_indices.extend(path.iter().copied());
        }
        let page_indices = page_indices.into_iter().collect::<Vec<_>>();
        let physical_pages = self.inner.read_pages(&page_indices)?;
        let mut pages = BTreeMap::new();
        for (page_idx, physical) in page_indices.iter().zip(&physical_pages) {
            pages.insert(
                *page_idx,
                EmbeddedPage::decode(physical, self.logical_page_size)?,
            );
        }
        for path in paths {
            verify_path_from_pages(path, &pages, self.store_id, self.root_hash)?;
        }
        Ok(pages)
    }
}

fn verify_path_from_pages(
    path: &[usize],
    pages: &BTreeMap<usize, EmbeddedPage>,
    store_id: [u8; 16],
    root_hash: [u8; 32],
) -> Result<()> {
    let mut expected_hash = root_hash;
    for (depth, &page_idx) in path.iter().enumerate() {
        let page = pages
            .get(&page_idx)
            .expect("verified path pages include every requested page");
        let got = page.hash(store_id, page_idx);
        if !hash_eq(&got, &expected_hash) {
            return Err(Error::InvalidInput(format!(
                "embedded tree authentication failed for page {}",
                page_idx
            )));
        }
        if let Some(&next_idx) = path.get(depth + 1) {
            expected_hash = page.child_hash(page_idx, next_idx)?;
        }
    }
    Ok(())
}

fn cache_covers_paths(pages: &BTreeMap<usize, EmbeddedPage>, paths: &[Vec<usize>]) -> bool {
    paths
        .iter()
        .flat_map(|path| path.iter())
        .all(|page_idx| pages.contains_key(page_idx))
}

impl<S: PageStore> PathPageStore for EmbeddedTreePageStore<S> {
    fn page_size(&self) -> usize {
        self.logical_page_size
    }

    fn page_count(&self) -> usize {
        self.page_count
    }

    fn read_path_pages(&mut self, path: &[usize]) -> Result<Vec<Vec<u8>>> {
        self.read_path(path)
    }

    fn write_path_pages(&mut self, path: &[usize], pages: &[Vec<u8>]) -> Result<()> {
        self.write_path(path, pages)
    }

    fn read_paths_pages(&mut self, paths: &[Vec<usize>]) -> Result<Vec<Vec<Vec<u8>>>> {
        self.read_paths(paths)
    }

    fn write_paths_pages(&mut self, paths: &[Vec<usize>], pages: &[Vec<Vec<u8>>]) -> Result<()> {
        self.write_paths(paths, pages)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }

    fn embedded_tree_state(&self) -> Option<EmbeddedTreeState> {
        Some(self.state())
    }
}

impl EmbeddedPage {
    fn decode(input: &[u8], logical_page_size: usize) -> Result<Self> {
        let expected = logical_page_size + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE;
        if input.len() != expected {
            return Err(Error::InvalidInput(format!(
                "embedded page len {} != expected {}",
                input.len(),
                expected
            )));
        }
        let left_start = logical_page_size;
        let right_start = left_start + CHILD_HASH_BYTES;
        let mut left_hash = [0u8; 32];
        let mut right_hash = [0u8; 32];
        left_hash.copy_from_slice(&input[left_start..right_start]);
        right_hash.copy_from_slice(&input[right_start..right_start + CHILD_HASH_BYTES]);
        Ok(Self {
            logical: input[..logical_page_size].to_vec(),
            left_hash,
            right_hash,
        })
    }

    fn encode(&self, out: &mut [u8], logical_page_size: usize) -> Result<()> {
        let expected = logical_page_size + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE;
        if out.len() != expected {
            return Err(Error::InvalidInput(format!(
                "embedded output len {} != expected {}",
                out.len(),
                expected
            )));
        }
        if self.logical.len() != logical_page_size {
            return Err(Error::InvalidInput(format!(
                "logical page len {} != expected {}",
                self.logical.len(),
                logical_page_size
            )));
        }
        let left_start = logical_page_size;
        let right_start = left_start + CHILD_HASH_BYTES;
        out[..logical_page_size].copy_from_slice(&self.logical);
        out[left_start..right_start].copy_from_slice(&self.left_hash);
        out[right_start..right_start + CHILD_HASH_BYTES].copy_from_slice(&self.right_hash);
        Ok(())
    }

    fn hash(&self, store_id: [u8; 16], page_idx: usize) -> [u8; 32] {
        hash_embedded_page(
            store_id,
            page_idx,
            &self.logical,
            self.left_hash,
            self.right_hash,
        )
    }

    fn child_hash(&self, page_idx: usize, child_idx: usize) -> Result<[u8; 32]> {
        if child_idx == left_child(page_idx) {
            Ok(self.left_hash)
        } else if child_idx == right_child(page_idx) {
            Ok(self.right_hash)
        } else {
            Err(Error::InvalidInput(format!(
                "page {} is not a child of page {}",
                child_idx, page_idx
            )))
        }
    }

    fn set_child_hash(&mut self, page_idx: usize, child_idx: usize, hash: [u8; 32]) -> Result<()> {
        if child_idx == left_child(page_idx) {
            self.left_hash = hash;
        } else if child_idx == right_child(page_idx) {
            self.right_hash = hash;
        } else {
            return Err(Error::InvalidInput(format!(
                "page {} is not a child of page {}",
                child_idx, page_idx
            )));
        }
        Ok(())
    }
}

fn validate_dimensions(
    store: &impl PageStore,
    page_count: usize,
    logical_page_size: usize,
    physical_page_size: usize,
) -> Result<()> {
    if page_count == 0 || logical_page_size == 0 {
        return Err(Error::InvalidInput(
            "page_count and logical_page_size must be > 0".into(),
        ));
    }
    if store.page_count() != page_count {
        return Err(Error::InvalidInput(format!(
            "store page_count {} != expected {}",
            store.page_count(),
            page_count
        )));
    }
    if store.page_size() != physical_page_size {
        return Err(Error::InvalidInput(format!(
            "store page_size {} != embedded physical page_size {}",
            store.page_size(),
            physical_page_size
        )));
    }
    Ok(())
}

fn validate_path(path: &[usize], page_count: usize) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidInput("embedded tree path is empty".into()));
    }
    if path[0] != 0 {
        return Err(Error::InvalidInput(
            "embedded tree path must start at root".into(),
        ));
    }
    for (depth, &page_idx) in path.iter().enumerate() {
        if page_idx >= page_count {
            return Err(Error::InvalidInput(format!(
                "path page {} out of range {}",
                page_idx, page_count
            )));
        }
        if depth > 0 {
            let parent = path[depth - 1];
            if page_idx != left_child(parent) && page_idx != right_child(parent) {
                return Err(Error::InvalidInput(format!(
                    "path page {} is not a child of previous page {}",
                    page_idx, parent
                )));
            }
        }
    }
    Ok(())
}

fn child_hash(hashes: &[[u8; 32]], child_idx: usize) -> [u8; 32] {
    hashes.get(child_idx).copied().unwrap_or([0u8; 32])
}

const fn left_child(page_idx: usize) -> usize {
    page_idx * 2 + 1
}

const fn right_child(page_idx: usize) -> usize {
    page_idx * 2 + 2
}

fn hash_embedded_page(
    store_id: [u8; 16],
    page_idx: usize,
    logical: &[u8],
    left_hash: [u8; 32],
    right_hash: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PAGE_DOMAIN);
    hasher.update(store_id);
    hasher.update((page_idx as u64).to_le_bytes());
    hasher.update((logical.len() as u64).to_le_bytes());
    hasher.update(logical);
    hasher.update(left_hash);
    hasher.update(right_hash);
    hasher.finalize().into()
}

fn hash_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&l, &r) in left.iter().zip(right) {
        diff |= l ^ r;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::TraceEvent, MemPageStore, OramParams, TracingStore};

    const STORE_ID: [u8; 16] = *b"embed-tree-test!";

    fn sample_store(params: &OramParams) -> MemPageStore {
        let logical_page_size = 8;
        let physical_page_size =
            EmbeddedTreePageStore::<MemPageStore>::physical_page_size_for(logical_page_size);
        let mut store = MemPageStore::new(params.bucket_count(), physical_page_size).unwrap();
        let mut page = vec![0u8; physical_page_size];
        for page_idx in 0..params.bucket_count() {
            page.fill(0);
            page[..logical_page_size].copy_from_slice(&(page_idx as u64).to_le_bytes());
            store.write_page(page_idx, &page).unwrap();
        }
        store
    }

    #[test]
    fn embedded_tree_reads_and_updates_paths() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let store = sample_store(&params);
        let mut auth = EmbeddedTreePageStore::build(store, STORE_ID, 8).unwrap();
        let original_root = auth.root_hash();

        let path = params.path_nodes(2);
        let pages = auth.read_path(&path).unwrap();
        assert_eq!(pages.len(), params.height());
        assert_eq!(
            u64::from_le_bytes(pages[0].as_slice().try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(pages.last().unwrap().as_slice().try_into().unwrap()),
            *path.last().unwrap() as u64
        );

        let mut updated = pages.clone();
        updated
            .last_mut()
            .unwrap()
            .copy_from_slice(&99u64.to_le_bytes());
        auth.write_path(&path, &updated).unwrap();
        assert_ne!(auth.root_hash(), original_root);
        let reread = auth.read_path(&path).unwrap();
        assert_eq!(reread.last().unwrap(), &99u64.to_le_bytes());

        let sibling_path = params.path_nodes(3);
        let sibling = auth.read_path(&sibling_path).unwrap();
        assert_eq!(
            u64::from_le_bytes(sibling.last().unwrap().as_slice().try_into().unwrap()),
            *sibling_path.last().unwrap() as u64
        );
    }

    #[test]
    fn embedded_tree_detects_data_rollback_on_path() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let store = sample_store(&params);
        let auth = EmbeddedTreePageStore::build(store, STORE_ID, 8).unwrap();
        let state = auth.state();
        let mut inner = auth.into_inner();

        let path = params.path_nodes(1);
        let tampered_idx = *path.last().unwrap();
        let mut physical = vec![0u8; state.logical_page_size + EMBEDDED_TREE_AUTH_BYTES_PER_PAGE];
        inner.read_page(tampered_idx, &mut physical).unwrap();
        physical[0] ^= 0x55;
        inner.write_page(tampered_idx, &physical).unwrap();

        let mut reopened = EmbeddedTreePageStore::from_state(inner, state).unwrap();
        let err = reopened.read_path(&path).unwrap_err();
        assert!(err
            .to_string()
            .contains("embedded tree authentication failed"));
    }

    #[test]
    fn embedded_tree_path_trace_touches_only_path_pages() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let traced = TracingStore::new(sample_store(&params));
        let mut auth = EmbeddedTreePageStore::build(traced, STORE_ID, 8).unwrap();
        auth.inner().take_trace();

        let path = params.path_nodes(0);
        let mut pages = auth.read_path(&path).unwrap();
        let trace = auth.inner().take_trace();
        let expected: Vec<_> = path.iter().copied().map(TraceEvent::Read).collect();
        assert_eq!(trace, expected);

        pages[0].copy_from_slice(&42u64.to_le_bytes());
        auth.write_path(&path, &pages).unwrap();
        let trace = auth.inner().take_trace();
        let expected: Vec<_> = path.iter().copied().map(TraceEvent::Write).collect();
        assert_eq!(trace, expected);
    }

    #[test]
    fn embedded_tree_batch_read_prefetches_unique_path_pages() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let traced = TracingStore::new(sample_store(&params));
        let mut auth = EmbeddedTreePageStore::build(traced, STORE_ID, 8).unwrap();
        auth.inner().take_trace();

        let paths = vec![params.path_nodes(0), params.path_nodes(1)];
        let pages = auth.read_paths(&paths).unwrap();
        assert_eq!(pages.len(), 2);
        let trace = auth.inner().take_trace();
        assert_eq!(
            trace,
            vec![
                TraceEvent::Read(0),
                TraceEvent::Read(1),
                TraceEvent::Read(3),
                TraceEvent::Read(4),
            ]
        );
    }

    #[test]
    fn embedded_tree_batch_write_preserves_overlapping_hash_updates() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let traced = TracingStore::new(sample_store(&params));
        let mut auth = EmbeddedTreePageStore::build(traced, STORE_ID, 8).unwrap();
        auth.inner().take_trace();

        let paths = vec![params.path_nodes(0), params.path_nodes(2)];
        let mut pages = auth.read_paths(&paths).unwrap();
        pages[0]
            .last_mut()
            .unwrap()
            .copy_from_slice(&101u64.to_le_bytes());
        pages[1]
            .last_mut()
            .unwrap()
            .copy_from_slice(&202u64.to_le_bytes());
        auth.inner().take_trace();

        auth.write_paths(&paths, &pages).unwrap();
        let trace = auth.inner().take_trace();
        assert_eq!(
            trace,
            vec![
                TraceEvent::Write(0),
                TraceEvent::Write(1),
                TraceEvent::Write(2),
                TraceEvent::Write(3),
                TraceEvent::Write(5),
            ]
        );

        assert_eq!(
            auth.read_path(&paths[0]).unwrap().last().unwrap(),
            &101u64.to_le_bytes()
        );
        assert_eq!(
            auth.read_path(&paths[1]).unwrap().last().unwrap(),
            &202u64.to_le_bytes()
        );
    }

    #[test]
    fn embedded_tree_rejects_non_path_shapes() {
        let params = OramParams::with_leaves(4, 8, 4).unwrap();
        let store = sample_store(&params);
        let mut auth = EmbeddedTreePageStore::build(store, STORE_ID, 8).unwrap();

        let err = auth.read_path(&[1, 3]).unwrap_err();
        assert!(err.to_string().contains("must start at root"));
        let err = auth.read_path(&[0, 4]).unwrap_err();
        assert!(err.to_string().contains("not a child"));
    }
}
