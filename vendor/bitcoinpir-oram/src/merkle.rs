use crate::{Error, PageStore, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LEAF_DOMAIN: &[u8] = b"bpir-oram-page-v1";
const EMPTY_LEAF_DOMAIN: &[u8] = b"bpir-oram-empty-page-v1";
const NODE_DOMAIN: &[u8] = b"bpir-oram-node-v1";

/// Page-store wrapper that authenticates disk-resident pages against a trusted
/// Merkle root.
///
/// This first implementation keeps the full Merkle tree in trusted memory. For
/// the production SEV-SNP shape, this is the same API boundary we need for a
/// split design where only the top subtree roots stay in trusted memory and
/// lower hash nodes live on disk.
pub struct MerklePageStore<S> {
    inner: S,
    store_id: [u8; 16],
    page_size: usize,
    page_count: usize,
    leaf_base: usize,
    hashes: Vec<[u8; 32]>,
}

impl<S: PageStore> MerklePageStore<S> {
    /// Build a trusted Merkle tree over the current contents of `inner`.
    ///
    /// Call this immediately after offline image generation, or after startup
    /// regeneration before serving requests. The resulting root must remain in
    /// trusted memory with the ORAM controller state.
    pub fn new(mut inner: S, store_id: [u8; 16]) -> Result<Self> {
        let page_count = inner.page_count();
        let page_size = inner.page_size();
        if page_count == 0 || page_size == 0 {
            return Err(Error::InvalidInput(
                "page_count and page_size must be > 0".into(),
            ));
        }

        let leaf_base = page_count
            .checked_next_power_of_two()
            .ok_or_else(|| Error::InvalidInput("page_count is too large".into()))?;
        let mut hashes = vec![[0u8; 32]; leaf_base * 2];
        let mut page = vec![0u8; page_size];

        for page_idx in 0..leaf_base {
            hashes[leaf_base + page_idx] = if page_idx < page_count {
                inner.read_page(page_idx, &mut page)?;
                hash_leaf(store_id, page_idx, &page)
            } else {
                hash_empty_leaf(store_id, page_idx, page_size)
            };
        }
        for node_idx in (1..leaf_base).rev() {
            hashes[node_idx] = hash_node(node_idx, hashes[node_idx * 2], hashes[node_idx * 2 + 1]);
        }

        Ok(Self {
            inner,
            store_id,
            page_size,
            page_count,
            leaf_base,
            hashes,
        })
    }

    /// Current trusted Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.hashes[1]
    }

    /// Logical store domain separating metadata/payload and index/chunk roots.
    pub const fn store_id(&self) -> [u8; 16] {
        self.store_id
    }

    /// Trusted memory consumed by the in-memory hash tree.
    pub fn trusted_hash_bytes(&self) -> usize {
        (self.hashes.len() - 1) * 32
    }

    /// Consume the wrapper and return the underlying store.
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn check_page(&self, page_idx: usize, len: usize) -> Result<()> {
        if page_idx >= self.page_count {
            return Err(Error::InvalidInput(format!(
                "page_idx {} out of range {}",
                page_idx, self.page_count
            )));
        }
        if len != self.page_size {
            return Err(Error::InvalidInput(format!(
                "page buffer len {} != page_size {}",
                len, self.page_size
            )));
        }
        Ok(())
    }

    fn leaf_slot(&self, page_idx: usize) -> usize {
        self.leaf_base + page_idx
    }

    fn update_leaf(&mut self, page_idx: usize, leaf_hash: [u8; 32]) {
        let mut node_idx = self.leaf_slot(page_idx);
        self.hashes[node_idx] = leaf_hash;
        while node_idx > 1 {
            node_idx /= 2;
            self.hashes[node_idx] = hash_node(
                node_idx,
                self.hashes[node_idx * 2],
                self.hashes[node_idx * 2 + 1],
            );
        }
    }
}

impl<S: PageStore> PageStore for MerklePageStore<S> {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn page_count(&self) -> usize {
        self.page_count
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        self.check_page(page_idx, out.len())?;
        self.inner.read_page(page_idx, out)?;
        let got = hash_leaf(self.store_id, page_idx, out);
        let expected = self.hashes[self.leaf_slot(page_idx)];
        if !hash_eq(&got, &expected) {
            return Err(Error::InvalidInput(format!(
                "Merkle page authentication failed for page {}",
                page_idx
            )));
        }
        Ok(())
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        self.check_page(page_idx, input.len())?;
        self.inner.write_page(page_idx, input)?;
        self.update_leaf(page_idx, hash_leaf(self.store_id, page_idx, input));
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

/// Page-store wrapper with disk-backed lower Merkle nodes and trusted top-tree
/// hashes.
///
/// `trusted_levels` counts levels from the root. `trusted_levels = 1` keeps
/// only the root in trusted memory; `trusted_levels = 2` keeps the root and its
/// two children. Lower node hashes, including leaf hashes, are packed into
/// `hash_store`.
pub struct TieredMerklePageStore<S, H> {
    inner: S,
    hash_store: H,
    store_id: [u8; 16],
    page_size: usize,
    page_count: usize,
    leaf_base: usize,
    trusted_levels: usize,
    trusted_node_limit: usize,
    hashes_per_page: usize,
    disk_hash_nodes: usize,
    trusted_hashes: Vec<[u8; 32]>,
}

/// Trusted top-tree state needed to reopen a [`TieredMerklePageStore`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TieredMerkleState {
    /// Logical store domain separating metadata/payload and index/chunk roots.
    pub store_id: [u8; 16],
    /// Number of data pages authenticated by this tree.
    pub page_count: usize,
    /// Data page size in bytes.
    pub page_size: usize,
    /// Number of Merkle levels kept in trusted memory, counting the root.
    pub trusted_levels: usize,
    /// Disk hash-store page size in bytes.
    pub hash_page_size: usize,
    /// Trusted top-tree hashes. Index 0 is unused so heap node ids can index
    /// directly into this vector.
    pub trusted_hashes: Vec<[u8; 32]>,
}

impl<S: PageStore, H: PageStore> TieredMerklePageStore<S, H> {
    /// Build trusted top-tree hashes plus a disk-backed lower hash store over
    /// the current contents of `inner`.
    ///
    /// This is the production-oriented shape for runtime rollback detection:
    /// keep a public top subtree in trusted memory, spill lower hashes to disk,
    /// and authenticate every data-page read back to the trusted frontier.
    pub fn build(
        inner: S,
        hash_store: H,
        store_id: [u8; 16],
        trusted_levels: usize,
    ) -> Result<Self> {
        let page_count = inner.page_count();
        let page_size = inner.page_size();
        if page_count == 0 || page_size == 0 {
            return Err(Error::InvalidInput(
                "page_count and page_size must be > 0".into(),
            ));
        }
        let leaf_base = leaf_base_for_page_count(page_count)?;
        let trusted_node_limit = trusted_node_limit(leaf_base, trusted_levels)?;
        let hashes_per_page = hashes_per_page(hash_store.page_size())?;
        let disk_hash_nodes = disk_hash_nodes(leaf_base, trusted_node_limit);
        let required_hash_pages = pages_for_hash_nodes(disk_hash_nodes, hashes_per_page);
        if hash_store.page_count() < required_hash_pages {
            return Err(Error::InvalidInput(format!(
                "hash store has {} pages, need at least {}",
                hash_store.page_count(),
                required_hash_pages
            )));
        }

        let mut store = Self {
            inner,
            hash_store,
            store_id,
            page_size,
            page_count,
            leaf_base,
            trusted_levels,
            trusted_node_limit,
            hashes_per_page,
            disk_hash_nodes,
            trusted_hashes: vec![[0u8; 32]; trusted_node_limit],
        };
        store.rebuild_hashes()?;
        Ok(store)
    }

    /// Reopen using trusted top-tree state from the TEE controller state.
    pub fn from_trusted_state(inner: S, hash_store: H, state: TieredMerkleState) -> Result<Self> {
        let page_count = inner.page_count();
        let page_size = inner.page_size();
        if page_count != state.page_count {
            return Err(Error::InvalidInput(format!(
                "data store page_count {} != trusted Merkle page_count {}",
                page_count, state.page_count
            )));
        }
        if page_size != state.page_size {
            return Err(Error::InvalidInput(format!(
                "data store page_size {} != trusted Merkle page_size {}",
                page_size, state.page_size
            )));
        }
        if hash_store.page_size() != state.hash_page_size {
            return Err(Error::InvalidInput(format!(
                "hash store page_size {} != trusted Merkle hash_page_size {}",
                hash_store.page_size(),
                state.hash_page_size
            )));
        }

        let leaf_base = leaf_base_for_page_count(page_count)?;
        let trusted_node_limit = trusted_node_limit(leaf_base, state.trusted_levels)?;
        if state.trusted_hashes.len() != trusted_node_limit {
            return Err(Error::InvalidInput(format!(
                "trusted hash count {} != expected {}",
                state.trusted_hashes.len(),
                trusted_node_limit
            )));
        }
        let hashes_per_page = hashes_per_page(hash_store.page_size())?;
        let disk_hash_nodes = disk_hash_nodes(leaf_base, trusted_node_limit);
        let required_hash_pages = pages_for_hash_nodes(disk_hash_nodes, hashes_per_page);
        if hash_store.page_count() < required_hash_pages {
            return Err(Error::InvalidInput(format!(
                "hash store has {} pages, need at least {}",
                hash_store.page_count(),
                required_hash_pages
            )));
        }

        Ok(Self {
            inner,
            hash_store,
            store_id: state.store_id,
            page_size,
            page_count,
            leaf_base,
            trusted_levels: state.trusted_levels,
            trusted_node_limit,
            hashes_per_page,
            disk_hash_nodes,
            trusted_hashes: state.trusted_hashes,
        })
    }

    /// Hash-store pages needed for `page_count` data pages and the selected
    /// trusted top-tree depth.
    pub fn required_hash_pages(
        page_count: usize,
        hash_page_size: usize,
        trusted_levels: usize,
    ) -> Result<usize> {
        let leaf_base = leaf_base_for_page_count(page_count)?;
        let trusted_node_limit = trusted_node_limit(leaf_base, trusted_levels)?;
        let hashes_per_page = hashes_per_page(hash_page_size)?;
        Ok(pages_for_hash_nodes(
            disk_hash_nodes(leaf_base, trusted_node_limit),
            hashes_per_page,
        ))
    }

    /// Current trusted Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.trusted_hashes[1]
    }

    /// Number of lower Merkle nodes stored in `hash_store`.
    pub const fn disk_hash_nodes(&self) -> usize {
        self.disk_hash_nodes
    }

    /// Trusted memory consumed by the top-tree hashes.
    pub fn trusted_hash_bytes(&self) -> usize {
        (self.trusted_node_limit - 1) * 32
    }

    /// Snapshot trusted top-tree state for durable TEE state.
    pub fn trusted_state(&self) -> TieredMerkleState {
        TieredMerkleState {
            store_id: self.store_id,
            page_count: self.page_count,
            page_size: self.page_size,
            trusted_levels: self.trusted_levels,
            hash_page_size: self.hash_store.page_size(),
            trusted_hashes: self.trusted_hashes.clone(),
        }
    }

    /// Logical store domain separating metadata/payload and index/chunk roots.
    pub const fn store_id(&self) -> [u8; 16] {
        self.store_id
    }

    /// Consume the wrapper and return the underlying data and hash stores.
    pub fn into_parts(self) -> (S, H) {
        (self.inner, self.hash_store)
    }

    fn rebuild_hashes(&mut self) -> Result<()> {
        let mut page = vec![0u8; self.page_size];
        for page_idx in 0..self.leaf_base {
            let hash = if page_idx < self.page_count {
                self.inner.read_page(page_idx, &mut page)?;
                hash_leaf(self.store_id, page_idx, &page)
            } else {
                hash_empty_leaf(self.store_id, page_idx, self.page_size)
            };
            self.write_hash(self.leaf_base + page_idx, hash)?;
        }

        let height = self.height();
        for level in (0..height).rev() {
            for node_idx in (1usize << level)..(1usize << (level + 1)) {
                let left = self.read_hash(node_idx * 2)?;
                let right = self.read_hash(node_idx * 2 + 1)?;
                self.write_hash(node_idx, hash_node(node_idx, left, right))?;
            }
        }
        Ok(())
    }

    fn check_page(&self, page_idx: usize, len: usize) -> Result<()> {
        if page_idx >= self.page_count {
            return Err(Error::InvalidInput(format!(
                "page_idx {} out of range {}",
                page_idx, self.page_count
            )));
        }
        if len != self.page_size {
            return Err(Error::InvalidInput(format!(
                "page buffer len {} != page_size {}",
                len, self.page_size
            )));
        }
        Ok(())
    }

    fn height(&self) -> usize {
        self.leaf_base.trailing_zeros() as usize
    }

    fn read_hash(&mut self, node_idx: usize) -> Result<[u8; 32]> {
        self.check_node_idx(node_idx)?;
        if node_idx < self.trusted_node_limit {
            Ok(self.trusted_hashes[node_idx])
        } else {
            self.read_disk_hash(node_idx)
        }
    }

    fn write_hash(&mut self, node_idx: usize, hash: [u8; 32]) -> Result<()> {
        self.check_node_idx(node_idx)?;
        if node_idx < self.trusted_node_limit {
            self.trusted_hashes[node_idx] = hash;
            Ok(())
        } else {
            self.write_disk_hash(node_idx, hash)
        }
    }

    fn check_node_idx(&self, node_idx: usize) -> Result<()> {
        if node_idx == 0 || node_idx >= self.leaf_base * 2 {
            return Err(Error::InvalidInput(format!(
                "Merkle node {} out of range",
                node_idx
            )));
        }
        Ok(())
    }

    fn disk_hash_position(&self, node_idx: usize) -> Result<(usize, usize)> {
        if node_idx < self.trusted_node_limit {
            return Err(Error::InvalidInput(format!(
                "Merkle node {} is trusted, not disk-backed",
                node_idx
            )));
        }
        let disk_offset = node_idx - self.trusted_node_limit;
        if disk_offset >= self.disk_hash_nodes {
            return Err(Error::InvalidInput(format!(
                "Merkle disk offset {} out of range {}",
                disk_offset, self.disk_hash_nodes
            )));
        }
        let page_idx = disk_offset / self.hashes_per_page;
        let offset = (disk_offset % self.hashes_per_page) * 32;
        Ok((page_idx, offset))
    }

    fn read_disk_hash(&mut self, node_idx: usize) -> Result<[u8; 32]> {
        let (page_idx, offset) = self.disk_hash_position(node_idx)?;
        let mut page = vec![0u8; self.hash_store.page_size()];
        self.hash_store.read_page(page_idx, &mut page)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&page[offset..offset + 32]);
        Ok(hash)
    }

    fn write_disk_hash(&mut self, node_idx: usize, hash: [u8; 32]) -> Result<()> {
        let (page_idx, offset) = self.disk_hash_position(node_idx)?;
        let mut page = vec![0u8; self.hash_store.page_size()];
        self.hash_store.read_page(page_idx, &mut page)?;
        page[offset..offset + 32].copy_from_slice(&hash);
        self.hash_store.write_page(page_idx, &page)
    }

    fn verify_page_hash(&mut self, page_idx: usize, leaf_hash: [u8; 32]) -> Result<()> {
        let mut node_idx = self.leaf_base + page_idx;
        let mut current = leaf_hash;
        while node_idx >= self.trusted_node_limit {
            let sibling_idx = sibling_node(node_idx);
            let sibling = self.read_hash(sibling_idx)?;
            let parent_idx = node_idx / 2;
            current = if is_left_child(node_idx) {
                hash_node(parent_idx, current, sibling)
            } else {
                hash_node(parent_idx, sibling, current)
            };
            node_idx = parent_idx;
        }

        let trusted = self.trusted_hashes[node_idx];
        if !hash_eq(&current, &trusted) {
            return Err(Error::InvalidInput(format!(
                "Merkle page authentication failed for page {}",
                page_idx
            )));
        }
        Ok(())
    }

    fn update_page_hash(&mut self, page_idx: usize, leaf_hash: [u8; 32]) -> Result<()> {
        let mut node_idx = self.leaf_base + page_idx;
        let mut current = leaf_hash;
        self.write_hash(node_idx, current)?;
        while node_idx > 1 {
            let sibling_idx = sibling_node(node_idx);
            let sibling = self.read_hash(sibling_idx)?;
            let parent_idx = node_idx / 2;
            current = if is_left_child(node_idx) {
                hash_node(parent_idx, current, sibling)
            } else {
                hash_node(parent_idx, sibling, current)
            };
            node_idx = parent_idx;
            self.write_hash(node_idx, current)?;
        }
        Ok(())
    }
}

impl<S: PageStore, H: PageStore> PageStore for TieredMerklePageStore<S, H> {
    fn page_size(&self) -> usize {
        self.page_size
    }

    fn page_count(&self) -> usize {
        self.page_count
    }

    fn read_page(&mut self, page_idx: usize, out: &mut [u8]) -> Result<()> {
        self.check_page(page_idx, out.len())?;
        self.inner.read_page(page_idx, out)?;
        self.verify_page_hash(page_idx, hash_leaf(self.store_id, page_idx, out))
    }

    fn write_page(&mut self, page_idx: usize, input: &[u8]) -> Result<()> {
        self.check_page(page_idx, input.len())?;
        self.inner.write_page(page_idx, input)?;
        self.update_page_hash(page_idx, hash_leaf(self.store_id, page_idx, input))
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()?;
        self.hash_store.flush()
    }

    fn tiered_merkle_state(&self) -> Option<TieredMerkleState> {
        Some(self.trusted_state())
    }
}

fn hash_leaf(store_id: [u8; 16], page_idx: usize, page: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_DOMAIN);
    h.update(store_id);
    h.update((page_idx as u64).to_le_bytes());
    h.update((page.len() as u64).to_le_bytes());
    h.update(page);
    finalize_hash(h)
}

fn hash_empty_leaf(store_id: [u8; 16], page_idx: usize, page_size: usize) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(EMPTY_LEAF_DOMAIN);
    h.update(store_id);
    h.update((page_idx as u64).to_le_bytes());
    h.update((page_size as u64).to_le_bytes());
    finalize_hash(h)
}

fn hash_node(node_idx: usize, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE_DOMAIN);
    h.update((node_idx as u64).to_le_bytes());
    h.update(left);
    h.update(right);
    finalize_hash(h)
}

fn finalize_hash(h: Sha256) -> [u8; 32] {
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hash_eq(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (&l, &r) in lhs.iter().zip(rhs.iter()) {
        diff |= l ^ r;
    }
    diff == 0
}

fn leaf_base_for_page_count(page_count: usize) -> Result<usize> {
    if page_count == 0 {
        return Err(Error::InvalidInput("page_count must be > 0".into()));
    }
    page_count
        .checked_next_power_of_two()
        .ok_or_else(|| Error::InvalidInput("page_count is too large".into()))
}

fn trusted_node_limit(leaf_base: usize, trusted_levels: usize) -> Result<usize> {
    let tree_levels = leaf_base.trailing_zeros() as usize + 1;
    if trusted_levels == 0 || trusted_levels > tree_levels {
        return Err(Error::InvalidInput(format!(
            "trusted_levels {} out of range 1..={}",
            trusted_levels, tree_levels
        )));
    }
    1usize
        .checked_shl(trusted_levels as u32)
        .ok_or_else(|| Error::InvalidInput("trusted_levels is too large".into()))
}

fn hashes_per_page(page_size: usize) -> Result<usize> {
    if page_size < 32 {
        return Err(Error::InvalidInput(format!(
            "hash store page_size {} must be at least 32",
            page_size
        )));
    }
    Ok(page_size / 32)
}

fn disk_hash_nodes(leaf_base: usize, trusted_node_limit: usize) -> usize {
    leaf_base * 2 - trusted_node_limit
}

fn pages_for_hash_nodes(hash_nodes: usize, hashes_per_page: usize) -> usize {
    hash_nodes.div_ceil(hashes_per_page)
}

fn sibling_node(node_idx: usize) -> usize {
    node_idx ^ 1
}

fn is_left_child(node_idx: usize) -> bool {
    node_idx & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemPageStore;

    const STORE_ID: [u8; 16] = *b"test-meta-store!";

    #[test]
    fn merkle_store_reads_existing_pages_and_updates_root() {
        let mut inner = MemPageStore::new(4, 8).unwrap();
        inner.write_page(0, &[1; 8]).unwrap();
        inner.write_page(1, &[2; 8]).unwrap();
        inner.write_page(2, &[3; 8]).unwrap();
        inner.write_page(3, &[4; 8]).unwrap();

        let mut store = MerklePageStore::new(inner, STORE_ID).unwrap();
        let before = store.root();

        let mut out = [0u8; 8];
        store.read_page(2, &mut out).unwrap();
        assert_eq!(out, [3; 8]);

        store.write_page(2, &[9; 8]).unwrap();
        assert_ne!(store.root(), before);
        store.read_page(2, &mut out).unwrap();
        assert_eq!(out, [9; 8]);
    }

    #[test]
    fn merkle_store_detects_runtime_rollback() {
        let mut inner = MemPageStore::new(2, 8).unwrap();
        inner.write_page(0, &[1; 8]).unwrap();
        inner.write_page(1, &[2; 8]).unwrap();

        let mut store = MerklePageStore::new(inner, STORE_ID).unwrap();
        store.write_page(1, &[7; 8]).unwrap();

        // Simulate the host rolling back the underlying disk page without the
        // trusted in-memory Merkle root moving back.
        store.inner.write_page(1, &[2; 8]).unwrap();

        let mut out = [0u8; 8];
        let err = store.read_page(1, &mut out).unwrap_err();
        assert!(err
            .to_string()
            .contains("Merkle page authentication failed"));
    }

    #[test]
    fn merkle_roots_are_domain_separated_by_store_id() {
        let mut left = MemPageStore::new(1, 8).unwrap();
        left.write_page(0, &[5; 8]).unwrap();
        let mut right = MemPageStore::new(1, 8).unwrap();
        right.write_page(0, &[5; 8]).unwrap();

        let left = MerklePageStore::new(left, *b"index-meta-store").unwrap();
        let right = MerklePageStore::new(right, *b"chunk-meta-store").unwrap();
        assert_ne!(left.root(), right.root());
    }

    #[test]
    fn tiered_merkle_store_keeps_only_top_hashes_in_memory() {
        let inner = filled_store(8);
        let hash_pages =
            TieredMerklePageStore::<MemPageStore, MemPageStore>::required_hash_pages(8, 64, 2)
                .unwrap();
        assert_eq!(hash_pages, 6);
        let hash_store = MemPageStore::new(hash_pages, 64).unwrap();

        let mut store = TieredMerklePageStore::build(inner, hash_store, STORE_ID, 2).unwrap();
        assert_eq!(store.trusted_hash_bytes(), 3 * 32);
        assert_eq!(store.disk_hash_nodes(), 12);

        let mut out = [0u8; 8];
        store.read_page(6, &mut out).unwrap();
        assert_eq!(out, [6; 8]);

        let before = store.root();
        store.write_page(6, &[99; 8]).unwrap();
        assert_ne!(store.root(), before);
        store.read_page(6, &mut out).unwrap();
        assert_eq!(out, [99; 8]);
    }

    #[test]
    fn tiered_merkle_store_detects_data_page_rollback() {
        let inner = filled_store(8);
        let hash_pages =
            TieredMerklePageStore::<MemPageStore, MemPageStore>::required_hash_pages(8, 64, 2)
                .unwrap();
        let hash_store = MemPageStore::new(hash_pages, 64).unwrap();
        let mut store = TieredMerklePageStore::build(inner, hash_store, STORE_ID, 2).unwrap();

        store.write_page(6, &[99; 8]).unwrap();
        store.inner.write_page(6, &[6; 8]).unwrap();

        let mut out = [0u8; 8];
        let err = store.read_page(6, &mut out).unwrap_err();
        assert!(err
            .to_string()
            .contains("Merkle page authentication failed"));
    }

    #[test]
    fn tiered_merkle_store_detects_lower_hash_rollback() {
        let inner = filled_store(8);
        let hash_pages =
            TieredMerklePageStore::<MemPageStore, MemPageStore>::required_hash_pages(8, 64, 1)
                .unwrap();
        let hash_store = MemPageStore::new(hash_pages, 64).unwrap();
        let mut store = TieredMerklePageStore::build(inner, hash_store, STORE_ID, 1).unwrap();

        let mut old_frontier_hash_page = vec![0u8; store.hash_store.page_size()];
        store
            .hash_store
            .read_page(0, &mut old_frontier_hash_page)
            .unwrap();

        store.write_page(1, &[77; 8]).unwrap();
        store
            .hash_store
            .write_page(0, &old_frontier_hash_page)
            .unwrap();

        // Reading from the sibling top subtree needs the rolled-back lower
        // hash node as its authentication sibling, so the trusted root rejects.
        let mut out = [0u8; 8];
        let err = store.read_page(4, &mut out).unwrap_err();
        assert!(err
            .to_string()
            .contains("Merkle page authentication failed"));
    }

    fn filled_store(pages: usize) -> MemPageStore {
        let mut inner = MemPageStore::new(pages, 8).unwrap();
        for page_idx in 0..pages {
            inner.write_page(page_idx, &[page_idx as u8; 8]).unwrap();
        }
        inner
    }
}
