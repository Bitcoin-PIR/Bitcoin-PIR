use crate::{ct, Bucket, Error, OramBlock, OramParams, OramState, PageStore, Result};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Disk-backed Path ORAM controller.
///
/// This v0 keeps the position map and stash in trusted memory and stores one
/// encrypted bucket per page in the backing store.
#[derive(Debug)]
pub struct PathOram<S> {
    params: OramParams,
    store: S,
    pos_map: Vec<u32>,
    stash: Vec<OramBlock>,
    rng: ChaCha20Rng,
}

impl<S: PageStore> PathOram<S> {
    /// Build a trusted initial ORAM image from logical blocks.
    ///
    /// This initialization is intentionally non-oblivious. Use it for an
    /// offline trusted builder or before exposing the VM to the storage-trace
    /// adversary.
    pub fn build_trusted(
        params: OramParams,
        mut store: S,
        blocks: Vec<Vec<u8>>,
        seed: [u8; 32],
    ) -> Result<Self> {
        validate_store(&params, &store)?;
        if blocks.len() != params.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "got {} blocks, expected {}",
                blocks.len(),
                params.logical_blocks
            )));
        }

        zero_store(&params, &mut store)?;

        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut pos_map = Vec::with_capacity(params.logical_blocks);
        let mut stash = Vec::new();

        for (logical_id, payload) in blocks.into_iter().enumerate() {
            let leaf = random_leaf(&params, &mut rng);
            pos_map.push(leaf);
            stash.push(OramBlock::real(
                logical_id as u64,
                leaf,
                payload,
                params.block_size,
            )?);
        }

        let mut oram = Self {
            params,
            store,
            pos_map,
            stash,
            rng,
        };
        oram.greedy_flush_all()?;
        oram.pad_stash();
        oram.check_stash()?;
        Ok(oram)
    }

    /// Re-open an already initialized ORAM state.
    ///
    /// The caller must provide the current position map and stash. Production
    /// checkpointing is deliberately out of scope for v0.
    pub fn from_parts(
        params: OramParams,
        store: S,
        pos_map: Vec<u32>,
        stash: Vec<OramBlock>,
        seed: [u8; 32],
    ) -> Result<Self> {
        validate_store(&params, &store)?;
        if pos_map.len() != params.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "pos_map len {} != logical_blocks {}",
                pos_map.len(),
                params.logical_blocks
            )));
        }
        for &leaf in &pos_map {
            if leaf as usize >= params.leaves {
                return Err(Error::InvalidInput(format!("leaf {leaf} out of range")));
            }
        }
        let mut oram = Self {
            params,
            store,
            pos_map,
            stash,
            rng: ChaCha20Rng::from_seed(seed),
        };
        oram.pad_stash();
        oram.check_stash()?;
        Ok(oram)
    }

    /// Re-open an ORAM from a trusted controller state.
    pub fn from_state(store: S, state: OramState) -> Result<Self> {
        validate_store(&state.params, &store)?;
        if state.pos_map.len() != state.params.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "pos_map len {} != logical_blocks {}",
                state.pos_map.len(),
                state.params.logical_blocks
            )));
        }
        for &leaf in &state.pos_map {
            if leaf as usize >= state.params.leaves {
                return Err(Error::InvalidInput(format!("leaf {leaf} out of range")));
            }
        }
        let mut oram = Self {
            params: state.params,
            store,
            pos_map: state.pos_map,
            stash: state.stash,
            rng: state.rng,
        };
        oram.pad_stash();
        oram.check_stash()?;
        Ok(oram)
    }

    /// Snapshot the trusted controller state.
    pub fn snapshot(&self) -> OramState {
        OramState::new(
            self.params.clone(),
            self.pos_map.clone(),
            self.stash.clone(),
            self.rng.clone(),
        )
    }

    /// Immutable view of public parameters.
    pub fn params(&self) -> &OramParams {
        &self.params
    }

    /// Current stash length.
    pub fn stash_len(&self) -> usize {
        self.occupied_stash_len()
    }

    /// Borrow the current position map.
    pub fn position_map(&self) -> &[u32] {
        &self.pos_map
    }

    /// Borrow the current stash.
    pub fn stash(&self) -> &[OramBlock] {
        &self.stash
    }

    /// Consume the controller and return its storage.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Flush the underlying storage.
    pub fn flush(&mut self) -> Result<()> {
        self.store.flush()
    }

    /// Read a logical block.
    pub fn read(&mut self, logical_id: u64) -> Result<Vec<u8>> {
        self.access(logical_id, |_| {})
    }

    /// Read and update a logical block.
    pub fn access<F>(&mut self, logical_id: u64, update: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&mut [u8]),
    {
        if logical_id as usize >= self.params.logical_blocks {
            return Err(Error::InvalidInput(format!(
                "logical_id {logical_id} out of range"
            )));
        }

        let old_leaf = self.pos_map[logical_id as usize];
        let new_leaf = random_leaf(&self.params, &mut self.rng);
        self.pos_map[logical_id as usize] = new_leaf;

        let path = self.params.path_nodes(old_leaf);
        self.read_path_into_stash(&path)?;

        let mut found = 0u8;
        let mut output = vec![0u8; self.params.block_size];
        for block in &self.stash {
            let matched = block.logical_id_choice(logical_id);
            ct::cmov_bytes(&mut output, &block.payload, matched);
            found = ct::or(found, matched);
        }
        if found == 0 {
            return Err(Error::BlockNotFound(logical_id));
        }

        let mut new_payload = output.clone();
        update(&mut new_payload);
        for block in &mut self.stash {
            let matched = block.logical_id_choice(logical_id);
            ct::cmov_bytes(&mut block.payload, &new_payload, matched);
            ct::cmov_u32(&mut block.leaf, new_leaf, matched);
        }

        self.write_path_from_stash(&path)?;
        self.check_stash()?;
        Ok(output)
    }

    fn read_path_into_stash(&mut self, path: &[usize]) -> Result<()> {
        let mut buf = vec![0u8; self.params.bucket_bytes()];
        for &node in path {
            self.store.read_page(node, &mut buf)?;
            let bucket = Bucket::decode(&buf, self.params.bucket_size, self.params.block_size)?;
            for block in bucket.blocks {
                self.insert_into_stash(block)?;
            }
        }
        Ok(())
    }

    fn write_path_from_stash(&mut self, path: &[usize]) -> Result<()> {
        let mut path_by_depth = path.iter().copied().enumerate().collect::<Vec<_>>();
        path_by_depth.reverse();

        for (depth, node_idx) in path_by_depth {
            let mut bucket = Bucket::dummy(self.params.bucket_size, self.params.block_size);
            for slot in &mut bucket.blocks {
                let mut selected = OramBlock::dummy(self.params.block_size);
                let mut filled = 0u8;
                for stash_slot in &mut self.stash {
                    let occupied = ct::choice_from_bool(stash_slot.occupied);
                    let can_place = ct::and(
                        ct::and(occupied, ct::not(filled)),
                        Self::node_contains_leaf_choice(
                            &self.params,
                            depth,
                            node_idx,
                            stash_slot.leaf,
                        ),
                    );
                    selected.cmov_from(stash_slot, can_place);
                    stash_slot.clear_if(can_place, self.params.block_size);
                    filled = ct::or(filled, can_place);
                }
                *slot = selected;
            }
            let encoded = bucket.encode(self.params.bucket_size, self.params.block_size)?;
            self.store.write_page(node_idx, &encoded)?;
        }
        Ok(())
    }

    fn node_contains_leaf_choice(
        params: &OramParams,
        depth: usize,
        node_idx: usize,
        leaf: u32,
    ) -> ct::Choice {
        let safe_leaf = ((leaf as usize) & (params.leaves - 1)) as u32;
        ct::eq_usize(params.node_index(depth, safe_leaf), node_idx)
    }

    fn greedy_flush_all(&mut self) -> Result<()> {
        let mut buckets = (0..self.params.bucket_count())
            .map(|_| Bucket::dummy(self.params.bucket_size, self.params.block_size))
            .collect::<Vec<_>>();
        let mut remaining = Vec::new();

        for block in self.stash.drain(..) {
            let path = self.params.path_nodes(block.leaf);
            let mut pending = Some(block);
            for node_idx in path.into_iter().rev() {
                for slot in &mut buckets[node_idx].blocks {
                    if !slot.occupied {
                        *slot = pending.take().expect("pending block present");
                        break;
                    }
                }
                if pending.is_none() {
                    break;
                }
            }
            if let Some(block) = pending {
                remaining.push(block);
            }
        }

        self.stash = remaining;
        for (node_idx, bucket) in buckets.iter().enumerate() {
            let encoded = bucket.encode(self.params.bucket_size, self.params.block_size)?;
            self.store.write_page(node_idx, &encoded)?;
        }
        Ok(())
    }

    fn insert_into_stash(&mut self, block: OramBlock) -> Result<()> {
        let block_occupied = ct::choice_from_bool(block.occupied);
        let mut inserted = ct::not(block_occupied);
        for slot in &mut self.stash {
            let can_insert = ct::and(
                ct::and(block_occupied, ct::not(inserted)),
                ct::not(ct::choice_from_bool(slot.occupied)),
            );
            slot.cmov_from(&block, can_insert);
            inserted = ct::or(inserted, can_insert);
        }

        if inserted == 0 {
            return Err(Error::StashOverflow {
                len: self.params.stash_capacity + 1,
                capacity: self.params.stash_capacity,
            });
        }
        Ok(())
    }

    fn pad_stash(&mut self) {
        if self.stash.len() > self.params.stash_capacity {
            return;
        }
        self.stash.resize_with(self.params.stash_capacity, || {
            OramBlock::dummy(self.params.block_size)
        });
    }

    fn occupied_stash_len(&self) -> usize {
        self.stash.iter().filter(|block| block.occupied).count()
    }

    fn check_stash(&self) -> Result<()> {
        let occupied = self.occupied_stash_len();
        if occupied > self.params.stash_capacity {
            return Err(Error::StashOverflow {
                len: occupied,
                capacity: self.params.stash_capacity,
            });
        }
        if self.stash.len() != self.params.stash_capacity {
            return Err(Error::InvalidInput(format!(
                "stash slots {} != stash_capacity {}",
                self.stash.len(),
                self.params.stash_capacity
            )));
        }
        Ok(())
    }
}

fn validate_store(params: &OramParams, store: &impl PageStore) -> Result<()> {
    if store.page_count() != params.bucket_count() {
        return Err(Error::InvalidInput(format!(
            "store has {} pages, expected {}",
            store.page_count(),
            params.bucket_count()
        )));
    }
    if store.page_size() != params.bucket_bytes() {
        return Err(Error::InvalidInput(format!(
            "store page_size {} != bucket_bytes {}",
            store.page_size(),
            params.bucket_bytes()
        )));
    }
    Ok(())
}

fn zero_store(params: &OramParams, store: &mut impl PageStore) -> Result<()> {
    let empty = Bucket::dummy(params.bucket_size, params.block_size)
        .encode(params.bucket_size, params.block_size)?;
    for page_idx in 0..params.bucket_count() {
        store.write_page(page_idx, &empty)?;
    }
    Ok(())
}

fn random_leaf(params: &OramParams, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
    (rng.next_u64() as usize % params.leaves) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AeadPageStore, FilePageStore, MemPageStore, TracingStore, AEAD_OVERHEAD};
    use std::collections::HashSet;

    fn blocks(n: usize, block_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut block = vec![0u8; block_size];
                block[..8].copy_from_slice(&(i as u64).to_le_bytes());
                block
            })
            .collect()
    }

    #[test]
    fn mem_oram_roundtrip() {
        let params = OramParams::with_leaves(64, 32, 64).unwrap();
        let store = MemPageStore::new(params.bucket_count(), params.bucket_bytes()).unwrap();
        let mut oram = PathOram::build_trusted(params, store, blocks(64, 32), [7; 32]).unwrap();

        for logical_id in [0u64, 7, 31, 63, 7, 0] {
            let got = oram.read(logical_id).unwrap();
            assert_eq!(&got[..8], &logical_id.to_le_bytes());
        }
    }

    #[test]
    fn update_changes_payload() {
        let params = OramParams::with_leaves(32, 16, 32).unwrap();
        let store = MemPageStore::new(params.bucket_count(), params.bucket_bytes()).unwrap();
        let mut oram = PathOram::build_trusted(params, store, blocks(32, 16), [9; 32]).unwrap();

        let old = oram
            .access(5, |payload| {
                payload[..8].copy_from_slice(&999u64.to_le_bytes())
            })
            .unwrap();
        assert_eq!(&old[..8], &5u64.to_le_bytes());
        let new = oram.read(5).unwrap();
        assert_eq!(&new[..8], &999u64.to_le_bytes());
    }

    #[test]
    fn trace_shape_is_fixed_per_access() {
        let params = OramParams::with_leaves(16, 16, 16).unwrap();
        let store = TracingStore::new(
            MemPageStore::new(params.bucket_count(), params.bucket_bytes()).unwrap(),
        );
        let mut oram =
            PathOram::build_trusted(params.clone(), store, blocks(16, 16), [11; 32]).unwrap();
        oram.store.take_trace();

        let _ = oram.read(1).unwrap();
        let trace_a = oram.store.take_trace();
        let _ = oram.read(9).unwrap();
        let trace_b = oram.store.take_trace();

        assert_eq!(trace_a.len(), params.height() * 2);
        assert_eq!(trace_b.len(), params.height() * 2);
        assert_eq!(
            trace_a
                .iter()
                .filter(|event| matches!(event, crate::store::TraceEvent::Read(_)))
                .count(),
            params.height()
        );
        assert_eq!(
            trace_a
                .iter()
                .filter(|event| matches!(event, crate::store::TraceEvent::Write(_)))
                .count(),
            params.height()
        );
        assert_eq!(trace_a.len(), trace_b.len());
    }

    #[test]
    fn paths_cover_distinct_nodes_per_depth() {
        let params = OramParams::with_leaves(8, 8, 8).unwrap();
        let path = params.path_nodes(5);
        assert_eq!(path.len(), params.height());
        assert_eq!(path[0], 0);
        assert_eq!(
            path[path.len() - 1],
            params.node_index(params.height() - 1, 5)
        );
        assert_eq!(
            path.iter().copied().collect::<HashSet<_>>().len(),
            path.len()
        );
    }

    #[test]
    fn file_and_aead_store_roundtrip() {
        let params = OramParams::with_leaves(16, 24, 16).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oram.pages");
        let file = FilePageStore::open(
            &path,
            params.bucket_count(),
            params.bucket_bytes() + AEAD_OVERHEAD,
        )
        .unwrap();
        let encrypted = AeadPageStore::new(file, [42; 32], params.bucket_bytes()).unwrap();
        let mut oram =
            PathOram::build_trusted(params, encrypted, blocks(16, 24), [13; 32]).unwrap();

        let got = oram.read(12).unwrap();
        assert_eq!(&got[..8], &12u64.to_le_bytes());
    }

    #[test]
    fn state_roundtrip_reopens_controller() {
        let params = OramParams::with_leaves(32, 16, 32).unwrap();
        let store = MemPageStore::new(params.bucket_count(), params.bucket_bytes()).unwrap();
        let mut oram =
            PathOram::build_trusted(params.clone(), store, blocks(32, 16), [17; 32]).unwrap();
        assert_eq!(&oram.read(3).unwrap()[..8], &3u64.to_le_bytes());

        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("controller.state");
        let snapshot = oram.snapshot();
        snapshot.save_atomic(&state_path).unwrap();
        let state = OramState::load(&state_path).unwrap();
        let store = oram.into_store();
        let mut reopened = PathOram::from_state(store, state).unwrap();

        assert_eq!(&reopened.read(3).unwrap()[..8], &3u64.to_le_bytes());
        assert_eq!(&reopened.read(29).unwrap()[..8], &29u64.to_le_bytes());
    }

    #[test]
    fn stash_uses_fixed_capacity_slots() {
        let params = OramParams::with_leaves(64, 16, 64)
            .unwrap()
            .with_stash_capacity(256)
            .unwrap();
        let store = MemPageStore::new(params.bucket_count(), params.bucket_bytes()).unwrap();
        let mut oram =
            PathOram::build_trusted(params.clone(), store, blocks(64, 16), [19; 32]).unwrap();

        assert_eq!(oram.stash().len(), params.stash_capacity);
        assert_eq!(oram.stash_len(), 0);

        for logical_id in [1u64, 2, 3, 4, 5, 1, 63, 0] {
            let got = oram.read(logical_id).unwrap();
            assert_eq!(&got[..8], &logical_id.to_le_bytes());
            assert_eq!(oram.stash().len(), params.stash_capacity);
        }
    }
}
