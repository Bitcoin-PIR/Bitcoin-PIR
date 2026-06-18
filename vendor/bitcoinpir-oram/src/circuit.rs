//! Circuit ORAM design helpers.
//!
//! This module contains public scheduling state shared by the planned
//! disk-backed Circuit ORAM controller and the stash-pressure simulator. The
//! schedule is intentionally independent of logical addresses and stash
//! occupancy: real accesses add a fixed amount of public eviction debt, and
//! background work drains that debt in reverse-bit order.

use crate::{
    ct, CircuitOramState, CircuitStoreAuthState, Error, OramBlock, OramParams, PageStore, Result,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

const META_OCCUPIED: u8 = 1;
const META_EMPTY: u8 = 0;

/// Public eviction schedule for deterministic Circuit ORAM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CircuitEvictionSchedule {
    leaf_bits: u32,
    evictions_per_access: u64,
    issued_accesses: u64,
    completed_evictions: u64,
}

impl CircuitEvictionSchedule {
    /// Circuit ORAM's deterministic variant uses two eviction paths per access.
    pub const DEFAULT_EVICTIONS_PER_ACCESS: u64 = 2;

    /// Construct a schedule for the leaf count in `params`.
    pub fn new(params: &OramParams) -> Self {
        Self::with_rate(params, Self::DEFAULT_EVICTIONS_PER_ACCESS)
    }

    /// Construct a schedule with an explicit public eviction rate.
    pub fn with_rate(params: &OramParams, evictions_per_access: u64) -> Self {
        debug_assert!(params.leaves.is_power_of_two());
        debug_assert!(params.leaves <= u32::MAX as usize);
        Self {
            leaf_bits: params.leaf_bits() as u32,
            evictions_per_access,
            issued_accesses: 0,
            completed_evictions: 0,
        }
    }

    /// Reconstruct a schedule from checkpointed public counters.
    pub fn from_counters(
        params: &OramParams,
        evictions_per_access: u64,
        issued_accesses: u64,
        completed_evictions: u64,
    ) -> Result<Self> {
        let schedule = Self {
            leaf_bits: params.leaf_bits() as u32,
            evictions_per_access,
            issued_accesses,
            completed_evictions,
        };
        schedule.pending_evictions()?;
        Ok(schedule)
    }

    /// Record one real ORAM access, adding public eviction debt.
    pub fn record_access(&mut self) -> Result<()> {
        self.issued_accesses = self
            .issued_accesses
            .checked_add(1)
            .ok_or_else(|| Error::InvalidInput("access counter overflow".into()))?;
        Ok(())
    }

    /// Number of completed real ORAM accesses.
    pub const fn issued_accesses(&self) -> u64 {
        self.issued_accesses
    }

    /// Number of completed background eviction paths.
    pub const fn completed_evictions(&self) -> u64 {
        self.completed_evictions
    }

    /// Public number of eviction paths scheduled per real access.
    pub const fn evictions_per_access(&self) -> u64 {
        self.evictions_per_access
    }

    /// Public eviction paths that have been scheduled but not yet processed.
    pub fn pending_evictions(&self) -> Result<u64> {
        let scheduled = self
            .issued_accesses
            .checked_mul(self.evictions_per_access)
            .ok_or_else(|| Error::InvalidInput("eviction counter overflow".into()))?;
        scheduled
            .checked_sub(self.completed_evictions)
            .ok_or_else(|| Error::InvalidInput("completed evictions exceed schedule".into()))
    }

    /// Check that checkpointed public counters match this ORAM tree.
    pub fn validate_for_params(&self, params: &OramParams) -> Result<()> {
        if self.leaf_bits != params.leaf_bits() as u32 {
            return Err(Error::InvalidInput(format!(
                "schedule leaf_bits {} != params leaf_bits {}",
                self.leaf_bits,
                params.leaf_bits()
            )));
        }
        self.pending_evictions()?;
        Ok(())
    }

    /// Leaf for the next deterministic eviction path, even if no debt is due.
    pub fn next_eviction_leaf(&self) -> u32 {
        reverse_bits_mod(self.completed_evictions, self.leaf_bits)
    }

    /// Drain one pending eviction path if any debt exists.
    pub fn complete_one_eviction(&mut self) -> Result<Option<u32>> {
        if self.pending_evictions()? == 0 {
            return Ok(None);
        }
        let leaf = self.next_eviction_leaf();
        self.completed_evictions = self
            .completed_evictions
            .checked_add(1)
            .ok_or_else(|| Error::InvalidInput("eviction counter overflow".into()))?;
        Ok(Some(leaf))
    }

    /// Drain up to `budget` public eviction paths.
    pub fn drain_evictions(&mut self, budget: u64) -> Result<Vec<u32>> {
        let mut leaves = Vec::new();
        for _ in 0..budget {
            match self.complete_one_eviction()? {
                Some(leaf) => leaves.push(leaf),
                None => break,
            }
        }
        Ok(leaves)
    }

    /// Leaf selected by the global deterministic eviction index.
    pub fn eviction_leaf_at(params: &OramParams, eviction_index: u64) -> u32 {
        reverse_bits_mod(eviction_index, params.leaf_bits() as u32)
    }
}

fn reverse_bits_mod(index: u64, leaf_bits: u32) -> u32 {
    debug_assert!(leaf_bits > 0);
    debug_assert!(leaf_bits <= 32);
    let mask = if leaf_bits == 32 {
        u32::MAX
    } else {
        (1u32 << leaf_bits) - 1
    };
    let low = (index as u32) & mask;
    low.reverse_bits() >> (32 - leaf_bits)
}

/// One metadata slot in a split Circuit ORAM bucket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitMetaSlot {
    /// Whether the slot contains a real block.
    pub occupied: bool,
    /// Logical block id. Meaningful only when `occupied`.
    pub logical_id: u64,
    /// Current random leaf label. Meaningful only when `occupied`.
    pub leaf: u32,
}

impl CircuitMetaSlot {
    /// Bytes per serialized metadata slot.
    pub const SERIALIZED_LEN: usize = 1 + 8 + 4;

    /// Construct a dummy metadata slot.
    pub const fn dummy() -> Self {
        Self {
            occupied: false,
            logical_id: u64::MAX,
            leaf: u32::MAX,
        }
    }

    /// Construct a real metadata slot.
    pub const fn real(logical_id: u64, leaf: u32) -> Self {
        Self {
            occupied: true,
            logical_id,
            leaf,
        }
    }

    fn encode_into(&self, out: &mut [u8]) -> Result<()> {
        if out.len() != Self::SERIALIZED_LEN {
            return Err(Error::InvalidInput(format!(
                "meta output len {} != expected {}",
                out.len(),
                Self::SERIALIZED_LEN
            )));
        }
        out[0] = if self.occupied {
            META_OCCUPIED
        } else {
            META_EMPTY
        };
        out[1..9].copy_from_slice(&self.logical_id.to_le_bytes());
        out[9..13].copy_from_slice(&self.leaf.to_le_bytes());
        Ok(())
    }

    fn decode_from(input: &[u8]) -> Result<Self> {
        if input.len() != Self::SERIALIZED_LEN {
            return Err(Error::InvalidInput(format!(
                "meta input len {} != expected {}",
                input.len(),
                Self::SERIALIZED_LEN
            )));
        }
        let occupied = match input[0] {
            META_EMPTY => false,
            META_OCCUPIED => true,
            other => {
                return Err(Error::InvalidInput(format!(
                    "invalid meta occupied byte {other}"
                )));
            }
        };
        let mut logical_id = [0u8; 8];
        logical_id.copy_from_slice(&input[1..9]);
        let mut leaf = [0u8; 4];
        leaf.copy_from_slice(&input[9..13]);
        Ok(Self {
            occupied,
            logical_id: u64::from_le_bytes(logical_id),
            leaf: u32::from_le_bytes(leaf),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CircuitMetaBucket {
    slots: Vec<CircuitMetaSlot>,
}

impl CircuitMetaBucket {
    fn dummy(bucket_size: usize) -> Self {
        Self {
            slots: vec![CircuitMetaSlot::dummy(); bucket_size],
        }
    }

    fn encode(&self, bucket_size: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; circuit_meta_page_bytes(bucket_size)];
        self.encode_into(bucket_size, &mut out)?;
        Ok(out)
    }

    fn encode_into(&self, bucket_size: usize, out: &mut [u8]) -> Result<()> {
        if self.slots.len() != bucket_size {
            return Err(Error::InvalidInput(format!(
                "meta bucket has {} slots, expected {}",
                self.slots.len(),
                bucket_size
            )));
        }
        let expected = circuit_meta_page_bytes(bucket_size);
        if out.len() != expected {
            return Err(Error::InvalidInput(format!(
                "meta output len {} != expected {}",
                out.len(),
                expected
            )));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            let start = i * CircuitMetaSlot::SERIALIZED_LEN;
            slot.encode_into(&mut out[start..start + CircuitMetaSlot::SERIALIZED_LEN])?;
        }
        Ok(())
    }

    fn decode(input: &[u8], bucket_size: usize) -> Result<Self> {
        let expected = circuit_meta_page_bytes(bucket_size);
        if input.len() != expected {
            return Err(Error::InvalidInput(format!(
                "meta bucket input len {} != expected {}",
                input.len(),
                expected
            )));
        }
        let mut slots = Vec::with_capacity(bucket_size);
        for chunk in input.chunks_exact(CircuitMetaSlot::SERIALIZED_LEN) {
            slots.push(CircuitMetaSlot::decode_from(chunk)?);
        }
        Ok(Self { slots })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CircuitPayloadBucket {
    slots: Vec<Vec<u8>>,
}

impl CircuitPayloadBucket {
    fn dummy(bucket_size: usize, block_size: usize) -> Self {
        Self {
            slots: (0..bucket_size).map(|_| vec![0u8; block_size]).collect(),
        }
    }

    fn encode(&self, bucket_size: usize, block_size: usize) -> Result<Vec<u8>> {
        if self.slots.len() != bucket_size {
            return Err(Error::InvalidInput(format!(
                "payload bucket has {} slots, expected {}",
                self.slots.len(),
                bucket_size
            )));
        }
        let mut out = vec![0u8; circuit_payload_page_bytes(bucket_size, block_size)];
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.len() != block_size {
                return Err(Error::InvalidInput(format!(
                    "payload slot len {} != block_size {}",
                    slot.len(),
                    block_size
                )));
            }
            let start = i * block_size;
            out[start..start + block_size].copy_from_slice(slot);
        }
        Ok(out)
    }

    fn decode(input: &[u8], bucket_size: usize, block_size: usize) -> Result<Self> {
        let expected = circuit_payload_page_bytes(bucket_size, block_size);
        if input.len() != expected {
            return Err(Error::InvalidInput(format!(
                "payload bucket input len {} != expected {}",
                input.len(),
                expected
            )));
        }
        let slots = input
            .chunks_exact(block_size)
            .map(|chunk| chunk.to_vec())
            .collect();
        Ok(Self { slots })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CircuitEvictionSource {
    Path { depth: usize, slot: usize },
    Stash { slot: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CircuitEvictionCandidate {
    meta: CircuitMetaSlot,
    source: CircuitEvictionSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CircuitEvictionPlacement {
    candidate_idx: Option<usize>,
}

impl CircuitEvictionPlacement {
    const fn dummy() -> Self {
        Self {
            candidate_idx: None,
        }
    }

    const fn real(candidate_idx: usize) -> Self {
        Self {
            candidate_idx: Some(candidate_idx),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CircuitEvictionPlan {
    candidates: Vec<CircuitEvictionCandidate>,
    placements: Vec<Vec<CircuitEvictionPlacement>>,
    selected: Vec<bool>,
    path_candidate_indices: Vec<Vec<Option<usize>>>,
}

/// Plaintext bytes in one metadata bucket page.
pub const fn circuit_meta_page_bytes(bucket_size: usize) -> usize {
    bucket_size * CircuitMetaSlot::SERIALIZED_LEN
}

/// Plaintext bytes in one payload bucket page.
pub const fn circuit_payload_page_bytes(bucket_size: usize, block_size: usize) -> usize {
    bucket_size * block_size
}

/// Trusted random-access source for offline Circuit ORAM initialization.
///
/// Initialization is intentionally non-oblivious: it happens before the ORAM
/// image is exposed to an adversarial storage trace. The online controller only
/// relies on the resulting bucket pages and trusted state.
pub trait TrustedBlockSource {
    /// Number of logical ORAM blocks available from this source.
    fn logical_blocks(&self) -> usize;

    /// Fixed payload bytes in each logical ORAM block.
    fn block_size(&self) -> usize;

    /// Read one logical block payload.
    fn read_block(&mut self, logical_id: usize) -> Result<Vec<u8>>;
}

struct VecBlockSource {
    blocks: Vec<Vec<u8>>,
    block_size: usize,
}

impl VecBlockSource {
    fn new(blocks: Vec<Vec<u8>>, block_size: usize) -> Self {
        Self { blocks, block_size }
    }
}

impl TrustedBlockSource for VecBlockSource {
    fn logical_blocks(&self) -> usize {
        self.blocks.len()
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn read_block(&mut self, logical_id: usize) -> Result<Vec<u8>> {
        self.blocks.get(logical_id).cloned().ok_or_else(|| {
            Error::InvalidInput(format!(
                "logical block {} out of range {}",
                logical_id,
                self.blocks.len()
            ))
        })
    }
}

/// Split-store Circuit ORAM controller prototype.
///
/// This controller implements the Circuit ORAM access shape and public
/// deterministic eviction schedule over separate metadata and payload stores.
/// The current eviction implementation uses greedy path eviction; the exact
/// `deepest`/`target` metadata scans from the Circuit ORAM paper can replace
/// `write_path_from_stash` without changing the public scheduler or store
/// layout.
#[derive(Debug)]
pub struct CircuitOram<M, P> {
    params: OramParams,
    meta_store: M,
    payload_store: P,
    pos_map: Vec<u32>,
    stash: Vec<OramBlock>,
    rng: ChaCha20Rng,
    schedule: CircuitEvictionSchedule,
}

impl<M: PageStore, P: PageStore> CircuitOram<M, P> {
    /// Build a trusted initial Circuit ORAM image from logical blocks.
    ///
    /// This initialization is non-oblivious and intended for offline image
    /// creation before exposing storage traces.
    pub fn build_trusted(
        params: OramParams,
        meta_store: M,
        payload_store: P,
        blocks: Vec<Vec<u8>>,
        seed: [u8; 32],
    ) -> Result<Self> {
        let block_size = params.block_size;
        Self::build_trusted_from_source(
            params,
            meta_store,
            payload_store,
            VecBlockSource::new(blocks, block_size),
            seed,
        )
    }

    /// Build a trusted initial Circuit ORAM image from a streaming block source.
    ///
    /// This compatibility helper materializes the iterator and then uses the
    /// random-access builder. Real cuckoo table builds should call
    /// [`Self::build_trusted_from_source`] directly so payloads are not kept in
    /// memory.
    pub fn build_trusted_from_iter<I>(
        params: OramParams,
        meta_store: M,
        payload_store: P,
        blocks: I,
        seed: [u8; 32],
    ) -> Result<Self>
    where
        I: IntoIterator<Item = Result<Vec<u8>>>,
    {
        let blocks = blocks.into_iter().collect::<Result<Vec<_>>>()?;
        Self::build_trusted(params, meta_store, payload_store, blocks, seed)
    }

    /// Build a trusted initial Circuit ORAM image from a random-access source.
    ///
    /// This keeps only bucket metadata and the fixed stash in memory. The build
    /// first plans block placement using metadata, then writes metadata and
    /// payload bucket pages sequentially exactly once. It avoids the previous
    /// per-block read/modify/write loop over the payload image, which is the
    /// expensive part for encrypted disk-backed stores.
    pub fn build_trusted_from_source<S>(
        params: OramParams,
        mut meta_store: M,
        mut payload_store: P,
        mut source: S,
        seed: [u8; 32],
    ) -> Result<Self>
    where
        S: TrustedBlockSource,
    {
        validate_circuit_stores(&params, &meta_store, &payload_store)?;
        validate_block_source(&params, &source)?;

        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut pos_map = vec![0u32; params.logical_blocks];
        let mut stash = Vec::new();
        let mut initial_stash_ids = Vec::new();
        let mut meta_buckets = (0..params.bucket_count())
            .map(|_| CircuitMetaBucket::dummy(params.bucket_size))
            .collect::<Vec<_>>();

        for (logical_id, pos) in pos_map.iter_mut().enumerate() {
            let leaf = random_leaf(&params, &mut rng);
            *pos = leaf;
            if !place_initial_meta(&params, &mut meta_buckets, logical_id as u64, leaf)? {
                initial_stash_ids.push((logical_id, leaf));
                if initial_stash_ids.len() > params.stash_capacity {
                    return Err(Error::StashOverflow {
                        len: initial_stash_ids.len(),
                        capacity: params.stash_capacity,
                    });
                }
            }
        }

        write_initial_metadata(&params, &mut meta_store, &meta_buckets)?;
        write_initial_payloads(&params, &mut payload_store, &meta_buckets, &mut source)?;

        for (logical_id, leaf) in initial_stash_ids {
            let payload = read_source_block(&params, &mut source, logical_id)?;
            stash.push(OramBlock::real(
                logical_id as u64,
                leaf,
                payload,
                params.block_size,
            )?);
        }

        let mut oram = Self {
            schedule: CircuitEvictionSchedule::new(&params),
            params,
            meta_store,
            payload_store,
            pos_map,
            stash,
            rng,
        };
        oram.pad_stash();
        oram.check_stash()?;
        Ok(oram)
    }

    /// Re-open a split-store Circuit ORAM from trusted controller state.
    pub fn from_state(meta_store: M, payload_store: P, state: CircuitOramState) -> Result<Self> {
        validate_circuit_stores(&state.params, &meta_store, &payload_store)?;
        validate_circuit_state(&state.params, &state.pos_map, &state.stash, &state.schedule)?;
        let mut oram = Self {
            params: state.params,
            meta_store,
            payload_store,
            pos_map: state.pos_map,
            stash: state.stash,
            rng: state.rng,
            schedule: state.schedule,
        };
        oram.pad_stash();
        oram.check_stash()?;
        Ok(oram)
    }

    /// Snapshot the trusted Circuit ORAM controller state.
    pub fn snapshot(&self) -> CircuitOramState {
        CircuitOramState::new(
            self.params.clone(),
            self.pos_map.clone(),
            self.stash.clone(),
            self.rng.clone(),
            self.schedule.clone(),
        )
    }

    /// Immutable view of public ORAM parameters.
    pub fn params(&self) -> &OramParams {
        &self.params
    }

    /// Borrow the public deterministic eviction schedule.
    pub fn schedule(&self) -> &CircuitEvictionSchedule {
        &self.schedule
    }

    /// Current public pending eviction debt.
    pub fn pending_evictions(&self) -> Result<u64> {
        self.schedule.pending_evictions()
    }

    /// Current occupied stash slots.
    pub fn stash_len(&self) -> usize {
        self.occupied_stash_len()
    }

    /// Borrow the current position map.
    pub fn position_map(&self) -> &[u32] {
        &self.pos_map
    }

    /// Borrow the current fixed-capacity stash.
    pub fn stash(&self) -> &[OramBlock] {
        &self.stash
    }

    /// Consume the controller and return metadata and payload stores.
    pub fn into_stores(self) -> (M, P) {
        (self.meta_store, self.payload_store)
    }

    /// Flush both backing stores.
    pub fn flush(&mut self) -> Result<()> {
        self.meta_store.flush()?;
        self.payload_store.flush()
    }

    /// Snapshot authenticated page-store roots, if both stores provide them.
    pub fn store_auth_state(&self) -> Option<CircuitStoreAuthState> {
        Some(CircuitStoreAuthState::new(
            self.meta_store.tiered_merkle_state()?,
            self.payload_store.tiered_merkle_state()?,
        ))
    }

    /// Read a logical block and schedule public background eviction debt.
    pub fn read(&mut self, logical_id: u64) -> Result<Vec<u8>> {
        self.access(logical_id, |_| {})
    }

    /// Read and update a logical block. Eviction is delayed until
    /// `drain_evictions` is called.
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
        self.read_and_remove_target_path(old_leaf, logical_id)?;

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

        let new_leaf = random_leaf(&self.params, &mut self.rng);
        self.pos_map[logical_id as usize] = new_leaf;
        let mut new_payload = output.clone();
        update(&mut new_payload);
        for block in &mut self.stash {
            let matched = block.logical_id_choice(logical_id);
            ct::cmov_bytes(&mut block.payload, &new_payload, matched);
            ct::cmov_u32(&mut block.leaf, new_leaf, matched);
        }

        self.schedule.record_access()?;
        self.check_stash()?;
        Ok(output)
    }

    /// Drain up to `budget` pending public eviction paths.
    pub fn drain_evictions(&mut self, budget: u64) -> Result<u64> {
        let mut drained = 0u64;
        for _ in 0..budget {
            if self.schedule.pending_evictions()? == 0 {
                break;
            }
            let leaf = self.schedule.next_eviction_leaf();
            self.evict_path(leaf)?;
            let completed = self.schedule.complete_one_eviction()?;
            debug_assert_eq!(completed, Some(leaf));
            drained += 1;
        }
        self.check_stash()?;
        Ok(drained)
    }

    fn read_and_remove_target_path(&mut self, leaf: u32, logical_id: u64) -> Result<()> {
        let path = self.params.path_nodes(leaf);
        let mut meta_buf = vec![0u8; circuit_meta_page_bytes(self.params.bucket_size)];
        let mut payload_buf =
            vec![0u8; circuit_payload_page_bytes(self.params.bucket_size, self.params.block_size)];

        for node_idx in path {
            self.meta_store.read_page(node_idx, &mut meta_buf)?;
            self.payload_store.read_page(node_idx, &mut payload_buf)?;
            let mut meta_bucket = CircuitMetaBucket::decode(&meta_buf, self.params.bucket_size)?;
            let mut payload_bucket = CircuitPayloadBucket::decode(
                &payload_buf,
                self.params.bucket_size,
                self.params.block_size,
            )?;

            let mut removed = false;
            for (slot_idx, meta) in meta_bucket.slots.iter_mut().enumerate() {
                if meta.occupied && meta.logical_id == logical_id && !removed {
                    let payload = payload_bucket.slots[slot_idx].clone();
                    self.insert_into_stash(OramBlock::real(
                        logical_id,
                        meta.leaf,
                        payload,
                        self.params.block_size,
                    )?)?;
                    *meta = CircuitMetaSlot::dummy();
                    payload_bucket.slots[slot_idx].fill(0);
                    removed = true;
                }
            }

            let encoded_meta = meta_bucket.encode(self.params.bucket_size)?;
            let encoded_payload =
                payload_bucket.encode(self.params.bucket_size, self.params.block_size)?;
            self.meta_store.write_page(node_idx, &encoded_meta)?;
            self.payload_store.write_page(node_idx, &encoded_payload)?;
        }
        Ok(())
    }

    fn evict_path(&mut self, leaf: u32) -> Result<()> {
        let path = self.params.path_nodes(leaf);
        let deepest_meta = self.read_path_metadata(&path)?;
        let target_meta = self.read_path_metadata(&path)?;
        debug_assert_eq!(deepest_meta, target_meta);
        let plan = self.plan_eviction_placements(&path, &target_meta)?;
        self.apply_eviction_plan(&path, &target_meta, plan)?;
        Ok(())
    }

    fn read_path_metadata(&mut self, path: &[usize]) -> Result<Vec<CircuitMetaBucket>> {
        let mut meta_buf = vec![0u8; circuit_meta_page_bytes(self.params.bucket_size)];
        let mut buckets = Vec::with_capacity(path.len());
        for &node_idx in path {
            self.meta_store.read_page(node_idx, &mut meta_buf)?;
            buckets.push(CircuitMetaBucket::decode(
                &meta_buf,
                self.params.bucket_size,
            )?);
        }
        Ok(buckets)
    }

    fn plan_eviction_placements(
        &self,
        path: &[usize],
        path_meta: &[CircuitMetaBucket],
    ) -> Result<CircuitEvictionPlan> {
        if path.len() != self.params.height() || path_meta.len() != self.params.height() {
            return Err(Error::InvalidInput(
                "eviction path metadata length does not match tree height".into(),
            ));
        }

        let mut candidates = Vec::new();
        let mut path_candidate_indices =
            vec![vec![None; self.params.bucket_size]; self.params.height()];

        for (slot_idx, block) in self.stash.iter().enumerate() {
            if block.occupied {
                candidates.push(CircuitEvictionCandidate {
                    meta: CircuitMetaSlot::real(block.logical_id, block.leaf),
                    source: CircuitEvictionSource::Stash { slot: slot_idx },
                });
            }
        }

        for (depth, bucket) in path_meta.iter().enumerate() {
            if bucket.slots.len() != self.params.bucket_size {
                return Err(Error::InvalidInput(format!(
                    "metadata bucket at depth {} has {} slots, expected {}",
                    depth,
                    bucket.slots.len(),
                    self.params.bucket_size
                )));
            }
            for (slot_idx, meta) in bucket.slots.iter().enumerate() {
                if meta.occupied {
                    let candidate_idx = candidates.len();
                    candidates.push(CircuitEvictionCandidate {
                        meta: *meta,
                        source: CircuitEvictionSource::Path {
                            depth,
                            slot: slot_idx,
                        },
                    });
                    path_candidate_indices[depth][slot_idx] = Some(candidate_idx);
                }
            }
        }

        let mut placements = vec![
            vec![CircuitEvictionPlacement::dummy(); self.params.bucket_size];
            self.params.height()
        ];
        let mut selected = vec![false; candidates.len()];

        for depth in (0..self.params.height()).rev() {
            let node_idx = path[depth];
            for placement in &mut placements[depth] {
                for (candidate_idx, candidate) in candidates.iter().enumerate() {
                    if selected[candidate_idx] {
                        continue;
                    }
                    if self
                        .params
                        .node_contains_leaf(depth, node_idx, candidate.meta.leaf)
                    {
                        *placement = CircuitEvictionPlacement::real(candidate_idx);
                        selected[candidate_idx] = true;
                        break;
                    }
                }
            }
        }

        Ok(CircuitEvictionPlan {
            candidates,
            placements,
            selected,
            path_candidate_indices,
        })
    }

    fn apply_eviction_plan(
        &mut self,
        path: &[usize],
        path_meta: &[CircuitMetaBucket],
        plan: CircuitEvictionPlan,
    ) -> Result<()> {
        let mut payloads = self.load_eviction_payloads(path, path_meta, &plan)?;
        self.ensure_eviction_stash_capacity(&plan)?;

        for (candidate_idx, candidate) in plan.candidates.iter().enumerate() {
            if plan.selected[candidate_idx] {
                if let CircuitEvictionSource::Stash { slot } = candidate.source {
                    self.stash[slot].clear_if(1, self.params.block_size);
                }
            }
        }

        for (candidate_idx, candidate) in plan.candidates.iter().enumerate() {
            if !plan.selected[candidate_idx] {
                if let CircuitEvictionSource::Path { .. } = candidate.source {
                    self.insert_into_stash(OramBlock::real(
                        candidate.meta.logical_id,
                        candidate.meta.leaf,
                        std::mem::take(&mut payloads[candidate_idx]),
                        self.params.block_size,
                    )?)?;
                }
            }
        }

        for (depth, &node_idx) in path.iter().enumerate() {
            let mut meta_bucket = CircuitMetaBucket::dummy(self.params.bucket_size);
            let mut payload_bucket =
                CircuitPayloadBucket::dummy(self.params.bucket_size, self.params.block_size);
            for (slot_idx, placement) in plan.placements[depth].iter().enumerate() {
                if let Some(candidate_idx) = placement.candidate_idx {
                    let candidate = &plan.candidates[candidate_idx];
                    meta_bucket.slots[slot_idx] = candidate.meta;
                    payload_bucket.slots[slot_idx] = payloads[candidate_idx].clone();
                }
            }

            let encoded_meta = meta_bucket.encode(self.params.bucket_size)?;
            let encoded_payload =
                payload_bucket.encode(self.params.bucket_size, self.params.block_size)?;
            self.meta_store.write_page(node_idx, &encoded_meta)?;
            self.payload_store.write_page(node_idx, &encoded_payload)?;
        }
        Ok(())
    }

    fn load_eviction_payloads(
        &mut self,
        path: &[usize],
        path_meta: &[CircuitMetaBucket],
        plan: &CircuitEvictionPlan,
    ) -> Result<Vec<Vec<u8>>> {
        if path.len() != path_meta.len() || path.len() != plan.path_candidate_indices.len() {
            return Err(Error::InvalidInput(
                "eviction payload path length mismatch".into(),
            ));
        }

        let mut payloads = vec![vec![0u8; self.params.block_size]; plan.candidates.len()];
        for (candidate_idx, candidate) in plan.candidates.iter().enumerate() {
            if let CircuitEvictionSource::Stash { slot } = candidate.source {
                payloads[candidate_idx].copy_from_slice(&self.stash[slot].payload);
            }
        }

        let mut payload_buf =
            vec![0u8; circuit_payload_page_bytes(self.params.bucket_size, self.params.block_size)];
        for (depth, &node_idx) in path.iter().enumerate() {
            self.payload_store.read_page(node_idx, &mut payload_buf)?;
            let payload_bucket = CircuitPayloadBucket::decode(
                &payload_buf,
                self.params.bucket_size,
                self.params.block_size,
            )?;
            for (slot_idx, candidate_idx) in plan.path_candidate_indices[depth].iter().enumerate() {
                if let Some(candidate_idx) = candidate_idx {
                    payloads[*candidate_idx].copy_from_slice(&payload_bucket.slots[slot_idx]);
                }
            }
        }
        Ok(payloads)
    }

    fn ensure_eviction_stash_capacity(&self, plan: &CircuitEvictionPlan) -> Result<()> {
        let mut selected_stash = 0usize;
        let mut unselected_path = 0usize;

        for (candidate_idx, candidate) in plan.candidates.iter().enumerate() {
            match candidate.source {
                CircuitEvictionSource::Stash { .. } => {
                    if plan.selected[candidate_idx] {
                        selected_stash += 1;
                    }
                }
                CircuitEvictionSource::Path { .. } => {
                    if !plan.selected[candidate_idx] {
                        unselected_path += 1;
                    }
                }
            }
        }

        let occupied = self.occupied_stash_len();
        let free_after_selected_stash = self.params.stash_capacity - occupied + selected_stash;
        if unselected_path > free_after_selected_stash {
            return Err(Error::StashOverflow {
                len: occupied - selected_stash + unselected_path,
                capacity: self.params.stash_capacity,
            });
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

fn validate_circuit_stores(
    params: &OramParams,
    meta_store: &impl PageStore,
    payload_store: &impl PageStore,
) -> Result<()> {
    if meta_store.page_count() != params.bucket_count() {
        return Err(Error::InvalidInput(format!(
            "metadata store has {} pages, expected {}",
            meta_store.page_count(),
            params.bucket_count()
        )));
    }
    let expected_meta_page = circuit_meta_page_bytes(params.bucket_size);
    if meta_store.page_size() != expected_meta_page {
        return Err(Error::InvalidInput(format!(
            "metadata page_size {} != expected {}",
            meta_store.page_size(),
            expected_meta_page
        )));
    }
    if payload_store.page_count() != params.bucket_count() {
        return Err(Error::InvalidInput(format!(
            "payload store has {} pages, expected {}",
            payload_store.page_count(),
            params.bucket_count()
        )));
    }
    let expected_payload_page = circuit_payload_page_bytes(params.bucket_size, params.block_size);
    if payload_store.page_size() != expected_payload_page {
        return Err(Error::InvalidInput(format!(
            "payload page_size {} != expected {}",
            payload_store.page_size(),
            expected_payload_page
        )));
    }
    Ok(())
}

fn validate_block_source(params: &OramParams, source: &impl TrustedBlockSource) -> Result<()> {
    if source.logical_blocks() != params.logical_blocks {
        return Err(Error::InvalidInput(format!(
            "block source has {} logical blocks, expected {}",
            source.logical_blocks(),
            params.logical_blocks
        )));
    }
    if source.block_size() != params.block_size {
        return Err(Error::InvalidInput(format!(
            "block source block_size {} != expected {}",
            source.block_size(),
            params.block_size
        )));
    }
    Ok(())
}

fn validate_circuit_state(
    params: &OramParams,
    pos_map: &[u32],
    stash: &[OramBlock],
    schedule: &CircuitEvictionSchedule,
) -> Result<()> {
    if pos_map.len() != params.logical_blocks {
        return Err(Error::InvalidInput(format!(
            "pos_map len {} != logical_blocks {}",
            pos_map.len(),
            params.logical_blocks
        )));
    }
    for &leaf in pos_map {
        if leaf as usize >= params.leaves {
            return Err(Error::InvalidInput(format!("leaf {leaf} out of range")));
        }
    }
    for block in stash {
        if block.payload.len() != params.block_size {
            return Err(Error::InvalidInput(format!(
                "stash payload len {} != block_size {}",
                block.payload.len(),
                params.block_size
            )));
        }
        if block.occupied && block.leaf as usize >= params.leaves {
            return Err(Error::InvalidInput(format!(
                "stash leaf {} out of range",
                block.leaf
            )));
        }
    }
    schedule.validate_for_params(params)?;
    Ok(())
}

fn place_initial_meta(
    params: &OramParams,
    meta_buckets: &mut [CircuitMetaBucket],
    logical_id: u64,
    leaf: u32,
) -> Result<bool> {
    let path = params.path_nodes(leaf);
    for node_idx in path.into_iter().rev() {
        for slot_idx in 0..params.bucket_size {
            if !meta_buckets[node_idx].slots[slot_idx].occupied {
                meta_buckets[node_idx].slots[slot_idx] = CircuitMetaSlot::real(logical_id, leaf);
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn write_initial_metadata(
    params: &OramParams,
    meta_store: &mut impl PageStore,
    meta_buckets: &[CircuitMetaBucket],
) -> Result<()> {
    if meta_buckets.len() != params.bucket_count() {
        return Err(Error::InvalidInput(format!(
            "metadata bucket count {} != expected {}",
            meta_buckets.len(),
            params.bucket_count()
        )));
    }
    let mut encoded = vec![0u8; circuit_meta_page_bytes(params.bucket_size)];
    for (node_idx, bucket) in meta_buckets.iter().enumerate() {
        bucket.encode_into(params.bucket_size, &mut encoded)?;
        meta_store.write_page(node_idx, &encoded)?;
    }
    Ok(())
}

fn write_initial_payloads<S: TrustedBlockSource>(
    params: &OramParams,
    payload_store: &mut impl PageStore,
    meta_buckets: &[CircuitMetaBucket],
    source: &mut S,
) -> Result<()> {
    if meta_buckets.len() != params.bucket_count() {
        return Err(Error::InvalidInput(format!(
            "metadata bucket count {} != expected {}",
            meta_buckets.len(),
            params.bucket_count()
        )));
    }
    let mut encoded = vec![0u8; circuit_payload_page_bytes(params.bucket_size, params.block_size)];
    for (node_idx, bucket) in meta_buckets.iter().enumerate() {
        encoded.fill(0);
        for (slot_idx, meta) in bucket.slots.iter().enumerate() {
            if meta.occupied {
                let payload = read_source_block(params, source, meta.logical_id as usize)?;
                let start = slot_idx * params.block_size;
                encoded[start..start + params.block_size].copy_from_slice(&payload);
            }
        }
        payload_store.write_page(node_idx, &encoded)?;
    }
    Ok(())
}

fn read_source_block<S: TrustedBlockSource>(
    params: &OramParams,
    source: &mut S,
    logical_id: usize,
) -> Result<Vec<u8>> {
    let payload = source.read_block(logical_id)?;
    if payload.len() != params.block_size {
        return Err(Error::InvalidInput(format!(
            "source payload for logical block {} has {} bytes, expected {}",
            logical_id,
            payload.len(),
            params.block_size
        )));
    }
    Ok(payload)
}

fn random_leaf(params: &OramParams, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
    (rng.next_u64() as usize % params.leaves) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::TraceEvent, MemPageStore, TracingStore};

    fn blocks(n: usize, block_size: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut block = vec![0u8; block_size];
                block[..8].copy_from_slice(&(i as u64).to_le_bytes());
                block
            })
            .collect()
    }

    fn params(leaves: usize) -> OramParams {
        OramParams::with_leaves(16, 32, leaves)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap()
    }

    #[test]
    fn deterministic_eviction_sequence_is_reverse_bit_order() {
        let params = params(8);
        let leaves = (0..8)
            .map(|i| CircuitEvictionSchedule::eviction_leaf_at(&params, i))
            .collect::<Vec<_>>();

        assert_eq!(leaves, vec![0, 4, 2, 6, 1, 5, 3, 7]);
    }

    #[test]
    fn each_access_adds_two_public_eviction_paths() {
        let params = params(8);
        let mut schedule = CircuitEvictionSchedule::new(&params);

        schedule.record_access().unwrap();
        schedule.record_access().unwrap();

        assert_eq!(schedule.issued_accesses(), 2);
        assert_eq!(schedule.pending_evictions().unwrap(), 4);
        assert_eq!(schedule.drain_evictions(3).unwrap(), vec![0, 4, 2]);
        assert_eq!(schedule.completed_evictions(), 3);
        assert_eq!(schedule.pending_evictions().unwrap(), 1);
        assert_eq!(schedule.drain_evictions(10).unwrap(), vec![6]);
        assert_eq!(schedule.pending_evictions().unwrap(), 0);
    }

    #[test]
    fn delayed_eviction_preserves_public_order() {
        let params = params(8);
        let mut immediate = CircuitEvictionSchedule::new(&params);
        let mut delayed = CircuitEvictionSchedule::new(&params);

        let mut immediate_leaves = Vec::new();
        for _ in 0..4 {
            immediate.record_access().unwrap();
            immediate_leaves.extend(immediate.drain_evictions(2).unwrap());
        }

        for _ in 0..4 {
            delayed.record_access().unwrap();
        }
        let delayed_leaves = delayed.drain_evictions(8).unwrap();

        assert_eq!(immediate_leaves, delayed_leaves);
    }

    #[test]
    fn checkpointed_counters_resume_debt() {
        let params = params(8);
        let mut schedule = CircuitEvictionSchedule::from_counters(&params, 2, 5, 7).unwrap();

        assert_eq!(schedule.evictions_per_access(), 2);
        assert_eq!(schedule.pending_evictions().unwrap(), 3);
        assert_eq!(schedule.drain_evictions(3).unwrap(), vec![7, 0, 4]);
        assert_eq!(schedule.pending_evictions().unwrap(), 0);
    }

    #[test]
    fn invalid_checkpoint_rejects_overcompleted_evictions() {
        let params = params(8);
        let err = CircuitEvictionSchedule::from_counters(&params, 2, 5, 11).unwrap_err();

        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn split_store_circuit_oram_roundtrip() {
        let params = OramParams::with_leaves(64, 32, 64)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(256)
            .unwrap();
        let meta_store = MemPageStore::new(
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = MemPageStore::new(
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram =
            CircuitOram::build_trusted(params, meta_store, payload_store, blocks(64, 32), [21; 32])
                .unwrap();

        for logical_id in [0u64, 7, 31, 63, 7, 0] {
            let got = oram.read(logical_id).unwrap();
            assert_eq!(&got[..8], &logical_id.to_le_bytes());
            oram.drain_evictions(2).unwrap();
        }
        assert_eq!(oram.pending_evictions().unwrap(), 0);
    }

    #[test]
    fn split_store_circuit_oram_update_changes_payload() {
        let params = OramParams::with_leaves(32, 16, 32)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();
        let meta_store = MemPageStore::new(
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = MemPageStore::new(
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram =
            CircuitOram::build_trusted(params, meta_store, payload_store, blocks(32, 16), [22; 32])
                .unwrap();

        let old = oram
            .access(5, |payload| {
                payload[8..16].copy_from_slice(&99u64.to_le_bytes())
            })
            .unwrap();
        assert_eq!(&old[..8], &5u64.to_le_bytes());
        oram.drain_evictions(2).unwrap();

        let new = oram.read(5).unwrap();
        assert_eq!(&new[..8], &5u64.to_le_bytes());
        assert_eq!(&new[8..16], &99u64.to_le_bytes());
    }

    #[test]
    fn split_store_state_roundtrip_reopens_controller() {
        let params = OramParams::with_leaves(32, 16, 32)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();
        let meta_store = MemPageStore::new(
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = MemPageStore::new(
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram =
            CircuitOram::build_trusted(params, meta_store, payload_store, blocks(32, 16), [25; 32])
                .unwrap();

        assert_eq!(&oram.read(3).unwrap()[..8], &3u64.to_le_bytes());
        assert_eq!(&oram.read(11).unwrap()[..8], &11u64.to_le_bytes());
        assert_eq!(oram.drain_evictions(1).unwrap(), 1);
        let pending_before_snapshot = oram.pending_evictions().unwrap();
        assert_eq!(pending_before_snapshot, 3);

        let snapshot = oram.snapshot();
        let (meta_store, payload_store) = oram.into_stores();
        let mut reopened = CircuitOram::from_state(meta_store, payload_store, snapshot).unwrap();

        assert_eq!(
            reopened.pending_evictions().unwrap(),
            pending_before_snapshot
        );
        assert_eq!(&reopened.read(3).unwrap()[..8], &3u64.to_le_bytes());
        assert_eq!(
            reopened.pending_evictions().unwrap(),
            pending_before_snapshot + 2
        );
        assert_eq!(
            reopened.drain_evictions(10).unwrap(),
            pending_before_snapshot + 2
        );
        assert_eq!(reopened.pending_evictions().unwrap(), 0);
    }

    #[test]
    fn split_store_access_adds_deferred_eviction_debt() {
        let params = OramParams::with_leaves(32, 16, 32)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();
        let meta_store = MemPageStore::new(
            params.bucket_count(),
            circuit_meta_page_bytes(params.bucket_size),
        )
        .unwrap();
        let payload_store = MemPageStore::new(
            params.bucket_count(),
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
        )
        .unwrap();
        let mut oram =
            CircuitOram::build_trusted(params, meta_store, payload_store, blocks(32, 16), [23; 32])
                .unwrap();

        for logical_id in 0..4 {
            oram.read(logical_id).unwrap();
        }

        assert_eq!(oram.pending_evictions().unwrap(), 8);
        assert_eq!(oram.stash_len(), 4);
        assert_eq!(oram.drain_evictions(3).unwrap(), 3);
        assert_eq!(oram.pending_evictions().unwrap(), 5);
    }

    #[test]
    fn split_store_initialization_writes_each_bucket_once_without_output_reads() {
        let params = OramParams::with_leaves(16, 16, 16)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();
        let meta_store = TracingStore::new(
            MemPageStore::new(
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
            )
            .unwrap(),
        );
        let payload_store = TracingStore::new(
            MemPageStore::new(
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
            )
            .unwrap(),
        );
        let oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 16),
            [26; 32],
        )
        .unwrap();

        let expected_writes = (0..params.bucket_count())
            .map(TraceEvent::Write)
            .collect::<Vec<_>>();
        assert_eq!(oram.meta_store.take_trace(), expected_writes.clone());
        assert_eq!(oram.payload_store.take_trace(), expected_writes);
    }

    #[test]
    fn split_store_trace_shape_is_fixed_for_online_access_and_eviction() {
        let params = OramParams::with_leaves(16, 16, 16)
            .unwrap()
            .with_bucket_size(2)
            .unwrap()
            .with_stash_capacity(128)
            .unwrap();
        let meta_store = TracingStore::new(
            MemPageStore::new(
                params.bucket_count(),
                circuit_meta_page_bytes(params.bucket_size),
            )
            .unwrap(),
        );
        let payload_store = TracingStore::new(
            MemPageStore::new(
                params.bucket_count(),
                circuit_payload_page_bytes(params.bucket_size, params.block_size),
            )
            .unwrap(),
        );
        let mut oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 16),
            [24; 32],
        )
        .unwrap();
        oram.meta_store.take_trace();
        oram.payload_store.take_trace();

        oram.read(3).unwrap();
        let meta_access = oram.meta_store.take_trace();
        let payload_access = oram.payload_store.take_trace();
        assert_eq!(meta_access.len(), params.height() * 2);
        assert_eq!(payload_access.len(), params.height() * 2);
        assert!(meta_access
            .chunks_exact(2)
            .all(|chunk| matches!(chunk, [TraceEvent::Read(_), TraceEvent::Write(_)])));
        assert!(payload_access
            .chunks_exact(2)
            .all(|chunk| matches!(chunk, [TraceEvent::Read(_), TraceEvent::Write(_)])));

        oram.drain_evictions(1).unwrap();
        let meta_evict = oram.meta_store.take_trace();
        let payload_evict = oram.payload_store.take_trace();
        assert_eq!(meta_evict.len(), params.height() * 3);
        assert_eq!(payload_evict.len(), params.height() * 2);
        assert!(meta_evict[..params.height() * 2]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(meta_evict[params.height() * 2..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
        assert!(payload_evict[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(payload_evict[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
    }
}
