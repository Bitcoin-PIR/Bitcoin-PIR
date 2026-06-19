//! Circuit ORAM design helpers.
//!
//! This module contains public scheduling state shared by the planned
//! disk-backed Circuit ORAM controller and the stash-pressure simulator. The
//! schedule is intentionally independent of logical addresses and stash
//! occupancy: real accesses add a fixed amount of public eviction debt, and
//! background work drains that debt in reverse-bit order.

use crate::{
    ct, CircuitOramState, CircuitStoreAuthState, Error, OramBlock, OramParams, PageStore,
    PathPageStore, Result,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

    fn logical_id_choice(&self, logical_id: u64) -> ct::Choice {
        ct::and(
            ct::choice_from_bool(self.occupied),
            ct::eq_u64(self.logical_id, logical_id),
        )
    }

    fn clear_if(&mut self, choice: ct::Choice) {
        let mut occupied = self.occupied as u8;
        ct::cmov_u8(&mut occupied, META_EMPTY, choice);
        self.occupied = occupied != 0;
        ct::cmov_u64(&mut self.logical_id, u64::MAX, choice);
        ct::cmov_u32(&mut self.leaf, u32::MAX, choice);
    }

    fn cmov_from(&mut self, other: &Self, choice: ct::Choice) {
        let mut occupied = self.occupied as u8;
        ct::cmov_u8(&mut occupied, other.occupied as u8, choice);
        self.occupied = occupied != 0;
        ct::cmov_u64(&mut self.logical_id, other.logical_id, choice);
        ct::cmov_u32(&mut self.leaf, other.leaf, choice);
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

#[derive(Clone, Debug)]
struct CircuitEvictionCandidate {
    meta: CircuitMetaSlot,
    active: ct::Choice,
}

#[derive(Clone, Copy, Debug)]
struct CircuitEvictionPlacement {
    candidate_idx: usize,
    occupied: ct::Choice,
}

impl CircuitEvictionPlacement {
    fn dummy() -> Self {
        Self {
            candidate_idx: 0,
            occupied: ct::choice_from_bool(false),
        }
    }
}

#[derive(Clone, Debug)]
struct CircuitEvictionPlan {
    candidates: Vec<CircuitEvictionCandidate>,
    placements: Vec<Vec<CircuitEvictionPlacement>>,
    selected: Vec<ct::Choice>,
    path_candidate_indices: Vec<Vec<usize>>,
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
}

impl<M: PathPageStore, P: PathPageStore> CircuitOram<M, P> {
    /// Re-open a split-store Circuit ORAM from trusted controller state.
    pub fn from_state(meta_store: M, payload_store: P, state: CircuitOramState) -> Result<Self> {
        validate_circuit_stores(&state.params, &meta_store, &payload_store)?;
        validate_circuit_state(&state.params, &state.pos_map, &state.stash, &state.schedule)?;
        validate_bound_auth_state(state.auth.as_ref(), &meta_store, &payload_store)?;
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
        .with_auth(self.store_auth_state())
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
        store_auth_state_from_stores(&self.meta_store, &self.payload_store)
    }

    /// Read a logical block and schedule public background eviction debt.
    pub fn read(&mut self, logical_id: u64) -> Result<Vec<u8>> {
        self.access(logical_id, |_| {})
    }

    /// Read several logical blocks as one online batch and schedule eviction debt.
    ///
    /// Eviction is still delayed until `drain_evictions` is called. Repeated
    /// logical ids use the previous occurrence's freshly remapped random leaf,
    /// preserving sequential access semantics without branching on duplicates.
    pub fn read_batch(&mut self, logical_ids: &[u64]) -> Result<Vec<Vec<u8>>> {
        self.access_batch(logical_ids, |_, _| {})
    }

    /// Perform one dummy ORAM access on a random leaf path.
    ///
    /// This has the online trace shape of a real path access and records the
    /// same public eviction debt, but it does not select or reassign any
    /// logical block. Callers use this for explicit padded/empty query slots:
    /// the access schedule remains fixed while no user key is interpreted.
    pub fn dummy_access(&mut self) -> Result<()> {
        let leaf = random_leaf(&self.params, &mut self.rng);
        self.read_and_rewrite_path(leaf)?;
        self.schedule.record_access()?;
        self.check_stash()
    }

    /// Perform several dummy ORAM accesses as one online path batch.
    ///
    /// The chosen leaves remain random and independent, matching repeated
    /// [`Self::dummy_access`] calls, but backing stores that support path
    /// batches can collapse the physical reads/writes for overlapping paths.
    pub fn dummy_access_batch(&mut self, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }

        let paths = (0..count)
            .map(|_| {
                self.params
                    .path_nodes(random_leaf(&self.params, &mut self.rng))
            })
            .collect::<Vec<_>>();
        let meta_path_pages = self.meta_store.read_paths_pages(&paths)?;
        let payload_path_pages = self.payload_store.read_paths_pages(&paths)?;
        let meta_overlay = overlay_path_pages(
            &paths,
            meta_path_pages,
            circuit_meta_page_bytes(self.params.bucket_size),
        )?;
        let payload_overlay = overlay_path_pages(
            &paths,
            payload_path_pages,
            circuit_payload_page_bytes(self.params.bucket_size, self.params.block_size),
        )?;

        let meta_write_pages = collect_overlay_paths(&paths, &meta_overlay)?;
        let payload_write_pages = collect_overlay_paths(&paths, &payload_overlay)?;
        self.meta_store
            .write_paths_pages(&paths, &meta_write_pages)?;
        self.payload_store
            .write_paths_pages(&paths, &payload_write_pages)?;
        for _ in 0..count {
            self.schedule.record_access()?;
        }
        self.check_stash()
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

        let old_leaf = scan_pos_map_lookup(&self.pos_map, logical_id);
        self.read_and_remove_target_path(old_leaf, logical_id)?;

        let mut found = ct::choice_from_bool(false);
        let mut output = vec![0u8; self.params.block_size];
        for block in &self.stash {
            let matched = block.logical_id_choice(logical_id);
            ct::cmov_bytes(&mut output, &block.payload, matched);
            found = ct::or(found, matched);
        }
        if ct::not(found).unwrap_u8() == 1 {
            return Err(Error::BlockNotFound(logical_id));
        }

        let new_leaf = random_leaf(&self.params, &mut self.rng);
        scan_pos_map_update(&mut self.pos_map, logical_id, new_leaf);
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

    /// Read/update several logical blocks as one online batch.
    ///
    /// The old-leaf paths are prefetched into an in-memory page overlay, each
    /// access is then applied in caller order, and all touched paths are written
    /// back as one path batch. This preserves sequential ORAM semantics,
    /// including repeated logical ids, while reducing the storage roundtrips for
    /// the online phase.
    pub fn access_batch<F>(&mut self, logical_ids: &[u64], mut update: F) -> Result<Vec<Vec<u8>>>
    where
        F: FnMut(u64, &mut [u8]),
    {
        if logical_ids.is_empty() {
            return Ok(Vec::new());
        }
        for &logical_id in logical_ids {
            if logical_id as usize >= self.params.logical_blocks {
                return Err(Error::InvalidInput(format!(
                    "logical_id {logical_id} out of range"
                )));
            }
        }
        let old_leaves = scan_pos_map_lookup_batch(&self.pos_map, logical_ids);
        let mut next_rng = self.rng.clone();
        let new_leaves = logical_ids
            .iter()
            .map(|_| random_leaf(&self.params, &mut next_rng))
            .collect::<Vec<_>>();
        let access_leaves = batch_access_leaves(logical_ids, &old_leaves, &new_leaves);
        let paths = access_leaves
            .iter()
            .map(|&leaf| self.params.path_nodes(leaf))
            .collect::<Vec<_>>();
        let meta_path_pages = self.meta_store.read_paths_pages(&paths)?;
        let payload_path_pages = self.payload_store.read_paths_pages(&paths)?;
        let mut meta_overlay = overlay_path_pages(
            &paths,
            meta_path_pages,
            circuit_meta_page_bytes(self.params.bucket_size),
        )?;
        let mut payload_overlay = overlay_path_pages(
            &paths,
            payload_path_pages,
            circuit_payload_page_bytes(self.params.bucket_size, self.params.block_size),
        )?;

        let mut outputs = Vec::with_capacity(logical_ids.len());
        for ((&logical_id, &new_leaf), path) in logical_ids.iter().zip(&new_leaves).zip(&paths) {
            self.remove_target_from_overlays(
                path,
                logical_id,
                &mut meta_overlay,
                &mut payload_overlay,
            )?;

            let mut found = ct::choice_from_bool(false);
            let mut output = vec![0u8; self.params.block_size];
            for block in &self.stash {
                let matched = block.logical_id_choice(logical_id);
                ct::cmov_bytes(&mut output, &block.payload, matched);
                found = ct::or(found, matched);
            }
            if ct::not(found).unwrap_u8() == 1 {
                return Err(Error::BlockNotFound(logical_id));
            }
            let mut new_payload = output.clone();
            update(logical_id, &mut new_payload);
            for block in &mut self.stash {
                let matched = block.logical_id_choice(logical_id);
                ct::cmov_bytes(&mut block.payload, &new_payload, matched);
                ct::cmov_u32(&mut block.leaf, new_leaf, matched);
            }

            self.schedule.record_access()?;
            outputs.push(output);
        }
        scan_pos_map_update_batch(&mut self.pos_map, logical_ids, &new_leaves);
        self.rng = next_rng;

        let meta_write_pages = collect_overlay_paths(&paths, &meta_overlay)?;
        let payload_write_pages = collect_overlay_paths(&paths, &payload_overlay)?;
        self.meta_store
            .write_paths_pages(&paths, &meta_write_pages)?;
        self.payload_store
            .write_paths_pages(&paths, &payload_write_pages)?;
        self.check_stash()?;
        Ok(outputs)
    }

    /// Drain up to `budget` pending public eviction paths.
    pub fn drain_evictions(&mut self, budget: u64) -> Result<u64> {
        let pending = self.schedule.pending_evictions()?;
        let to_drain = budget.min(pending);
        if to_drain == 0 {
            return Ok(0);
        }
        let start = self.schedule.completed_evictions();
        let leaves = (0..to_drain)
            .map(|offset| CircuitEvictionSchedule::eviction_leaf_at(&self.params, start + offset))
            .collect::<Vec<_>>();
        let paths = leaves
            .iter()
            .map(|&leaf| self.params.path_nodes(leaf))
            .collect::<Vec<_>>();
        let meta_path_pages = self.meta_store.read_paths_pages(&paths)?;
        let payload_path_pages = self.payload_store.read_paths_pages(&paths)?;
        let mut meta_overlay = overlay_path_pages(
            &paths,
            meta_path_pages,
            circuit_meta_page_bytes(self.params.bucket_size),
        )?;
        let mut payload_overlay = overlay_path_pages(
            &paths,
            payload_path_pages,
            circuit_payload_page_bytes(self.params.bucket_size, self.params.block_size),
        )?;

        for path in &paths {
            self.evict_path_in_overlays(path, &mut meta_overlay, &mut payload_overlay)?;
        }

        let meta_write_pages = collect_overlay_paths(&paths, &meta_overlay)?;
        let payload_write_pages = collect_overlay_paths(&paths, &payload_overlay)?;
        self.meta_store
            .write_paths_pages(&paths, &meta_write_pages)?;
        self.payload_store
            .write_paths_pages(&paths, &payload_write_pages)?;
        for leaf in leaves {
            let completed = self.schedule.complete_one_eviction()?;
            debug_assert_eq!(completed, Some(leaf));
        }
        self.check_stash()?;
        Ok(to_drain)
    }

    fn read_and_remove_target_path(&mut self, leaf: u32, logical_id: u64) -> Result<()> {
        let path = self.params.path_nodes(leaf);
        let mut meta_pages = self.meta_store.read_path_pages(&path)?;
        let mut payload_pages = self.payload_store.read_path_pages(&path)?;
        let mut selected = OramBlock::dummy(self.params.block_size);
        let mut removed = ct::choice_from_bool(false);

        // Deliberately rewrite every page on the path, even if only one slot
        // changed. Rewriting only changed pages would leak the target depth in
        // the host-visible write set.
        for (meta_buf, payload_buf) in meta_pages.iter_mut().zip(&mut payload_pages) {
            let mut meta_bucket = CircuitMetaBucket::decode(meta_buf, self.params.bucket_size)?;
            let mut payload_bucket = CircuitPayloadBucket::decode(
                payload_buf,
                self.params.bucket_size,
                self.params.block_size,
            )?;

            select_and_remove_target_slots(
                &mut meta_bucket,
                &mut payload_bucket,
                logical_id,
                self.params.block_size,
                &mut selected,
                &mut removed,
            );

            *meta_buf = meta_bucket.encode(self.params.bucket_size)?;
            *payload_buf =
                payload_bucket.encode(self.params.bucket_size, self.params.block_size)?;
        }
        self.insert_into_stash(selected)?;
        self.meta_store.write_path_pages(&path, &meta_pages)?;
        self.payload_store.write_path_pages(&path, &payload_pages)?;
        Ok(())
    }

    fn remove_target_from_overlays(
        &mut self,
        path: &[usize],
        logical_id: u64,
        meta_overlay: &mut BTreeMap<usize, Vec<u8>>,
        payload_overlay: &mut BTreeMap<usize, Vec<u8>>,
    ) -> Result<()> {
        let mut selected = OramBlock::dummy(self.params.block_size);
        let mut removed = ct::choice_from_bool(false);
        // `path` is a public random ORAM path. BTreeMap lookups are keyed only
        // by public page indices; block contents never influence overlay keys
        // or the number of path pages visited.
        for page_idx in path {
            let meta_buf = meta_overlay
                .get_mut(page_idx)
                .expect("batch overlay includes every path page");
            let payload_buf = payload_overlay
                .get_mut(page_idx)
                .expect("batch overlay includes every path page");
            let mut meta_bucket = CircuitMetaBucket::decode(meta_buf, self.params.bucket_size)?;
            let mut payload_bucket = CircuitPayloadBucket::decode(
                payload_buf,
                self.params.bucket_size,
                self.params.block_size,
            )?;

            select_and_remove_target_slots(
                &mut meta_bucket,
                &mut payload_bucket,
                logical_id,
                self.params.block_size,
                &mut selected,
                &mut removed,
            );

            *meta_buf = meta_bucket.encode(self.params.bucket_size)?;
            *payload_buf =
                payload_bucket.encode(self.params.bucket_size, self.params.block_size)?;
        }
        self.insert_into_stash(selected)?;
        Ok(())
    }

    fn read_and_rewrite_path(&mut self, leaf: u32) -> Result<()> {
        let path = self.params.path_nodes(leaf);
        let meta_pages = self.meta_store.read_path_pages(&path)?;
        let payload_pages = self.payload_store.read_path_pages(&path)?;
        self.meta_store.write_path_pages(&path, &meta_pages)?;
        self.payload_store.write_path_pages(&path, &payload_pages)?;
        Ok(())
    }

    fn evict_path_in_overlays(
        &mut self,
        path: &[usize],
        meta_overlay: &mut BTreeMap<usize, Vec<u8>>,
        payload_overlay: &mut BTreeMap<usize, Vec<u8>>,
    ) -> Result<()> {
        let deepest_meta = self.path_metadata_from_overlay(path, meta_overlay)?;
        let target_meta = self.path_metadata_from_overlay(path, meta_overlay)?;
        debug_assert_eq!(deepest_meta, target_meta);
        let plan = self.plan_eviction_placements(path, &target_meta)?;
        self.apply_eviction_plan_to_overlays(
            path,
            &target_meta,
            plan,
            meta_overlay,
            payload_overlay,
        )
    }

    fn path_metadata_from_overlay(
        &self,
        path: &[usize],
        meta_overlay: &BTreeMap<usize, Vec<u8>>,
    ) -> Result<Vec<CircuitMetaBucket>> {
        let mut buckets = Vec::with_capacity(path.len());
        for page_idx in path {
            let meta_buf = meta_overlay
                .get(page_idx)
                .expect("eviction overlay includes every path page");
            buckets.push(CircuitMetaBucket::decode(
                meta_buf,
                self.params.bucket_size,
            )?);
        }
        Ok(buckets)
    }

    #[inline(never)]
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
        if self.stash.len() != self.params.stash_capacity {
            return Err(Error::InvalidInput(format!(
                "stash slots {} != stash_capacity {}",
                self.stash.len(),
                self.params.stash_capacity
            )));
        }

        let mut candidates = Vec::with_capacity(self.eviction_candidate_count());
        let mut path_candidate_indices =
            vec![vec![0; self.params.bucket_size]; self.params.height()];

        for block in &self.stash {
            candidates.push(CircuitEvictionCandidate {
                meta: CircuitMetaSlot {
                    occupied: block.occupied,
                    logical_id: block.logical_id,
                    leaf: block.leaf,
                },
                active: ct::choice_from_bool(block.occupied),
            });
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
                let candidate_idx = candidates.len();
                candidates.push(CircuitEvictionCandidate {
                    meta: *meta,
                    active: ct::choice_from_bool(meta.occupied),
                });
                path_candidate_indices[depth][slot_idx] = candidate_idx;
            }
        }

        let mut placements = vec![
            vec![CircuitEvictionPlacement::dummy(); self.params.bucket_size];
            self.params.height()
        ];
        let mut selected = vec![ct::choice_from_bool(false); candidates.len()];

        for depth in (0..self.params.height()).rev() {
            let node_idx = path[depth];
            for placement in &mut placements[depth] {
                let mut placed = ct::choice_from_bool(false);
                let mut placement_idx = 0usize;
                for (candidate_idx, candidate) in candidates.iter().enumerate() {
                    let can_place = ct::and(
                        ct::and(candidate.active, ct::not(selected[candidate_idx])),
                        ct::and(
                            ct::not(placed),
                            self.node_contains_leaf_choice(depth, node_idx, candidate.meta.leaf),
                        ),
                    );
                    ct::cmov_usize(&mut placement_idx, candidate_idx, can_place);
                    selected[candidate_idx] = ct::or(selected[candidate_idx], can_place);
                    placed = ct::or(placed, can_place);
                }
                placement.candidate_idx = placement_idx;
                placement.occupied = placed;
            }
        }

        Ok(CircuitEvictionPlan {
            candidates,
            placements,
            selected,
            path_candidate_indices,
        })
    }

    #[inline(never)]
    fn apply_eviction_plan_to_overlays(
        &mut self,
        path: &[usize],
        path_meta: &[CircuitMetaBucket],
        plan: CircuitEvictionPlan,
        meta_overlay: &mut BTreeMap<usize, Vec<u8>>,
        payload_overlay: &mut BTreeMap<usize, Vec<u8>>,
    ) -> Result<()> {
        let payloads =
            self.load_eviction_payloads_from_overlay(path, path_meta, &plan, payload_overlay)?;
        self.ensure_eviction_stash_capacity(&plan)?;

        for slot in 0..self.params.stash_capacity {
            let clear = ct::and(plan.candidates[slot].active, plan.selected[slot]);
            self.stash[slot].clear_if(clear, self.params.block_size);
        }

        for depth in 0..self.params.height() {
            for slot_idx in 0..self.params.bucket_size {
                let candidate_idx = plan.path_candidate_indices[depth][slot_idx];
                let candidate = &plan.candidates[candidate_idx];
                let reinsert = ct::and(candidate.active, ct::not(plan.selected[candidate_idx]));
                self.insert_candidate_into_stash(
                    candidate.meta,
                    &payloads[candidate_idx],
                    reinsert,
                )?;
            }
        }

        // Eviction paths and page indices are public. Overlay writes are keyed
        // by those public page indices; secret placement choices only affect
        // masked slot contents inside the page bytes.
        for (depth, page_idx) in path.iter().enumerate() {
            let mut meta_bucket = CircuitMetaBucket::dummy(self.params.bucket_size);
            let mut payload_bucket =
                CircuitPayloadBucket::dummy(self.params.bucket_size, self.params.block_size);
            for (slot_idx, placement) in plan.placements[depth].iter().enumerate() {
                let mut meta_slot = CircuitMetaSlot::dummy();
                let mut payload_slot = vec![0u8; self.params.block_size];
                for (candidate_idx, candidate) in plan.candidates.iter().enumerate() {
                    let select = ct::and(
                        placement.occupied,
                        ct::eq_usize(placement.candidate_idx, candidate_idx),
                    );
                    meta_slot.cmov_from(&candidate.meta, select);
                    ct::cmov_bytes(&mut payload_slot, &payloads[candidate_idx], select);
                }
                meta_bucket.slots[slot_idx] = meta_slot;
                payload_bucket.slots[slot_idx] = payload_slot;
            }

            meta_overlay.insert(*page_idx, meta_bucket.encode(self.params.bucket_size)?);
            payload_overlay.insert(
                *page_idx,
                payload_bucket.encode(self.params.bucket_size, self.params.block_size)?,
            );
        }
        Ok(())
    }

    fn eviction_candidate_count(&self) -> usize {
        self.params.stash_capacity + self.params.height() * self.params.bucket_size
    }

    fn node_contains_leaf_choice(&self, depth: usize, node_idx: usize, leaf: u32) -> ct::Choice {
        // `depth` and `node_idx` are public loop values. `leaf` is secret block
        // metadata, so target builds should inspect the generated shift
        // instructions for the SEV-SNP CPU. On the current target this is kept
        // as a documented audit item rather than a barrel-select rewrite.
        let safe_leaf = ((leaf as usize) & (self.params.leaves - 1)) as u32;
        ct::eq_usize(self.params.node_index(depth, safe_leaf), node_idx)
    }

    #[inline(never)]
    fn load_eviction_payloads_from_overlay(
        &self,
        path: &[usize],
        path_meta: &[CircuitMetaBucket],
        plan: &CircuitEvictionPlan,
        payload_overlay: &BTreeMap<usize, Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>> {
        if path.len() != path_meta.len()
            || path.len() != plan.path_candidate_indices.len()
            || plan.candidates.len() != self.eviction_candidate_count()
        {
            return Err(Error::InvalidInput(
                "eviction payload path length mismatch".into(),
            ));
        }

        let mut payloads = vec![vec![0u8; self.params.block_size]; plan.candidates.len()];
        for (slot, payload) in payloads
            .iter_mut()
            .enumerate()
            .take(self.params.stash_capacity)
        {
            payload.copy_from_slice(&self.stash[slot].payload);
        }

        for (depth, page_idx) in path.iter().enumerate() {
            let payload_buf = payload_overlay
                .get(page_idx)
                .expect("eviction overlay includes every path page");
            let payload_bucket = CircuitPayloadBucket::decode(
                payload_buf,
                self.params.bucket_size,
                self.params.block_size,
            )?;
            for (slot_idx, candidate_idx) in plan.path_candidate_indices[depth].iter().enumerate() {
                payloads[*candidate_idx].copy_from_slice(&payload_bucket.slots[slot_idx]);
            }
        }
        Ok(payloads)
    }

    #[inline(never)]
    fn ensure_eviction_stash_capacity(&self, plan: &CircuitEvictionPlan) -> Result<()> {
        let mut selected_stash = 0usize;
        let mut unselected_path = 0usize;

        for slot in 0..self.params.stash_capacity {
            let selected = ct::and(plan.candidates[slot].active, plan.selected[slot]);
            selected_stash += selected.unwrap_u8() as usize;
        }
        for depth in 0..self.params.height() {
            for slot_idx in 0..self.params.bucket_size {
                let candidate_idx = plan.path_candidate_indices[depth][slot_idx];
                let candidate = &plan.candidates[candidate_idx];
                let reinsert = ct::and(candidate.active, ct::not(plan.selected[candidate_idx]));
                unselected_path += reinsert.unwrap_u8() as usize;
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

    #[inline(never)]
    fn insert_candidate_into_stash(
        &mut self,
        meta: CircuitMetaSlot,
        payload: &[u8],
        insert_choice: ct::Choice,
    ) -> Result<()> {
        if payload.len() != self.params.block_size {
            return Err(Error::InvalidInput(format!(
                "payload len {} != block_size {}",
                payload.len(),
                self.params.block_size
            )));
        }
        let block = OramBlock {
            occupied: true,
            logical_id: meta.logical_id,
            leaf: meta.leaf,
            payload: payload.to_vec(),
        };
        let mut inserted = ct::not(insert_choice);
        for slot in &mut self.stash {
            let can_insert = ct::and(
                ct::and(insert_choice, ct::not(inserted)),
                ct::not(ct::choice_from_bool(slot.occupied)),
            );
            slot.cmov_from(&block, can_insert);
            inserted = ct::or(inserted, can_insert);
        }

        if ct::not(inserted).unwrap_u8() == 1 {
            return Err(Error::StashOverflow {
                len: self.params.stash_capacity + 1,
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

        if ct::not(inserted).unwrap_u8() == 1 {
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
        self.stash
            .iter()
            .map(|block| ct::choice_from_bool(block.occupied).unwrap_u8() as usize)
            .sum()
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

fn scan_pos_map_lookup(pos_map: &[u32], logical_id: u64) -> u32 {
    let mut leaf = 0u32;
    for (idx, &candidate_leaf) in pos_map.iter().enumerate() {
        let matched = ct::eq_u64(idx as u64, logical_id);
        ct::cmov_u32(&mut leaf, candidate_leaf, matched);
    }
    leaf
}

fn scan_pos_map_update(pos_map: &mut [u32], logical_id: u64, new_leaf: u32) {
    for (idx, leaf) in pos_map.iter_mut().enumerate() {
        let matched = ct::eq_u64(idx as u64, logical_id);
        ct::cmov_u32(leaf, new_leaf, matched);
    }
}

fn scan_pos_map_lookup_batch(pos_map: &[u32], logical_ids: &[u64]) -> Vec<u32> {
    let mut leaves = vec![0u32; logical_ids.len()];
    for (idx, &candidate_leaf) in pos_map.iter().enumerate() {
        for (&logical_id, leaf) in logical_ids.iter().zip(&mut leaves) {
            let matched = ct::eq_u64(idx as u64, logical_id);
            ct::cmov_u32(leaf, candidate_leaf, matched);
        }
    }
    leaves
}

fn scan_pos_map_update_batch(pos_map: &mut [u32], logical_ids: &[u64], new_leaves: &[u32]) {
    debug_assert_eq!(logical_ids.len(), new_leaves.len());
    for (idx, leaf) in pos_map.iter_mut().enumerate() {
        for (&logical_id, &new_leaf) in logical_ids.iter().zip(new_leaves) {
            let matched = ct::eq_u64(idx as u64, logical_id);
            ct::cmov_u32(leaf, new_leaf, matched);
        }
    }
}

fn batch_access_leaves(logical_ids: &[u64], old_leaves: &[u32], new_leaves: &[u32]) -> Vec<u32> {
    debug_assert_eq!(logical_ids.len(), old_leaves.len());
    debug_assert_eq!(logical_ids.len(), new_leaves.len());

    let mut access_leaves = old_leaves.to_vec();
    for i in 0..logical_ids.len() {
        for j in 0..i {
            let repeated = ct::eq_u64(logical_ids[i], logical_ids[j]);
            ct::cmov_u32(&mut access_leaves[i], new_leaves[j], repeated);
        }
    }
    access_leaves
}

fn select_and_remove_target_slots(
    meta_bucket: &mut CircuitMetaBucket,
    payload_bucket: &mut CircuitPayloadBucket,
    logical_id: u64,
    block_size: usize,
    selected: &mut OramBlock,
    removed: &mut ct::Choice,
) {
    debug_assert_eq!(meta_bucket.slots.len(), payload_bucket.slots.len());
    for (meta, payload) in meta_bucket.slots.iter_mut().zip(&mut payload_bucket.slots) {
        debug_assert_eq!(payload.len(), block_size);
        let matched = ct::and(meta.logical_id_choice(logical_id), ct::not(*removed));
        cmov_block_from_meta_payload(selected, meta, payload, matched);
        meta.clear_if(matched);
        clear_payload_if(payload, matched);
        *removed = ct::or(*removed, matched);
    }
}

fn cmov_block_from_meta_payload(
    block: &mut OramBlock,
    meta: &CircuitMetaSlot,
    payload: &[u8],
    choice: ct::Choice,
) {
    debug_assert_eq!(block.payload.len(), payload.len());
    let mut occupied = block.occupied as u8;
    ct::cmov_u8(&mut occupied, meta.occupied as u8, choice);
    block.occupied = occupied != 0;
    ct::cmov_u64(&mut block.logical_id, meta.logical_id, choice);
    ct::cmov_u32(&mut block.leaf, meta.leaf, choice);
    ct::cmov_bytes(&mut block.payload, payload, choice);
}

#[inline(never)]
fn clear_payload_if(payload: &mut [u8], choice: ct::Choice) {
    let keep_mask = std::hint::black_box(!ct::mask8(choice));
    for byte in payload {
        // Keep this as volatile byte operations: LLVM otherwise recognizes the
        // all-zero case and turns the loop into a branch to memset/bzero.
        unsafe {
            let current = std::ptr::read_volatile(byte);
            std::ptr::write_volatile(byte, current & keep_mask);
        }
    }
}

fn overlay_path_pages(
    paths: &[Vec<usize>],
    path_pages: Vec<Vec<Vec<u8>>>,
    page_size: usize,
) -> Result<BTreeMap<usize, Vec<u8>>> {
    if paths.len() != path_pages.len() {
        return Err(Error::InvalidInput(format!(
            "path count {} != page-path count {}",
            paths.len(),
            path_pages.len()
        )));
    }
    // The overlay map is keyed only by public ORAM page indices. Insertion
    // order follows public batch/path/depth order returned by the store layer;
    // secret block metadata is opaque page bytes and never chooses a key.
    let mut overlay = BTreeMap::new();
    for (path, pages) in paths.iter().zip(path_pages) {
        if path.len() != pages.len() {
            return Err(Error::InvalidInput(format!(
                "path length {} != page count {}",
                path.len(),
                pages.len()
            )));
        }
        for (page_idx, page) in path.iter().zip(pages) {
            if page.len() != page_size {
                return Err(Error::InvalidInput(format!(
                    "path page len {} != page_size {}",
                    page.len(),
                    page_size
                )));
            }
            if let Some(existing) = overlay.get(page_idx) {
                if existing != &page {
                    return Err(Error::InvalidInput(format!(
                        "batch read returned inconsistent bytes for page {}",
                        page_idx
                    )));
                }
            } else {
                overlay.insert(*page_idx, page);
            }
        }
    }
    Ok(overlay)
}

fn collect_overlay_paths(
    paths: &[Vec<usize>],
    overlay: &BTreeMap<usize, Vec<u8>>,
) -> Result<Vec<Vec<Vec<u8>>>> {
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let mut pages = Vec::with_capacity(path.len());
        for page_idx in path {
            pages.push(
                overlay
                    .get(page_idx)
                    .ok_or_else(|| {
                        Error::InvalidInput(format!(
                            "batch overlay missing requested page {}",
                            page_idx
                        ))
                    })?
                    .clone(),
            );
        }
        out.push(pages);
    }
    Ok(out)
}

fn validate_circuit_stores(
    params: &OramParams,
    meta_store: &impl PathPageStore,
    payload_store: &impl PathPageStore,
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

fn store_auth_state_from_stores<M: PathPageStore, P: PathPageStore>(
    meta_store: &M,
    payload_store: &P,
) -> Option<CircuitStoreAuthState> {
    match (
        meta_store.tiered_merkle_state(),
        payload_store.tiered_merkle_state(),
    ) {
        (Some(meta), Some(payload)) => Some(CircuitStoreAuthState::new(meta, payload)),
        _ => Some(CircuitStoreAuthState::new_embedded(
            meta_store.embedded_tree_state()?,
            payload_store.embedded_tree_state()?,
        )),
    }
}

fn validate_bound_auth_state<M: PathPageStore, P: PathPageStore>(
    expected: Option<&CircuitStoreAuthState>,
    meta_store: &M,
    payload_store: &P,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = store_auth_state_from_stores(meta_store, payload_store).ok_or_else(|| {
        Error::InvalidInput(
            "Circuit ORAM state is bound to auth roots but stores expose no auth state".into(),
        )
    })?;
    if &actual != expected {
        return Err(Error::InvalidInput(
            "Circuit ORAM auth roots do not match controller state".into(),
        ));
    }
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
    debug_assert!(params.leaves.is_power_of_two());
    (rng.next_u64() as usize & (params.leaves - 1)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        store::TraceEvent, CircuitStoreAuthLayout, EmbeddedTreePageStore, MemPageStore, PageStore,
        TracingStore,
    };
    use std::collections::{BTreeMap, BTreeSet};

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

    fn empty_circuit_oram(params: OramParams) -> CircuitOram<MemPageStore, MemPageStore> {
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
        CircuitOram {
            pos_map: vec![0; params.logical_blocks],
            stash: vec![OramBlock::dummy(params.block_size); params.stash_capacity],
            rng: ChaCha20Rng::from_seed([44; 32]),
            schedule: CircuitEvictionSchedule::new(&params),
            params,
            meta_store,
            payload_store,
        }
    }

    fn test_payload(params: &OramParams, logical_id: u64) -> Vec<u8> {
        let mut payload = vec![logical_id as u8; params.block_size];
        payload[..8].copy_from_slice(&logical_id.to_le_bytes());
        payload
    }

    fn seal_embedded_store(
        mut logical_store: MemPageStore,
        logical_page_size: usize,
        store_id: [u8; 16],
    ) -> EmbeddedTreePageStore<TracingStore<MemPageStore>> {
        let physical_page_size =
            EmbeddedTreePageStore::<MemPageStore>::physical_page_size_for(logical_page_size);
        let page_count = PageStore::page_count(&logical_store);
        let mut physical_store = MemPageStore::new(page_count, physical_page_size).unwrap();
        let mut logical = vec![0u8; logical_page_size];
        let mut physical = vec![0u8; physical_page_size];
        for page_idx in 0..page_count {
            logical_store.read_page(page_idx, &mut logical).unwrap();
            physical.fill(0);
            physical[..logical_page_size].copy_from_slice(&logical);
            physical_store.write_page(page_idx, &physical).unwrap();
        }
        EmbeddedTreePageStore::build(
            TracingStore::new(physical_store),
            store_id,
            logical_page_size,
        )
        .unwrap()
    }

    #[test]
    fn position_map_batch_scan_matches_many_queries() {
        let mut pos_map = vec![70, 31, 90, 42, 63, 12];

        let leaves = scan_pos_map_lookup_batch(&pos_map, &[3, 0, 4]);
        assert_eq!(leaves, vec![42, 70, 63]);

        scan_pos_map_update_batch(&mut pos_map, &[3, 0, 4], &[420, 700, 630]);
        assert_eq!(pos_map, vec![700, 31, 90, 420, 630, 12]);

        assert_eq!(scan_pos_map_lookup(&pos_map, 4), 630);
        scan_pos_map_update(&mut pos_map, 1, 310);
        assert_eq!(pos_map, vec![700, 310, 90, 420, 630, 12]);

        let access_leaves =
            batch_access_leaves(&[2, 4, 2, 2], &[20, 40, 20, 20], &[21, 41, 22, 23]);
        assert_eq!(access_leaves, vec![20, 40, 21, 22]);
    }

    #[test]
    fn greedy_eviction_plan_places_candidates_once_on_valid_buckets() {
        let params = params(8);
        let mut oram = empty_circuit_oram(params.clone());
        oram.stash[0] =
            OramBlock::real(10, 0, test_payload(&params, 10), params.block_size).unwrap();
        oram.stash[1] =
            OramBlock::real(11, 0, test_payload(&params, 11), params.block_size).unwrap();
        oram.stash[2] =
            OramBlock::real(12, 1, test_payload(&params, 12), params.block_size).unwrap();

        let path = params.path_nodes(0);
        let mut path_meta = vec![CircuitMetaBucket::dummy(params.bucket_size); params.height()];
        path_meta[0].slots[0] = CircuitMetaSlot::real(13, 7);
        path_meta[1].slots[0] = CircuitMetaSlot::real(14, 2);
        path_meta[3].slots[0] = CircuitMetaSlot::real(15, 0);

        let plan = oram.plan_eviction_placements(&path, &path_meta).unwrap();

        let candidate_idx = |logical_id| {
            plan.candidates
                .iter()
                .position(|candidate| candidate.meta.logical_id == logical_id)
                .expect("candidate exists")
        };
        let assert_real = |placement: CircuitEvictionPlacement, candidate_idx| {
            assert_eq!(placement.occupied.unwrap_u8(), 1);
            assert_eq!(placement.candidate_idx, candidate_idx);
        };
        let assert_dummy = |placement: CircuitEvictionPlacement| {
            assert_eq!(placement.occupied.unwrap_u8(), 0);
        };
        assert_real(plan.placements[3][0], candidate_idx(10));
        assert_real(plan.placements[3][1], candidate_idx(11));
        assert_real(plan.placements[2][0], candidate_idx(12));
        assert_real(plan.placements[2][1], candidate_idx(15));
        assert_real(plan.placements[1][0], candidate_idx(14));
        assert_dummy(plan.placements[1][1]);
        assert_real(plan.placements[0][0], candidate_idx(13));
        assert_dummy(plan.placements[0][1]);

        let mut seen = vec![0usize; plan.candidates.len()];
        for (depth, placements) in plan.placements.iter().enumerate() {
            for placement in placements {
                if placement.occupied.unwrap_u8() == 1 {
                    let candidate_idx = placement.candidate_idx;
                    let candidate = &plan.candidates[candidate_idx];
                    assert_eq!(plan.selected[candidate_idx].unwrap_u8(), 1);
                    assert!(params.node_contains_leaf(depth, path[depth], candidate.meta.leaf));
                    seen[candidate_idx] += 1;
                }
            }
        }
        for (candidate_idx, selected) in plan.selected.iter().enumerate() {
            assert_eq!(seen[candidate_idx], selected.unwrap_u8() as usize);
        }
    }

    #[test]
    fn greedy_eviction_apply_preserves_payloads_and_moves_overflow_to_stash() {
        let params = params(8);
        let mut oram = empty_circuit_oram(params.clone());
        oram.stash[0] =
            OramBlock::real(20, 5, test_payload(&params, 20), params.block_size).unwrap();
        oram.stash[1] =
            OramBlock::real(24, 0, test_payload(&params, 24), params.block_size).unwrap();

        let path = params.path_nodes(0);
        let mut path_meta = vec![CircuitMetaBucket::dummy(params.bucket_size); params.height()];
        let mut path_payload =
            vec![
                CircuitPayloadBucket::dummy(params.bucket_size, params.block_size);
                params.height()
            ];
        path_meta[0].slots[0] = CircuitMetaSlot::real(21, 6);
        path_payload[0].slots[0] = test_payload(&params, 21);
        path_meta[0].slots[1] = CircuitMetaSlot::real(22, 7);
        path_payload[0].slots[1] = test_payload(&params, 22);
        path_meta[3].slots[0] = CircuitMetaSlot::real(23, 0);
        path_payload[3].slots[0] = test_payload(&params, 23);

        let mut meta_overlay = BTreeMap::new();
        let mut payload_overlay = BTreeMap::new();
        for (depth, &page_idx) in path.iter().enumerate() {
            meta_overlay.insert(
                page_idx,
                path_meta[depth].encode(params.bucket_size).unwrap(),
            );
            payload_overlay.insert(
                page_idx,
                path_payload[depth]
                    .encode(params.bucket_size, params.block_size)
                    .unwrap(),
            );
        }

        oram.evict_path_in_overlays(&path, &mut meta_overlay, &mut payload_overlay)
            .unwrap();

        let stash_ids = oram
            .stash
            .iter()
            .filter(|block| block.occupied)
            .map(|block| block.logical_id)
            .collect::<Vec<_>>();
        assert_eq!(stash_ids, vec![22]);
        assert_eq!(oram.stash[0].payload, test_payload(&params, 22));

        let mut path_ids = Vec::new();
        for (depth, page_idx) in path.iter().enumerate() {
            let meta_bucket =
                CircuitMetaBucket::decode(&meta_overlay[page_idx], params.bucket_size).unwrap();
            let payload_bucket = CircuitPayloadBucket::decode(
                &payload_overlay[page_idx],
                params.bucket_size,
                params.block_size,
            )
            .unwrap();
            for (slot_idx, meta) in meta_bucket.slots.iter().enumerate() {
                if meta.occupied {
                    assert!(params.node_contains_leaf(depth, path[depth], meta.leaf));
                    assert_eq!(
                        payload_bucket.slots[slot_idx],
                        test_payload(&params, meta.logical_id)
                    );
                    path_ids.push(meta.logical_id);
                }
            }
        }
        path_ids.sort_unstable();
        assert_eq!(path_ids, vec![20, 21, 23, 24]);
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
    fn split_store_runtime_accepts_embedded_tree_path_stores() {
        let params = params(16);
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
        let oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 32),
            [31; 32],
        )
        .unwrap();
        let state = oram.snapshot();
        let (meta_store, payload_store) = oram.into_stores();
        let embedded_meta = seal_embedded_store(
            meta_store,
            circuit_meta_page_bytes(params.bucket_size),
            *b"circ-meta-embed!",
        );
        let embedded_payload = seal_embedded_store(
            payload_store,
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            *b"circ-data-embed!",
        );

        embedded_meta.inner().take_trace();
        embedded_payload.inner().take_trace();
        let mut reopened = CircuitOram::from_state(embedded_meta, embedded_payload, state).unwrap();

        let payload = reopened.read(3).unwrap();
        assert_eq!(u64::from_le_bytes(payload[..8].try_into().unwrap()), 3);
        let meta_access = reopened.meta_store.inner().take_trace();
        let payload_access = reopened.payload_store.inner().take_trace();
        assert_eq!(meta_access.len(), params.height() * 2);
        assert_eq!(payload_access.len(), params.height() * 2);
        assert!(meta_access[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(meta_access[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
        assert!(payload_access[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(payload_access[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));

        assert_eq!(reopened.drain_evictions(1).unwrap(), 1);
    }

    #[test]
    fn split_store_state_rejects_mismatched_auth_roots() {
        let params = params(16);
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
        let oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 32),
            [34; 32],
        )
        .unwrap();
        let state = oram.snapshot();
        let (meta_store, payload_store) = oram.into_stores();
        let embedded_meta = seal_embedded_store(
            meta_store,
            circuit_meta_page_bytes(params.bucket_size),
            *b"circ-meta-bind!!",
        );
        let embedded_payload = seal_embedded_store(
            payload_store,
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            *b"circ-data-bind!!",
        );

        let reopened = CircuitOram::from_state(embedded_meta, embedded_payload, state).unwrap();
        let mut bad_state = reopened.snapshot();
        match &mut bad_state
            .auth
            .as_mut()
            .expect("embedded stores bind auth state")
            .layout
        {
            CircuitStoreAuthLayout::EmbeddedTree { meta, .. } => meta.root_hash[0] ^= 1,
            CircuitStoreAuthLayout::TieredMerkle { meta, .. } => meta.trusted_hashes[0][0] ^= 1,
        }
        let (meta_store, payload_store) = reopened.into_stores();

        let err = CircuitOram::from_state(meta_store, payload_store, bad_state)
            .expect_err("mismatched auth roots must be rejected");
        assert!(format!("{err}").contains("auth roots do not match"));
    }

    #[test]
    fn split_store_batch_read_uses_embedded_tree_batch_paths() {
        let params = params(16);
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
        let oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 32),
            [32; 32],
        )
        .unwrap();
        let state = oram.snapshot();
        let requested = [3u64, 7u64];
        let paths = requested
            .iter()
            .map(|logical_id| params.path_nodes(state.pos_map[*logical_id as usize]))
            .collect::<Vec<_>>();
        let expected_unique = paths
            .iter()
            .flat_map(|path| path.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let (meta_store, payload_store) = oram.into_stores();
        let embedded_meta = seal_embedded_store(
            meta_store,
            circuit_meta_page_bytes(params.bucket_size),
            *b"circ-meta-batch!",
        );
        let embedded_payload = seal_embedded_store(
            payload_store,
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            *b"circ-data-batch!",
        );

        embedded_meta.inner().take_trace();
        embedded_payload.inner().take_trace();
        let mut reopened = CircuitOram::from_state(embedded_meta, embedded_payload, state).unwrap();

        let outputs = reopened.read_batch(&requested).unwrap();
        assert_eq!(outputs.len(), requested.len());
        for (output, logical_id) in outputs.iter().zip(requested) {
            assert_eq!(
                u64::from_le_bytes(output[..8].try_into().unwrap()),
                logical_id
            );
        }

        let meta_access = reopened.meta_store.inner().take_trace();
        let payload_access = reopened.payload_store.inner().take_trace();
        let expected_reads = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Read)
            .collect::<Vec<_>>();
        let expected_writes = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Write)
            .collect::<Vec<_>>();
        assert_eq!(
            meta_access,
            [expected_reads.as_slice(), expected_writes.as_slice()].concat()
        );
        assert_eq!(
            payload_access,
            [expected_reads.as_slice(), expected_writes.as_slice()].concat()
        );
        assert_eq!(
            reopened.pending_evictions().unwrap(),
            requested.len() as u64 * 2
        );

        reopened.meta_store.inner().take_trace();
        reopened.payload_store.inner().take_trace();
        let eviction_paths = (0..4)
            .map(|idx| params.path_nodes(CircuitEvictionSchedule::eviction_leaf_at(&params, idx)))
            .collect::<Vec<_>>();
        let expected_unique = eviction_paths
            .iter()
            .flat_map(|path| path.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(reopened.drain_evictions(4).unwrap(), 4);
        let meta_evict = reopened.meta_store.inner().take_trace();
        let payload_evict = reopened.payload_store.inner().take_trace();
        let expected_reads = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Read)
            .collect::<Vec<_>>();
        let expected_writes = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Write)
            .collect::<Vec<_>>();
        let expected_evict = [expected_reads.as_slice(), expected_writes.as_slice()].concat();
        assert_eq!(meta_evict, expected_evict);
        assert_eq!(payload_evict, expected_evict);
        assert_eq!(reopened.pending_evictions().unwrap(), 0);
    }

    #[test]
    fn split_store_batch_dummy_uses_embedded_tree_batch_paths() {
        let params = params(16);
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
        let oram = CircuitOram::build_trusted(
            params.clone(),
            meta_store,
            payload_store,
            blocks(16, 32),
            [33; 32],
        )
        .unwrap();
        let state = oram.snapshot();
        let mut rng = state.rng.clone();
        let count = 3usize;
        let paths = (0..count)
            .map(|_| params.path_nodes(random_leaf(&params, &mut rng)))
            .collect::<Vec<_>>();
        let expected_unique = paths
            .iter()
            .flat_map(|path| path.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let pos_map_before = state.pos_map.clone();

        let (meta_store, payload_store) = oram.into_stores();
        let embedded_meta = seal_embedded_store(
            meta_store,
            circuit_meta_page_bytes(params.bucket_size),
            *b"circ-meta-dummy!",
        );
        let embedded_payload = seal_embedded_store(
            payload_store,
            circuit_payload_page_bytes(params.bucket_size, params.block_size),
            *b"circ-data-dummy!",
        );

        embedded_meta.inner().take_trace();
        embedded_payload.inner().take_trace();
        let mut reopened = CircuitOram::from_state(embedded_meta, embedded_payload, state).unwrap();

        reopened.dummy_access_batch(count).unwrap();
        assert_eq!(reopened.position_map(), pos_map_before.as_slice());
        assert_eq!(
            reopened.pending_evictions().unwrap(),
            count as u64 * CircuitEvictionSchedule::DEFAULT_EVICTIONS_PER_ACCESS
        );

        let meta_access = reopened.meta_store.inner().take_trace();
        let payload_access = reopened.payload_store.inner().take_trace();
        let expected_reads = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Read)
            .collect::<Vec<_>>();
        let expected_writes = expected_unique
            .iter()
            .copied()
            .map(TraceEvent::Write)
            .collect::<Vec<_>>();
        let expected = [expected_reads.as_slice(), expected_writes.as_slice()].concat();
        assert_eq!(meta_access, expected);
        assert_eq!(payload_access, expected);
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
        assert!(meta_access[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(meta_access[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
        assert!(payload_access[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(payload_access[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));

        oram.drain_evictions(1).unwrap();
        let meta_evict = oram.meta_store.take_trace();
        let payload_evict = oram.payload_store.take_trace();
        assert_eq!(meta_evict.len(), params.height() * 2);
        assert_eq!(payload_evict.len(), params.height() * 2);
        assert!(meta_evict[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(meta_evict[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
        assert!(payload_evict[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(payload_evict[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));

        let pos_map_before_dummy = oram.position_map().to_vec();
        assert_eq!(oram.pending_evictions().unwrap(), 1);
        oram.meta_store.take_trace();
        oram.payload_store.take_trace();

        oram.dummy_access().unwrap();
        assert_eq!(oram.position_map(), pos_map_before_dummy.as_slice());
        assert_eq!(oram.pending_evictions().unwrap(), 3);
        let meta_dummy = oram.meta_store.take_trace();
        let payload_dummy = oram.payload_store.take_trace();
        assert_eq!(meta_dummy.len(), params.height() * 2);
        assert_eq!(payload_dummy.len(), params.height() * 2);
        assert!(meta_dummy[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(meta_dummy[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
        assert!(payload_dummy[..params.height()]
            .iter()
            .all(|event| matches!(event, TraceEvent::Read(_))));
        assert!(payload_dummy[params.height()..]
            .iter()
            .all(|event| matches!(event, TraceEvent::Write(_))));
    }
}
