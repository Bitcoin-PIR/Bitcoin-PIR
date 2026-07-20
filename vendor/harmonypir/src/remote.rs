//! Stateful HarmonyPIR client for remote transports.
//!
//! This module owns the protocol state and the privacy-preserving wire shape,
//! but deliberately does not own a socket, an HTTP/WebSocket protocol, or a
//! browser binding.  Callers send the bytes returned by [`RemoteClient`] to
//! their transport and feed the flat response bytes back into the client.
//!
//! Every real and synthetic request contains exactly `T - 1` sorted, distinct
//! `u32` indices.  Empty cells are padded with random indices from the same
//! padded database domain.  That fixed-count property is part of the protocol
//! privacy boundary and must not be replaced with a variable-length request.

use std::collections::{HashMap, HashSet};
use std::fmt;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::params::{Params, BETA};
#[cfg(feature = "fastprp-prp")]
use crate::prp::fast::FastPrpWrapper;
use crate::prp::hoang::HoangPrp;
use crate::prp::Prp;
use crate::relocation::{RelocationDS, EMPTY};

/// Legacy wire identifier for the HMR12/Hoang PRP backend.
pub const PRP_HMR12: u8 = 0;
/// Legacy wire identifier for the FastPRP backend.
pub const PRP_FASTPRP: u8 = 1;

/// PRP backend used by a remote client group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrpBackend {
    Hmr12 = PRP_HMR12,
    FastPrp = PRP_FASTPRP,
}

impl TryFrom<u8> for PrpBackend {
    type Error = RemoteError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            PRP_HMR12 => Ok(Self::Hmr12),
            PRP_FASTPRP => Ok(Self::FastPrp),
            unsupported => Err(RemoteError::new(format!(
                "unsupported HarmonyPIR PRP backend: {unsupported}"
            ))),
        }
    }
}

/// Error returned by the transport-independent remote client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    message: String,
}

impl RemoteError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RemoteError {}

/// Result type used by the remote client API.
pub type Result<T> = std::result::Result<T, RemoteError>;

/// Compute the HMR12 round count for a database with `n` padded rows.
pub fn compute_rounds(n: u32) -> usize {
    let domain = 2 * n as usize;
    let log_domain = (domain as f64).log2().ceil() as usize;
    let r_raw = log_domain + 40;
    r_raw.div_ceil(BETA) * BETA
}

/// Derive a deterministic per-group key from a master key and group id.
///
/// This preserves the byte-for-byte derivation used by the original
/// `harmonypir-wasm` wrapper.
pub fn derive_group_key(master_key: &[u8], group_id: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    let len = master_key.len().min(16);
    key[..len].copy_from_slice(&master_key[..len]);
    let id_bytes = group_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

/// Compute the balanced segment size `T ~= sqrt(2N)`.
pub fn find_best_t(n: u32) -> u32 {
    let two_n = 2 * n as u64;
    (two_n as f64).sqrt().round().max(1.0) as u32
}

/// Pad `N` so that `T` divides `2N`.
pub fn pad_n_for_t(n: u32, t: u32) -> Result<(u32, u32)> {
    if n == 0 {
        return Err(RemoteError::new("N must be greater than zero"));
    }
    if t == 0 {
        return Err(RemoteError::new("T must be greater than zero"));
    }
    let two_n = 2_u64
        .checked_mul(n as u64)
        .ok_or_else(|| RemoteError::new("2*N overflow"))?;
    let t64 = t as u64;
    let unit = if t64 % 2 == 0 {
        t64
    } else {
        t64.checked_mul(2)
            .ok_or_else(|| RemoteError::new("padding unit overflow"))?
    };
    let padded_2n = two_n
        .checked_add(unit - 1)
        .ok_or_else(|| RemoteError::new("padded 2*N overflow"))?
        / unit
        * unit;
    let padded_n = u32::try_from(padded_2n / 2)
        .map_err(|_| RemoteError::new("padded N does not fit in u32"))?;
    Ok((padded_n, t))
}

fn validate_backend(backend: PrpBackend) -> Result<()> {
    match backend {
        PrpBackend::Hmr12 => Ok(()),
        PrpBackend::FastPrp => {
            #[cfg(feature = "fastprp-prp")]
            {
                Ok(())
            }
            #[cfg(not(feature = "fastprp-prp"))]
            {
                Err(RemoteError::new(
                    "FastPRP backend requested, but harmonypir was built without the `fastprp-prp` feature",
                ))
            }
        }
    }
}

fn build_prp(
    backend: PrpBackend,
    key: &[u8; 16],
    domain: usize,
    n: u32,
    cache: &[u8],
) -> Result<Box<dyn Prp>> {
    validate_backend(backend)?;
    #[cfg(not(feature = "fastprp-prp"))]
    let _ = cache;
    match backend {
        PrpBackend::Hmr12 => Ok(Box::new(HoangPrp::new(domain, compute_rounds(n), key))),
        #[cfg(feature = "fastprp-prp")]
        PrpBackend::FastPrp => {
            if cache.is_empty() {
                Ok(Box::new(FastPrpWrapper::new(key, domain)))
            } else {
                Ok(Box::new(FastPrpWrapper::from_cache(key, domain, cache)))
            }
        }
        #[cfg(not(feature = "fastprp-prp"))]
        PrpBackend::FastPrp => unreachable!("validate_backend rejects FastPRP"),
    }
}

fn save_prp_cache(backend: PrpBackend, key: &[u8; 16], domain: usize, existing: &[u8]) -> Vec<u8> {
    #[cfg(feature = "fastprp-prp")]
    if backend == PrpBackend::FastPrp {
        if !existing.is_empty() {
            return existing.to_vec();
        }
        return FastPrpWrapper::new(key, domain).save_cache();
    }
    let _ = (backend, key, domain, existing);
    Vec::new()
}

fn make_rng_seed(key: &[u8; 16], group_id: u32, query_count: u32) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(key);
    seed[16..20].copy_from_slice(&group_id.to_le_bytes());
    seed[20..24].copy_from_slice(&query_count.to_le_bytes());
    seed
}

/// A fixed-count request ready for a caller-owned remote transport.
#[must_use = "send this request and complete it with RemoteClient::process_response"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRequest {
    bytes: Vec<u8>,
    segment: u32,
    position: u32,
    query_index: u32,
}

impl RemoteRequest {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn segment(&self) -> u32 {
        self.segment
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn query_index(&self) -> u32 {
        self.query_index
    }
}

/// Two requests built against the correct sequential DS' states.
#[must_use = "send both requests and complete them with RemoteClient::process_response_pair"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRequestPair {
    request_1: RemoteRequest,
    request_2: RemoteRequest,
}

impl RemoteRequestPair {
    pub fn request_1(&self) -> &RemoteRequest {
        &self.request_1
    }

    pub fn request_2(&self) -> &RemoteRequest {
        &self.request_2
    }

    pub fn into_parts(self) -> (RemoteRequest, RemoteRequest) {
        (self.request_1, self.request_2)
    }
}

#[derive(Debug)]
struct QueryContext {
    request_bytes: Vec<u8>,
    s: usize,
    r: usize,
    q: usize,
    position_map: Vec<usize>,
    is_dummy: Vec<bool>,
}

#[derive(Debug)]
struct PendingPair {
    first: QueryContext,
    d_1: Vec<usize>,
    second: QueryContext,
}

#[derive(Debug)]
struct DeferredRelocation {
    context: QueryContext,
    entries: Vec<Vec<u8>>,
    answer: Vec<u8>,
}

#[derive(Debug)]
enum InFlight {
    Idle,
    Single(QueryContext),
    Pair(PendingPair),
    Deferred(DeferredRelocation),
}

/// Stateful per-group client for a caller-owned remote transport.
pub struct RemoteClient {
    params: Params,
    ds: RelocationDS,
    hints: Vec<Vec<u8>>,
    query_count: usize,
    rng: ChaCha20Rng,
    backend: PrpBackend,
    prp_cache: Vec<u8>,
    real_n: u32,
    relocated_segments: Vec<u32>,
    in_flight: InFlight,
}

impl RemoteClient {
    /// Construct a group with the HMR12 backend.
    pub fn new(n: u32, w: u32, t: u32, master_key: &[u8], group_id: u32) -> Result<Self> {
        Self::new_with_backend(n, w, t, master_key, group_id, PrpBackend::Hmr12)
    }

    /// Construct a group with an explicitly selected PRP backend.
    pub fn new_with_backend(
        n: u32,
        w: u32,
        t: u32,
        master_key: &[u8],
        group_id: u32,
        backend: PrpBackend,
    ) -> Result<Self> {
        if n == 0 {
            return Err(RemoteError::new("N must be greater than zero"));
        }
        if w == 0 {
            return Err(RemoteError::new("row width must be greater than zero"));
        }
        let t = if t == 0 { find_best_t(n) } else { t };
        let (padded_n, t) = pad_n_for_t(n, t)?;
        let params = Params::new(padded_n as usize, w as usize, t as usize)
            .map_err(|error| RemoteError::new(format!("invalid params: {error}")))?;
        if params.t < 2 {
            return Err(RemoteError::new("T must be at least two"));
        }
        if params.t - 1 > params.n {
            return Err(RemoteError::new(
                "T-1 exceeds padded N; fixed-count padding is impossible",
            ));
        }

        let key = derive_group_key(master_key, group_id);
        let domain = 2 * params.n;
        let prp_cache = save_prp_cache(backend, &key, domain, &[]);
        let prp = build_prp(backend, &key, domain, padded_n, &prp_cache)?;
        let ds = RelocationDS::new(params.n, params.t, prp)
            .map_err(|error| RemoteError::new(format!("DS init failed: {error}")))?;
        let hints = vec![vec![0; params.w]; params.m];
        let rng = ChaCha20Rng::from_seed(make_rng_seed(&key, group_id, 0));

        Ok(Self {
            params,
            ds,
            hints,
            query_count: 0,
            rng,
            backend,
            prp_cache,
            real_n: n,
            relocated_segments: Vec::new(),
            in_flight: InFlight::Idle,
        })
    }

    /// Replace all hint parities from a flat `M * w` byte buffer.
    pub fn load_hints(&mut self, data: &[u8]) -> Result<()> {
        self.require_idle("load_hints")?;
        let expected = self
            .params
            .m
            .checked_mul(self.params.w)
            .ok_or_else(|| RemoteError::new("hint length overflow"))?;
        if data.len() != expected {
            return Err(RemoteError::new(format!(
                "expected {expected} bytes of hints, got {}",
                data.len()
            )));
        }
        for (hint, chunk) in self.hints.iter_mut().zip(data.chunks_exact(self.params.w)) {
            hint.copy_from_slice(chunk);
        }
        Ok(())
    }

    /// Build one fixed-count request and enter the single-query in-flight state.
    pub fn build_request(&mut self, q: u32) -> Result<RemoteRequest> {
        self.require_idle("build_request")?;
        let context = self.build_request_context(q)?;
        let request = Self::request_from_context(q, &context);
        self.in_flight = InFlight::Single(context);
        Ok(request)
    }

    /// Build a realistic request without consuming a query or changing DS'/hints.
    pub fn build_dummy_request(&mut self) -> Result<RemoteRequest> {
        self.require_idle("build_dummy_request")?;
        let q = self.rng.next_u32() % self.real_n;
        let context = self.build_request_context(q)?;
        Ok(Self::request_from_context(q, &context))
    }

    /// Build a transport-only synthetic dummy with the exact real request size.
    pub fn build_synthetic_dummy(&mut self) -> Vec<u8> {
        let target = self.params.t - 1;
        let domain = self.params.n as u32;
        let mut indices = Vec::with_capacity(target);
        let mut seen = HashSet::with_capacity(target);
        while indices.len() < target {
            let value = self.rng.next_u32() % domain;
            if seen.insert(value) {
                indices.push(value);
            }
        }
        indices.sort_unstable();
        encode_indices(&indices)
    }

    /// Consume a flat response and finish a previously built request.
    pub fn process_response(&mut self, response: &[u8]) -> Result<Vec<u8>> {
        let context = match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Single(context) => context,
            other => {
                self.in_flight = other;
                return Err(RemoteError::new(
                    "process_response requires one pending single request",
                ));
            }
        };

        match self.recover_answer(&context, response) {
            Ok((answer, entries)) => {
                self.relocate_and_update_hints(&context, &entries, &answer)?;
                self.query_count += 1;
                Ok(answer)
            }
            Err(error) => {
                self.in_flight = InFlight::Single(context);
                Err(error)
            }
        }
    }

    /// Recover the answer now and defer the local relocation step.
    pub fn process_response_xor_only(&mut self, response: &[u8]) -> Result<Vec<u8>> {
        let context = match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Single(context) => context,
            other => {
                self.in_flight = other;
                return Err(RemoteError::new(
                    "process_response_xor_only requires one pending single request",
                ));
            }
        };
        match self.recover_answer_owned(&context, response) {
            Ok((answer, entries)) => {
                self.in_flight = InFlight::Deferred(DeferredRelocation {
                    context,
                    entries,
                    answer: answer.clone(),
                });
                Ok(answer)
            }
            Err(error) => {
                self.in_flight = InFlight::Single(context);
                Err(error)
            }
        }
    }

    /// Finish a relocation deferred by [`Self::process_response_xor_only`].
    pub fn finish_relocation(&mut self) -> Result<()> {
        let deferred = match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Deferred(deferred) => deferred,
            other => {
                self.in_flight = other;
                return Err(RemoteError::new(
                    "finish_relocation requires a deferred response",
                ));
            }
        };
        let refs: Vec<&[u8]> = deferred.entries.iter().map(Vec::as_slice).collect();
        self.relocate_and_update_hints(&deferred.context, &refs, &deferred.answer)?;
        self.query_count += 1;
        Ok(())
    }

    /// Build two requests while preserving sequential DS' semantics.
    pub fn build_request_pair(&mut self, q_1: u32, q_2: u32) -> Result<RemoteRequestPair> {
        self.require_idle("build_request_pair")?;
        if self.query_count + 2 > self.params.max_queries {
            return Err(RemoteError::new(
                "not enough query budget remaining for a pair (need 2)",
            ));
        }
        self.validate_query(q_1)?;
        self.validate_query(q_2)?;

        let first = self.build_request_context(q_1)?;
        let m_1 = self.ds.relocated_segment_count();
        self.ds
            .relocate_segment(first.s)
            .map_err(|error| RemoteError::new(format!("relocate first segment failed: {error}")))?;
        self.relocated_segments.push(first.s as u32);

        let mut d_1 = vec![0; self.params.t];
        for (i, destination) in d_1.iter_mut().enumerate() {
            let empty_value = self.params.n + m_1 * self.params.t + i;
            *destination = self.ds.locate_extended(empty_value).map_err(|error| {
                RemoteError::new(format!("locate first destination failed: {error}"))
            })? / self.params.t;
        }

        let second = self.build_request_context(q_2).map_err(|error| {
            RemoteError::new(format!(
                "second pair request failed after first relocation: {error}"
            ))
        })?;
        let request_1 = Self::request_from_context(q_1, &first);
        let request_2 = Self::request_from_context(q_2, &second);
        self.in_flight = InFlight::Pair(PendingPair { first, d_1, second });
        Ok(RemoteRequestPair {
            request_1,
            request_2,
        })
    }

    /// Finish the two requests created by [`Self::build_request_pair`].
    pub fn process_response_pair(
        &mut self,
        response_1: &[u8],
        response_2: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let pending = match std::mem::replace(&mut self.in_flight, InFlight::Idle) {
            InFlight::Pair(pending) => pending,
            other => {
                self.in_flight = other;
                return Err(RemoteError::new(
                    "process_response_pair requires one pending request pair",
                ));
            }
        };

        if let Err(error) = self.validate_response(&pending.first, response_1, "response_1") {
            self.in_flight = InFlight::Pair(pending);
            return Err(error);
        }
        if let Err(error) = self.validate_response(&pending.second, response_2, "response_2") {
            self.in_flight = InFlight::Pair(pending);
            return Err(error);
        }

        let (answer_1, entries_1) = self.recover_answer(&pending.first, response_1)?;

        let mut position_to_entry_1 = vec![None; self.params.t];
        for (entry_index, &position) in pending.first.position_map.iter().enumerate() {
            position_to_entry_1[position] = Some(entry_index);
        }
        for (i, &destination) in pending.d_1.iter().enumerate() {
            if i == pending.first.r {
                xor_into(&mut self.hints[destination], &answer_1);
            } else if let Some(entry_index) = position_to_entry_1[i] {
                xor_into(&mut self.hints[destination], entries_1[entry_index]);
            }
        }

        // This intentionally happens after the first hint update: the first
        // relocation may have written H[s_2], exactly as in two sequential
        // requests.
        let (answer_2, entries_2) = self.recover_answer(&pending.second, response_2)?;
        self.relocate_and_update_hints(&pending.second, &entries_2, &answer_2)?;
        self.query_count += 2;
        Ok((answer_1, answer_2))
    }

    /// Serialize state in the legacy `harmonypir-wasm` v1 byte format.
    ///
    /// The format is retained as an explicit compatibility boundary so native,
    /// browser, and Python adapters can all restore the same state. In-flight
    /// requests are rejected because their round-local metadata is not encoded.
    pub fn serialize_legacy_state(&self) -> Result<Vec<u8>> {
        self.require_idle("serialize_legacy_state")?;

        let relocated_len = self
            .relocated_segments
            .len()
            .checked_mul(4)
            .ok_or_else(|| RemoteError::new("relocated segment length overflow"))?;
        let hints_len = self
            .params
            .m
            .checked_mul(self.params.w)
            .ok_or_else(|| RemoteError::new("hint length overflow"))?;
        let total = 29_usize
            .checked_add(relocated_len)
            .and_then(|value| value.checked_add(self.prp_cache.len()))
            .and_then(|value| value.checked_add(hints_len))
            .ok_or_else(|| RemoteError::new("serialized state length overflow"))?;
        let mut bytes = Vec::with_capacity(total);

        bytes.extend_from_slice(&(self.params.n as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.params.w as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.params.t as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.query_count as u32).to_le_bytes());
        bytes.push(self.backend as u8);
        bytes.extend_from_slice(&self.real_n.to_le_bytes());
        bytes.extend_from_slice(&(self.relocated_segments.len() as u32).to_le_bytes());
        for segment in &self.relocated_segments {
            bytes.extend_from_slice(&segment.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.prp_cache.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.prp_cache);
        for hint in &self.hints {
            bytes.extend_from_slice(hint);
        }
        debug_assert_eq!(bytes.len(), total);
        Ok(bytes)
    }

    /// Restore a client from the legacy `harmonypir-wasm` v1 state format.
    pub fn deserialize_legacy_state(data: &[u8], master_key: &[u8], group_id: u32) -> Result<Self> {
        fn take<'a>(
            data: &'a [u8],
            position: &mut usize,
            length: usize,
            field: &str,
        ) -> Result<&'a [u8]> {
            let end = position
                .checked_add(length)
                .ok_or_else(|| RemoteError::new(format!("serialized {field} offset overflow")))?;
            let value = data.get(*position..end).ok_or_else(|| {
                RemoteError::new(format!(
                    "serialized state truncated while reading {field}: need {end}, have {}",
                    data.len()
                ))
            })?;
            *position = end;
            Ok(value)
        }

        fn read_u32(data: &[u8], position: &mut usize, field: &str) -> Result<u32> {
            let bytes: [u8; 4] = take(data, position, 4, field)?
                .try_into()
                .map_err(|_| RemoteError::new(format!("serialized {field} has invalid width")))?;
            Ok(u32::from_le_bytes(bytes))
        }

        if data.len() < 29 {
            return Err(RemoteError::new("serialized state is too short"));
        }
        let mut position = 0;
        let padded_n = read_u32(data, &mut position, "padded_n")?;
        let w = read_u32(data, &mut position, "w")?;
        let t = read_u32(data, &mut position, "t")?;
        let query_count = read_u32(data, &mut position, "query_count")? as usize;
        let backend = PrpBackend::try_from(take(data, &mut position, 1, "prp_backend")?[0])?;
        validate_backend(backend)?;
        let real_n = read_u32(data, &mut position, "real_n")?;
        let relocated_count = read_u32(data, &mut position, "relocated_count")? as usize;
        let relocated_len = relocated_count
            .checked_mul(4)
            .ok_or_else(|| RemoteError::new("relocated segment length overflow"))?;
        let relocated_bytes = take(data, &mut position, relocated_len, "relocated segments")?;
        let mut relocated_segments = Vec::new();
        relocated_segments
            .try_reserve_exact(relocated_count)
            .map_err(|_| RemoteError::new("relocated segment count is too large"))?;
        for bytes in relocated_bytes.chunks_exact(4) {
            relocated_segments.push(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                RemoteError::new("serialized relocated segment has invalid width")
            })?));
        }

        let cache_len = read_u32(data, &mut position, "cache_len")? as usize;
        let prp_cache = take(data, &mut position, cache_len, "PRP cache")?.to_vec();
        let params = Params::new(padded_n as usize, w as usize, t as usize)
            .map_err(|error| RemoteError::new(format!("invalid serialized params: {error}")))?;
        if real_n == 0 || real_n > padded_n {
            return Err(RemoteError::new(format!(
                "serialized real_n {real_n} is outside 1..={padded_n}"
            )));
        }
        if query_count > params.max_queries || relocated_count != query_count {
            return Err(RemoteError::new(format!(
                "serialized query/relocation count mismatch: queries={query_count}, relocations={relocated_count}"
            )));
        }
        let hints_len = params
            .m
            .checked_mul(params.w)
            .ok_or_else(|| RemoteError::new("serialized hint length overflow"))?;
        let hints_data = take(data, &mut position, hints_len, "hints")?;
        if position != data.len() {
            return Err(RemoteError::new(format!(
                "serialized state has {} trailing bytes",
                data.len() - position
            )));
        }

        let key = derive_group_key(master_key, group_id);
        let domain = params
            .n
            .checked_mul(2)
            .ok_or_else(|| RemoteError::new("serialized PRP domain overflow"))?;
        let prp = build_prp(backend, &key, domain, padded_n, &prp_cache)?;
        let mut ds = RelocationDS::new(params.n, params.t, prp)
            .map_err(|error| RemoteError::new(format!("DS restore failed: {error}")))?;
        for segment in &relocated_segments {
            ds.relocate_segment(*segment as usize)
                .map_err(|error| RemoteError::new(format!("replay relocation failed: {error}")))?;
        }

        let mut hints = vec![vec![0; params.w]; params.m];
        for (hint, chunk) in hints.iter_mut().zip(hints_data.chunks_exact(params.w)) {
            hint.copy_from_slice(chunk);
        }
        let rng = ChaCha20Rng::from_seed(make_rng_seed(
            &key,
            group_id,
            query_count
                .try_into()
                .map_err(|_| RemoteError::new("serialized query count does not fit in u32"))?,
        ));

        Ok(Self {
            params,
            ds,
            hints,
            query_count,
            rng,
            backend,
            prp_cache,
            real_n,
            relocated_segments,
            in_flight: InFlight::Idle,
        })
    }

    pub fn queries_remaining(&self) -> u32 {
        (self.params.max_queries - self.query_count) as u32
    }

    pub fn queries_used(&self) -> u32 {
        self.query_count as u32
    }

    pub fn padded_n(&self) -> u32 {
        self.params.n as u32
    }

    pub fn real_n(&self) -> u32 {
        self.real_n
    }

    pub fn row_width(&self) -> u32 {
        self.params.w as u32
    }

    pub fn segment_size(&self) -> u32 {
        self.params.t as u32
    }

    pub fn segment_count(&self) -> u32 {
        self.params.m as u32
    }

    pub fn max_queries(&self) -> u32 {
        self.params.max_queries as u32
    }

    pub fn backend(&self) -> PrpBackend {
        self.backend
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.in_flight, InFlight::Idle)
    }

    fn require_idle(&self, method: &str) -> Result<()> {
        if self.is_idle() {
            Ok(())
        } else {
            Err(RemoteError::new(format!(
                "{method} called while another query operation is in flight"
            )))
        }
    }

    fn validate_query(&self, q: u32) -> Result<()> {
        if q >= self.real_n {
            return Err(RemoteError::new(format!(
                "query index {q} is outside the real database domain 0..{}",
                self.real_n
            )));
        }
        if self.query_count >= self.params.max_queries {
            return Err(RemoteError::new("no more queries available; rehint needed"));
        }
        Ok(())
    }

    fn build_request_context(&mut self, q: u32) -> Result<QueryContext> {
        self.validate_query(q)?;
        let q_usize = q as usize;
        let t = self.params.t;
        let target = t - 1;
        let domain = self.params.n as u32;

        let cell = self
            .ds
            .locate(q_usize)
            .map_err(|error| RemoteError::new(format!("locate failed: {error}")))?;
        let segment = cell / t;
        let position = cell % t;

        let mut cells = Vec::with_capacity(target);
        let mut cell_positions = Vec::with_capacity(target);
        for i in 0..t {
            if i != position {
                cells.push(segment * t + i);
                cell_positions.push(i);
            }
        }
        let values = self
            .ds
            .batch_access(&cells)
            .map_err(|error| RemoteError::new(format!("batch access failed: {error}")))?;

        let mut real = Vec::with_capacity(target);
        for (index, &value) in values.iter().enumerate() {
            if value != EMPTY {
                real.push((value as u32, cell_positions[index]));
            }
        }
        let real_by_index: HashMap<u32, usize> = real.iter().copied().collect();
        let mut chosen: HashSet<u32> = real_by_index.keys().copied().collect();
        let dummy_count = target - real.len();
        let mut dummies = Vec::with_capacity(dummy_count);
        while dummies.len() < dummy_count {
            let candidate = self.rng.next_u32() % domain;
            if chosen.insert(candidate) {
                dummies.push(candidate);
            }
        }

        let mut merged: Vec<u32> = real_by_index.keys().copied().chain(dummies).collect();
        merged.sort_unstable();
        debug_assert_eq!(merged.len(), target);

        let mut is_dummy = Vec::with_capacity(target);
        let mut position_map = Vec::with_capacity(real.len());
        for index in &merged {
            if let Some(&original_position) = real_by_index.get(index) {
                is_dummy.push(false);
                position_map.push(original_position);
            } else {
                is_dummy.push(true);
            }
        }

        Ok(QueryContext {
            request_bytes: encode_indices(&merged),
            s: segment,
            r: position,
            q: q_usize,
            position_map,
            is_dummy,
        })
    }

    fn request_from_context(q: u32, context: &QueryContext) -> RemoteRequest {
        debug_assert_eq!(q as usize, context.q);
        RemoteRequest {
            bytes: context.request_bytes.clone(),
            segment: context.s as u32,
            position: context.r as u32,
            query_index: q,
        }
    }

    fn validate_response(
        &self,
        context: &QueryContext,
        response: &[u8],
        label: &str,
    ) -> Result<()> {
        let expected = context
            .is_dummy
            .len()
            .checked_mul(self.params.w)
            .ok_or_else(|| RemoteError::new("response length overflow"))?;
        if response.len() != expected {
            return Err(RemoteError::new(format!(
                "expected {expected} bytes for {label} ({} entries x {}B), got {}",
                context.is_dummy.len(),
                self.params.w,
                response.len()
            )));
        }
        Ok(())
    }

    fn recover_answer<'a>(
        &self,
        context: &QueryContext,
        response: &'a [u8],
    ) -> Result<(Vec<u8>, Vec<&'a [u8]>)> {
        self.validate_response(context, response, "response")?;
        let entries: Vec<&[u8]> = response.chunks_exact(self.params.w).collect();
        let mut answer = self.hints[context.s].clone();
        for (entry, is_dummy) in entries.iter().zip(&context.is_dummy) {
            if !is_dummy {
                xor_into(&mut answer, entry);
            }
        }
        let real_entries = entries
            .into_iter()
            .zip(&context.is_dummy)
            .filter_map(|(entry, is_dummy)| (!is_dummy).then_some(entry))
            .collect::<Vec<_>>();
        if real_entries.len() != context.position_map.len() {
            return Err(RemoteError::new(
                "response metadata is inconsistent with the request position map",
            ));
        }
        Ok((answer, real_entries))
    }

    fn recover_answer_owned(
        &self,
        context: &QueryContext,
        response: &[u8],
    ) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        let (answer, entries) = self.recover_answer(context, response)?;
        Ok((answer, entries.into_iter().map(<[u8]>::to_vec).collect()))
    }

    fn relocate_and_update_hints(
        &mut self,
        context: &QueryContext,
        entries: &[&[u8]],
        answer: &[u8],
    ) -> Result<()> {
        let relocation_index = self.ds.relocated_segment_count();
        self.ds
            .relocate_segment(context.s)
            .map_err(|error| RemoteError::new(format!("relocate failed: {error}")))?;
        self.relocated_segments.push(context.s as u32);

        let mut position_to_entry = vec![None; self.params.t];
        for (entry_index, &position) in context.position_map.iter().enumerate() {
            position_to_entry[position] = Some(entry_index);
        }
        for (i, entry_index) in position_to_entry.iter().enumerate() {
            let empty_value = self.params.n + relocation_index * self.params.t + i;
            let destination = self.ds.locate_extended(empty_value).map_err(|error| {
                RemoteError::new(format!("locate relocation destination failed: {error}"))
            })? / self.params.t;
            if i == context.r {
                xor_into(&mut self.hints[destination], answer);
            } else if let Some(entry_index) = entry_index {
                xor_into(&mut self.hints[destination], entries[*entry_index]);
            }
        }
        Ok(())
    }
}

fn encode_indices(indices: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(indices.len() * 4);
    for index in indices {
        bytes.extend_from_slice(&index.to_le_bytes());
    }
    bytes
}

fn xor_into(destination: &mut [u8], source: &[u8]) {
    debug_assert_eq!(destination.len(), source.len());
    for (destination, source) in destination.iter_mut().zip(source) {
        *destination ^= *source;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db(n: usize, w: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|row| {
                (0..w)
                    .map(|column| (row as u8).wrapping_mul(31).wrapping_add(column as u8))
                    .collect()
            })
            .collect()
    }

    fn initialized_client(n: u32, w: u32, t: u32, key: &[u8], group_id: u32) -> RemoteClient {
        let mut client = RemoteClient::new(n, w, t, key, group_id).unwrap();
        let db = test_db(n as usize, w as usize);
        let mut hints = vec![vec![0u8; w as usize]; client.params.m];
        for (index, row) in db.iter().enumerate() {
            let segment = client.ds.locate(index).unwrap() / client.params.t;
            xor_into(&mut hints[segment], row);
        }
        let flat: Vec<u8> = hints.into_iter().flatten().collect();
        client.load_hints(&flat).unwrap();
        client
    }

    fn decode_indices(request: &RemoteRequest) -> Vec<u32> {
        request
            .as_bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect()
    }

    fn response(request: &RemoteRequest, db: &[Vec<u8>], w: usize) -> Vec<u8> {
        let zero = vec![0u8; w];
        decode_indices(request)
            .into_iter()
            .flat_map(|index| {
                db.get(index as usize)
                    .unwrap_or(&zero)
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn group_key_and_padding_match_legacy_wrapper() {
        assert_eq!(derive_group_key(&[0x42; 16], 0), [0x42; 16]);
        let key = derive_group_key(&[0x42; 16], 0x0102_0304);
        assert_eq!(&key[12..], &[0x46, 0x41, 0x40, 0x43]);
        assert_eq!(pad_n_for_t(10, 5).unwrap(), (10, 5));
        assert_eq!(pad_n_for_t(11, 5).unwrap(), (15, 5));
    }

    #[test]
    fn every_request_has_fixed_sorted_distinct_shape_across_aging() {
        let key = [0x5a; 16];
        let db = test_db(64, 8);
        let mut client = initialized_client(64, 8, 8, &key, 7);
        for query in [3, 17, 3, 42] {
            let request = client.build_request(query).unwrap();
            assert_eq!(request.as_bytes().len(), (client.params.t - 1) * 4);
            let indices = decode_indices(&request);
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(indices.iter().all(|index| *index < client.padded_n()));
            let response = response(&request, &db, 8);
            let answer = client.process_response(&response).unwrap();
            assert_eq!(answer, db[query as usize]);
        }
    }

    #[test]
    fn synthetic_dummy_uses_the_same_fixed_shape() {
        let mut client = RemoteClient::new(64, 8, 8, &[0x11; 16], 2).unwrap();
        let bytes = client.build_synthetic_dummy();
        assert_eq!(bytes.len(), 7 * 4);
        let indices: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn request_bytes_match_legacy_wrapper_golden_fixture() {
        let mut client = RemoteClient::new(64, 8, 8, &[0x5a; 16], 7).unwrap();
        client.load_hints(&vec![0; 16 * 8]).unwrap();
        let request = client.build_request(3).unwrap();
        let expected = [
            0x1f, 0, 0, 0, 0x22, 0, 0, 0, 0x23, 0, 0, 0, 0x26, 0, 0, 0, 0x31, 0, 0, 0, 0x3d, 0, 0,
            0, 0x3f, 0, 0, 0,
        ];
        assert_eq!(request.as_bytes(), expected);
    }

    #[test]
    fn pair_pipeline_matches_two_sequential_queries() {
        let key = [0x33; 16];
        let db = test_db(64, 8);
        let mut pair = initialized_client(64, 8, 8, &key, 4);
        let mut sequential = initialized_client(64, 8, 8, &key, 4);

        let requests = pair.build_request_pair(5, 29).unwrap();
        let (pair_request_1, pair_request_2) = requests.into_parts();

        let sequential_request_1 = sequential.build_request(5).unwrap();
        assert_eq!(pair_request_1, sequential_request_1);
        let response_1 = response(&pair_request_1, &db, 8);
        let sequential_answer_1 = sequential.process_response(&response_1).unwrap();

        let sequential_request_2 = sequential.build_request(29).unwrap();
        assert_eq!(pair_request_2, sequential_request_2);
        let response_2 = response(&pair_request_2, &db, 8);
        let sequential_answer_2 = sequential.process_response(&response_2).unwrap();

        let (pair_answer_1, pair_answer_2) = pair
            .process_response_pair(&response_1, &response_2)
            .unwrap();
        assert_eq!(pair_answer_1, sequential_answer_1);
        assert_eq!(pair_answer_2, sequential_answer_2);
        assert_eq!(pair_answer_1, db[5]);
        assert_eq!(pair_answer_2, db[29]);
        assert_eq!(
            pair.serialize_legacy_state().unwrap(),
            sequential.serialize_legacy_state().unwrap()
        );
    }

    #[test]
    fn legacy_state_format_has_a_golden_fixture() {
        let mut client = RemoteClient::new(8, 2, 4, &[0x42; 16], 0).unwrap();
        client.load_hints(&[0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
        let expected = [
            8, 0, 0, 0, // padded_n
            2, 0, 0, 0, // w
            4, 0, 0, 0, // t
            0, 0, 0, 0, // query_count
            0, // HMR12
            8, 0, 0, 0, // real_n
            0, 0, 0, 0, // relocated segments
            0, 0, 0, 0, // PRP cache
            0, 1, 2, 3, 4, 5, 6, 7, // hints
        ];
        let state = client.serialize_legacy_state().unwrap();
        assert_eq!(state, expected);

        let restored = RemoteClient::deserialize_legacy_state(&state, &[0x42; 16], 0).unwrap();
        assert_eq!(restored.serialize_legacy_state().unwrap(), state);
    }

    #[test]
    fn serialization_rejects_in_flight_and_malformed_state() {
        let mut client = initialized_client(64, 8, 8, &[0x77; 16], 1);
        let _request = client.build_request(3).unwrap();
        assert!(client.serialize_legacy_state().is_err());

        let mut valid = RemoteClient::new(8, 2, 4, &[0x42; 16], 0)
            .unwrap()
            .serialize_legacy_state()
            .unwrap();
        valid.push(0xff);
        assert!(RemoteClient::deserialize_legacy_state(&valid, &[0x42; 16], 0).is_err());
        assert!(RemoteClient::deserialize_legacy_state(&valid[..12], &[0x42; 16], 0).is_err());
    }

    #[test]
    fn response_length_error_keeps_request_retryable() {
        let db = test_db(64, 8);
        let mut client = initialized_client(64, 8, 8, &[0x21; 16], 3);
        let request = client.build_request(12).unwrap();
        assert!(client.process_response(&[0; 8]).is_err());
        assert!(!client.is_idle());
        let valid_response = response(&request, &db, 8);
        assert_eq!(client.process_response(&valid_response).unwrap(), db[12]);
        assert!(client.is_idle());
    }

    #[test]
    fn queries_cannot_target_virtual_padding_rows() {
        let mut client = RemoteClient::new(11, 8, 5, &[0x31; 16], 0).unwrap();
        assert_eq!(client.padded_n(), 15);
        assert!(client.build_request(11).is_err());
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn fastprp_cache_survives_legacy_state_roundtrip() {
        let key = [0x19; 16];
        let client =
            RemoteClient::new_with_backend(64, 8, 8, &key, 9, PrpBackend::FastPrp).unwrap();
        let state = client.serialize_legacy_state().unwrap();
        let restored = RemoteClient::deserialize_legacy_state(&state, &key, 9).unwrap();
        assert_eq!(restored.backend(), PrpBackend::FastPrp);
        assert_eq!(restored.serialize_legacy_state().unwrap(), state);
    }
}
