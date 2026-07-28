//! Explicit, one-shot NUT-07 checks for already-held provider custody.

use std::fmt;

use pir_payment_crypto::cashu_hash_to_curve_v1;
use pir_service_protocol::derive_cashu_mint_id;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::dto::decode_json_v1;
use crate::dto::{
    decode_lower_hex, decode_mint_response_json_v1, encode_json_v1, is_bounded_nut07_witness_v1,
    lower_hex, CashuPostCheckStateRequestJsonV1, CashuPostCheckStateResponseJsonV1,
    CashuProofStateJsonV1,
};
use crate::{
    CashuClientErrorV1, CashuCustodyBundleV1, CashuMintRouteV1, CashuMintTransportV1,
    CashuMintTrustV1, CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1, CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1,
    MAX_CASHU_MINT_JSON_BYTES_V1,
};

/// Maximum custody lots accepted by one explicit NUT-07 batch.
pub const MAX_CASHU_NUT07_BUNDLES_V1: usize = 512;
/// Maximum notes accepted by one explicit NUT-07 batch.
pub const MAX_CASHU_NUT07_NOTES_V1: usize = 512;

const CASHU_NUT07_EVIDENCE_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-nut07-evidence/v1";
const CASHU_NUT07_RESPONSE_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-nut07-response/v1";
const CASHU_NUT07_LOT_OBSERVATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/cashu-nut07-lot-observation/v1";
const CASHU_NUT07_EXPORT_OBSERVATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/cashu-nut07-export-observation/v1";
const CASHU_NUT07_WITNESS_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/cashu-nut07-witness/v1";

/// Canonical NUT-07 states accepted by the public checker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CashuNut07NoteStateV1 {
    Unspent = 0,
    Pending = 1,
    Spent = 2,
}

/// One transient, exact checked `Y` and state pair.
///
/// The value is intentionally not `Clone` or `Copy`. Its debug output is
/// redacted and its `Y` is zeroized on drop. Callers that copy the borrowed
/// `Y` or consume it with [`Self::into_sensitive_parts`] assume responsibility
/// for zeroizing that copy and must never persist or log it.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct CashuNut07CheckedNoteV1 {
    y: [u8; 33],
    state: CashuNut07NoteStateV1,
}

impl CashuNut07CheckedNoteV1 {
    pub const fn y(&self) -> &[u8; 33] {
        &self.y
    }

    pub const fn state(&self) -> CashuNut07NoteStateV1 {
        self.state
    }

    /// Transfer the sensitive `Y` to the caller, zeroizing this object's copy.
    pub fn into_sensitive_parts(mut self) -> ([u8; 33], CashuNut07NoteStateV1) {
        let y = std::mem::replace(&mut self.y, [0u8; 33]);
        (y, self.state)
    }
}

impl fmt::Debug for CashuNut07CheckedNoteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuNut07CheckedNoteV1")
            .field("y", &"[REDACTED_Y]")
            .field("state", &self.state)
            .finish()
    }
}

impl Drop for CashuNut07CheckedNoteV1 {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

/// Per-custody-lot state summary with transient checked notes.
///
/// Raw `Y` values are reachable only through explicit accessors, are omitted
/// from debug output, and are zeroized when their checked-note values drop.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct CashuNut07LotResultV1 {
    note_set_digest: [u8; 32],
    settlement_value: u64,
    note_count: u32,
    unspent_count: u32,
    pending_count: u32,
    spent_count: u32,
    observation_digest: [u8; 32],
    checked_notes: Vec<CashuNut07CheckedNoteV1>,
}

impl CashuNut07LotResultV1 {
    pub const fn note_set_digest(&self) -> &[u8; 32] {
        &self.note_set_digest
    }

    pub const fn settlement_value(&self) -> u64 {
        self.settlement_value
    }

    pub const fn note_count(&self) -> u32 {
        self.note_count
    }

    pub const fn unspent_count(&self) -> u32 {
        self.unspent_count
    }

    pub const fn pending_count(&self) -> u32 {
        self.pending_count
    }

    pub const fn spent_count(&self) -> u32 {
        self.spent_count
    }

    /// Exact per-lot observation digest; it exposes neither `Y` nor witness.
    pub const fn observation_digest(&self) -> &[u8; 32] {
        &self.observation_digest
    }

    /// Borrow the exact transient checks for this lot in ascending `Y` order.
    pub fn checked_notes(&self) -> &[CashuNut07CheckedNoteV1] {
        &self.checked_notes
    }

    /// Consume this summary and transfer its sensitive checked-note values.
    pub fn into_checked_notes(self) -> Vec<CashuNut07CheckedNoteV1> {
        self.checked_notes
    }

    /// True only when every note in this exact custody lot is `SPENT`.
    pub const fn all_spent(&self) -> bool {
        self.note_count != 0 && self.spent_count == self.note_count
    }
}

impl fmt::Debug for CashuNut07LotResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuNut07LotResultV1")
            .field("note_set_digest", &"[REDACTED_DIGEST]")
            .field("settlement_value", &self.settlement_value)
            .field("note_count", &self.note_count)
            .field("unspent_count", &self.unspent_count)
            .field("pending_count", &self.pending_count)
            .field("spent_count", &self.spent_count)
            .field("observation_digest", &"[REDACTED_DIGEST]")
            .field("checked_note_count", &self.checked_notes.len())
            .field("all_spent", &self.all_spent())
            .finish()
    }
}

/// Bounded, locally validated summary of one exact NUT-07 response.
///
/// `evidence_digest` is a deterministic local commitment to the validated
/// summaries; it is not a mint signature and must not be treated as one.
#[must_use]
#[derive(Eq, PartialEq)]
pub struct CashuNut07BatchResultV1 {
    mint_id: [u8; 32],
    unit: String,
    lots: Vec<CashuNut07LotResultV1>,
    nut07_response_digest: [u8; 32],
    evidence_digest: [u8; 32],
    settlement_value: u64,
    note_count: u32,
    unspent_count: u32,
    pending_count: u32,
    spent_count: u32,
}

impl CashuNut07BatchResultV1 {
    pub const fn mint_id(&self) -> &[u8; 32] {
        &self.mint_id
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn lots(&self) -> &[CashuNut07LotResultV1] {
        &self.lots
    }

    /// Consume the batch while preserving exact per-lot checked-note mapping.
    pub fn into_lots(self) -> Vec<CashuNut07LotResultV1> {
        self.lots
    }

    /// Domain-separated digest of the exact canonical NUT-07 response.
    ///
    /// The committed encoding is the response domain, mint ID, length-prefixed
    /// unit, note count, then ascending `Y`, its one-byte canonical
    /// [`CashuNut07NoteStateV1`] discriminant, and a domain-separated witness
    /// digest for every checked note. That inner digest commits a null/value
    /// tag and, for a value, its length and opaque bytes. Witness bytes never
    /// leave the checker result.
    pub const fn nut07_response_digest(&self) -> &[u8; 32] {
        &self.nut07_response_digest
    }

    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    pub const fn settlement_value(&self) -> u64 {
        self.settlement_value
    }

    pub const fn note_count(&self) -> u32 {
        self.note_count
    }

    pub const fn unspent_count(&self) -> u32 {
        self.unspent_count
    }

    pub const fn pending_count(&self) -> u32 {
        self.pending_count
    }

    pub const fn spent_count(&self) -> u32 {
        self.spent_count
    }

    /// True only when every note in every returned lot is `SPENT`.
    pub const fn all_spent(&self) -> bool {
        self.note_count != 0 && self.spent_count == self.note_count
    }
}

impl fmt::Debug for CashuNut07BatchResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuNut07BatchResultV1")
            .field("mint_id", &"[REDACTED_DIGEST]")
            .field("unit", &"[REDACTED_UNIT]")
            .field("lot_count", &self.lots.len())
            .field("nut07_response_digest", &"[REDACTED_DIGEST]")
            .field("evidence_digest", &"[REDACTED_DIGEST]")
            .field("settlement_value", &self.settlement_value)
            .field("note_count", &self.note_count)
            .field("unspent_count", &self.unspent_count)
            .field("pending_count", &self.pending_count)
            .field("spent_count", &self.spent_count)
            .field("all_spent", &self.all_spent())
            .finish()
    }
}

struct PreparedYV1 {
    y: [u8; 33],
    lot_index: usize,
}

impl Drop for PreparedYV1 {
    fn drop(&mut self) {
        self.y.zeroize();
    }
}

/// Perform one manually triggered, bounded NUT-07 batch for an exact
/// endpoint/pin/manifest/unit cohort.
///
/// This function never polls and never writes a store. Callers must keep this
/// operation off the PIR query path and decide separately whether an
/// `all_spent()` lot result is committed atomically. NUT-07 warns that checking
/// a token's state before deleting it can make sender/receiver correlation
/// easier, so callers should avoid query-correlated timing and unnecessary
/// repetition.
///
/// The supplied transport remains responsible for endpoint pinning, strict
/// HTTPS, no redirects, JSON content type, and the response byte bound defined
/// by [`CashuMintTransportV1`].
pub fn check_cashu_custody_bundles_once_v1(
    transport: &dyn CashuMintTransportV1,
    bundles: &[CashuCustodyBundleV1],
) -> Result<CashuNut07BatchResultV1, CashuClientErrorV1> {
    if bundles.is_empty() || bundles.len() > MAX_CASHU_NUT07_BUNDLES_V1 {
        return Err(CashuClientErrorV1::InvalidItemCount);
    }
    for bundle in bundles {
        bundle.validate()?;
    }
    let total_notes = bundles.iter().try_fold(0usize, |count, bundle| {
        count
            .checked_add(bundle.notes().len())
            .ok_or(CashuClientErrorV1::InvalidItemCount)
    })?;
    if total_notes == 0 || total_notes > MAX_CASHU_NUT07_NOTES_V1 {
        return Err(CashuClientErrorV1::InvalidItemCount);
    }

    let first = &bundles[0];
    let trust = CashuMintTrustV1::from_parts(first.mint_endpoint(), first.leaf_spki_sha256_pins())
        .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?;
    if bundles.iter().any(|bundle| {
        bundle.mint_endpoint() != first.mint_endpoint()
            || bundle.manifest_digest() != first.manifest_digest()
            || bundle.leaf_spki_sha256_pins() != first.leaf_spki_sha256_pins()
            || bundle.unit() != first.unit()
    }) {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }

    let mut ordered_bundles = bundles.iter().collect::<Vec<_>>();
    ordered_bundles.sort_unstable_by_key(|bundle| *bundle.note_set_digest());
    if ordered_bundles
        .windows(2)
        .any(|pair| pair[0].note_set_digest() == pair[1].note_set_digest())
    {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }

    let mint_id = derive_cashu_mint_id(first.mint_endpoint());
    let mut prepared_ys = Vec::<PreparedYV1>::with_capacity(total_notes);
    let mut lots = Vec::with_capacity(ordered_bundles.len());
    let mut batch_value = 0u64;

    for (lot_index, bundle) in ordered_bundles.into_iter().enumerate() {
        let mut lot_value = 0u64;
        let mut y_digests = Zeroizing::new(Vec::<[u8; 32]>::with_capacity(bundle.notes().len()));
        for note in bundle.notes() {
            if prepared_ys.len() >= MAX_CASHU_NUT07_NOTES_V1 {
                return Err(CashuClientErrorV1::InvalidItemCount);
            }
            lot_value = lot_value
                .checked_add(note.amount())
                .ok_or(CashuClientErrorV1::InvalidCustodyPlaintext)?;
            let y = Zeroizing::new(
                cashu_hash_to_curve_v1(note.secret().as_bytes())
                    .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?,
            );
            let mut y_hasher = Sha256::new();
            y_hasher.update(CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1);
            y_hasher.update(mint_id);
            y_hasher.update(y.as_slice());
            let y_digest: [u8; 32] = y_hasher.finalize().into();
            if &y_digest != note.y_digest() {
                return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
            }
            y_digests.push(y_digest);
            prepared_ys.push(PreparedYV1 { y: *y, lot_index });
        }
        y_digests.sort_unstable();
        if y_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let mut set_hasher = Sha256::new();
        set_hasher.update(CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1);
        set_hasher.update((y_digests.len() as u32).to_le_bytes());
        for y_digest in y_digests.iter() {
            set_hasher.update(y_digest);
        }
        let note_set_digest: [u8; 32] = set_hasher.finalize().into();
        if &note_set_digest != bundle.note_set_digest() {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        batch_value = batch_value
            .checked_add(lot_value)
            .ok_or(CashuClientErrorV1::InvalidCustodyPlaintext)?;
        lots.push(CashuNut07LotResultV1 {
            note_set_digest,
            settlement_value: lot_value,
            note_count: u32::try_from(bundle.notes().len())
                .map_err(|_| CashuClientErrorV1::InvalidItemCount)?,
            unspent_count: 0,
            pending_count: 0,
            spent_count: 0,
            observation_digest: [0u8; 32],
            checked_notes: Vec::with_capacity(bundle.notes().len()),
        });
    }

    prepared_ys.sort_unstable_by(|left, right| left.y.cmp(&right.y));
    if prepared_ys.windows(2).any(|pair| pair[0].y == pair[1].y) {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }
    let request = CashuPostCheckStateRequestJsonV1 {
        ys: prepared_ys.iter().map(|item| lower_hex(&item.y)).collect(),
    };
    let request_body = Zeroizing::new(encode_json_v1(&request)?);
    let response_body = Zeroizing::new(
        transport
            .post_json(
                trust,
                CashuMintRouteV1::CheckState,
                &request_body,
                MAX_CASHU_MINT_JSON_BYTES_V1,
            )
            .map_err(|_| CashuClientErrorV1::Nut07CheckUnavailable)?,
    );
    let response =
        decode_mint_response_json_v1::<CashuPostCheckStateResponseJsonV1>(&response_body)
            .map_err(|_| CashuClientErrorV1::Nut07ResponseInvalid)?;
    if response.states.len() != prepared_ys.len() {
        return Err(CashuClientErrorV1::Nut07ResponseInvalid);
    }

    let mut response_hasher = Sha256::new();
    response_hasher.update(CASHU_NUT07_RESPONSE_DIGEST_DOMAIN_V1);
    response_hasher.update(mint_id);
    response_hasher.update((first.unit().len() as u32).to_le_bytes());
    response_hasher.update(first.unit().as_bytes());
    response_hasher.update((response.states.len() as u32).to_le_bytes());
    let mut lot_observation_hashers = lots
        .iter()
        .map(|lot| {
            let mut hasher = Sha256::new();
            hasher.update(CASHU_NUT07_LOT_OBSERVATION_DIGEST_DOMAIN_V1);
            hasher.update(mint_id);
            hasher.update((first.unit().len() as u32).to_le_bytes());
            hasher.update(first.unit().as_bytes());
            hasher.update(lot.note_set_digest);
            hasher.update(lot.note_count.to_le_bytes());
            hasher
        })
        .collect::<Vec<_>>();
    for (state, prepared) in response.states.iter().zip(&prepared_ys) {
        let echoed_y = Zeroizing::new(decode_lower_hex::<33>(
            &state.y,
            CashuClientErrorV1::Nut07ResponseInvalid,
        )?);
        if echoed_y.as_slice() != prepared.y.as_slice()
            || !is_bounded_nut07_witness_v1(state.witness.as_deref())
        {
            return Err(CashuClientErrorV1::Nut07ResponseInvalid);
        }
        let canonical_state = match state.state {
            CashuProofStateJsonV1::Unspent => CashuNut07NoteStateV1::Unspent,
            CashuProofStateJsonV1::Pending => CashuNut07NoteStateV1::Pending,
            CashuProofStateJsonV1::Spent => CashuNut07NoteStateV1::Spent,
        };
        response_hasher.update(echoed_y.as_slice());
        response_hasher.update([canonical_state as u8]);
        let witness_digest = witness_digest_v1(state.witness.as_deref());
        response_hasher.update(witness_digest);
        let lot_hasher = lot_observation_hashers
            .get_mut(prepared.lot_index)
            .ok_or(CashuClientErrorV1::Nut07ResponseInvalid)?;
        lot_hasher.update(echoed_y.as_slice());
        lot_hasher.update([canonical_state as u8]);
        lot_hasher.update(witness_digest);
        let lot = lots
            .get_mut(prepared.lot_index)
            .ok_or(CashuClientErrorV1::Nut07ResponseInvalid)?;
        match canonical_state {
            CashuNut07NoteStateV1::Unspent => lot.unspent_count += 1,
            CashuNut07NoteStateV1::Pending => lot.pending_count += 1,
            CashuNut07NoteStateV1::Spent => lot.spent_count += 1,
        }
        lot.checked_notes.push(CashuNut07CheckedNoteV1 {
            y: *echoed_y,
            state: canonical_state,
        });
    }

    let note_count =
        u32::try_from(prepared_ys.len()).map_err(|_| CashuClientErrorV1::InvalidItemCount)?;
    let unspent_count = lots.iter().map(|lot| lot.unspent_count).sum();
    let pending_count = lots.iter().map(|lot| lot.pending_count).sum();
    let spent_count = lots.iter().map(|lot| lot.spent_count).sum();
    if lots
        .iter()
        .any(|lot| usize::try_from(lot.note_count).ok() != Some(lot.checked_notes.len()))
    {
        return Err(CashuClientErrorV1::Nut07ResponseInvalid);
    }
    for (lot, hasher) in lots.iter_mut().zip(lot_observation_hashers) {
        lot.observation_digest = hasher.finalize().into();
    }
    let nut07_response_digest: [u8; 32] = response_hasher.finalize().into();
    let evidence_digest = evidence_digest_v1(&mint_id, first.unit(), &lots, &nut07_response_digest);
    Ok(CashuNut07BatchResultV1 {
        mint_id,
        unit: first.unit().to_owned(),
        lots,
        nut07_response_digest,
        evidence_digest,
        settlement_value: batch_value,
        note_count,
        unspent_count,
        pending_count,
        spent_count,
    })
}

fn evidence_digest_v1(
    mint_id: &[u8; 32],
    unit: &str,
    lots: &[CashuNut07LotResultV1],
    nut07_response_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CASHU_NUT07_EVIDENCE_DIGEST_DOMAIN_V1);
    hasher.update(mint_id);
    hasher.update((unit.len() as u32).to_le_bytes());
    hasher.update(unit.as_bytes());
    hasher.update(nut07_response_digest);
    hasher.update((lots.len() as u32).to_le_bytes());
    for lot in lots {
        hasher.update(lot.note_set_digest);
        hasher.update(lot.settlement_value.to_le_bytes());
        hasher.update(lot.note_count.to_le_bytes());
        hasher.update(lot.unspent_count.to_le_bytes());
        hasher.update(lot.pending_count.to_le_bytes());
        hasher.update(lot.spent_count.to_le_bytes());
        hasher.update(lot.observation_digest);
    }
    hasher.finalize().into()
}

fn witness_digest_v1(witness: Option<&str>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CASHU_NUT07_WITNESS_DIGEST_DOMAIN_V1);
    match witness {
        None => hasher.update([0u8]),
        Some(value) => {
            hasher.update([1u8]);
            hasher.update((value.len() as u32).to_le_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// Derive one unlinkable-per-export digest from an in-memory batch result.
///
/// Only exact per-lot observation digests are aggregated; raw `Y`, witnesses,
/// and the full-batch response digest are never returned. `lot_note_sets` must
/// be the export's exact member order and cannot contain duplicates.
pub fn derive_cashu_nut07_export_observation_digest_v1(
    batch: &CashuNut07BatchResultV1,
    export_id: &[u8; 16],
    lot_note_sets: &[[u8; 32]],
) -> Result<[u8; 32], CashuClientErrorV1> {
    if export_id.iter().all(|byte| *byte == 0)
        || lot_note_sets.is_empty()
        || lot_note_sets.len() > MAX_CASHU_NUT07_BUNDLES_V1
    {
        return Err(CashuClientErrorV1::InvalidItemCount);
    }
    let mut seen = std::collections::HashSet::with_capacity(lot_note_sets.len());
    let mut selected = Vec::with_capacity(lot_note_sets.len());
    for note_set_digest in lot_note_sets {
        if !seen.insert(*note_set_digest) {
            return Err(CashuClientErrorV1::Nut07ResponseInvalid);
        }
        let lot = batch
            .lots
            .iter()
            .find(|lot| lot.note_set_digest == *note_set_digest)
            .ok_or(CashuClientErrorV1::Nut07ResponseInvalid)?;
        selected.push(lot);
    }

    let mut hasher = Sha256::new();
    hasher.update(CASHU_NUT07_EXPORT_OBSERVATION_DIGEST_DOMAIN_V1);
    hasher.update(export_id);
    hasher.update(batch.mint_id);
    hasher.update((batch.unit.len() as u32).to_le_bytes());
    hasher.update(batch.unit.as_bytes());
    hasher.update((selected.len() as u32).to_le_bytes());
    for lot in selected {
        hasher.update(lot.note_set_digest);
        hasher.update(lot.settlement_value.to_le_bytes());
        hasher.update(lot.note_count.to_le_bytes());
        hasher.update(lot.observation_digest);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::CashuProofStateEntryJsonV1;
    use crate::{CashuCustodyNoteV1, CashuMintTransportFailureV1, CashuMintTransportV1};

    #[derive(Clone, Copy)]
    enum Reply {
        Spent,
        Reversed,
        MissingWitness,
        UnknownState,
        OpaqueWitness,
        OversizedWitness,
    }

    struct FakeTransport(Reply);

    struct NeverTransport;

    impl CashuMintTransportV1 for NeverTransport {
        fn post_json(
            &self,
            _trust: CashuMintTrustV1<'_>,
            _route: CashuMintRouteV1,
            _request_json: &[u8],
            _max_response_bytes: usize,
        ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
            panic!("cohort validation must fail before transport")
        }
    }

    impl CashuMintTransportV1 for FakeTransport {
        fn post_json(
            &self,
            _trust: CashuMintTrustV1<'_>,
            route: CashuMintRouteV1,
            request_json: &[u8],
            _max_response_bytes: usize,
        ) -> Result<Vec<u8>, CashuMintTransportFailureV1> {
            assert_eq!(route, CashuMintRouteV1::CheckState);
            let request: CashuPostCheckStateRequestJsonV1 = decode_json_v1(request_json).unwrap();
            if matches!(self.0, Reply::MissingWitness) {
                return Ok(format!(
                    r#"{{"states":[{{"Y":"{}","state":"SPENT"}}]}}"#,
                    request.ys[0]
                )
                .into_bytes());
            }
            if matches!(self.0, Reply::UnknownState) {
                return Ok(format!(
                    r#"{{"states":[{{"Y":"{}","state":"UNKNOWN","witness":null}}]}}"#,
                    request.ys[0]
                )
                .into_bytes());
            }
            let mut ys = request.ys.to_vec();
            if matches!(self.0, Reply::Reversed) {
                ys.reverse();
            }
            encode_json_v1(&CashuPostCheckStateResponseJsonV1 {
                states: ys
                    .into_iter()
                    .map(|y| CashuProofStateEntryJsonV1 {
                        y,
                        state: CashuProofStateJsonV1::Spent,
                        witness: match self.0 {
                            Reply::OpaqueWitness => Some("opaque-nut10-witness".to_owned()),
                            Reply::OversizedWitness => {
                                Some("w".repeat(crate::dto::MAX_NUT07_WITNESS_BYTES_V1 + 1))
                            }
                            _ => None,
                        },
                    })
                    .collect(),
            })
            .map_err(|_| {
                CashuMintTransportFailureV1::ambiguous(
                    crate::CashuMintTransportFailureKindV1::HttpError,
                    None,
                )
            })
        }
    }

    fn custody_bundle_with_trust(
        seeds: &[(u64, u64)],
        manifest_digest: [u8; 32],
        leaf_spki_sha256_pins: Vec<[u8; 32]>,
    ) -> CashuCustodyBundleV1 {
        let endpoint = "https://mint.example.test".to_owned();
        let mint_id = derive_cashu_mint_id(&endpoint);
        let mut notes = Vec::new();
        let mut y_digests = Vec::new();
        for (amount, seed) in seeds {
            let secret = format!("{seed:064x}");
            let y = cashu_hash_to_curve_v1(secret.as_bytes()).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1);
            hasher.update(mint_id);
            hasher.update(y);
            let y_digest: [u8; 32] = hasher.finalize().into();
            y_digests.push(y_digest);
            notes.push(CashuCustodyNoteV1::new(*amount, secret, [2u8; 33], y_digest).unwrap());
        }
        crate::custody::sort_custody_notes(&mut notes);
        y_digests.sort_unstable();
        let mut hasher = Sha256::new();
        hasher.update(CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1);
        hasher.update((y_digests.len() as u32).to_le_bytes());
        for digest in y_digests {
            hasher.update(digest);
        }
        CashuCustodyBundleV1::new(
            endpoint,
            manifest_digest,
            leaf_spki_sha256_pins,
            "sat".to_owned(),
            format!("01{}", "11".repeat(32)),
            hasher.finalize().into(),
            notes,
        )
        .unwrap()
    }

    fn custody_bundle(seeds: &[(u64, u64)]) -> CashuCustodyBundleV1 {
        custody_bundle_with_trust(seeds, [0x52; 32], vec![[0x31; 32]])
    }

    #[test]
    fn batch_rejects_manifest_or_pin_cohort_drift_before_transport() {
        let first = custody_bundle_with_trust(&[(2, 2)], [0x52; 32], vec![[0x31; 32]]);
        let different_manifest = custody_bundle_with_trust(&[(3, 3)], [0x53; 32], vec![[0x31; 32]]);
        let transport = NeverTransport;
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&transport, &[first, different_manifest]),
            Err(CashuClientErrorV1::InvalidCustodyPlaintext)
        );

        let first = custody_bundle_with_trust(&[(2, 2)], [0x52; 32], vec![[0x31; 32]]);
        let different_pin = custody_bundle_with_trust(&[(3, 3)], [0x52; 32], vec![[0x32; 32]]);
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&transport, &[first, different_pin]),
            Err(CashuClientErrorV1::InvalidCustodyPlaintext)
        );
    }

    #[test]
    fn all_spent_summary_contains_no_raw_y() {
        let bundles = vec![custody_bundle(&[(2, 2)]), custody_bundle(&[(3, 3)])];
        let result =
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::Spent), &bundles).unwrap();
        assert!(result.all_spent());
        assert_eq!(result.note_count(), 2);
        assert_eq!(result.settlement_value(), 5);
        assert!(result.lots().iter().all(CashuNut07LotResultV1::all_spent));
        assert!(result
            .lots()
            .iter()
            .all(|lot| lot.checked_notes().len() == 1));
        assert_ne!(result.nut07_response_digest(), &[0u8; 32]);
        assert_ne!(result.evidence_digest(), &[0u8; 32]);
        let first_y = lower_hex(result.lots()[0].checked_notes()[0].y());
        let debug = format!("{result:?}");
        assert!(!debug.contains("mint.example.test"));
        assert!(!debug.contains(&first_y));
        assert!(debug.contains("[REDACTED_DIGEST]"));
    }

    #[test]
    fn response_order_and_exact_y_are_enforced() {
        let bundles = vec![custody_bundle(&[(2, 2), (3, 3)])];
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::Reversed), &bundles),
            Err(CashuClientErrorV1::Nut07ResponseInvalid)
        );
    }

    #[test]
    fn nullable_witness_field_is_required() {
        let bundles = vec![custody_bundle(&[(2, 2)])];
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::MissingWitness), &bundles),
            Err(CashuClientErrorV1::Nut07ResponseInvalid)
        );
    }

    #[test]
    fn unknown_state_fails_closed() {
        let bundles = vec![custody_bundle(&[(2, 2)])];
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::UnknownState), &bundles),
            Err(CashuClientErrorV1::Nut07ResponseInvalid)
        );
    }

    #[test]
    fn bounded_opaque_witness_is_accepted_and_digest_bound() {
        let bundles = vec![custody_bundle(&[(2, 2)])];
        let without =
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::Spent), &bundles).unwrap();
        let with =
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::OpaqueWitness), &bundles)
                .unwrap();
        assert!(with.all_spent());
        assert_ne!(
            with.nut07_response_digest(),
            without.nut07_response_digest()
        );
        assert!(!format!("{with:?}").contains("opaque-nut10-witness"));
    }

    #[test]
    fn oversized_witness_fails_closed() {
        let bundles = vec![custody_bundle(&[(2, 2)])];
        assert_eq!(
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::OversizedWitness), &bundles,),
            Err(CashuClientErrorV1::Nut07ResponseInvalid)
        );
    }

    #[test]
    fn per_export_observation_digest_binds_export_and_ordered_lot_subset() {
        let bundles = vec![
            custody_bundle(&[(2, 2)]),
            custody_bundle(&[(3, 3)]),
            custody_bundle(&[(5, 5)]),
        ];
        let result =
            check_cashu_custody_bundles_once_v1(&FakeTransport(Reply::Spent), &bundles).unwrap();
        let note_sets = result
            .lots()
            .iter()
            .map(|lot| *lot.note_set_digest())
            .collect::<Vec<_>>();
        let first =
            derive_cashu_nut07_export_observation_digest_v1(&result, &[0x11; 16], &note_sets[..2])
                .unwrap();
        let different_export =
            derive_cashu_nut07_export_observation_digest_v1(&result, &[0x12; 16], &note_sets[..2])
                .unwrap();
        let reversed = derive_cashu_nut07_export_observation_digest_v1(
            &result,
            &[0x11; 16],
            &[note_sets[1], note_sets[0]],
        )
        .unwrap();
        let different_subset =
            derive_cashu_nut07_export_observation_digest_v1(&result, &[0x11; 16], &note_sets[1..])
                .unwrap();
        assert_ne!(first, different_export);
        assert_ne!(first, reversed);
        assert_ne!(first, different_subset);
        assert_eq!(
            derive_cashu_nut07_export_observation_digest_v1(
                &result,
                &[0x11; 16],
                &[note_sets[0], note_sets[0]],
            ),
            Err(CashuClientErrorV1::Nut07ResponseInvalid)
        );
    }
}
