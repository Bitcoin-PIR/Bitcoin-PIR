//! Secret-bearing, note-only provider custody plaintext.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use pir_payment_crypto::cashu_hash_to_curve_v1;
use pir_service_protocol::{derive_cashu_mint_id, validate_cashu_unit_v1};

use crate::{
    BoundedZeroizingWriterV1, CashuClientErrorV1, CashuCustodyAadV1, CashuTokenV4GroupV1,
    CashuTokenV4ProofV1, CashuTokenV4V1, CUSTODY_KEYSET_DIGEST_DOMAIN_V1, CUSTODY_LOT_ID_DOMAIN_V1,
    CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1, CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1,
    CUSTODY_UNIT_DIGEST_DOMAIN_V1, MAX_CASHUB_PROOFS_V1, MAX_CASHU_SWAP_ITEMS_V1,
    MAX_CUSTODY_CIPHERTEXT_BYTES_V1,
};

/// Leaves room for the production AEAD tag under the durable ciphertext cap.
pub const MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1: usize = MAX_CUSTODY_CIPHERTEXT_BYTES_V1 - 16;

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CashuCustodyNoteV1 {
    amount: u64,
    secret: SensitiveCustodyStringV1,
    c: SensitiveCustodyPointV1,
    y_digest: SensitiveCustodyDigestV1,
}

impl CashuCustodyNoteV1 {
    pub(crate) fn new(
        amount: u64,
        secret: String,
        c: [u8; 33],
        y_digest: [u8; 32],
    ) -> Result<Self, CashuClientErrorV1> {
        let mut secret = Zeroizing::new(secret);
        let c = Zeroizing::new(c);
        let y_digest = Zeroizing::new(y_digest);
        if amount == 0
            || secret.len() != 64
            || !secret
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !matches!(c[0], 0x02 | 0x03)
            || c[1..].iter().all(|byte| *byte == 0)
            || y_digest.iter().all(|byte| *byte == 0)
        {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(Self {
            amount,
            secret: SensitiveCustodyStringV1::new(std::mem::take(&mut *secret)),
            c: SensitiveCustodyPointV1::new(*c),
            y_digest: SensitiveCustodyDigestV1::new(*y_digest),
        })
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }

    pub fn secret(&self) -> &str {
        self.secret.as_str()
    }

    pub fn c(&self) -> &[u8; 33] {
        self.c.as_array()
    }

    pub fn y_digest(&self) -> &[u8; 32] {
        self.y_digest.as_array()
    }
}

impl fmt::Debug for CashuCustodyNoteV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuCustodyNoteV1")
            .field("amount", &"[REDACTED]")
            .field("secret", &"[REDACTED]")
            .field("c", &"[REDACTED_POINT]")
            .field("y_digest", &"[REDACTED_DIGEST]")
            .finish()
    }
}

struct SensitiveCustodyStringV1(Zeroizing<String>);

impl SensitiveCustodyStringV1 {
    fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl PartialEq for SensitiveCustodyStringV1 {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SensitiveCustodyStringV1 {}

impl Serialize for SensitiveCustodyStringV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveCustodyStringV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SensitiveCustodyStringVisitorV1)
    }
}

struct SensitiveCustodyStringVisitorV1;

impl<'de> Visitor<'de> for SensitiveCustodyStringVisitorV1 {
    type Value = SensitiveCustodyStringV1;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Cashu note secret of at most 64 bytes")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > 64 {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut owned = Zeroizing::new(String::with_capacity(value.len()));
        owned.push_str(value);
        Ok(SensitiveCustodyStringV1(owned))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let owned = Zeroizing::new(value);
        if owned.len() > 64 {
            return Err(E::invalid_length(owned.len(), &self));
        }
        Ok(SensitiveCustodyStringV1(owned))
    }
}

struct SensitiveCustodyPointV1(Zeroizing<[u8; 33]>);

impl SensitiveCustodyPointV1 {
    fn new(value: [u8; 33]) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_array(&self) -> &[u8; 33] {
        &self.0
    }

    fn copied(&self) -> [u8; 33] {
        *self.as_array()
    }
}

impl PartialEq for SensitiveCustodyPointV1 {
    fn eq(&self, other: &Self) -> bool {
        self.as_array() == other.as_array()
    }
}

impl Eq for SensitiveCustodyPointV1 {}

impl Serialize for SensitiveCustodyPointV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(self.as_array()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveCustodyPointV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SensitiveCustodyPointVisitorV1)
    }
}

struct SensitiveCustodyPointVisitorV1;

impl<'de> Visitor<'de> for SensitiveCustodyPointVisitorV1 {
    type Value = SensitiveCustodyPointV1;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 33 Cashu point bytes")
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_bytes(value)
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != 33 {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut point = Zeroizing::new([0u8; 33]);
        point.copy_from_slice(value);
        Ok(SensitiveCustodyPointV1(point))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = Zeroizing::new(value);
        self.visit_bytes(bytes.as_slice())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut point = Zeroizing::new([0u8; 33]);
        for index in 0..point.len() {
            point[index] = sequence
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(index, &self))?;
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(34, &self));
        }
        Ok(SensitiveCustodyPointV1(point))
    }
}

struct SensitiveCustodyDigestV1(Zeroizing<[u8; 32]>);

impl SensitiveCustodyDigestV1 {
    fn new(value: [u8; 32]) -> Self {
        Self(Zeroizing::new(value))
    }

    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    fn copied(&self) -> [u8; 32] {
        *self.as_array()
    }
}

impl PartialEq for SensitiveCustodyDigestV1 {
    fn eq(&self, other: &Self) -> bool {
        self.as_array() == other.as_array()
    }
}

impl Eq for SensitiveCustodyDigestV1 {}

impl Serialize for SensitiveCustodyDigestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_array().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SensitiveCustodyDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_tuple(32, SensitiveCustodyDigestVisitorV1)
    }
}

struct SensitiveCustodyDigestVisitorV1;

impl<'de> Visitor<'de> for SensitiveCustodyDigestVisitorV1 {
    type Value = SensitiveCustodyDigestV1;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 32 digest bytes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut bytes = Zeroizing::new([0u8; 32]);
        for index in 0..bytes.len() {
            bytes[index] = sequence
                .next_element()?
                .ok_or_else(|| de::Error::invalid_length(index, &self))?;
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(33, &self));
        }
        Ok(SensitiveCustodyDigestV1::new(*bytes))
    }
}

/// Decrypted custody material contains only standard provider-owned notes and
/// the minimum mint/keyset metadata needed to import them into a wallet.
#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CashuCustodyBundleV1 {
    version: u8,
    mint_endpoint: String,
    unit: String,
    active_keyset_id: String,
    note_set_digest: [u8; 32],
    notes: Vec<CashuCustodyNoteV1>,
}

impl fmt::Debug for CashuCustodyBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuCustodyBundleV1")
            .field("version", &self.version)
            .field("mint_endpoint", &"[REDACTED_ENDPOINT]")
            .field("unit", &"[REDACTED_UNIT]")
            .field("active_keyset_id", &"[REDACTED_KEYSET]")
            .field("note_set_digest", &"[REDACTED_DIGEST]")
            .field("note_count", &self.notes.len())
            .finish()
    }
}

impl Drop for CashuCustodyBundleV1 {
    fn drop(&mut self) {
        self.mint_endpoint.zeroize();
        self.unit.zeroize();
        self.active_keyset_id.zeroize();
        self.note_set_digest.zeroize();
    }
}

impl CashuCustodyBundleV1 {
    pub(crate) fn new(
        mint_endpoint: String,
        unit: String,
        active_keyset_id: String,
        note_set_digest: [u8; 32],
        notes: Vec<CashuCustodyNoteV1>,
    ) -> Result<Self, CashuClientErrorV1> {
        let value = Self {
            version: 1,
            mint_endpoint,
            unit,
            active_keyset_id,
            note_set_digest,
            notes,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn mint_endpoint(&self) -> &str {
        &self.mint_endpoint
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn active_keyset_id(&self) -> &str {
        &self.active_keyset_id
    }

    pub const fn note_set_digest(&self) -> &[u8; 32] {
        &self.note_set_digest
    }

    pub fn notes(&self) -> &[CashuCustodyNoteV1] {
        &self.notes
    }

    pub fn encode_canonical(&self) -> Result<Zeroizing<Vec<u8>>, CashuClientErrorV1> {
        self.validate()?;
        let mut writer = BoundedZeroizingWriterV1::new(MAX_CASHU_CUSTODY_PLAINTEXT_BYTES_V1);
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?;
        Ok(writer.into_inner())
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CashuClientErrorV1> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?;
        value.validate()?;
        if value.encode_canonical()?.as_slice() != bytes {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(value)
    }

    /// Verify decrypted notes against the exact public lot metadata that was
    /// authenticated by the custody cipher.
    pub fn validate_for_aad(&self, aad: &CashuCustodyAadV1) -> Result<(), CashuClientErrorV1> {
        self.validate()?;
        if derive_cashu_mint_id(&self.mint_endpoint) != aad.mint_id
            || digest(CUSTODY_UNIT_DIGEST_DOMAIN_V1, self.unit.as_bytes()) != aad.unit_digest
            || digest(
                CUSTODY_KEYSET_DIGEST_DOMAIN_V1,
                self.active_keyset_id.as_bytes(),
            ) != aad.active_keyset_digest
            || usize::try_from(aad.note_count).ok() != Some(self.notes.len())
        {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let mut total = 0u64;
        let mut y_digests = Vec::with_capacity(self.notes.len());
        for note in &self.notes {
            total = total
                .checked_add(note.amount)
                .ok_or(CashuClientErrorV1::InvalidCustodyPlaintext)?;
            let y = Zeroizing::new(
                cashu_hash_to_curve_v1(note.secret.as_str().as_bytes())
                    .map_err(|_| CashuClientErrorV1::InvalidCustodyPlaintext)?,
            );
            let mut hasher = Sha256::new();
            hasher.update(CUSTODY_NOTE_Y_DIGEST_DOMAIN_V1);
            hasher.update(aad.mint_id);
            hasher.update(y.as_slice());
            let y_digest: [u8; 32] = hasher.finalize().into();
            if &y_digest != note.y_digest.as_array() {
                return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
            }
            y_digests.push(y_digest);
        }
        y_digests.sort_unstable();
        if y_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let mut set_hasher = Sha256::new();
        set_hasher.update(CUSTODY_NOTE_SET_DIGEST_DOMAIN_V1);
        set_hasher.update((y_digests.len() as u32).to_le_bytes());
        for digest in &y_digests {
            set_hasher.update(digest);
        }
        let note_set_digest: [u8; 32] = set_hasher.finalize().into();
        if total != aad.settlement_value
            || note_set_digest != self.note_set_digest
            || note_set_digest != aad.note_set_digest
            || derive_lot_id(aad) != aad.lot_id
        {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), CashuClientErrorV1> {
        if self.version != 1
            || self.mint_endpoint.is_empty()
            || self.mint_endpoint.ends_with('/')
            || validate_cashu_unit_v1(&self.unit).is_err()
            || self.active_keyset_id.len() != 66
            || !self
                .active_keyset_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.note_set_digest.iter().all(|byte| *byte == 0)
            || self.notes.is_empty()
            || self.notes.len() > MAX_CASHU_SWAP_ITEMS_V1
        {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let canonical = self
            .notes
            .windows(2)
            .all(|pair| compare_custody_notes(&pair[0], &pair[1]).is_lt());
        if !canonical {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        Ok(())
    }
}

/// Aggregate already authenticated custody bundles into a standard,
/// deterministic NUT-00 V4 token. No memo or BitcoinPIR identifier is added.
pub fn encode_cashub_from_custody_bundles_v1(
    bundles: &[CashuCustodyBundleV1],
) -> Result<Zeroizing<String>, CashuClientErrorV1> {
    let first = bundles
        .first()
        .ok_or(CashuClientErrorV1::InvalidCustodyPlaintext)?;
    let mut grouped: BTreeMap<String, Vec<CashuTokenV4ProofV1>> = BTreeMap::new();
    let mut seen_y_digests = HashSet::new();
    let mut proof_count = 0usize;
    for bundle in bundles {
        bundle.validate()?;
        if bundle.mint_endpoint != first.mint_endpoint || bundle.unit != first.unit {
            return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
        }
        let proofs = grouped.entry(bundle.active_keyset_id.clone()).or_default();
        for note in &bundle.notes {
            if !seen_y_digests.insert(note.y_digest.copied()) {
                return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
            }
            proofs.push(CashuTokenV4ProofV1::new(
                note.amount,
                note.secret.as_str().to_owned(),
                note.c.copied(),
            )?);
            proof_count = proof_count
                .checked_add(1)
                .ok_or(CashuClientErrorV1::InvalidItemCount)?;
            if proof_count > MAX_CASHUB_PROOFS_V1 {
                return Err(CashuClientErrorV1::InvalidItemCount);
            }
        }
    }
    if grouped.len() > crate::MAX_CASHUB_GROUPS_V1 {
        return Err(CashuClientErrorV1::InvalidItemCount);
    }
    let mut short_counts = HashMap::<[u8; 8], usize>::new();
    for keyset_id in grouped.keys() {
        let full = decode_full_keyset_id(keyset_id)?;
        let short: [u8; 8] = full[..8].try_into().expect("fixed keyset prefix");
        *short_counts.entry(short).or_default() += 1;
    }
    let mut groups = Vec::with_capacity(grouped.len());
    for (keyset_id, mut proofs) in grouped {
        proofs.sort_by(|left, right| {
            left.amount()
                .cmp(&right.amount())
                .then_with(|| left.secret().cmp(right.secret()))
                .then_with(|| left.c().cmp(right.c()))
        });
        let full = decode_full_keyset_id(&keyset_id)?;
        let short: [u8; 8] = full[..8].try_into().expect("fixed keyset prefix");
        let encoded_id = if short_counts.get(&short) == Some(&1) {
            short.to_vec()
        } else {
            full.to_vec()
        };
        groups.push(CashuTokenV4GroupV1::new(encoded_id, proofs)?);
    }
    CashuTokenV4V1::new(first.mint_endpoint.clone(), first.unit.clone(), groups)?.encode_cashub()
}

fn decode_full_keyset_id(value: &str) -> Result<[u8; 33], CashuClientErrorV1> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CashuClientErrorV1::InvalidCustodyPlaintext);
    }
    let mut decoded = [0u8; 33];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, CashuClientErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CashuClientErrorV1::InvalidCustodyPlaintext),
    }
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into()
}

fn derive_lot_id(aad: &CashuCustodyAadV1) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(CUSTODY_LOT_ID_DOMAIN_V1);
    hasher.update(aad.mint_id);
    hasher.update(aad.manifest_digest);
    hasher.update(aad.unit_digest);
    hasher.update(aad.active_keyset_digest);
    hasher.update(aad.note_set_digest);
    hasher.update(aad.settlement_value.to_le_bytes());
    hasher.update(aad.note_count.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    digest[..16].try_into().expect("fixed digest prefix")
}

pub(crate) fn sort_custody_notes(notes: &mut [CashuCustodyNoteV1]) {
    notes.sort_by(compare_custody_notes);
}

fn compare_custody_notes(
    left: &CashuCustodyNoteV1,
    right: &CashuCustodyNoteV1,
) -> std::cmp::Ordering {
    left.amount
        .cmp(&right.amount)
        .then_with(|| left.y_digest.as_array().cmp(right.y_digest.as_array()))
        .then_with(|| left.secret.as_str().cmp(right.secret.as_str()))
        .then_with(|| left.c.as_array().cmp(right.c.as_array()))
}
