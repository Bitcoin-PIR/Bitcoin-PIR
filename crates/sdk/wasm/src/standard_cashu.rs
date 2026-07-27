//! Strict browser import for standard Cashu V3/V4 tokens.
//!
//! Wallet serialization is decoded only locally. The output is the protocol's
//! canonical [`StandardCashuSpendV1`] bytes, after closing the token against
//! the exact signed provider policy and embedded mint manifest. No mint I/O is
//! performed here.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use core::{cmp::Ordering, fmt, mem};
use pir_payment_crypto::verify_cashu_received_proof_dleq_v1;
use pir_sdk_client::AcceptedServicePolicyV1;
use pir_service_protocol::{
    CashuKeysetBindingV1, StandardCashuMintManifestV1, StandardCashuProofV1, StandardCashuSpendV1,
    MAX_AUTH_PROOF_LEN, MAX_STANDARD_CASHU_PROOFS_V1, MAX_STANDARD_CASHU_SECRET_LEN_V1,
};
use serde::{
    de::{self, MapAccess, SeqAccess},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_SERIALIZED_TOKEN_CHARS_V1: usize = 128 * 1024;
const MAX_DECODED_TOKEN_BYTES_V1: usize = 64 * 1024;
const MAX_TOKEN_MEMO_BYTES_V1: usize = 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenV3 {
    token: Vec<CashuTokenEntryV3>,
    unit: Option<String>,
    memo: Option<SensitiveCashuString>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenEntryV3 {
    mint: String,
    proofs: Vec<CashuProofV3>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuProofV3 {
    amount: u64,
    id: String,
    secret: SensitiveCashuString,
    #[serde(rename = "C")]
    c: SensitiveCashuString,
    /// Optional NUT-12 wallet proof data is consumed only by this local
    /// decoder and deliberately omitted from the provider presentation.
    #[serde(default)]
    dleq: Option<DiscardedCashuDleqFieldV3>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenV4 {
    #[serde(rename = "m")]
    mint: String,
    #[serde(rename = "u")]
    unit: String,
    #[serde(rename = "d")]
    memo: Option<SensitiveCashuString>,
    #[serde(rename = "t")]
    token: Vec<CashuTokenEntryV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuTokenEntryV4 {
    #[serde(rename = "i", with = "serde_bytes")]
    keyset_id: Vec<u8>,
    #[serde(rename = "p")]
    proofs: Vec<CashuProofV4>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CashuProofV4 {
    #[serde(rename = "a")]
    amount: u64,
    #[serde(rename = "s")]
    secret: SensitiveCashuString,
    #[serde(rename = "c")]
    c: SensitiveCashuBytes,
    /// NUT-12 proof data is intentionally not forwarded. In particular the
    /// wallet-private blinding scalar `r` must never reach a PIR provider.
    #[serde(rename = "d", default)]
    dleq: Option<DiscardedCashuDleqFieldV4>,
    /// NUT-10/NUT-11 witness material is outside the V1 privacy profile.
    #[serde(rename = "w", default)]
    witness: PresentCashuField,
}

/// Rust-owned token text which is wiped on every success and error path.
///
/// This does not and cannot wipe the original JavaScript string passed across
/// the wasm-bindgen boundary. The browser/JS engine owns that allocation.
struct SensitiveCashuString(Zeroizing<String>);

impl SensitiveCashuString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Transfer the existing allocation without cloning it, leaving an empty
    /// value for the zeroizing wrapper to drop.
    fn take(&mut self) -> String {
        mem::take(&mut *self.0)
    }
}

impl fmt::Debug for SensitiveCashuString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SensitiveCashuString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SensitiveStringVisitor;

        impl<'de> de::Visitor<'de> for SensitiveStringVisitor {
            type Value = SensitiveCashuString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded sensitive Cashu string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_STANDARD_CASHU_SECRET_LEN_V1 {
                    return Err(E::custom("Cashu string exceeds the V1 bound"));
                }
                let mut owned = Zeroizing::new(String::with_capacity(value.len()));
                owned.push_str(value);
                Ok(SensitiveCashuString(owned))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_STANDARD_CASHU_SECRET_LEN_V1 {
                    value.zeroize();
                    return Err(E::custom("Cashu string exceeds the V1 bound"));
                }
                Ok(SensitiveCashuString(Zeroizing::new(value)))
            }
        }

        // `deserialize_str` makes ciborium decode definite text into the
        // caller-supplied zeroizing scratch instead of first constructing an
        // ordinary String. V1 rejects indefinite/oversized sensitive text.
        deserializer.deserialize_str(SensitiveStringVisitor)
    }
}

/// `serde_bytes`-compatible owned bytes with a non-secret `Debug` view and
/// zeroization on drop. This preserves V4 CBOR acceptance while ensuring a
/// partially decoded proof does not leave its `C` allocation behind.
struct SensitiveCashuBytes(Zeroizing<Vec<u8>>);

impl SensitiveCashuBytes {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SensitiveCashuBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SensitiveCashuBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> de::Visitor<'de> for BytesVisitor {
            type Value = SensitiveCashuBytes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("byte array")
            }

            fn visit_seq<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                if let Some(size) = visitor.size_hint().filter(|size| *size != 33) {
                    return Err(de::Error::invalid_length(size, &self));
                }
                let mut bytes = Zeroizing::new(Vec::with_capacity(33));
                while let Some(byte) = visitor.next_element()? {
                    if bytes.len() == 33 {
                        return Err(de::Error::invalid_length(34, &self));
                    }
                    bytes.push(byte);
                }
                if bytes.len() != 33 {
                    return Err(de::Error::invalid_length(bytes.len(), &self));
                }
                Ok(SensitiveCashuBytes(bytes))
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() != 33 {
                    return Err(E::custom("Cashu V4 C must be exactly one compressed point"));
                }
                let mut bytes = Zeroizing::new(Vec::with_capacity(33));
                bytes.extend_from_slice(value);
                Ok(SensitiveCashuBytes(bytes))
            }

            fn visit_byte_buf<E>(self, mut value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() != 33 {
                    value.zeroize();
                    return Err(E::custom("Cashu V4 C must be exactly one compressed point"));
                }
                Ok(SensitiveCashuBytes(Zeroizing::new(value)))
            }
        }

        // As above, request borrowed bytes so ciborium uses the caller-owned
        // zeroizing scratch instead of allocating an ordinary Vec first.
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

impl fmt::Debug for CashuProofV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuProofV3")
            .field("amount", &self.amount)
            .field("id", &self.id)
            .field("secret", &"[REDACTED]")
            .field("C", &"[REDACTED]")
            .field("has_dleq", &self.dleq.is_some())
            .finish()
    }
}

impl fmt::Debug for CashuProofV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CashuProofV4")
            .field("amount", &self.amount)
            .field("secret", &"[REDACTED]")
            .field("c", &"[REDACTED]")
            .field("has_dleq", &self.dleq.is_some())
            .field("has_witness", &self.witness.0)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscardedCashuDleqFieldV3 {
    #[serde(deserialize_with = "deserialize_dleq_text_scalar")]
    e: DiscardedCashuDleqScalar,
    #[serde(deserialize_with = "deserialize_dleq_text_scalar")]
    s: DiscardedCashuDleqScalar,
    #[serde(deserialize_with = "deserialize_dleq_text_scalar")]
    r: DiscardedCashuDleqScalar,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscardedCashuDleqFieldV4 {
    #[serde(deserialize_with = "deserialize_dleq_bytes_scalar")]
    e: DiscardedCashuDleqScalar,
    #[serde(deserialize_with = "deserialize_dleq_bytes_scalar")]
    s: DiscardedCashuDleqScalar,
    #[serde(deserialize_with = "deserialize_dleq_bytes_scalar")]
    r: DiscardedCashuDleqScalar,
}

impl DiscardedCashuDleqFieldV3 {
    fn verify_received_proof(
        &self,
        secret: &str,
        unblinded_signature: &[u8; 33],
        denomination_public_key: &[u8; 33],
    ) -> Result<(), String> {
        verify_received_dleq_v1(
            secret.as_bytes(),
            unblinded_signature,
            denomination_public_key,
            &self.e,
            &self.s,
            &self.r,
        )
    }
}

impl DiscardedCashuDleqFieldV4 {
    fn verify_received_proof(
        &self,
        secret: &str,
        unblinded_signature: &[u8; 33],
        denomination_public_key: &[u8; 33],
    ) -> Result<(), String> {
        verify_received_dleq_v1(
            secret.as_bytes(),
            unblinded_signature,
            denomination_public_key,
            &self.e,
            &self.s,
            &self.r,
        )
    }
}

fn verify_received_dleq_v1(
    secret: &[u8],
    unblinded_signature: &[u8; 33],
    denomination_public_key: &[u8; 33],
    e: &DiscardedCashuDleqScalar,
    s: &DiscardedCashuDleqScalar,
    r: &DiscardedCashuDleqScalar,
) -> Result<(), String> {
    verify_cashu_received_proof_dleq_v1(
        secret,
        unblinded_signature,
        denomination_public_key,
        &e.0,
        &s.0,
        &r.0,
    )
    .map_err(|_| "Cashu token contains an invalid NUT-12 DLEQ proof".to_owned())
}

struct DiscardedCashuDleqScalar([u8; 32]);

impl fmt::Debug for DiscardedCashuDleqScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for DiscardedCashuDleqScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct DleqTextScalarVisitor;

impl<'de> de::Visitor<'de> for DleqTextScalarVisitor {
    type Value = DiscardedCashuDleqScalar;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("one 64-character lowercase hex scalar")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(E::custom(
                "Cashu DLEQ scalar is not canonical lowercase hex",
            ));
        }
        let mut decoded = [0u8; 32];
        if hex::decode_to_slice(value, &mut decoded).is_err() {
            decoded.zeroize();
            return Err(E::custom("Cashu DLEQ scalar is invalid hex"));
        }
        Ok(DiscardedCashuDleqScalar(decoded))
    }

    fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let result = self.visit_str(&value);
        value.zeroize();
        result
    }
}

struct DleqBytesScalarVisitor;

impl<'de> de::Visitor<'de> for DleqBytesScalarVisitor {
    type Value = DiscardedCashuDleqScalar;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("one 32-byte scalar")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let decoded: [u8; 32] = value
            .try_into()
            .map_err(|_| E::custom("Cashu DLEQ scalar must be exactly 32 bytes"))?;
        Ok(DiscardedCashuDleqScalar(decoded))
    }

    fn visit_byte_buf<E>(self, mut value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let result = self.visit_bytes(&value);
        value.zeroize();
        result
    }
}

fn deserialize_dleq_text_scalar<'de, D>(
    deserializer: D,
) -> Result<DiscardedCashuDleqScalar, D::Error>
where
    D: Deserializer<'de>,
{
    // Reject CBOR byte strings and indefinite text. V3 uses exact lowercase
    // hex JSON; escaped JSON remains owned by the caller's JS engine boundary.
    deserializer.deserialize_str(DleqTextScalarVisitor)
}

fn deserialize_dleq_bytes_scalar<'de, D>(
    deserializer: D,
) -> Result<DiscardedCashuDleqScalar, D::Error>
where
    D: Deserializer<'de>,
{
    // V4 uses exact 32-byte CBOR values. `deserialize_bytes` rejects
    // indefinite byte strings and decodes definite values through our
    // zeroizing ciborium scratch.
    deserializer.deserialize_bytes(DleqBytesScalarVisitor)
}

#[derive(Default)]
struct PresentCashuField(bool);

impl<'de> Deserialize<'de> for PresentCashuField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

/// Owns normalized bearer proofs while parsing is still fallible. This makes
/// every early return wipe proofs already accepted from earlier token entries.
#[derive(Default)]
struct SensitiveCashuProofBuffer(Vec<StandardCashuProofV1>);

impl SensitiveCashuProofBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(
            capacity.min(MAX_STANDARD_CASHU_PROOFS_V1),
        ))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn push(&mut self, proof: StandardCashuProofV1) {
        self.0.push(proof);
    }

    fn into_inner(mut self) -> Vec<StandardCashuProofV1> {
        mem::take(&mut self.0)
    }
}

impl fmt::Debug for SensitiveCashuProofBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveCashuProofBuffer")
            .field("proof_count", &self.0.len())
            .field("proofs", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SensitiveCashuProofBuffer {
    fn drop(&mut self) {
        zeroize_standard_cashu_proofs(&mut self.0);
    }
}

/// Keeps the final Rust-owned normalized spend zeroizing on both validation
/// failure and successful encoding. The returned wire bytes intentionally
/// remain owned by the caller because they are the next-hop capability.
struct SensitiveCashuSpend(StandardCashuSpendV1);

impl SensitiveCashuSpend {
    fn new(mut proofs: Vec<StandardCashuProofV1>) -> Self {
        proofs.sort_by(standard_cashu_proof_order);
        Self(StandardCashuSpendV1 { proofs })
    }

    fn as_spend(&self) -> &StandardCashuSpendV1 {
        &self.0
    }
}

impl fmt::Debug for SensitiveCashuSpend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveCashuSpend")
            .field("proof_count", &self.0.proofs.len())
            .field("proofs", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SensitiveCashuSpend {
    fn drop(&mut self) {
        zeroize_standard_cashu_proofs(&mut self.0.proofs);
    }
}

fn zeroize_standard_cashu_proofs(proofs: &mut [StandardCashuProofV1]) {
    for proof in proofs {
        proof.secret.zeroize();
        proof.c.zeroize();
    }
}

fn standard_cashu_proof_order(
    left: &StandardCashuProofV1,
    right: &StandardCashuProofV1,
) -> Ordering {
    left.keyset_id
        .as_bytes()
        .cmp(right.keyset_id.as_bytes())
        .then_with(|| left.amount.cmp(&right.amount))
        .then_with(|| left.secret.as_bytes().cmp(right.secret.as_bytes()))
        .then_with(|| left.c.cmp(&right.c))
}

fn standard_cashu_spend_wire_len(spend: &StandardCashuSpendV1) -> usize {
    spend.proofs.iter().fold(2usize, |length, proof| {
        length.saturating_add(
            proof
                .keyset_id
                .len()
                .saturating_add(8 + 2 + proof.secret.len() + proof.c.len()),
        )
    })
}

pub(crate) fn import_standard_cashu_token_v1(
    accepted: &AcceptedServicePolicyV1,
    scope_id: &[u8; 32],
    offer_id: u32,
    serialized_token: &str,
    now_unix: u64,
) -> Result<Vec<u8>, String> {
    // `serialized_token` is borrowed from a wasm-bindgen JavaScript input.
    // Rust can wipe every allocation it creates below, but cannot reliably
    // erase the original JS string or copies retained by the JS engine.
    if now_unix == 0 {
        return Err("trusted wall clock is required for Cashu import".into());
    }
    let offer = accepted
        .policy()
        .scopes
        .iter()
        .find(|scope| &scope.scope.scope_id() == scope_id)
        .and_then(|scope| scope.offers.iter().find(|offer| offer.offer_id == offer_id))
        .ok_or_else(|| "selected Cashu scope/offer is not in the accepted policy".to_owned())?;
    let manifest = offer
        .cashu_mint_manifest
        .as_ref()
        .ok_or_else(|| "selected offer has no signed standard Cashu manifest".to_owned())?;

    let token = serialized_token
        .strip_prefix("cashu:")
        .unwrap_or(serialized_token);
    if token.len() > MAX_SERIALIZED_TOKEN_CHARS_V1 || token.trim() != token {
        return Err(
            "serialized Cashu token is oversized or contains surrounding whitespace".into(),
        );
    }
    let proofs = if let Some(encoded) = token.strip_prefix("cashuA") {
        parse_v3(encoded, manifest)?
    } else if let Some(encoded) = token.strip_prefix("cashuB") {
        parse_v4(encoded, manifest)?
    } else {
        return Err("only Cashu V3 (cashuA) and V4 (cashuB) tokens are accepted".into());
    };
    let spend = SensitiveCashuSpend::new(proofs);
    spend
        .as_spend()
        .total_amount()
        .map_err(|error| format!("Cashu proof list is invalid: {error}"))?;
    if standard_cashu_spend_wire_len(spend.as_spend()) > MAX_AUTH_PROOF_LEN {
        return Err("Cashu token does not fit the bounded authorization proof".into());
    }
    accepted
        .dangerous_unpaired_prepare_standard_cashu_spend_v1(
            scope_id,
            offer_id,
            spend.as_spend(),
            now_unix,
        )
        .map_err(|error| format!("Cashu token does not match the signed offer: {error}"))
}

fn parse_v3(
    encoded: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<Vec<StandardCashuProofV1>, String> {
    let bytes = decode_token_base64(encoded)?;
    // The V1 profile requires canonical unescaped ASCII for every accepted
    // V3 field. Besides reducing alternate encodings, this prevents
    // serde_json from materializing escaped proof secrets/C/DLEQ scalars in
    // its ordinary heap scratch buffer before our zeroizing visitors run.
    if bytes.contains(&b'\\') {
        return Err("Cashu V3 token contains a non-canonical JSON escape".to_owned());
    }
    let mut token: CashuTokenV3 = serde_json::from_slice(bytes.as_slice())
        .map_err(|_| "Cashu V3 token is not strict known-field JSON".to_owned())?;
    if token.token.len() != 1 {
        return Err("Cashu V3 import requires exactly one mint entry".into());
    }
    validate_mint_unit_memo(
        &token.token[0].mint,
        token.unit.as_deref(),
        token.memo.as_ref().map(SensitiveCashuString::as_str),
        manifest,
    )?;
    let entry = token
        .token
        .pop()
        .expect("one V3 mint entry was checked above");
    drop(token);

    let mut normalized = SensitiveCashuProofBuffer::with_capacity(entry.proofs.len());
    for mut proof in entry.proofs {
        if normalized.len() == MAX_STANDARD_CASHU_PROOFS_V1 {
            return Err("Cashu token contains too many proofs".into());
        }
        reject_nut10_secret(proof.secret.as_str())?;
        let keyset_id = resolve_text_keyset_id(&proof.id, manifest)?;
        let c = decode_canonical_compressed_point_hex(proof.c.as_str())?;
        if let Some(dleq) = proof.dleq.take() {
            // NUT-12 requires a receiving wallet to verify supplied DLEQ
            // metadata. Its private `r` is wiped here and never copied into
            // the canonical provider presentation.
            let denomination_public_key =
                denomination_public_key(manifest, &keyset_id, proof.amount)?;
            dleq.verify_received_proof(proof.secret.as_str(), &c, denomination_public_key)?;
        }
        normalized.push(StandardCashuProofV1 {
            keyset_id,
            amount: proof.amount,
            secret: proof.secret.take(),
            c,
        });
    }
    Ok(normalized.into_inner())
}

fn parse_v4(
    encoded: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<Vec<StandardCashuProofV1>, String> {
    let bytes = decode_token_base64(encoded)?;
    let mut scratch = Zeroizing::new([0u8; 4_096]);
    let mut token: CashuTokenV4 =
        ciborium::from_reader_with_buffer(bytes.as_slice(), scratch.as_mut_slice())
            .map_err(|_| "Cashu V4 token is not strict known-field CBOR".to_owned())?;
    validate_mint_unit_memo(
        &token.mint,
        Some(&token.unit),
        token.memo.as_ref().map(SensitiveCashuString::as_str),
        manifest,
    )?;
    if token.token.is_empty() || token.token.len() > MAX_STANDARD_CASHU_PROOFS_V1 {
        return Err("Cashu V4 token has an invalid number of keyset groups".into());
    }
    let groups = mem::take(&mut token.token);
    drop(token);
    let mut normalized = SensitiveCashuProofBuffer::default();
    for group in groups {
        let keyset_id = resolve_binary_keyset_id(&group.keyset_id, manifest)?;
        for mut proof in group.proofs {
            if proof.witness.0 {
                return Err("Cashu witness fields are disabled by the V1 privacy profile".into());
            }
            if normalized.len() == MAX_STANDARD_CASHU_PROOFS_V1 {
                return Err("Cashu token contains too many proofs".into());
            }
            reject_nut10_secret(proof.secret.as_str())?;
            let c: [u8; 33] = proof
                .c
                .as_slice()
                .try_into()
                .map_err(|_| "Cashu V4 C must be exactly one compressed point".to_owned())?;
            if let Some(dleq) = proof.dleq.take() {
                let denomination_public_key =
                    denomination_public_key(manifest, &keyset_id, proof.amount)?;
                dleq.verify_received_proof(proof.secret.as_str(), &c, denomination_public_key)?;
            }
            normalized.push(StandardCashuProofV1 {
                keyset_id: keyset_id.clone(),
                amount: proof.amount,
                secret: proof.secret.take(),
                c,
            });
        }
    }
    Ok(normalized.into_inner())
}

fn validate_mint_unit_memo(
    mint: &str,
    unit: Option<&str>,
    memo: Option<&str>,
    manifest: &StandardCashuMintManifestV1,
) -> Result<(), String> {
    if mint != manifest.mint_endpoint {
        return Err("Cashu token mint does not match the signed manifest".into());
    }
    if unit.is_some_and(|value| value != manifest.unit) {
        return Err("Cashu token unit does not match the signed manifest".into());
    }
    if memo.is_some_and(|value| value.len() > MAX_TOKEN_MEMO_BYTES_V1) {
        return Err("Cashu token memo exceeds the local import bound".into());
    }
    Ok(())
}

fn decode_token_base64(encoded: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if encoded.is_empty() || encoded.len() > MAX_SERIALIZED_TOKEN_CHARS_V1 {
        return Err("Cashu token payload is empty or oversized".into());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(encoded.len().saturating_mul(3) / 4));
    if encoded.contains('=') {
        URL_SAFE
            .decode_vec(encoded, &mut decoded)
            .map_err(|_| "Cashu token uses invalid padded base64url".to_owned())?;
        let mut canonical = Zeroizing::new(String::with_capacity(encoded.len()));
        URL_SAFE.encode_string(decoded.as_slice(), &mut canonical);
        if canonical.as_str() != encoded {
            return Err("Cashu token uses a non-canonical padded base64url encoding".into());
        }
    } else {
        URL_SAFE_NO_PAD
            .decode_vec(encoded, &mut decoded)
            .map_err(|_| "Cashu token uses invalid unpadded base64url".to_owned())?;
        let mut canonical = Zeroizing::new(String::with_capacity(encoded.len()));
        URL_SAFE_NO_PAD.encode_string(decoded.as_slice(), &mut canonical);
        if canonical.as_str() != encoded {
            return Err("Cashu token uses a non-canonical unpadded base64url encoding".into());
        }
    }
    if decoded.is_empty() || decoded.len() > MAX_DECODED_TOKEN_BYTES_V1 {
        return Err("decoded Cashu token is empty or oversized".into());
    }
    Ok(decoded)
}

fn resolve_text_keyset_id(
    value: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Cashu keyset ID must be canonical lowercase hex".into());
    }
    match value.len() {
        16 => resolve_short_keyset_id(value, manifest),
        66 => manifest
            .accepted_input_keysets
            .iter()
            .find(|keyset| keyset.keyset_id == value)
            .map(|keyset| keyset.keyset_id.clone())
            .ok_or_else(|| "Cashu keyset is not accepted by the signed manifest".to_owned()),
        _ => Err("Cashu keyset ID must use the 8-byte short or 33-byte full form".into()),
    }
}

fn resolve_binary_keyset_id(
    value: &[u8],
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    match value.len() {
        8 => resolve_short_keyset_id(&hex::encode(value), manifest),
        33 => resolve_text_keyset_id(&hex::encode(value), manifest),
        _ => Err("Cashu V4 keyset ID must be exactly 8 or 33 bytes".into()),
    }
}

fn resolve_short_keyset_id(
    short: &str,
    manifest: &StandardCashuMintManifestV1,
) -> Result<String, String> {
    let mut matches: Vec<&CashuKeysetBindingV1> = manifest
        .accepted_input_keysets
        .iter()
        .filter(|keyset| {
            keyset.keyset_id.starts_with(short) || legacy_keyset_id_v1(keyset) == short
        })
        .collect();
    matches.dedup_by_key(|keyset| keyset.keyset_id.as_str());
    match matches.as_slice() {
        [keyset] => Ok(keyset.keyset_id.clone()),
        [] => Err("short Cashu keyset ID is not accepted by the signed manifest".into()),
        _ => Err("short Cashu keyset ID is ambiguous in the signed manifest".into()),
    }
}

fn denomination_public_key<'a>(
    manifest: &'a StandardCashuMintManifestV1,
    keyset_id: &str,
    amount: u64,
) -> Result<&'a [u8; 33], String> {
    manifest
        .accepted_input_keysets
        .iter()
        .find(|keyset| keyset.keyset_id == keyset_id)
        .and_then(|keyset| keyset.keys.iter().find(|key| key.amount == amount))
        .map(|key| &key.public_key)
        .ok_or_else(|| "Cashu proof denomination is not in the signed manifest".to_owned())
}

fn legacy_keyset_id_v1(keyset: &CashuKeysetBindingV1) -> String {
    let mut hasher = Sha256::new();
    for key in &keyset.keys {
        hasher.update(key.public_key);
    }
    let digest = hasher.finalize();
    format!("00{}", hex::encode(&digest[..7]))
}

fn decode_canonical_compressed_point_hex(value: &str) -> Result<[u8; 33], String> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Cashu V3 C must be canonical lowercase compressed-point hex".into());
    }
    let mut bytes = [0u8; 33];
    if hex::decode_to_slice(value, &mut bytes).is_err() {
        bytes.zeroize();
        return Err("Cashu V3 C is not valid hex".to_owned());
    }
    Ok(bytes)
}

fn reject_nut10_secret(secret: &str) -> Result<(), String> {
    if serde_json::from_str::<Nut10Shape>(secret).is_ok_and(|shape| shape.0) {
        return Err(
            "Cashu NUT-10 structured secrets are disabled by the V1 privacy profile".into(),
        );
    }
    Ok(())
}

/// Allocation-free shape probe for the only NUT-10 form rejected by V1:
/// `[string, object]`. It avoids cloning a bearer secret into a temporary
/// `serde_json::Value` merely to classify its top-level JSON types.
struct Nut10Shape(bool);

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonValueKind {
    String,
    Object,
    Other,
}

impl<'de> Deserialize<'de> for Nut10Shape {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShapeVisitor;

        impl<'de> de::Visitor<'de> for ShapeVisitor {
            type Value = Nut10Shape;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let first = sequence.next_element::<JsonValueKind>()?;
                let second = sequence.next_element::<JsonValueKind>()?;
                let mut has_extra = false;
                while sequence.next_element::<de::IgnoredAny>()?.is_some() {
                    has_extra = true;
                }
                Ok(Nut10Shape(
                    !has_extra
                        && first == Some(JsonValueKind::String)
                        && second == Some(JsonValueKind::Object),
                ))
            }
        }

        deserializer.deserialize_any(ShapeVisitor)
    }
}

impl<'de> Deserialize<'de> for JsonValueKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct KindVisitor;

        impl<'de> de::Visitor<'de> for KindVisitor {
            type Value = JsonValueKind;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any JSON value")
            }

            fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
                Ok(JsonValueKind::Other)
            }

            fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
                Ok(JsonValueKind::Other)
            }

            fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
                Ok(JsonValueKind::Other)
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
                Ok(JsonValueKind::Other)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(JsonValueKind::Other)
            }

            fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
                Ok(JsonValueKind::String)
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E> {
                value.zeroize();
                Ok(JsonValueKind::String)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                while sequence.next_element::<de::IgnoredAny>()?.is_some() {}
                Ok(JsonValueKind::Other)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                while map
                    .next_entry::<de::IgnoredAny, de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(JsonValueKind::Object)
            }
        }

        deserializer.deserialize_any(KindVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pir_payment_crypto::{
        blind_cashu_message_v1, verify_and_unblind_cashu_promise_v1, K256CashuMintKeyringV1,
    };
    use pir_sdk_client::{accept_service_policy_response_v1, ServicePolicyCheckpointV1};
    use pir_service_protocol::{
        derive_cashu_keyset_id_v2, AcquisitionMethod, AuthPaddingClassV1, AuthScheme, BackendId,
        CashuDenominationKeyV1, CashuRequiredNutsV1, DatasetBindingV1, DeploymentStatus,
        EntitlementLimitsV1, FreeModeV1, PriceV1, PrivacyLeakageV1, ServiceOfferV1,
        ServicePolicyResponseV1, ServicePolicyV1, ServiceScopePolicyV1, ServiceScopeV1,
        VerificationMode, WorkloadId, RESP_SERVICE_POLICY_V1,
    };
    use std::collections::BTreeMap;

    #[derive(Deserialize)]
    struct CdkKeysResponseV1 {
        keysets: Vec<CdkKeysetV1>,
    }

    #[derive(Deserialize)]
    struct CdkKeysetV1 {
        id: String,
        unit: String,
        active: bool,
        keys: BTreeMap<String, String>,
        input_fee_ppk: u32,
    }

    const GENERATOR_COMPRESSED: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn accepted_cashu_policy(price: u64) -> (AcceptedServicePolicyV1, [u8; 32]) {
        let keys = vec![CashuDenominationKeyV1 {
            amount: 1,
            public_key: GENERATOR_COMPRESSED,
        }];
        let keyset = CashuKeysetBindingV1 {
            keyset_id: derive_cashu_keyset_id_v2(&keys, "sat", 0, None).unwrap(),
            unit: "sat".into(),
            input_fee_ppk: 0,
            final_expiry: None,
            keys,
        };
        assert_eq!(
            keyset.keyset_id,
            "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
        );
        let manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint: "https://mint.example".into(),
            unit: "sat".into(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets: vec![keyset.clone()],
            active_output_keyset: keyset,
        };
        let provider_id = [0x51; 32];
        let scope = ServiceScopeV1 {
            provider_id,
            backend: BackendId::DpfPirV1,
            workload: WorkloadId::DpfEvaluateJobV1,
            protocol_version: 1,
            dataset: DatasetBindingV1::Class { class_id: 1 },
            operation_profile: 1,
            entitlement_profile: 1,
        };
        let scope_id = scope.scope_id();
        let offer = ServiceOfferV1 {
            offer_id: 7,
            acquisition: AcquisitionMethod::CashuEcashV1,
            free_mode: FreeModeV1::NotFree,
            free_quota: 0,
            free_window_seconds: 0,
            free_pow_difficulty_bits: 0,
            priority_class: 1,
            authorization: AuthScheme::CashuEcashV1,
            verification: VerificationMode::StandardCashuMintOnline,
            deployment_status: DeploymentStatus::Stable,
            price: PriceV1::Cashu {
                unit: "sat".into(),
                amount: price,
            },
            issuer_id: manifest.mint_id(),
            key_id: manifest.manifest_digest().unwrap().to_vec(),
            credential_binding: None,
            cashu_mint_manifest: Some(manifest),
            endpoint: "https://mint.example".into(),
            invoice_expiry_seconds: 0,
            claim_window_seconds: 0,
            minimum_credential_validity_seconds: 60,
            retired_policy_grace_seconds: 0,
            credential_count: 1,
            credential_presentation_limit: 1,
            privacy_leakage: PrivacyLeakageV1::from_bits(
                PrivacyLeakageV1::ISSUER_REDEMPTION_TIMING
                    | PrivacyLeakageV1::ISSUER_LEARNS_PROVIDER,
            )
            .unwrap(),
        };
        let signing = SigningKey::from_bytes(&[0x52; 32]);
        let policy = ServicePolicyV1::sign(
            provider_id,
            1,
            100,
            500,
            AuthPaddingClassV1::Class16KiB,
            vec![ServiceScopePolicyV1 {
                scope,
                limits: EntitlementLimitsV1 {
                    max_logical_inputs: 1,
                    max_frames: 10,
                    max_request_bytes: 1_000,
                    max_response_bytes: 2_000,
                    max_wall_time_ms: 1_000,
                    max_concurrent_sockets: 1,
                    max_hint_groups: 0,
                    max_work_units: 100,
                },
                offers: vec![offer],
            }],
            &signing,
        )
        .unwrap();
        let mut response = vec![RESP_SERVICE_POLICY_V1];
        response.extend_from_slice(&ServicePolicyResponseV1 { policy }.encode().unwrap());
        let accepted = accept_service_policy_response_v1(
            &response,
            provider_id,
            &signing.verifying_key(),
            120,
            &ServicePolicyCheckpointV1::initial(),
            [9; 32],
        )
        .unwrap();
        (accepted, scope_id)
    }

    fn cashu_a(json: &str) -> String {
        format!("cashuA{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
    }

    fn fixture_json() -> &'static str {
        include_str!("../tests/fixtures/standard_cashu_v3.json").trim_end()
    }

    fn cashu_b(
        proofs: Vec<ciborium::value::Value>,
        extra_root: Option<(&str, ciborium::value::Value)>,
    ) -> String {
        use ciborium::value::Value;
        let full_id =
            hex::decode("0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31")
                .unwrap();
        let mut root = vec![
            (
                Value::Text("m".into()),
                Value::Text("https://mint.example".into()),
            ),
            (Value::Text("u".into()), Value::Text("sat".into())),
            (
                Value::Text("t".into()),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("i".into()), Value::Bytes(full_id[..8].to_vec())),
                    (Value::Text("p".into()), Value::Array(proofs)),
                ])]),
            ),
        ];
        if let Some((key, value)) = extra_root {
            root.push((Value::Text(key.into()), value));
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(root), &mut bytes).unwrap();
        format!("cashuB{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    fn v4_proof(extra: Option<(&str, ciborium::value::Value)>) -> ciborium::value::Value {
        use ciborium::value::Value;
        let mut fields = vec![
            (Value::Text("a".into()), Value::Integer(1u64.into())),
            (
                Value::Text("s".into()),
                Value::Text("fixture-secret".into()),
            ),
            (
                Value::Text("c".into()),
                Value::Bytes(GENERATOR_COMPRESSED.to_vec()),
            ),
        ];
        if let Some((key, value)) = extra {
            fields.push((Value::Text(key.into()), value));
        }
        Value::Map(fields)
    }

    struct ReceivedDleqFixture {
        c: [u8; 33],
        e: [u8; 32],
        s: [u8; 32],
        r: [u8; 32],
    }

    fn received_dleq_fixture(secret: &str) -> ReceivedDleqFixture {
        let mut mint_secret = [0u8; 32];
        mint_secret[31] = 1;
        let keyring = K256CashuMintKeyringV1::from_secret_keys([mint_secret]).unwrap();
        let public_key = keyring.denomination_public_keys()[0];
        assert_eq!(public_key, GENERATOR_COMPRESSED);
        let mut r = [0u8; 32];
        r[31] = 7;
        let mut nonce = [0u8; 32];
        nonce[31] = 19;
        let blinded_message = blind_cashu_message_v1(secret.as_bytes(), &r).unwrap();
        let promise = keyring
            .blind_sign_with_dleq_v1(&public_key, &blinded_message, &nonce)
            .unwrap();
        let verified = verify_and_unblind_cashu_promise_v1(
            secret.as_bytes(),
            &r,
            &public_key,
            &blinded_message,
            promise.blinded_signature(),
            promise.dleq_e(),
            promise.dleq_s(),
        )
        .unwrap();
        ReceivedDleqFixture {
            c: *verified.unblinded_signature(),
            e: *promise.dleq_e(),
            s: *promise.dleq_s(),
            r,
        }
    }

    #[test]
    fn sensitive_import_types_move_without_clone_and_redact_debug() {
        let mut secret: SensitiveCashuString =
            serde_json::from_str("\"unique-bearer-secret\"").unwrap();
        let allocation = secret.as_str().as_ptr();
        assert_eq!(format!("{secret:?}"), "[REDACTED]");

        let mut moved = secret.take();
        assert_eq!(moved, "unique-bearer-secret");
        assert_eq!(moved.as_ptr(), allocation, "secret allocation was cloned");
        assert!(secret.as_str().is_empty());
        moved.zeroize();

        let token: CashuTokenV3 = serde_json::from_str(fixture_json()).unwrap();
        let proof_debug = format!("{:?}", token.token[0].proofs[0]);
        assert!(proof_debug.contains("[REDACTED]"));
        assert!(!proof_debug.contains("fixture-secret"));
        assert!(!proof_debug.contains("0279be667ef9dcbb"));

        let mut scratch = Zeroizing::new([0u8; 4_096]);
        let indefinite_text = [0x7f, 0x61, b'x', 0xff];
        assert!(
            ciborium::from_reader_with_buffer::<SensitiveCashuString, _>(
                indefinite_text.as_slice(),
                scratch.as_mut_slice(),
            )
            .is_err()
        );
        let mut scratch = Zeroizing::new([0u8; 4_096]);
        let indefinite_bytes = [0x5f, 0x41, 0x02, 0xff];
        assert!(ciborium::from_reader_with_buffer::<SensitiveCashuBytes, _>(
            indefinite_bytes.as_slice(),
            scratch.as_mut_slice(),
        )
        .is_err());
    }

    #[test]
    fn normalized_proof_zeroizer_clears_bearer_material() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let manifest = accepted
            .policy()
            .scopes
            .iter()
            .find(|scope| scope.scope.scope_id() == scope_id)
            .and_then(|scope| scope.offers.first())
            .and_then(|offer| offer.cashu_mint_manifest.as_ref())
            .unwrap();
        let token = cashu_a(fixture_json());
        let mut proofs = parse_v3(token.strip_prefix("cashuA").unwrap(), manifest).unwrap();
        zeroize_standard_cashu_proofs(&mut proofs);
        assert!(proofs[0].secret.is_empty());
        assert_eq!(proofs[0].c, [0; 33]);
    }

    #[test]
    fn nut10_shape_probe_preserves_exact_rejection_boundary() {
        assert!(reject_nut10_secret(r#"["P2PK",{"data":"02aa"}]"#).is_err());
        for accepted in [
            r#"["P2PK",{"data":"02aa"},3]"#,
            r#"["P2PK",["not-an-object"]]"#,
            r#"{"kind":"P2PK"}"#,
            "ordinary-bearer-secret",
            r#"["unterminated""#,
        ] {
            assert!(reject_nut10_secret(accepted).is_ok(), "{accepted}");
        }
    }

    #[test]
    fn locked_v3_fixture_imports_to_canonical_spend() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let bytes =
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(fixture_json()), 120)
                .unwrap();
        let spend = StandardCashuSpendV1::decode(&bytes).unwrap();
        assert_eq!(spend.proofs.len(), 1);
        assert_eq!(spend.proofs[0].secret, "fixture-secret");
        assert_eq!(spend.proofs[0].keyset_id.len(), 66);
        assert_eq!(spend.encode().unwrap(), bytes);
    }

    #[test]
    fn v3_rejects_wrong_mint_unit_keyset_and_amount() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        for bad in [
            fixture_json().replace("https://mint.example", "https://other.example"),
            fixture_json().replace("\"unit\":\"sat\"", "\"unit\":\"usd\""),
            fixture_json().replace(
                "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
                "01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            fixture_json().replace("\"amount\":1", "\"amount\":2"),
        ] {
            assert!(
                import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&bad), 120,)
                    .is_err()
            );
        }
    }

    #[test]
    fn v3_verifies_and_strips_dleq_but_rejects_duplicate_unknown_witness_and_nut10() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let proof = "{\"amount\":1,\"id\":\"0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31\",\"secret\":\"fixture-secret\",\"C\":\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"}";
        let duplicate = format!(
            "{{\"token\":[{{\"mint\":\"https://mint.example\",\"proofs\":[{proof},{proof}]}}],\"unit\":\"sat\"}}",
        );
        let unknown = fixture_json().replace("\"C\":", "\"unknown\":1,\"C\":");
        let witness = fixture_json().replace("\"C\":", "\"witness\":\"x\",\"C\":");
        let valid_dleq = received_dleq_fixture("fixture-secret");
        let dleq_r = hex::encode(valid_dleq.r);
        let dleq = fixture_json()
            .replace(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                &hex::encode(valid_dleq.c),
            )
            .replace(
                "\"C\":",
                &format!(
                    "\"dleq\":{{\"e\":\"{}\",\"s\":\"{}\",\"r\":\"{dleq_r}\"}},\"C\":",
                    hex::encode(valid_dleq.e),
                    hex::encode(valid_dleq.s),
                ),
            );
        let bad_dleq = dleq.replacen(&hex::encode(valid_dleq.e), &"11".repeat(32), 1);
        let malformed_dleq = fixture_json().replace(
            "\"C\":",
            "\"dleq\":{\"e\":\"00\",\"s\":\"00\",\"r\":\"not-a-scalar\"},\"C\":",
        );
        let unknown_dleq = fixture_json().replace(
            "\"C\":",
            &format!(
                "\"dleq\":{{\"e\":\"{}\",\"s\":\"{}\",\"r\":\"{}\",\"x\":1}},\"C\":",
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32),
            ),
        );
        let nut10 = fixture_json().replace(
            "\"fixture-secret\"",
            "\"[\\\"P2PK\\\",{\\\"data\\\":\\\"02aa\\\"}]\"",
        );
        let escaped_secret = fixture_json().replace("fixture-secret", "\\u0066ixture-secret");
        for bad in [
            duplicate,
            unknown,
            witness,
            nut10,
            bad_dleq,
            malformed_dleq,
            unknown_dleq,
            escaped_secret,
        ] {
            assert!(
                import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&bad), 120,)
                    .is_err()
            );
        }
        let imported =
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&dleq), 120)
                .expect("valid NUT-12 metadata is verified and stripped locally");
        assert!(!imported
            .windows(dleq_r.len())
            .any(|window| window == dleq_r.as_bytes()));
    }

    #[test]
    fn rejects_noncanonical_base64_and_uppercase_hex() {
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let noncanonical = format!("{}=", cashu_a(fixture_json()));
        let uppercase = fixture_json().replace(
            "0106b3f35573b8d261be5295471cb08a8013c8448894e48905a00c13d968f54c31",
            "0106B3F35573B8D261BE5295471CB08A8013C8448894E48905A00C13D968F54C31",
        );
        assert!(
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &noncanonical, 120,).is_err()
        );
        assert!(
            import_standard_cashu_token_v1(&accepted, &scope_id, 7, &cashu_a(&uppercase), 120,)
                .is_err()
        );
    }

    #[test]
    fn v4_imports_short_v2_id_verifies_and_strips_dleq_and_rejects_disabled_fields() {
        use ciborium::value::Value;
        let (accepted, scope_id) = accepted_cashu_policy(1);
        let valid = cashu_b(vec![v4_proof(None)], None);
        let bytes = import_standard_cashu_token_v1(&accepted, &scope_id, 7, &valid, 120).unwrap();
        assert_eq!(
            StandardCashuSpendV1::decode(&bytes).unwrap().proofs.len(),
            1
        );

        let empty = cashu_b(Vec::new(), None);
        let valid_dleq = received_dleq_fixture("fixture-secret");
        let mut dleq_proof = v4_proof(Some((
            "d",
            Value::Map(vec![
                (Value::Text("e".into()), Value::Bytes(valid_dleq.e.to_vec())),
                (Value::Text("s".into()), Value::Bytes(valid_dleq.s.to_vec())),
                (Value::Text("r".into()), Value::Bytes(valid_dleq.r.to_vec())),
            ]),
        )));
        let Value::Map(dleq_fields) = &mut dleq_proof else {
            unreachable!("v4_proof always returns a map")
        };
        dleq_fields
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::Text(name) if name == "c"))
            .expect("V4 proof C field")
            .1 = Value::Bytes(valid_dleq.c.to_vec());
        let dleq = cashu_b(vec![dleq_proof], None);
        let mut bad_dleq_e = valid_dleq.e;
        bad_dleq_e[31] ^= 1;
        let mut bad_dleq_proof = v4_proof(Some((
            "d",
            Value::Map(vec![
                (Value::Text("e".into()), Value::Bytes(bad_dleq_e.to_vec())),
                (Value::Text("s".into()), Value::Bytes(valid_dleq.s.to_vec())),
                (Value::Text("r".into()), Value::Bytes(valid_dleq.r.to_vec())),
            ]),
        )));
        let Value::Map(bad_dleq_fields) = &mut bad_dleq_proof else {
            unreachable!("v4_proof always returns a map")
        };
        bad_dleq_fields
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::Text(name) if name == "c"))
            .expect("V4 proof C field")
            .1 = Value::Bytes(valid_dleq.c.to_vec());
        let bad_dleq = cashu_b(vec![bad_dleq_proof], None);
        let witness = cashu_b(
            vec![v4_proof(Some(("w", Value::Text("signature".into()))))],
            None,
        );
        let malformed_dleq = cashu_b(
            vec![v4_proof(Some((
                "d",
                Value::Map(vec![
                    (Value::Text("e".into()), Value::Bytes(vec![1; 31])),
                    (Value::Text("s".into()), Value::Bytes(vec![2; 32])),
                    (Value::Text("r".into()), Value::Bytes(vec![3; 32])),
                ]),
            )))],
            None,
        );
        let unknown_dleq = cashu_b(
            vec![v4_proof(Some((
                "d",
                Value::Map(vec![
                    (Value::Text("e".into()), Value::Bytes(vec![1; 32])),
                    (Value::Text("s".into()), Value::Bytes(vec![2; 32])),
                    (Value::Text("r".into()), Value::Bytes(vec![3; 32])),
                    (Value::Text("x".into()), Value::Integer(1u64.into())),
                ]),
            )))],
            None,
        );
        let unknown = cashu_b(
            vec![v4_proof(None)],
            Some(("x", Value::Integer(1u64.into()))),
        );
        let mut text_c_proof = v4_proof(None);
        let Value::Map(fields) = &mut text_c_proof else {
            unreachable!("v4_proof always returns a map")
        };
        let c = fields
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::Text(name) if name == "c"))
            .expect("V4 proof C field");
        c.1 = Value::Text(hex::encode(GENERATOR_COMPRESSED));
        let text_c = cashu_b(vec![text_c_proof], None);
        let imported = import_standard_cashu_token_v1(&accepted, &scope_id, 7, &dleq, 120)
            .expect("valid V4 NUT-12 metadata is verified and stripped locally");
        assert_eq!(
            StandardCashuSpendV1::decode(&imported)
                .unwrap()
                .proofs
                .len(),
            1
        );
        for bad in [
            empty,
            witness,
            unknown,
            bad_dleq,
            malformed_dleq,
            unknown_dleq,
            text_c,
        ] {
            assert!(import_standard_cashu_token_v1(&accepted, &scope_id, 7, &bad, 120,).is_err());
        }
    }

    /// Opt-in interoperability check driven by
    /// `scripts/payment-v1-cdk-regtest-e2e.sh`. The manifest is assembled
    /// directly from a disposable loopback mint because production policy
    /// validation correctly forbids HTTP mint endpoints.
    #[test]
    #[ignore = "requires a disposable local cdk-mintd instance"]
    fn real_cdk_cashub_interop() {
        let token_path = std::env::var("BITCOINPIR_CDK_CASHUB_TOKEN_FILE")
            .expect("BITCOINPIR_CDK_CASHUB_TOKEN_FILE");
        let keys_path =
            std::env::var("BITCOINPIR_CDK_KEYS_FILE").expect("BITCOINPIR_CDK_KEYS_FILE");
        let mint_endpoint =
            std::env::var("BITCOINPIR_CDK_MINT_ENDPOINT").expect("BITCOINPIR_CDK_MINT_ENDPOINT");
        let expected_amount = std::env::var("BITCOINPIR_CDK_EXPECTED_AMOUNT")
            .expect("BITCOINPIR_CDK_EXPECTED_AMOUNT")
            .parse::<u64>()
            .expect("expected amount u64");
        let token = zeroize::Zeroizing::new(
            std::fs::read_to_string(token_path).expect("read owner-only disposable Cashu token"),
        );
        let keys: CdkKeysResponseV1 = serde_json::from_slice(
            &std::fs::read(keys_path).expect("read disposable CDK keyset response"),
        )
        .expect("decode CDK /v1/keys response");
        let active = keys
            .keysets
            .into_iter()
            .find(|keyset| keyset.active && keyset.unit == "sat")
            .expect("one active sat keyset");
        let mut denominations = active
            .keys
            .into_iter()
            .map(|(amount, public_key)| {
                let public_key: [u8; 33] = hex::decode(public_key)
                    .expect("CDK denomination public key hex")
                    .try_into()
                    .expect("CDK compressed public key length");
                CashuDenominationKeyV1 {
                    amount: amount.parse().expect("CDK denomination amount"),
                    public_key,
                }
            })
            .collect::<Vec<_>>();
        denominations.sort_by_key(|key| key.amount);
        let keyset = CashuKeysetBindingV1 {
            keyset_id: active.id,
            unit: active.unit,
            input_fee_ppk: active.input_fee_ppk,
            final_expiry: None,
            keys: denominations,
        };
        keyset.encode().expect("CDK keyset matches NUT-02 V2");
        let manifest = StandardCashuMintManifestV1 {
            manifest_epoch: 1,
            mint_endpoint,
            unit: "sat".to_owned(),
            required_nuts: CashuRequiredNutsV1::required_v1(),
            accepted_input_keysets: vec![keyset.clone()],
            active_output_keyset: keyset.clone(),
        };
        let serialized = token.trim();
        let serialized = serialized.strip_prefix("cashu:").unwrap_or(serialized);
        let encoded = serialized
            .strip_prefix("cashuB")
            .expect("CDK emitted NUT-00 V4 token");
        let proofs = parse_v4(encoded, &manifest).expect("import real CDK cashuB");
        assert_eq!(
            proofs.iter().map(|proof| proof.amount).sum::<u64>(),
            expected_amount
        );
        assert!(proofs
            .iter()
            .all(|proof| proof.keyset_id == keyset.keyset_id));
        let spend = StandardCashuSpendV1::new_canonical(proofs).expect("canonical CDK spend");
        assert_eq!(
            StandardCashuSpendV1::decode(&spend.encode().unwrap())
                .unwrap()
                .proofs
                .iter()
                .map(|proof| proof.amount)
                .sum::<u64>(),
            expected_amount
        );
    }
}
