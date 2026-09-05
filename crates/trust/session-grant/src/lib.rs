//! Session grants: prepaid, offline-verifiable admission for BitcoinPIR
//! query opcodes.
//!
//! ## Model
//!
//! A **cashier** — operator-owned and deployed outside the PIR hosts — takes
//! payment (Cashu ecash, Lightning, …) and returns a short-lived,
//! Ed25519-signed [`SessionGrant`] carrying a credit balance. A PIR server
//! pins the cashier's public key(s) and verifies grants offline: it holds no
//! payment secret, talks to no mint, and never learns what was paid. Every
//! accepted query-bearing request frame spends one credit from the grant's
//! balance in the server's in-memory [`GrantLedger`], keyed by grant id, so a
//! client can reconnect and keep spending the same grant until it is
//! exhausted or expires.
//!
//! Servers that pin the same cashier key meter independently; settlement
//! between operator and cashier happens outside this crate.
//!
//! ## Wire format (version 1, [`SESSION_GRANT_LEN`] = 133 bytes)
//!
//! | offset | length | field |
//! | --- | --- | --- |
//! | 0 | 1 | `version` = 1 |
//! | 1 | 32 | `issuer_pubkey` — Ed25519 verifying key of the cashier |
//! | 33 | 16 | `grant_id` — cashier-chosen, unique per grant; the ledger key |
//! | 49 | 8 | `issued_at` — Unix seconds, little-endian |
//! | 57 | 8 | `expires_at` — Unix seconds, little-endian, exclusive |
//! | 65 | 4 | `credits` — little-endian, at least 1 |
//! | 69 | 64 | `signature` — Ed25519 over [`SESSION_GRANT_DOMAIN_TAG`] ‖ bytes `0..69` |
//!
//! Any layout change bumps the version; verifiers reject unknown versions.
//!
//! Pure cryptography and bookkeeping: no filesystem, clock, or network. The
//! caller supplies `now` in Unix seconds everywhere time matters.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Current wire-format version.
pub const SESSION_GRANT_VERSION: u8 = 1;
/// Domain separation prefix of the signing preimage. Bump with the version.
pub const SESSION_GRANT_DOMAIN_TAG: &[u8] = b"BPIR-SESSION-GRANT-V1";
/// Length of an Ed25519 public key (RFC 8032).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a grant id.
pub const GRANT_ID_LEN: usize = 16;
/// Length of an Ed25519 signature (RFC 8032).
pub const SIGNATURE_LEN: usize = 64;
/// Bytes covered by the signature: everything before it.
pub const SESSION_GRANT_SIGNED_LEN: usize = 1 + PUBLIC_KEY_LEN + GRANT_ID_LEN + 8 + 8 + 4;
/// Encoded length of a grant.
pub const SESSION_GRANT_LEN: usize = SESSION_GRANT_SIGNED_LEN + SIGNATURE_LEN;
/// Tolerated clock difference between cashier and server, in seconds. A
/// grant whose `issued_at` lies further in the future is rejected.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// Longest `expires_at - issued_at` a verifier accepts, in seconds. Bounds
/// how long a ledger entry can live.
pub const MAX_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;

/// Cashier-chosen grant identifier; the ledger key.
pub type GrantId = [u8; GRANT_ID_LEN];
/// Raw Ed25519 public key bytes.
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

const VERSION_OFFSET: usize = 0;
const ISSUER_OFFSET: usize = 1;
const GRANT_ID_OFFSET: usize = ISSUER_OFFSET + PUBLIC_KEY_LEN;
const ISSUED_AT_OFFSET: usize = GRANT_ID_OFFSET + GRANT_ID_LEN;
const EXPIRES_AT_OFFSET: usize = ISSUED_AT_OFFSET + 8;
const CREDITS_OFFSET: usize = EXPIRES_AT_OFFSET + 8;
const SIGNATURE_OFFSET: usize = CREDITS_OFFSET + 4;
const _: () = assert!(SIGNATURE_OFFSET == SESSION_GRANT_SIGNED_LEN);
const _: () = assert!(SESSION_GRANT_LEN == 133);

/// Wire-format, verification, and ledger errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// The encoded grant is not exactly [`SESSION_GRANT_LEN`] bytes.
    BadLength { expected: usize, got: usize },
    /// The version byte is not [`SESSION_GRANT_VERSION`].
    UnknownVersion(u8),
    /// A field violates the grant contract (zero credits, inverted window).
    InvalidField(&'static str),
    /// A public key is not a valid Ed25519 point.
    BadPublicKey,
    /// Ed25519 signature verification failed.
    BadSignature,
    /// The grant's issuer key is not in the pinned set.
    UntrustedIssuer,
    /// `issued_at` is more than [`MAX_CLOCK_SKEW_SECS`] in the future.
    NotYetValid,
    /// `now >= expires_at`.
    Expired,
    /// `expires_at - issued_at` exceeds [`MAX_LIFETIME_SECS`].
    LifetimeTooLong,
    /// Every credit of the grant has been spent.
    Exhausted,
    /// The grant id is unknown to this ledger (never presented, or evicted).
    NotAdmitted,
    /// The grant id was already admitted with different credits or expiry.
    Conflict,
    /// A public-key file is neither 32 raw bytes nor 64 hex characters.
    InvalidPublicKeyFile(&'static str),
    /// A trusted-issuer set must contain at least one key.
    NoTrustedIssuers,
    /// The same public key was pinned twice.
    DuplicateIssuer,
}

impl core::fmt::Display for GrantError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadLength { expected, got } => {
                write!(f, "session grant must be {expected} bytes, got {got}")
            }
            Self::UnknownVersion(version) => {
                write!(f, "unknown session grant version {version}")
            }
            Self::InvalidField(what) => write!(f, "invalid session grant: {what}"),
            Self::BadPublicKey => f.write_str("public key is not a valid Ed25519 point"),
            Self::BadSignature => f.write_str("session grant signature verification failed"),
            Self::UntrustedIssuer => {
                f.write_str("session grant issuer is not a pinned cashier key")
            }
            Self::NotYetValid => f.write_str("session grant is issued too far in the future"),
            Self::Expired => f.write_str("session grant has expired"),
            Self::LifetimeTooLong => write!(
                f,
                "session grant lifetime exceeds {MAX_LIFETIME_SECS} seconds"
            ),
            Self::Exhausted => f.write_str("session grant credits are exhausted"),
            Self::NotAdmitted => f.write_str("session grant has not been presented on this server"),
            Self::Conflict => {
                f.write_str("session grant id was already admitted with different terms")
            }
            Self::InvalidPublicKeyFile(what) => write!(f, "invalid public key file: {what}"),
            Self::NoTrustedIssuers => f.write_str("no cashier public key is pinned"),
            Self::DuplicateIssuer => f.write_str("duplicate cashier public key"),
        }
    }
}

impl std::error::Error for GrantError {}

/// A decoded grant. Decoding checks structure only; call
/// [`SessionGrant::verify`] before trusting any field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub issuer_pubkey: PublicKey,
    pub grant_id: GrantId,
    pub issued_at: u64,
    pub expires_at: u64,
    pub credits: u32,
    pub signature: [u8; SIGNATURE_LEN],
}

/// The outcome of a successful [`SessionGrant::verify`]: the fields a
/// ledger needs, produced only after the signature, issuer, and time
/// window checks passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub grant_id: GrantId,
    pub credits: u32,
    pub expires_at: u64,
}

impl SessionGrant {
    /// Strict decode of exactly [`SESSION_GRANT_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        if bytes.len() != SESSION_GRANT_LEN {
            return Err(GrantError::BadLength {
                expected: SESSION_GRANT_LEN,
                got: bytes.len(),
            });
        }
        let version = bytes[VERSION_OFFSET];
        if version != SESSION_GRANT_VERSION {
            return Err(GrantError::UnknownVersion(version));
        }
        let mut issuer_pubkey = [0u8; PUBLIC_KEY_LEN];
        issuer_pubkey.copy_from_slice(&bytes[ISSUER_OFFSET..GRANT_ID_OFFSET]);
        let mut grant_id = [0u8; GRANT_ID_LEN];
        grant_id.copy_from_slice(&bytes[GRANT_ID_OFFSET..ISSUED_AT_OFFSET]);
        let issued_at = u64::from_le_bytes(
            bytes[ISSUED_AT_OFFSET..EXPIRES_AT_OFFSET]
                .try_into()
                .expect("eight bytes"),
        );
        let expires_at = u64::from_le_bytes(
            bytes[EXPIRES_AT_OFFSET..CREDITS_OFFSET]
                .try_into()
                .expect("eight bytes"),
        );
        let credits = u32::from_le_bytes(
            bytes[CREDITS_OFFSET..SIGNATURE_OFFSET]
                .try_into()
                .expect("four bytes"),
        );
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[SIGNATURE_OFFSET..]);
        let grant = Self {
            issuer_pubkey,
            grant_id,
            issued_at,
            expires_at,
            credits,
            signature,
        };
        grant.check_fields()?;
        Ok(grant)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> [u8; SESSION_GRANT_LEN] {
        let mut out = [0u8; SESSION_GRANT_LEN];
        out[..SESSION_GRANT_SIGNED_LEN].copy_from_slice(&self.signed_bytes());
        out[SIGNATURE_OFFSET..].copy_from_slice(&self.signature);
        out
    }

    /// `SESSION_GRANT_DOMAIN_TAG ‖ signed bytes`: the message the cashier
    /// signs and the server verifies.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage =
            Vec::with_capacity(SESSION_GRANT_DOMAIN_TAG.len() + SESSION_GRANT_SIGNED_LEN);
        preimage.extend_from_slice(SESSION_GRANT_DOMAIN_TAG);
        preimage.extend_from_slice(&self.signed_bytes());
        preimage
    }

    /// Full verification: field contract, issuer pinned, signature, time
    /// window. Cheap checks run before the signature so untrusted input
    /// never costs a curve operation.
    pub fn verify(&self, issuers: &TrustedIssuers, now: u64) -> Result<VerifiedGrant, GrantError> {
        self.check_fields()?;
        if !issuers.contains(&self.issuer_pubkey) {
            return Err(GrantError::UntrustedIssuer);
        }
        self.verify_signature()?;
        self.check_time(now)?;
        Ok(VerifiedGrant {
            grant_id: self.grant_id,
            credits: self.credits,
            expires_at: self.expires_at,
        })
    }

    /// Signature check only, against the grant's own `issuer_pubkey`.
    /// Does not decide whether that key is trusted.
    pub fn verify_signature(&self) -> Result<(), GrantError> {
        let key =
            VerifyingKey::from_bytes(&self.issuer_pubkey).map_err(|_| GrantError::BadPublicKey)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_preimage(), &signature)
            .map_err(|_| GrantError::BadSignature)
    }

    /// `now` must be before `expires_at`, and `issued_at` may lead `now`
    /// by at most [`MAX_CLOCK_SKEW_SECS`].
    pub fn check_time(&self, now: u64) -> Result<(), GrantError> {
        if now >= self.expires_at {
            return Err(GrantError::Expired);
        }
        if self.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(GrantError::NotYetValid);
        }
        Ok(())
    }

    fn check_fields(&self) -> Result<(), GrantError> {
        if self.credits == 0 {
            return Err(GrantError::InvalidField("credits must be at least 1"));
        }
        if self.issued_at >= self.expires_at {
            return Err(GrantError::InvalidField(
                "expires_at must be after issued_at",
            ));
        }
        if self.expires_at - self.issued_at > MAX_LIFETIME_SECS {
            return Err(GrantError::LifetimeTooLong);
        }
        Ok(())
    }

    fn signed_bytes(&self) -> [u8; SESSION_GRANT_SIGNED_LEN] {
        let mut out = [0u8; SESSION_GRANT_SIGNED_LEN];
        out[VERSION_OFFSET] = SESSION_GRANT_VERSION;
        out[ISSUER_OFFSET..GRANT_ID_OFFSET].copy_from_slice(&self.issuer_pubkey);
        out[GRANT_ID_OFFSET..ISSUED_AT_OFFSET].copy_from_slice(&self.grant_id);
        out[ISSUED_AT_OFFSET..EXPIRES_AT_OFFSET].copy_from_slice(&self.issued_at.to_le_bytes());
        out[EXPIRES_AT_OFFSET..CREDITS_OFFSET].copy_from_slice(&self.expires_at.to_le_bytes());
        out[CREDITS_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&self.credits.to_le_bytes());
        out
    }
}

/// The cashier's signing side. Lives in the cashier process (and in tests);
/// a PIR server never constructs one.
pub struct GrantSigner {
    key: SigningKey,
}

impl GrantSigner {
    /// Build from a 32-byte Ed25519 seed (the format `bpir-admin keygen`
    /// writes).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// The key a server pins with `--session-grant-pubkey`.
    pub fn public_key(&self) -> PublicKey {
        self.key.verifying_key().to_bytes()
    }

    /// Sign a grant. The caller chooses a unique `grant_id`; the field
    /// contract (credits ≥ 1, `issued_at < expires_at`, lifetime cap) is
    /// enforced here so an unverifiable grant is never issued.
    pub fn issue(
        &self,
        grant_id: GrantId,
        issued_at: u64,
        expires_at: u64,
        credits: u32,
    ) -> Result<SessionGrant, GrantError> {
        let mut grant = SessionGrant {
            issuer_pubkey: self.public_key(),
            grant_id,
            issued_at,
            expires_at,
            credits,
            signature: [0u8; SIGNATURE_LEN],
        };
        grant.check_fields()?;
        grant.signature = self.key.sign(&grant.signing_preimage()).to_bytes();
        Ok(grant)
    }
}

/// The set of cashier public keys a server accepts. One key per service is
/// the intended deployment: the key is the audience, so no audience field
/// is needed in the grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedIssuers {
    keys: Vec<PublicKey>,
}

impl TrustedIssuers {
    /// Validate every key as an Ed25519 point and reject empty sets and
    /// duplicates.
    pub fn new(keys: &[PublicKey]) -> Result<Self, GrantError> {
        if keys.is_empty() {
            return Err(GrantError::NoTrustedIssuers);
        }
        let mut accepted: Vec<PublicKey> = Vec::with_capacity(keys.len());
        for key in keys {
            VerifyingKey::from_bytes(key).map_err(|_| GrantError::BadPublicKey)?;
            if accepted.contains(key) {
                return Err(GrantError::DuplicateIssuer);
            }
            accepted.push(*key);
        }
        Ok(Self { keys: accepted })
    }

    pub fn contains(&self, key: &PublicKey) -> bool {
        self.keys.contains(key)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Parse the contents of an operator-written public-key file: either the
/// 32 raw key bytes or 64 hex characters with optional surrounding
/// whitespace (the form `bpir-admin keygen` prints).
pub fn parse_public_key_file(contents: &[u8]) -> Result<PublicKey, GrantError> {
    const EXPECTED: &str = "expected 32 raw bytes or 64 hex characters";
    if contents.len() == PUBLIC_KEY_LEN {
        let mut key = [0u8; PUBLIC_KEY_LEN];
        key.copy_from_slice(contents);
        return Ok(key);
    }
    let text = core::str::from_utf8(contents)
        .map_err(|_| GrantError::InvalidPublicKeyFile(EXPECTED))?
        .trim();
    if text.len() != 2 * PUBLIC_KEY_LEN {
        return Err(GrantError::InvalidPublicKeyFile(EXPECTED));
    }
    let decoded =
        hex::decode(text).map_err(|_| GrantError::InvalidPublicKeyFile("not hexadecimal"))?;
    let mut key = [0u8; PUBLIC_KEY_LEN];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LedgerEntry {
    credits: u32,
    used: u32,
    expires_at: u64,
}

/// Expired entries are swept after this many admissions, so the ledger's
/// size is bounded by the grants admitted within one lifetime.
const SWEEP_EVERY_ADMISSIONS: u32 = 256;

/// Per-grant credit balances, shared by every connection of one server.
/// Not thread-safe by itself; the server wraps it in a mutex. A restart
/// clears it, which at worst re-credits grants that are still unexpired.
#[derive(Debug, Default)]
pub struct GrantLedger {
    entries: HashMap<GrantId, LedgerEntry>,
    admissions_since_sweep: u32,
}

impl GrantLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a verified grant, or re-attach to its existing balance.
    /// Returns the remaining credits. Idempotent for the same grant;
    /// rejects an id reused with different terms and grants that are
    /// already spent or expired.
    pub fn admit(&mut self, grant: &VerifiedGrant, now: u64) -> Result<u32, GrantError> {
        if now >= grant.expires_at {
            return Err(GrantError::Expired);
        }
        self.admissions_since_sweep += 1;
        if self.admissions_since_sweep >= SWEEP_EVERY_ADMISSIONS {
            self.sweep(now);
        }
        match self.entries.entry(grant.grant_id) {
            Entry::Occupied(entry) => {
                let existing = entry.get();
                if existing.credits != grant.credits || existing.expires_at != grant.expires_at {
                    return Err(GrantError::Conflict);
                }
                if existing.used >= existing.credits {
                    return Err(GrantError::Exhausted);
                }
                Ok(existing.credits - existing.used)
            }
            Entry::Vacant(slot) => {
                slot.insert(LedgerEntry {
                    credits: grant.credits,
                    used: 0,
                    expires_at: grant.expires_at,
                });
                Ok(grant.credits)
            }
        }
    }

    /// Spend one credit of an admitted grant. Returns the remaining
    /// credits. An expired entry is evicted on contact.
    pub fn consume(&mut self, grant_id: &GrantId, now: u64) -> Result<u32, GrantError> {
        let expired = matches!(self.entries.get(grant_id), Some(entry) if now >= entry.expires_at);
        if expired {
            self.entries.remove(grant_id);
            return Err(GrantError::Expired);
        }
        let entry = self
            .entries
            .get_mut(grant_id)
            .ok_or(GrantError::NotAdmitted)?;
        if entry.used >= entry.credits {
            return Err(GrantError::Exhausted);
        }
        entry.used += 1;
        Ok(entry.credits - entry.used)
    }

    /// Remaining credits of an admitted grant, if known.
    pub fn remaining(&self, grant_id: &GrantId) -> Option<u32> {
        self.entries
            .get(grant_id)
            .map(|entry| entry.credits - entry.used)
    }

    /// Drop every expired entry; returns how many were removed.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| now < entry.expires_at);
        self.admissions_since_sweep = 0;
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const ID: GrantId = [0x11; GRANT_ID_LEN];

    fn signer() -> GrantSigner {
        GrantSigner::from_seed(&[7u8; 32])
    }

    fn issuers(signer: &GrantSigner) -> TrustedIssuers {
        TrustedIssuers::new(&[signer.public_key()]).expect("one valid key")
    }

    fn grant(credits: u32) -> SessionGrant {
        signer()
            .issue(ID, NOW - 10, NOW + 3600, credits)
            .expect("valid grant")
    }

    #[test]
    fn encode_decode_round_trip() {
        let original = grant(5);
        let bytes = original.encode();
        assert_eq!(bytes.len(), SESSION_GRANT_LEN);
        assert_eq!(bytes[0], SESSION_GRANT_VERSION);
        let decoded = SessionGrant::decode(&bytes).expect("decodes");
        assert_eq!(decoded, original);
        assert!(original
            .signing_preimage()
            .starts_with(SESSION_GRANT_DOMAIN_TAG));
    }

    #[test]
    fn issued_grant_verifies_against_pinned_key() {
        let signer = signer();
        let verified = grant(3).verify(&issuers(&signer), NOW).expect("verifies");
        assert_eq!(
            verified,
            VerifiedGrant {
                grant_id: ID,
                credits: 3,
                expires_at: NOW + 3600,
            }
        );
    }

    #[test]
    fn untrusted_issuer_is_rejected_before_the_signature_check() {
        let other = GrantSigner::from_seed(&[9u8; 32]);
        let foreign = other.issue(ID, NOW - 10, NOW + 60, 1).expect("valid");
        assert_eq!(
            foreign.verify(&issuers(&signer()), NOW),
            Err(GrantError::UntrustedIssuer)
        );
        assert_eq!(foreign.verify_signature(), Ok(()));
    }

    #[test]
    fn every_byte_is_bound() {
        let signer = signer();
        let trusted = issuers(&signer);
        let bytes = grant(2).encode();
        for index in 0..SESSION_GRANT_LEN {
            let mut tampered = bytes;
            tampered[index] ^= 0x01;
            let outcome = SessionGrant::decode(&tampered).and_then(|g| g.verify(&trusted, NOW));
            assert!(outcome.is_err(), "byte {index} was not bound");
            if index >= SIGNATURE_OFFSET {
                assert_eq!(outcome, Err(GrantError::BadSignature), "byte {index}");
            }
        }
    }

    #[test]
    fn wrong_length_and_version_are_rejected() {
        let bytes = grant(1).encode();
        assert_eq!(
            SessionGrant::decode(&bytes[..SESSION_GRANT_LEN - 1]),
            Err(GrantError::BadLength {
                expected: SESSION_GRANT_LEN,
                got: SESSION_GRANT_LEN - 1,
            })
        );
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert!(matches!(
            SessionGrant::decode(&longer),
            Err(GrantError::BadLength { .. })
        ));
        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert_eq!(
            SessionGrant::decode(&wrong_version),
            Err(GrantError::UnknownVersion(2))
        );
    }

    #[test]
    fn field_contract_is_enforced_at_issue_and_decode() {
        let signer = signer();
        assert_eq!(
            signer.issue(ID, NOW, NOW + 10, 0),
            Err(GrantError::InvalidField("credits must be at least 1"))
        );
        assert_eq!(
            signer.issue(ID, NOW, NOW, 1),
            Err(GrantError::InvalidField(
                "expires_at must be after issued_at"
            ))
        );
        assert_eq!(
            signer.issue(ID, NOW, NOW + MAX_LIFETIME_SECS + 1, 1),
            Err(GrantError::LifetimeTooLong)
        );
        assert!(signer.issue(ID, NOW, NOW + MAX_LIFETIME_SECS, 1).is_ok());

        // Forged fields fail structurally before any signature work.
        let mut zero_credits = grant(1).encode();
        zero_credits[CREDITS_OFFSET..SIGNATURE_OFFSET].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            SessionGrant::decode(&zero_credits),
            Err(GrantError::InvalidField("credits must be at least 1"))
        );
    }

    #[test]
    fn time_window_uses_the_skew_tolerance() {
        let signer = signer();
        let trusted = issuers(&signer);
        let g = signer.issue(ID, NOW, NOW + 100, 1).expect("valid");
        assert!(g.verify(&trusted, NOW - MAX_CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            g.verify(&trusted, NOW - MAX_CLOCK_SKEW_SECS - 1),
            Err(GrantError::NotYetValid)
        );
        assert!(g.verify(&trusted, NOW + 99).is_ok());
        assert_eq!(g.verify(&trusted, NOW + 100), Err(GrantError::Expired));
    }

    #[test]
    fn ledger_meters_credits_across_reconnects() {
        let signer = signer();
        let trusted = issuers(&signer);
        let verified = grant(2).verify(&trusted, NOW).expect("verifies");
        let mut ledger = GrantLedger::new();
        assert_eq!(ledger.admit(&verified, NOW), Ok(2));
        assert_eq!(ledger.consume(&ID, NOW), Ok(1));
        // A reconnecting client re-presents the same grant and keeps its balance.
        assert_eq!(ledger.admit(&verified, NOW), Ok(1));
        assert_eq!(ledger.remaining(&ID), Some(1));
        assert_eq!(ledger.consume(&ID, NOW), Ok(0));
        assert_eq!(ledger.consume(&ID, NOW), Err(GrantError::Exhausted));
        assert_eq!(ledger.admit(&verified, NOW), Err(GrantError::Exhausted));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_unknown_and_conflicting_grants() {
        let mut ledger = GrantLedger::new();
        assert_eq!(ledger.consume(&ID, NOW), Err(GrantError::NotAdmitted));
        assert_eq!(ledger.remaining(&ID), None);
        let first = VerifiedGrant {
            grant_id: ID,
            credits: 4,
            expires_at: NOW + 60,
        };
        assert_eq!(ledger.admit(&first, NOW), Ok(4));
        let reused_id = VerifiedGrant {
            credits: 5,
            ..first
        };
        assert_eq!(ledger.admit(&reused_id, NOW), Err(GrantError::Conflict));
        assert_eq!(ledger.admit(&first, NOW + 60), Err(GrantError::Expired));
    }

    #[test]
    fn ledger_evicts_expired_entries() {
        let mut ledger = GrantLedger::new();
        let short = VerifiedGrant {
            grant_id: ID,
            credits: 1,
            expires_at: NOW + 1,
        };
        let long = VerifiedGrant {
            grant_id: [0x22; GRANT_ID_LEN],
            credits: 1,
            expires_at: NOW + 1000,
        };
        ledger.admit(&short, NOW).expect("admit");
        ledger.admit(&long, NOW).expect("admit");
        assert_eq!(ledger.consume(&ID, NOW + 1), Err(GrantError::Expired));
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger.consume(&ID, NOW + 1), Err(GrantError::NotAdmitted));
        assert_eq!(ledger.sweep(NOW + 1000), 1);
        assert!(ledger.is_empty());
    }

    #[test]
    fn ledger_sweeps_on_its_own_after_many_admissions() {
        let mut ledger = GrantLedger::new();
        let stale = VerifiedGrant {
            grant_id: ID,
            credits: 1,
            expires_at: NOW + 1,
        };
        ledger.admit(&stale, NOW).expect("admit");
        for n in 0..SWEEP_EVERY_ADMISSIONS {
            let mut grant_id = [0u8; GRANT_ID_LEN];
            grant_id[..4].copy_from_slice(&(n + 1).to_le_bytes());
            let fresh = VerifiedGrant {
                grant_id,
                credits: 1,
                expires_at: NOW + 1000,
            };
            ledger.admit(&fresh, NOW + 10).expect("admit");
        }
        assert_eq!(ledger.remaining(&ID), None, "stale entry was swept");
        assert_eq!(ledger.len(), SWEEP_EVERY_ADMISSIONS as usize);
    }

    #[test]
    fn public_key_file_accepts_raw_and_hex() {
        let key = signer().public_key();
        assert_eq!(parse_public_key_file(&key), Ok(key));
        let hex_lower = hex::encode(key);
        assert_eq!(parse_public_key_file(hex_lower.as_bytes()), Ok(key));
        let padded = format!("  {}\n", hex_lower.to_uppercase());
        assert_eq!(parse_public_key_file(padded.as_bytes()), Ok(key));
    }

    #[test]
    fn public_key_file_rejects_garbage() {
        assert!(parse_public_key_file(b"").is_err());
        assert!(parse_public_key_file(&[0u8; 31]).is_err());
        assert!(parse_public_key_file(&[0u8; 33]).is_err());
        assert!(parse_public_key_file(&[0xffu8; 64]).is_err());
        let not_hex = "zz".repeat(32);
        assert_eq!(
            parse_public_key_file(not_hex.as_bytes()),
            Err(GrantError::InvalidPublicKeyFile("not hexadecimal"))
        );
    }

    #[test]
    fn trusted_issuers_reject_empty_duplicate_and_invalid_keys() {
        let key = signer().public_key();
        assert_eq!(TrustedIssuers::new(&[]), Err(GrantError::NoTrustedIssuers));
        assert_eq!(
            TrustedIssuers::new(&[key, key]),
            Err(GrantError::DuplicateIssuer)
        );
        // y = 2 gives x^2 with no square root, so the encoding is not a point.
        let mut not_a_point = [0u8; PUBLIC_KEY_LEN];
        not_a_point[0] = 2;
        assert_eq!(
            TrustedIssuers::new(&[not_a_point]),
            Err(GrantError::BadPublicKey)
        );
        let two = TrustedIssuers::new(&[key, GrantSigner::from_seed(&[1u8; 32]).public_key()])
            .expect("two keys");
        assert_eq!(two.len(), 2);
        assert!(!two.is_empty());
        assert!(two.contains(&key));
    }
}
