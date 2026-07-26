//! Lightning-node boundary for BitcoinPIR credential purchases.
//!
//! The production trait is deliberately synchronous and transport-neutral.
//! HTTP/RPC adapters may execute it on a blocking worker, but must preserve
//! its exact idempotency and recovery contract. The included fake node is
//! strictly for local tests and never handles real funds.

#![forbid(unsafe_code)]

mod core_lightning;

pub use core_lightning::{
    anonymous_invoice_description_hash_v1, ClnRpcResponseV1, ClnRpcTransportErrorV1,
    ClnRpcTransportV1, CoreLightningBackendV1,
};
#[cfg(unix)]
pub use core_lightning::{UnixClnRpcSocketPolicyV1, UnixClnRpcTransportV1};

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash as _};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning_invoice::{
    Bolt11Invoice, Bolt11InvoiceDescriptionRef, Currency, InvoiceBuilder, PaymentSecret,
};
use pir_service_protocol::{
    LightningNetworkV1, MAX_BITCOIN_MSAT_V1, MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1,
};
use sha2::{Digest, Sha256};

const CREATE_REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/lightning-backend-create-request/v1";
const FAKE_PREIMAGE_DOMAIN_V1: &[u8] = b"BitcoinPIR/fake-lightning-preimage/v1";
const FAKE_PAYMENT_SECRET_DOMAIN_V1: &[u8] = b"BitcoinPIR/fake-lightning-payment-secret/v1";
const SETTLEMENT_EVIDENCE_DOMAIN_V1: &[u8] = b"BitcoinPIR/lightning-settlement-evidence/v1";
const BACKEND_LABEL_PREFIX_V1: &str = "bpir-v1-";
const BACKEND_LABEL_HEX_LEN_V1: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LightningBackendErrorV1 {
    InvalidRequest,
    RequestConflict,
    InvoiceNotFound,
    BackendUnavailable,
    OutcomeUnknown,
    InvoiceCreationFailed,
    LockPoisoned,
}

impl fmt::Display for LightningBackendErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid Lightning backend request",
            Self::RequestConflict => "Lightning backend idempotency conflict",
            Self::InvoiceNotFound => "Lightning invoice not found",
            Self::BackendUnavailable => "Lightning backend unavailable",
            Self::OutcomeUnknown => "Lightning backend outcome is unknown; recover by exact replay",
            Self::InvoiceCreationFailed => "Lightning invoice creation failed",
            Self::LockPoisoned => "Lightning backend state lock is poisoned",
        })
    }
}

impl std::error::Error for LightningBackendErrorV1 {}

/// Exact invoice creation input. This type intentionally has no `Debug`
/// implementation because the backend label becomes an issuer-side quote
/// correlator even though it is never placed in the BOLT11 invoice.
#[derive(Clone, Eq, PartialEq)]
pub struct CreateInvoiceRequestV1 {
    pub backend_label: String,
    pub network: LightningNetworkV1,
    pub expected_payee_pubkey: [u8; 33],
    pub amount_msat: u64,
    pub expiry_seconds: u32,
    /// A generic issuer-selected description hash. It must not encode a PIR
    /// query, Bitcoin address, selected peer, or credential serial.
    pub description_hash: [u8; 32],
}

impl CreateInvoiceRequestV1 {
    pub fn validate(&self) -> Result<(), LightningBackendErrorV1> {
        if !is_canonical_backend_label(&self.backend_label)
            || self.amount_msat == 0
            || self.amount_msat > MAX_BITCOIN_MSAT_V1
            || self.expiry_seconds == 0
            || self.expiry_seconds > MAX_BOLT11_INVOICE_EXPIRY_SECONDS_V1
            || self.description_hash.iter().all(|byte| *byte == 0)
            || PublicKey::from_slice(&self.expected_payee_pubkey).is_err()
        {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<[u8; 32], LightningBackendErrorV1> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(CREATE_REQUEST_DIGEST_DOMAIN_V1);
        hasher.update((self.backend_label.len() as u16).to_le_bytes());
        hasher.update(self.backend_label.as_bytes());
        hasher.update([self.network as u8]);
        hasher.update(self.expected_payee_pubkey);
        hasher.update(self.amount_msat.to_le_bytes());
        hasher.update(self.expiry_seconds.to_le_bytes());
        hasher.update(self.description_hash);
        Ok(hasher.finalize().into())
    }
}

/// Recoverable invoice facts returned after the backend has durably associated
/// the exact request with `backend_label`. It intentionally has no `Debug` so
/// structured logging cannot print the invoice or payment hash by accident.
#[derive(Clone, Eq, PartialEq)]
pub struct CreatedInvoiceV1 {
    pub invoice: String,
    pub payment_hash: [u8; 32],
    pub network: LightningNetworkV1,
    pub payee_pubkey: [u8; 33],
    pub amount_msat: u64,
    pub created_at: u64,
    pub expires_at: u64,
    pub expiry_seconds: u32,
}

/// Evidence that the exact backend response was reparsed as BOLT11 and bound
/// to the original creation request, including the invoice-embedded payment
/// hash. Fields are private so issuer code cannot replace this with a boolean
/// assertion.
#[derive(Clone, Copy)]
pub struct VerifiedCreatedInvoiceV1<'a> {
    created: &'a CreatedInvoiceV1,
}

impl<'a> VerifiedCreatedInvoiceV1<'a> {
    pub const fn created(&self) -> &'a CreatedInvoiceV1 {
        self.created
    }
}

impl CreatedInvoiceV1 {
    pub fn verify_for_request<'a>(
        &'a self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<VerifiedCreatedInvoiceV1<'a>, LightningBackendErrorV1> {
        request.validate()?;
        let invoice = Bolt11Invoice::from_str(&self.invoice)
            .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?;
        if invoice.to_string() != self.invoice
            || invoice.check_signature().is_err()
            || self.network != request.network
            || self.payee_pubkey != request.expected_payee_pubkey
            || self.amount_msat != request.amount_msat
            || self.created_at == 0
            || self.expiry_seconds != request.expiry_seconds
            || self.expires_at
                != self
                    .created_at
                    .checked_add(u64::from(request.expiry_seconds))
                    .ok_or(LightningBackendErrorV1::InvalidRequest)?
            || invoice_currency(&invoice) != Some(request.network)
            || invoice.get_payee_pub_key().serialize() != request.expected_payee_pubkey
            || invoice.amount_milli_satoshis() != Some(request.amount_msat)
            || invoice.duration_since_epoch().as_secs() != self.created_at
            || invoice.expiry_time().as_secs() != u64::from(request.expiry_seconds)
            || invoice.payment_hash().to_byte_array() != self.payment_hash
            || !matches!(
                invoice.description(),
                Bolt11InvoiceDescriptionRef::Hash(hash)
                    if hash.0.to_byte_array() == request.description_hash
            )
        {
            return Err(LightningBackendErrorV1::RequestConflict);
        }
        Ok(VerifiedCreatedInvoiceV1 { created: self })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvoiceObservationStateV1 {
    Open,
    Expired,
    Settled {
        settled_at: u64,
        amount_received_msat: u64,
        settlement_evidence_digest: [u8; 32],
    },
}

/// A lookup never returns a preimage. The payment hash is omitted as well: the
/// issuer already bound it when the invoice was created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvoiceObservationV1 {
    pub state: InvoiceObservationStateV1,
    pub observed_at: u64,
}

/// Production adapter boundary. Implementations must durably support lookup by
/// `backend_label`; a process-local cache is not authoritative.
pub trait LightningInvoiceBackendV1: fmt::Debug + Send + Sync + 'static {
    fn create_or_get_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1>;

    /// Retrieve durable invoice creation facts without creating anything.
    /// This is required for restart recovery after the issuer's original
    /// bounded creation window has elapsed.
    fn existing_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<CreatedInvoiceV1>, LightningBackendErrorV1>;

    fn lookup_invoice(
        &self,
        backend_label: &str,
        observed_at: u64,
    ) -> Result<InvoiceObservationV1, LightningBackendErrorV1>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeFailurePointV1 {
    CreateBeforeCommitOnce,
    CreateAfterCommitOnce,
    LookupOnce,
}

struct FakeInvoiceEntryV1 {
    request_digest: [u8; 32],
    created: CreatedInvoiceV1,
    // Fake-node-only secret. It is deliberately absent from every public API.
    _payment_preimage: [u8; 32],
    settlement: Option<(u64, u64, [u8; 32])>,
}

struct FakeNodeStateV1 {
    invoices: BTreeMap<String, FakeInvoiceEntryV1>,
    fail_once: Option<FakeFailurePointV1>,
    now_unix: u64,
}

/// Deterministic local-only fake. The signing key and derivation seed are
/// private and its `Debug` output is redacted.
pub struct FakeLightningNodeV1 {
    network: LightningNetworkV1,
    signing_key: SecretKey,
    payee_pubkey: [u8; 33],
    derivation_seed: [u8; 32],
    state: Mutex<FakeNodeStateV1>,
}

impl fmt::Debug for FakeLightningNodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeLightningNodeV1")
            .field("network", &self.network)
            .field("payee_pubkey", &"[redacted]")
            .field("signing_key", &"[redacted]")
            .field("derivation_seed", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl FakeLightningNodeV1 {
    pub fn new(
        network: LightningNetworkV1,
        signing_key: [u8; 32],
        derivation_seed: [u8; 32],
        initial_time_unix: u64,
    ) -> Result<Self, LightningBackendErrorV1> {
        if derivation_seed.iter().all(|byte| *byte == 0) || initial_time_unix == 0 {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let signing_key = SecretKey::from_slice(&signing_key)
            .map_err(|_| LightningBackendErrorV1::InvalidRequest)?;
        let secp = Secp256k1::new();
        let payee_pubkey = PublicKey::from_secret_key(&secp, &signing_key).serialize();
        Ok(Self {
            network,
            signing_key,
            payee_pubkey,
            derivation_seed,
            state: Mutex::new(FakeNodeStateV1 {
                invoices: BTreeMap::new(),
                fail_once: None,
                now_unix: initial_time_unix,
            }),
        })
    }

    pub const fn payee_pubkey(&self) -> [u8; 33] {
        self.payee_pubkey
    }

    /// Advance the deterministic fake node clock. Backwards time is rejected
    /// so tests cannot accidentally manufacture an invoice timestamp rollback.
    pub fn set_time(&self, now_unix: u64) -> Result<(), LightningBackendErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        if now_unix < state.now_unix {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        state.now_unix = now_unix;
        Ok(())
    }

    /// Inject exactly one local test failure. This is not a production
    /// operational API.
    pub fn fail_once(&self, point: FakeFailurePointV1) -> Result<(), LightningBackendErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        state.fail_once = Some(point);
        Ok(())
    }

    /// Simulate the Lightning node observing a settlement. Supplying a wrong
    /// amount is intentionally possible so issuer tests can prove that it
    /// never changes the entitlement.
    pub fn observe_settlement(
        &self,
        backend_label: &str,
        amount_received_msat: u64,
        settled_at: u64,
    ) -> Result<(), LightningBackendErrorV1> {
        if amount_received_msat == 0 || settled_at == 0 {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        let entry = state
            .invoices
            .get_mut(backend_label)
            .ok_or(LightningBackendErrorV1::InvoiceNotFound)?;
        if settled_at < entry.created.created_at {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let evidence = settlement_evidence_digest(
            backend_label,
            &entry.created.payment_hash,
            amount_received_msat,
            settled_at,
        );
        match entry.settlement {
            None => entry.settlement = Some((settled_at, amount_received_msat, evidence)),
            Some(existing) if existing == (settled_at, amount_received_msat, evidence) => {}
            Some(_) => return Err(LightningBackendErrorV1::RequestConflict),
        }
        Ok(())
    }

    fn build_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
        created_at: u64,
        payment_hash: [u8; 32],
        payment_secret: [u8; 32],
    ) -> Result<String, LightningBackendErrorV1> {
        let currency = match request.network {
            LightningNetworkV1::Bitcoin => Currency::Bitcoin,
            LightningNetworkV1::Testnet => Currency::BitcoinTestnet,
            LightningNetworkV1::Signet => Currency::Signet,
            LightningNetworkV1::Regtest => Currency::Regtest,
        };
        let secp = Secp256k1::new();
        let payment_hash = sha256::Hash::from_slice(&payment_hash)
            .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?;
        let description_hash = sha256::Hash::from_slice(&request.description_hash)
            .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?;
        InvoiceBuilder::new(currency)
            .amount_milli_satoshis(request.amount_msat)
            .description_hash(description_hash)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret(payment_secret))
            .duration_since_epoch(Duration::from_secs(created_at))
            .expiry_time(Duration::from_secs(u64::from(request.expiry_seconds)))
            .min_final_cltv_expiry_delta(18)
            .payee_pub_key(
                PublicKey::from_slice(&self.payee_pubkey)
                    .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?,
            )
            .build_signed(|message| secp.sign_ecdsa_recoverable(message, &self.signing_key))
            .map(|invoice| invoice.to_string())
            .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)
    }
}

fn invoice_currency(invoice: &Bolt11Invoice) -> Option<LightningNetworkV1> {
    match invoice.currency() {
        Currency::Bitcoin => Some(LightningNetworkV1::Bitcoin),
        Currency::BitcoinTestnet => Some(LightningNetworkV1::Testnet),
        Currency::Signet => Some(LightningNetworkV1::Signet),
        Currency::Regtest => Some(LightningNetworkV1::Regtest),
        Currency::Simnet => None,
    }
}

impl LightningInvoiceBackendV1 for FakeLightningNodeV1 {
    fn create_or_get_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        request.validate()?;
        if request.network != self.network || request.expected_payee_pubkey != self.payee_pubkey {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let request_digest = request.request_digest()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        if let Some(existing) = state.invoices.get(&request.backend_label) {
            return if existing.request_digest == request_digest {
                Ok(existing.created.clone())
            } else {
                Err(LightningBackendErrorV1::RequestConflict)
            };
        }
        if state.fail_once == Some(FakeFailurePointV1::CreateBeforeCommitOnce) {
            state.fail_once = None;
            return Err(LightningBackendErrorV1::BackendUnavailable);
        }

        let payment_preimage = derive_fake_secret(
            FAKE_PREIMAGE_DOMAIN_V1,
            &self.derivation_seed,
            &request.backend_label,
        );
        let payment_secret = derive_fake_secret(
            FAKE_PAYMENT_SECRET_DOMAIN_V1,
            &self.derivation_seed,
            &request.backend_label,
        );
        let payment_hash: [u8; 32] = Sha256::digest(payment_preimage).into();
        let created_at = state.now_unix;
        let invoice = self.build_invoice(request, created_at, payment_hash, payment_secret)?;
        let expires_at = created_at
            .checked_add(u64::from(request.expiry_seconds))
            .ok_or(LightningBackendErrorV1::InvalidRequest)?;
        let created = CreatedInvoiceV1 {
            invoice,
            payment_hash,
            network: request.network,
            payee_pubkey: request.expected_payee_pubkey,
            amount_msat: request.amount_msat,
            created_at,
            expires_at,
            expiry_seconds: request.expiry_seconds,
        };
        state.invoices.insert(
            request.backend_label.clone(),
            FakeInvoiceEntryV1 {
                request_digest,
                created: created.clone(),
                _payment_preimage: payment_preimage,
                settlement: None,
            },
        );
        if state.fail_once == Some(FakeFailurePointV1::CreateAfterCommitOnce) {
            state.fail_once = None;
            return Err(LightningBackendErrorV1::OutcomeUnknown);
        }
        Ok(created)
    }

    fn existing_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<CreatedInvoiceV1>, LightningBackendErrorV1> {
        if !is_canonical_backend_label(backend_label) {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        Ok(state
            .invoices
            .get(backend_label)
            .map(|entry| entry.created.clone()))
    }

    fn lookup_invoice(
        &self,
        backend_label: &str,
        observed_at: u64,
    ) -> Result<InvoiceObservationV1, LightningBackendErrorV1> {
        if !is_canonical_backend_label(backend_label) || observed_at == 0 {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| LightningBackendErrorV1::LockPoisoned)?;
        if state.fail_once == Some(FakeFailurePointV1::LookupOnce) {
            state.fail_once = None;
            return Err(LightningBackendErrorV1::BackendUnavailable);
        }
        let entry = state
            .invoices
            .get(backend_label)
            .ok_or(LightningBackendErrorV1::InvoiceNotFound)?;
        let state = match entry.settlement {
            Some((settled_at, amount_received_msat, settlement_evidence_digest)) => {
                InvoiceObservationStateV1::Settled {
                    settled_at,
                    amount_received_msat,
                    settlement_evidence_digest,
                }
            }
            None if observed_at >= entry.created.expires_at => InvoiceObservationStateV1::Expired,
            None => InvoiceObservationStateV1::Open,
        };
        Ok(InvoiceObservationV1 { state, observed_at })
    }
}

fn derive_fake_secret(domain: &[u8], seed: &[u8; 32], backend_label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(seed);
    hasher.update((backend_label.len() as u16).to_le_bytes());
    hasher.update(backend_label.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn settlement_evidence_digest(
    backend_label: &str,
    payment_hash: &[u8; 32],
    amount_received_msat: u64,
    settled_at: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_EVIDENCE_DOMAIN_V1);
    hasher.update((backend_label.len() as u16).to_le_bytes());
    hasher.update(backend_label.as_bytes());
    hasher.update(payment_hash);
    hasher.update(amount_received_msat.to_le_bytes());
    hasher.update(settled_at.to_le_bytes());
    hasher.finalize().into()
}

pub(crate) fn is_canonical_backend_label(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(BACKEND_LABEL_PREFIX_V1) else {
        return false;
    };
    hex.len() == BACKEND_LABEL_HEX_LEN_V1
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pir_service_protocol::ParsedBolt11InvoiceV1;
    use std::sync::Arc;
    use std::thread;

    fn node() -> FakeLightningNodeV1 {
        FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [3; 32], [7; 32], 1_700_000_000)
            .unwrap()
    }

    fn request(node: &FakeLightningNodeV1) -> CreateInvoiceRequestV1 {
        CreateInvoiceRequestV1 {
            backend_label: format!("{BACKEND_LABEL_PREFIX_V1}{}", "ab".repeat(32)),
            network: LightningNetworkV1::Regtest,
            expected_payee_pubkey: node.payee_pubkey(),
            amount_msat: 12_300,
            expiry_seconds: 600,
            description_hash: [9; 32],
        }
    }

    fn expect_backend_error<T>(
        result: Result<T, LightningBackendErrorV1>,
    ) -> LightningBackendErrorV1 {
        match result {
            Ok(_) => panic!("expected Lightning backend error"),
            Err(error) => error,
        }
    }

    #[test]
    fn fake_invoice_is_fixed_amount_signed_and_parseable() {
        let node = node();
        let request = request(&node);
        let created = node.create_or_get_invoice(&request).unwrap();
        created.verify_for_request(&request).unwrap();
        let parsed = ParsedBolt11InvoiceV1::parse(&created.invoice).unwrap();
        assert_eq!(parsed.network(), request.network);
        assert_eq!(parsed.payee_pubkey(), request.expected_payee_pubkey);
        assert_eq!(parsed.amount_msat(), request.amount_msat);
        assert_eq!(parsed.created_at(), created.created_at);
        assert_eq!(parsed.expiry_seconds(), request.expiry_seconds);
        assert_eq!(created.expires_at, created.created_at + 600);
    }

    #[test]
    fn backend_response_payment_hash_and_all_invoice_facts_are_rechecked() {
        let node = node();
        let request = request(&node);
        let created = node.create_or_get_invoice(&request).unwrap();

        let mut corrupt = created.clone();
        corrupt.payment_hash[0] ^= 1;
        assert_eq!(
            expect_backend_error(corrupt.verify_for_request(&request)),
            LightningBackendErrorV1::RequestConflict
        );

        let mut corrupt = created.clone();
        corrupt.amount_msat += 1;
        assert_eq!(
            expect_backend_error(corrupt.verify_for_request(&request)),
            LightningBackendErrorV1::RequestConflict
        );

        let mut wrong_request = request.clone();
        wrong_request.description_hash[0] ^= 1;
        // The description hash is committed inside the BOLT11 too, even
        // though it is deliberately omitted from CreatedInvoiceV1 fields.
        assert_eq!(
            expect_backend_error(created.verify_for_request(&wrong_request)),
            LightningBackendErrorV1::RequestConflict
        );
    }

    #[test]
    fn exact_creation_replay_is_stable_and_changed_request_conflicts() {
        let node = node();
        let request = request(&node);
        let first = node.create_or_get_invoice(&request).unwrap();
        node.set_time(first.created_at + 30).unwrap();
        let second = node.create_or_get_invoice(&request).unwrap();
        assert!(first == second);
        let mut changed = request.clone();
        changed.amount_msat += 1;
        assert_eq!(
            expect_backend_error(node.create_or_get_invoice(&changed)),
            LightningBackendErrorV1::RequestConflict
        );
    }

    #[test]
    fn lost_create_response_recovers_exact_invoice_without_duplicate() {
        let node = node();
        let request = request(&node);
        node.fail_once(FakeFailurePointV1::CreateAfterCommitOnce)
            .unwrap();
        assert_eq!(
            expect_backend_error(node.create_or_get_invoice(&request)),
            LightningBackendErrorV1::OutcomeUnknown
        );
        let recovered = node.create_or_get_invoice(&request).unwrap();
        assert!(recovered == node.create_or_get_invoice(&request).unwrap());
    }

    #[test]
    fn precommit_outage_does_not_create_an_invoice() {
        let node = node();
        let request = request(&node);
        node.fail_once(FakeFailurePointV1::CreateBeforeCommitOnce)
            .unwrap();
        assert_eq!(
            expect_backend_error(node.create_or_get_invoice(&request)),
            LightningBackendErrorV1::BackendUnavailable
        );
        assert_eq!(
            node.lookup_invoice(&request.backend_label, 1_700_000_000)
                .unwrap_err(),
            LightningBackendErrorV1::InvoiceNotFound
        );
        node.create_or_get_invoice(&request).unwrap();
    }

    #[test]
    fn expiry_does_not_preclude_late_settlement_reconciliation() {
        let node = node();
        let request = request(&node);
        let created = node.create_or_get_invoice(&request).unwrap();
        assert_eq!(
            node.lookup_invoice(&request.backend_label, created.expires_at)
                .unwrap()
                .state,
            InvoiceObservationStateV1::Expired
        );
        node.observe_settlement(
            &request.backend_label,
            request.amount_msat,
            created.expires_at + 1,
        )
        .unwrap();
        assert!(matches!(
            node.lookup_invoice(&request.backend_label, created.expires_at + 2)
                .unwrap()
                .state,
            InvoiceObservationStateV1::Settled {
                amount_received_msat: 12_300,
                ..
            }
        ));
    }

    #[test]
    fn wrong_settlement_amount_is_reported_not_normalized() {
        for amount in [12_299, 12_301] {
            let node = node();
            let request = request(&node);
            let created = node.create_or_get_invoice(&request).unwrap();
            node.observe_settlement(&request.backend_label, amount, created.created_at + 10)
                .unwrap();
            assert!(matches!(
                node.lookup_invoice(&request.backend_label, created.created_at + 11)
                    .unwrap()
                    .state,
                InvoiceObservationStateV1::Settled {
                    amount_received_msat,
                    ..
                } if amount_received_msat == amount
            ));
        }
    }

    #[test]
    fn concurrent_exact_creation_has_one_result() {
        let node = Arc::new(node());
        let request = request(&node);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let node = Arc::clone(&node);
            let request = request.clone();
            handles.push(thread::spawn(move || {
                node.create_or_get_invoice(&request).unwrap()
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn lookup_failure_is_one_shot_and_does_not_change_state() {
        let node = node();
        let request = request(&node);
        let created = node.create_or_get_invoice(&request).unwrap();
        node.fail_once(FakeFailurePointV1::LookupOnce).unwrap();
        assert_eq!(
            node.lookup_invoice(&request.backend_label, created.created_at + 1)
                .unwrap_err(),
            LightningBackendErrorV1::BackendUnavailable
        );
        assert_eq!(
            node.lookup_invoice(&request.backend_label, created.created_at + 1)
                .unwrap()
                .state,
            InvoiceObservationStateV1::Open
        );
    }

    #[test]
    fn invalid_network_payee_label_amount_and_fake_time_fail_closed() {
        let node = node();
        let base = request(&node);
        let mut cases = Vec::new();
        let mut invalid = base.clone();
        invalid.backend_label = "quote-1".to_owned();
        cases.push(invalid);
        let mut invalid = base.clone();
        invalid.amount_msat = 0;
        cases.push(invalid);
        let mut invalid = base.clone();
        invalid.network = LightningNetworkV1::Bitcoin;
        cases.push(invalid);
        let other =
            FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [4; 32], [8; 32], 1_700_000_000)
                .unwrap();
        let mut invalid = base;
        invalid.expected_payee_pubkey = other.payee_pubkey();
        cases.push(invalid);
        for invalid in cases {
            assert_eq!(
                expect_backend_error(node.create_or_get_invoice(&invalid)),
                LightningBackendErrorV1::InvalidRequest
            );
        }
        assert_eq!(
            FakeLightningNodeV1::new(LightningNetworkV1::Regtest, [4; 32], [8; 32], 0).unwrap_err(),
            LightningBackendErrorV1::InvalidRequest
        );
    }

    #[test]
    fn debug_output_redacts_all_fake_secret_material() {
        let node = node();
        let rendered = format!("{node:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains(&format!("{:?}", [3u8; 32])));
        assert!(!rendered.contains(&format!("{:?}", [7u8; 32])));
    }
}
