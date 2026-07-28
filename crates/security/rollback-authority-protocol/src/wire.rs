use core::fmt;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::codec::{domain_hash_v1, is_all_zero, put_u16, put_u64, Reader};
use crate::value::OpaqueAuthorityRecordV1;
use crate::RollbackAuthorityProtocolErrorV1;

pub const AUTHORITY_WIRE_VERSION_V1: u16 = 1;
pub const AUTHORITY_INSTANCE_ID_BYTES_V1: usize = 32;
pub const AUTHORITY_NAMESPACE_BYTES_V1: usize = 32;
pub const AUTHORITY_CLIENT_KEY_ID_BYTES_V1: usize = 32;
pub const AUTHORITY_CALL_NONCE_BYTES_V1: usize = 32;
pub const AUTHORITY_OPERATION_ID_BYTES_V1: usize = 32;
pub const AUTHORITY_OPERATION_DIGEST_BYTES_V1: usize = 32;
pub const AUTHORITY_REQUEST_DIGEST_BYTES_V1: usize = 32;

pub const SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1: usize = 299;
pub const SIGNED_AUTHORITY_INITIALIZE_REQUEST_BYTES_V1: usize = 852;
pub const SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1: usize = 1_404;
pub const MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1: usize = SIGNED_AUTHORITY_CAS_REQUEST_BYTES_V1;
pub const SIGNED_AUTHORITY_EMPTY_RESPONSE_BYTES_V1: usize = 300;
pub const SIGNED_AUTHORITY_RECORD_RESPONSE_BYTES_V1: usize = 852;
pub const MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1: usize = SIGNED_AUTHORITY_RECORD_RESPONSE_BYTES_V1;

const REQUEST_MAGIC_V1: &[u8; 8] = b"BPRARQ1\0";
const RESPONSE_MAGIC_V1: &[u8; 8] = b"BPRARS1\0";
const OPERATION_READ_V1: u8 = 1;
const OPERATION_COMPARE_AND_SWAP_V1: u8 = 2;
const REQUEST_SIGNATURE_BYTES: usize = 64;
const RESPONSE_SIGNATURE_BYTES: usize = 64;
const MIN_SIGNED_REQUEST_BYTES_V1: usize = SIGNED_AUTHORITY_READ_REQUEST_BYTES_V1;
const MIN_SIGNED_RESPONSE_BYTES_V1: usize = SIGNED_AUTHORITY_EMPTY_RESPONSE_BYTES_V1;

const CLIENT_KEY_ID_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/client-key-id/v1";
const OPERATION_DIGEST_DOMAIN_V1: &[u8] =
    b"BitcoinPIR/rollback-authority/stable-operation-digest/v1";
const REQUEST_DIGEST_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/exact-request-digest/v1";
const REQUEST_SIGNATURE_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/request-signature/v1";
const RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] = b"BitcoinPIR/rollback-authority/response-signature/v1";

/// Stable selector for a provisioned Ed25519 client public key.
pub fn authority_client_key_id_v1(client_verifying_key: &VerifyingKey) -> [u8; 32] {
    domain_hash_v1(CLIENT_KEY_ID_DOMAIN_V1, client_verifying_key.as_bytes())
}

/// Exact authority, namespace, and provisioned client-key binding.
///
/// The random namespace is linkable authority routing material and is
/// therefore redacted and zeroized even though it is not sufficient to
/// authorize a mutation without the client signature.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityBindingV1 {
    authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    namespace: [u8; AUTHORITY_NAMESPACE_BYTES_V1],
    client_key_id: [u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1],
}

impl fmt::Debug for AuthorityBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityBindingV1")
            .field("authority_instance_id", &"[REDACTED]")
            .field("namespace", &"[REDACTED]")
            .field("client_key_id", &"[REDACTED]")
            .finish()
    }
}

impl AuthorityBindingV1 {
    pub fn for_client_key(
        authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        namespace: [u8; AUTHORITY_NAMESPACE_BYTES_V1],
        client_verifying_key: &VerifyingKey,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        Self::from_wire_parts(
            authority_instance_id,
            namespace,
            authority_client_key_id_v1(client_verifying_key),
        )
    }

    pub fn authority_instance_id(&self) -> &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1] {
        &self.authority_instance_id
    }

    pub fn namespace(&self) -> &[u8; AUTHORITY_NAMESPACE_BYTES_V1] {
        &self.namespace
    }

    pub fn client_key_id(&self) -> &[u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1] {
        &self.client_key_id
    }

    /// Explicit copy for constructing separately zeroized protocol components.
    pub fn duplicate_for_protocol(&self) -> Self {
        Self {
            authority_instance_id: self.authority_instance_id,
            namespace: self.namespace,
            client_key_id: self.client_key_id,
        }
    }

    fn from_wire_parts(
        authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        namespace: [u8; AUTHORITY_NAMESPACE_BYTES_V1],
        client_key_id: [u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1],
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        if is_all_zero(&authority_instance_id)
            || is_all_zero(&namespace)
            || is_all_zero(&client_key_id)
        {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidIdentifier);
        }
        Ok(Self {
            authority_instance_id,
            namespace,
            client_key_id,
        })
    }
}

/// Per-attempt and per-operation replay binding.
///
/// Every network attempt, including a retry, must use a freshly generated
/// `call_nonce`. The `operation_id` remains stable across CAS retries. The
/// signed operation digest excludes only the call nonce, while the exact
/// request digest and response binding include it.
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityCallV1 {
    call_nonce: [u8; AUTHORITY_CALL_NONCE_BYTES_V1],
    operation_id: [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
}

impl fmt::Debug for AuthorityCallV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityCallV1")
            .field("call_nonce", &"[REDACTED]")
            .field("operation_id", &"[REDACTED]")
            .finish()
    }
}

impl AuthorityCallV1 {
    pub fn from_parts(
        call_nonce: [u8; AUTHORITY_CALL_NONCE_BYTES_V1],
        operation_id: [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        if is_all_zero(&call_nonce) {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidCallNonce);
        }
        if is_all_zero(&operation_id) {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOperationId);
        }
        Ok(Self {
            call_nonce,
            operation_id,
        })
    }

    pub fn generate() -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        let call_nonce = random_nonzero_32()?;
        let operation_id = random_nonzero_32()?;
        Self::from_parts(call_nonce, operation_id)
    }

    /// Generates a fresh network-attempt nonce for an existing durable CAS
    /// operation ID. Never reuse the previous request bytes or call nonce.
    pub fn for_operation(
        operation_id: [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        Self::from_parts(random_nonzero_32()?, operation_id)
    }

    pub fn call_nonce(&self) -> &[u8; AUTHORITY_CALL_NONCE_BYTES_V1] {
        &self.call_nonce
    }

    pub fn operation_id(&self) -> &[u8; AUTHORITY_OPERATION_ID_BYTES_V1] {
        &self.operation_id
    }
}

/// Client request signer bound to exactly one authority namespace.
pub struct AuthorityClientSignerV1 {
    binding: AuthorityBindingV1,
    signing_key: SigningKey,
}

impl fmt::Debug for AuthorityClientSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityClientSignerV1")
            .field("binding", &"[REDACTED]")
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl AuthorityClientSignerV1 {
    pub fn new(
        authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        namespace: [u8; AUTHORITY_NAMESPACE_BYTES_V1],
        signing_key: SigningKey,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        let binding = AuthorityBindingV1::for_client_key(
            authority_instance_id,
            namespace,
            &signing_key.verifying_key(),
        )?;
        Ok(Self {
            binding,
            signing_key,
        })
    }

    pub fn binding(&self) -> &AuthorityBindingV1 {
        &self.binding
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs a single-use online freshness check with an internally generated
    /// call nonce and operation ID.
    ///
    /// The returned typestate is consumed by read-response verification.
    /// Callers cannot supply or reuse an [`AuthorityCallV1`] for a Read. Never
    /// persist or replay a Read request/response pair as startup or recovery
    /// floor evidence.
    pub fn sign_fresh_read(
        &self,
    ) -> Result<SignedAuthorityReadAttemptV1, RollbackAuthorityProtocolErrorV1> {
        let call = AuthorityCallV1::generate()?;
        let request = self.sign_request(&call, OPERATION_READ_V1, |_| Ok(()))?;
        Ok(SignedAuthorityReadAttemptV1 { request })
    }

    /// Signs an initialize/CAS request. A present expected record requires the
    /// desired revision to be exactly one greater. The absent-record initial
    /// revision remains application-defined so both generation-zero and
    /// revision-one floor types can use this transport.
    pub fn sign_compare_and_swap(
        &self,
        call: &AuthorityCallV1,
        expected: Option<&OpaqueAuthorityRecordV1>,
        desired: &OpaqueAuthorityRecordV1,
    ) -> Result<SignedAuthorityRequestV1, RollbackAuthorityProtocolErrorV1> {
        validate_cas_revisions(expected, desired)?;
        self.sign_request(call, OPERATION_COMPARE_AND_SWAP_V1, |encoded| {
            match expected {
                None => encoded.push(0),
                Some(record) => {
                    encoded.push(1);
                    record.write_to(encoded);
                }
            }
            desired.write_to(encoded);
            Ok(())
        })
    }

    fn sign_request(
        &self,
        call: &AuthorityCallV1,
        operation: u8,
        encode_body: impl FnOnce(&mut Vec<u8>) -> Result<(), RollbackAuthorityProtocolErrorV1>,
    ) -> Result<SignedAuthorityRequestV1, RollbackAuthorityProtocolErrorV1> {
        let mut encoded = Vec::with_capacity(MIN_SIGNED_REQUEST_BYTES_V1);
        encode_request_header(&mut encoded, operation, &self.binding, call);
        let operation_body_offset = encoded.len();
        encode_body(&mut encoded)?;
        let operation_digest = operation_digest_v1(
            operation,
            &self.binding,
            call.operation_id(),
            &encoded[operation_body_offset..],
        );
        encoded.extend_from_slice(&operation_digest);
        let request_digest = domain_hash_v1(REQUEST_DIGEST_DOMAIN_V1, &encoded);
        encoded.extend_from_slice(&request_digest);
        append_signature(&mut encoded, REQUEST_SIGNATURE_DOMAIN_V1, &self.signing_key);
        Ok(SignedAuthorityRequestV1 { encoded })
    }
}

/// Exact client-signed CAS bytes for one network attempt.
///
/// A caller may retain them only to verify that attempt's response. After a
/// timeout it must generate a fresh call nonce and sign the same stable CAS
/// operation again; replaying this object is not a retry protocol.
pub struct SignedAuthorityRequestV1 {
    encoded: Vec<u8>,
}

impl fmt::Debug for SignedAuthorityRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityRequestV1")
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignedAuthorityRequestV1 {
    fn drop(&mut self) {
        self.encoded.zeroize();
    }
}

impl SignedAuthorityRequestV1 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Transfers the signed bytes without dropping their zeroize-on-drop
    /// wrapper. This consumes the local response-verification context.
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.encoded))
    }
}

/// One freshly generated, client-signed Read attempt.
///
/// This type is neither cloneable nor constructible from a caller-selected
/// [`AuthorityCallV1`]. Send [`Self::as_bytes`] once, then move the attempt into
/// [`verify_authority_read_response_v1`]. Moving it into [`Self::into_bytes`]
/// explicitly forfeits local response verification while retaining zeroizing
/// transport storage.
pub struct SignedAuthorityReadAttemptV1 {
    request: SignedAuthorityRequestV1,
}

impl fmt::Debug for SignedAuthorityReadAttemptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityReadAttemptV1")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

impl SignedAuthorityReadAttemptV1 {
    /// Borrows the exact request bytes for a single network send.
    pub fn as_bytes(&self) -> &[u8] {
        self.request.as_bytes()
    }

    /// Transfers the signed bytes without dropping their zeroize-on-drop
    /// wrapper. This consumes and forfeits the response-verification typestate.
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.request.into_bytes()
    }
}

/// Strictly parsed but unauthenticated routing selectors. Never authorize a
/// read or mutation from this value; it exists only to locate the provisioned
/// client public key before calling [`verify_authority_request_v1`].
#[derive(Eq, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct AuthorityRequestLocatorV1 {
    authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    namespace: [u8; AUTHORITY_NAMESPACE_BYTES_V1],
    client_key_id: [u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1],
}

impl fmt::Debug for AuthorityRequestLocatorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityRequestLocatorV1")
            .field("authority_instance_id", &"[UNTRUSTED_REDACTED]")
            .field("namespace", &"[UNTRUSTED_REDACTED]")
            .field("client_key_id", &"[UNTRUSTED_REDACTED]")
            .finish()
    }
}

impl AuthorityRequestLocatorV1 {
    pub fn authority_instance_id(&self) -> &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1] {
        &self.authority_instance_id
    }

    pub fn namespace(&self) -> &[u8; AUTHORITY_NAMESPACE_BYTES_V1] {
        &self.namespace
    }

    pub fn client_key_id(&self) -> &[u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1] {
        &self.client_key_id
    }
}

pub fn inspect_authority_request_locator_v1(
    encoded: &[u8],
) -> Result<AuthorityRequestLocatorV1, RollbackAuthorityProtocolErrorV1> {
    let parsed = parse_request(encoded)?;
    Ok(AuthorityRequestLocatorV1 {
        authority_instance_id: parsed.binding.authority_instance_id,
        namespace: parsed.binding.namespace,
        client_key_id: parsed.binding.client_key_id,
    })
}

/// Authenticates a strict request against one provisioned tuple. The returned
/// typestate is the only request type accepted by the authority response
/// signer.
pub fn verify_authority_request_v1(
    encoded: &[u8],
    expected_authority_instance_id: &[u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    expected_namespace: &[u8; AUTHORITY_NAMESPACE_BYTES_V1],
    client_verifying_key: &VerifyingKey,
) -> Result<VerifiedAuthorityRequestV1, RollbackAuthorityProtocolErrorV1> {
    let parsed = parse_request(encoded)?;
    let expected_client_key_id = authority_client_key_id_v1(client_verifying_key);
    if parsed.binding.authority_instance_id != *expected_authority_instance_id
        || parsed.binding.namespace != *expected_namespace
        || parsed.binding.client_key_id != expected_client_key_id
    {
        return Err(RollbackAuthorityProtocolErrorV1::BindingMismatch);
    }
    verify_signature(
        REQUEST_SIGNATURE_DOMAIN_V1,
        &encoded[..encoded.len() - REQUEST_SIGNATURE_BYTES],
        &parsed.signature,
        client_verifying_key,
    )?;
    Ok(VerifiedAuthorityRequestV1 {
        binding: parsed.binding,
        call: parsed.call,
        operation_digest: parsed.operation_digest,
        request_digest: parsed.request_digest,
        operation: parsed.operation,
    })
}

/// Verified request operation exposed by reference to avoid implicit copies of
/// linkable authority records.
#[derive(Clone, Copy)]
pub enum VerifiedAuthorityOperationRefV1<'a> {
    Read,
    CompareAndSwap {
        expected: Option<&'a OpaqueAuthorityRecordV1>,
        desired: &'a OpaqueAuthorityRecordV1,
    },
}

impl fmt::Debug for VerifiedAuthorityOperationRefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("Read"),
            Self::CompareAndSwap { expected, .. } => formatter
                .debug_struct("CompareAndSwap")
                .field("has_expected", &expected.is_some())
                .field("records", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Client-authenticated request ready for a linearizable authority backend.
pub struct VerifiedAuthorityRequestV1 {
    binding: AuthorityBindingV1,
    call: AuthorityCallV1,
    operation_digest: [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
    request_digest: [u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1],
    operation: ParsedAuthorityOperationV1,
}

impl fmt::Debug for VerifiedAuthorityRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthorityRequestV1")
            .field("binding", &"[REDACTED]")
            .field("call", &"[REDACTED]")
            .field("operation_digest", &"[REDACTED]")
            .field("request_digest", &"[REDACTED]")
            .field("operation", &self.operation())
            .finish()
    }
}

impl Drop for VerifiedAuthorityRequestV1 {
    fn drop(&mut self) {
        self.operation_digest.zeroize();
        self.request_digest.zeroize();
    }
}

impl VerifiedAuthorityRequestV1 {
    pub fn binding(&self) -> &AuthorityBindingV1 {
        &self.binding
    }

    pub fn call(&self) -> &AuthorityCallV1 {
        &self.call
    }

    pub fn operation_digest(&self) -> &[u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1] {
        &self.operation_digest
    }

    pub fn request_digest(&self) -> &[u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1] {
        &self.request_digest
    }

    pub fn operation(&self) -> VerifiedAuthorityOperationRefV1<'_> {
        match &self.operation {
            ParsedAuthorityOperationV1::Read => VerifiedAuthorityOperationRefV1::Read,
            ParsedAuthorityOperationV1::CompareAndSwap(cas) => {
                VerifiedAuthorityOperationRefV1::CompareAndSwap {
                    expected: cas.expected.as_ref(),
                    desired: &cas.desired,
                }
            }
        }
    }

    fn operation_code(&self) -> u8 {
        match &self.operation {
            ParsedAuthorityOperationV1::Read => OPERATION_READ_V1,
            ParsedAuthorityOperationV1::CompareAndSwap(_) => OPERATION_COMPARE_AND_SWAP_V1,
        }
    }
}

/// First terminal result atomically persisted for every CAS operation ID,
/// including operations which did not mutate the authority record.
#[derive(Clone, Copy)]
pub enum PersistedAuthorityTerminalOutcomeRefV1<'a> {
    Empty,
    Applied(&'a OpaqueAuthorityRecordV1),
    ConflictCurrent(&'a OpaqueAuthorityRecordV1),
}

impl fmt::Debug for PersistedAuthorityTerminalOutcomeRefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "Empty",
            Self::Applied(_) => "Applied([REDACTED])",
            Self::ConflictCurrent(_) => "ConflictCurrent([REDACTED])",
        })
    }
}

/// Whether the operation-log row was inserted by this exact linearization or
/// loaded for a retry with a fresh call nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityCasDispositionV1 {
    NewlyLinearized,
    ExactOperationReplay,
}

/// Exact operation-log row loaded by the authority backend.
///
/// Every CAS, including `Empty` and `ConflictCurrent`, must insert one terminal
/// row in the same linearizable durable transaction that observes/applies the
/// record. All references passed here must come from that one row. The unique
/// key is `(authority_instance_id, namespace, client_key_id, operation_id)`;
/// after a hit, the stored stable `operation_digest` must be compared. Making
/// the digest part of the unique key would incorrectly turn operation-ID reuse
/// with different content into a new mutation.
#[derive(Clone, Copy)]
pub struct PersistedAuthorityOperationRefV1<'a> {
    authority_instance_id: &'a [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    namespace: &'a [u8; AUTHORITY_NAMESPACE_BYTES_V1],
    client_key_id: &'a [u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1],
    operation_id: &'a [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
    operation_digest: &'a [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
    first_outcome: PersistedAuthorityTerminalOutcomeRefV1<'a>,
}

impl fmt::Debug for PersistedAuthorityOperationRefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedAuthorityOperationRefV1")
            .field("operation_log_row", &"[REDACTED]")
            .finish()
    }
}

impl<'a> PersistedAuthorityOperationRefV1<'a> {
    pub fn from_persisted_row(
        authority_instance_id: &'a [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        namespace: &'a [u8; AUTHORITY_NAMESPACE_BYTES_V1],
        client_key_id: &'a [u8; AUTHORITY_CLIENT_KEY_ID_BYTES_V1],
        operation_id: &'a [u8; AUTHORITY_OPERATION_ID_BYTES_V1],
        operation_digest: &'a [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
        first_outcome: PersistedAuthorityTerminalOutcomeRefV1<'a>,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        if is_all_zero(authority_instance_id)
            || is_all_zero(namespace)
            || is_all_zero(client_key_id)
        {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidIdentifier);
        }
        if is_all_zero(operation_id) {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOperationId);
        }
        Ok(Self {
            authority_instance_id,
            namespace,
            client_key_id,
            operation_id,
            operation_digest,
            first_outcome,
        })
    }
}

/// One CAS operation-log row and the namespace record observed when this exact
/// call nonce was first linearized. The backend must persist that per-call
/// snapshot atomically and supply it again for exact signed-request replay;
/// re-reading a later live record would make a replay an authority-state
/// oracle. A fresh-nonce retry gets its own linearization and snapshot. The
/// signer derives the only safe wire outcome; callers cannot independently
/// choose `Applied`/`AlreadyApplied`.
#[derive(Clone, Copy)]
pub struct AuthorityCasResolutionRefV1<'a> {
    persisted: PersistedAuthorityOperationRefV1<'a>,
    observed_current: Option<&'a OpaqueAuthorityRecordV1>,
    disposition: AuthorityCasDispositionV1,
}

impl fmt::Debug for AuthorityCasResolutionRefV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityCasResolutionRefV1")
            .field("resolution", &"[REDACTED]")
            .finish()
    }
}

impl<'a> AuthorityCasResolutionRefV1<'a> {
    pub fn from_linearized_transaction(
        persisted: PersistedAuthorityOperationRefV1<'a>,
        observed_current: Option<&'a OpaqueAuthorityRecordV1>,
        disposition: AuthorityCasDispositionV1,
    ) -> Self {
        Self {
            persisted,
            observed_current,
            disposition,
        }
    }
}

/// Authority response signer pinned to one instance identity.
pub struct AuthorityServerSignerV1 {
    authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
    signing_key: SigningKey,
}

impl fmt::Debug for AuthorityServerSignerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityServerSignerV1")
            .field("authority_instance_id", &"[REDACTED]")
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for AuthorityServerSignerV1 {
    fn drop(&mut self) {
        self.authority_instance_id.zeroize();
    }
}

impl AuthorityServerSignerV1 {
    pub fn new(
        authority_instance_id: [u8; AUTHORITY_INSTANCE_ID_BYTES_V1],
        signing_key: SigningKey,
    ) -> Result<Self, RollbackAuthorityProtocolErrorV1> {
        if is_all_zero(&authority_instance_id) {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidIdentifier);
        }
        Ok(Self {
            authority_instance_id,
            signing_key,
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign_read_response(
        &self,
        request: &VerifiedAuthorityRequestV1,
        current: Option<&OpaqueAuthorityRecordV1>,
    ) -> Result<SignedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
        self.ensure_request(request, OPERATION_READ_V1)?;
        self.sign_response(request, |encoded| {
            match current {
                None => encoded.push(0),
                Some(record) => {
                    encoded.push(1);
                    record.write_to(encoded);
                }
            }
            Ok(())
        })
    }

    pub fn sign_compare_and_swap_response(
        &self,
        request: &VerifiedAuthorityRequestV1,
        resolution: AuthorityCasResolutionRefV1<'_>,
    ) -> Result<SignedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
        self.ensure_request(request, OPERATION_COMPARE_AND_SWAP_V1)?;
        let outcome = derive_cas_outcome_ref(request, resolution)?;
        self.sign_response(request, |encoded| {
            match outcome {
                DerivedAuthorityCasOutcomeRefV1::Empty => encoded.push(0),
                DerivedAuthorityCasOutcomeRefV1::Applied(record) => {
                    encoded.push(1);
                    record.write_to(encoded);
                }
                DerivedAuthorityCasOutcomeRefV1::AlreadyApplied(record) => {
                    encoded.push(2);
                    record.write_to(encoded);
                }
                DerivedAuthorityCasOutcomeRefV1::ConflictCurrent(record) => {
                    encoded.push(3);
                    record.write_to(encoded);
                }
            }
            Ok(())
        })
    }

    fn ensure_request(
        &self,
        request: &VerifiedAuthorityRequestV1,
        expected_operation: u8,
    ) -> Result<(), RollbackAuthorityProtocolErrorV1> {
        if request.binding.authority_instance_id != self.authority_instance_id {
            return Err(RollbackAuthorityProtocolErrorV1::BindingMismatch);
        }
        if request.operation_code() != expected_operation {
            return Err(RollbackAuthorityProtocolErrorV1::UnexpectedResponse);
        }
        Ok(())
    }

    fn sign_response(
        &self,
        request: &VerifiedAuthorityRequestV1,
        encode_body: impl FnOnce(&mut Vec<u8>) -> Result<(), RollbackAuthorityProtocolErrorV1>,
    ) -> Result<SignedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
        let mut encoded = Vec::with_capacity(MIN_SIGNED_RESPONSE_BYTES_V1);
        encode_response_header(&mut encoded, request);
        encode_body(&mut encoded)?;
        append_signature(
            &mut encoded,
            RESPONSE_SIGNATURE_DOMAIN_V1,
            &self.signing_key,
        );
        Ok(SignedAuthorityResponseV1 { encoded })
    }
}

/// Exact authority-signed response bytes with redacted, zeroizing storage.
pub struct SignedAuthorityResponseV1 {
    encoded: Vec<u8>,
}

impl fmt::Debug for SignedAuthorityResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedAuthorityResponseV1")
            .field("encoded", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SignedAuthorityResponseV1 {
    fn drop(&mut self) {
        self.encoded.zeroize();
    }
}

impl SignedAuthorityResponseV1 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Transfers the signed bytes without dropping their zeroize-on-drop
    /// wrapper.
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(core::mem::take(&mut self.encoded))
    }
}

/// Owned, authority-signed CAS result.
pub enum VerifiedAuthorityCasOutcomeV1 {
    Empty,
    Applied(OpaqueAuthorityRecordV1),
    AlreadyApplied(OpaqueAuthorityRecordV1),
    ConflictCurrent(OpaqueAuthorityRecordV1),
}

impl fmt::Debug for VerifiedAuthorityCasOutcomeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "Empty",
            Self::Applied(_) => "Applied([REDACTED])",
            Self::AlreadyApplied(_) => "AlreadyApplied([REDACTED])",
            Self::ConflictCurrent(_) => "ConflictCurrent([REDACTED])",
        })
    }
}

/// Borrowed verified response body.
#[derive(Clone, Copy, Debug)]
pub enum VerifiedAuthorityResponseBodyRefV1<'a> {
    Read {
        current: Option<&'a OpaqueAuthorityRecordV1>,
    },
    CompareAndSwap(&'a VerifiedAuthorityCasOutcomeV1),
}

/// Authority-authenticated response already matched against one exact locally
/// signed request.
pub struct VerifiedAuthorityResponseV1 {
    binding: AuthorityBindingV1,
    call: AuthorityCallV1,
    operation_digest: [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
    request_digest: [u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1],
    body: ParsedAuthorityResponseBodyV1,
}

impl fmt::Debug for VerifiedAuthorityResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthorityResponseV1")
            .field("binding", &"[REDACTED]")
            .field("call", &"[REDACTED]")
            .field("operation_digest", &"[REDACTED]")
            .field("request_digest", &"[REDACTED]")
            .field("body", &self.body())
            .finish()
    }
}

impl Drop for VerifiedAuthorityResponseV1 {
    fn drop(&mut self) {
        self.operation_digest.zeroize();
        self.request_digest.zeroize();
    }
}

impl VerifiedAuthorityResponseV1 {
    pub fn binding(&self) -> &AuthorityBindingV1 {
        &self.binding
    }

    pub fn call(&self) -> &AuthorityCallV1 {
        &self.call
    }

    pub fn operation_digest(&self) -> &[u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1] {
        &self.operation_digest
    }

    pub fn request_digest(&self) -> &[u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1] {
        &self.request_digest
    }

    pub fn body(&self) -> VerifiedAuthorityResponseBodyRefV1<'_> {
        match &self.body {
            ParsedAuthorityResponseBodyV1::Read { current } => {
                VerifiedAuthorityResponseBodyRefV1::Read {
                    current: current.as_ref(),
                }
            }
            ParsedAuthorityResponseBodyV1::CompareAndSwap(outcome) => {
                VerifiedAuthorityResponseBodyRefV1::CompareAndSwap(outcome)
            }
        }
    }
}

/// Verifies a CAS response against every exact request binding. A valid
/// response for another nonce, operation, request body, namespace, client key,
/// or authority instance is rejected even when signed by the same server key.
/// CAS callers retain the stable operation ID and sign a new attempt for each
/// retry.
pub fn verify_authority_response_v1(
    encoded: &[u8],
    request: &SignedAuthorityRequestV1,
    authority_verifying_key: &VerifyingKey,
) -> Result<VerifiedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
    verify_response_against_request_v1(
        encoded,
        request.as_bytes(),
        OPERATION_COMPARE_AND_SWAP_V1,
        authority_verifying_key,
    )
}

/// Verifies one Read response and consumes its one-shot attempt typestate.
///
/// A consumed attempt cannot authenticate a second response, and a new Read
/// can only be created with fresh signer-generated call material.
pub fn verify_authority_read_response_v1(
    encoded: &[u8],
    attempt: SignedAuthorityReadAttemptV1,
    authority_verifying_key: &VerifyingKey,
) -> Result<VerifiedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
    verify_response_against_request_v1(
        encoded,
        attempt.as_bytes(),
        OPERATION_READ_V1,
        authority_verifying_key,
    )
}

fn verify_response_against_request_v1(
    encoded: &[u8],
    request: &[u8],
    expected_operation: u8,
    authority_verifying_key: &VerifyingKey,
) -> Result<VerifiedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
    let parsed_request = parse_request(request)?;
    if parsed_request.operation_code() != expected_operation {
        return Err(RollbackAuthorityProtocolErrorV1::UnexpectedResponse);
    }
    let parsed_response = parse_response(encoded)?;
    if parsed_response.operation != parsed_request.operation_code()
        || parsed_response.binding != parsed_request.binding
        || parsed_response.call != parsed_request.call
        || parsed_response.operation_digest != parsed_request.operation_digest
        || parsed_response.request_digest != parsed_request.request_digest
    {
        return Err(RollbackAuthorityProtocolErrorV1::UnexpectedResponse);
    }
    verify_signature(
        RESPONSE_SIGNATURE_DOMAIN_V1,
        &encoded[..encoded.len() - RESPONSE_SIGNATURE_BYTES],
        &parsed_response.signature,
        authority_verifying_key,
    )?;
    validate_parsed_response_body(&parsed_request.operation, &parsed_response.body)?;
    Ok(VerifiedAuthorityResponseV1 {
        binding: parsed_response.binding,
        call: parsed_response.call,
        operation_digest: parsed_response.operation_digest,
        request_digest: parsed_response.request_digest,
        body: parsed_response.body,
    })
}

enum ParsedAuthorityOperationV1 {
    Read,
    CompareAndSwap(Box<ParsedAuthorityCasV1>),
}

struct ParsedAuthorityCasV1 {
    expected: Option<OpaqueAuthorityRecordV1>,
    desired: OpaqueAuthorityRecordV1,
}

struct ParsedAuthorityRequestV1 {
    binding: AuthorityBindingV1,
    call: AuthorityCallV1,
    operation_digest: [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
    request_digest: [u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1],
    operation: ParsedAuthorityOperationV1,
    signature: [u8; REQUEST_SIGNATURE_BYTES],
}

impl ParsedAuthorityRequestV1 {
    fn operation_code(&self) -> u8 {
        match &self.operation {
            ParsedAuthorityOperationV1::Read => OPERATION_READ_V1,
            ParsedAuthorityOperationV1::CompareAndSwap(_) => OPERATION_COMPARE_AND_SWAP_V1,
        }
    }
}

enum ParsedAuthorityResponseBodyV1 {
    Read {
        current: Option<OpaqueAuthorityRecordV1>,
    },
    CompareAndSwap(VerifiedAuthorityCasOutcomeV1),
}

struct ParsedAuthorityResponseV1 {
    operation: u8,
    binding: AuthorityBindingV1,
    call: AuthorityCallV1,
    operation_digest: [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1],
    request_digest: [u8; AUTHORITY_REQUEST_DIGEST_BYTES_V1],
    body: ParsedAuthorityResponseBodyV1,
    signature: [u8; RESPONSE_SIGNATURE_BYTES],
}

fn parse_request(
    encoded: &[u8],
) -> Result<ParsedAuthorityRequestV1, RollbackAuthorityProtocolErrorV1> {
    if encoded.len() < MIN_SIGNED_REQUEST_BYTES_V1
        || encoded.len() > MAX_SIGNED_AUTHORITY_REQUEST_BYTES_V1
    {
        return Err(RollbackAuthorityProtocolErrorV1::InvalidLength);
    }
    let mut reader = Reader::new(encoded);
    if reader.fixed::<8>()? != *REQUEST_MAGIC_V1 {
        return Err(RollbackAuthorityProtocolErrorV1::InvalidMagic);
    }
    if reader.u16()? != AUTHORITY_WIRE_VERSION_V1 {
        return Err(RollbackAuthorityProtocolErrorV1::UnsupportedVersion);
    }
    let operation_code = reader.u8()?;
    let binding =
        AuthorityBindingV1::from_wire_parts(reader.fixed()?, reader.fixed()?, reader.fixed()?)?;
    let call = AuthorityCallV1::from_parts(reader.fixed()?, reader.fixed()?)?;
    let operation_body_offset = reader.offset();
    let operation = match operation_code {
        OPERATION_READ_V1 => ParsedAuthorityOperationV1::Read,
        OPERATION_COMPARE_AND_SWAP_V1 => {
            let expected = match reader.u8()? {
                0 => None,
                1 => Some(OpaqueAuthorityRecordV1::read_from(&mut reader)?),
                _ => return Err(RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding),
            };
            let desired = OpaqueAuthorityRecordV1::read_from(&mut reader)?;
            validate_cas_revisions(expected.as_ref(), &desired)?;
            ParsedAuthorityOperationV1::CompareAndSwap(Box::new(ParsedAuthorityCasV1 {
                expected,
                desired,
            }))
        }
        _ => return Err(RollbackAuthorityProtocolErrorV1::UnknownOperation),
    };
    let operation_body_end = reader.offset();
    let operation_digest = reader.fixed()?;
    if operation_digest
        != operation_digest_v1(
            operation_code,
            &binding,
            call.operation_id(),
            &encoded[operation_body_offset..operation_body_end],
        )
    {
        return Err(RollbackAuthorityProtocolErrorV1::OperationDigestMismatch);
    }
    let request_digest_offset = reader.offset();
    let request_digest = reader.fixed()?;
    let signature = reader.fixed()?;
    reader.finish()?;
    if request_digest != domain_hash_v1(REQUEST_DIGEST_DOMAIN_V1, &encoded[..request_digest_offset])
    {
        return Err(RollbackAuthorityProtocolErrorV1::RequestDigestMismatch);
    }
    Ok(ParsedAuthorityRequestV1 {
        binding,
        call,
        operation_digest,
        request_digest,
        operation,
        signature,
    })
}

fn parse_response(
    encoded: &[u8],
) -> Result<ParsedAuthorityResponseV1, RollbackAuthorityProtocolErrorV1> {
    if encoded.len() < MIN_SIGNED_RESPONSE_BYTES_V1
        || encoded.len() > MAX_SIGNED_AUTHORITY_RESPONSE_BYTES_V1
    {
        return Err(RollbackAuthorityProtocolErrorV1::InvalidLength);
    }
    let mut reader = Reader::new(encoded);
    if reader.fixed::<8>()? != *RESPONSE_MAGIC_V1 {
        return Err(RollbackAuthorityProtocolErrorV1::InvalidMagic);
    }
    if reader.u16()? != AUTHORITY_WIRE_VERSION_V1 {
        return Err(RollbackAuthorityProtocolErrorV1::UnsupportedVersion);
    }
    let operation = reader.u8()?;
    let binding =
        AuthorityBindingV1::from_wire_parts(reader.fixed()?, reader.fixed()?, reader.fixed()?)?;
    let call = AuthorityCallV1::from_parts(reader.fixed()?, reader.fixed()?)?;
    let operation_digest = reader.fixed()?;
    let request_digest = reader.fixed()?;
    let body = match operation {
        OPERATION_READ_V1 => {
            let current = match reader.u8()? {
                0 => None,
                1 => Some(OpaqueAuthorityRecordV1::read_from(&mut reader)?),
                _ => return Err(RollbackAuthorityProtocolErrorV1::NonCanonicalEncoding),
            };
            ParsedAuthorityResponseBodyV1::Read { current }
        }
        OPERATION_COMPARE_AND_SWAP_V1 => {
            let outcome = match reader.u8()? {
                0 => VerifiedAuthorityCasOutcomeV1::Empty,
                1 => VerifiedAuthorityCasOutcomeV1::Applied(OpaqueAuthorityRecordV1::read_from(
                    &mut reader,
                )?),
                2 => VerifiedAuthorityCasOutcomeV1::AlreadyApplied(
                    OpaqueAuthorityRecordV1::read_from(&mut reader)?,
                ),
                3 => VerifiedAuthorityCasOutcomeV1::ConflictCurrent(
                    OpaqueAuthorityRecordV1::read_from(&mut reader)?,
                ),
                _ => return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome),
            };
            ParsedAuthorityResponseBodyV1::CompareAndSwap(outcome)
        }
        _ => return Err(RollbackAuthorityProtocolErrorV1::UnknownOperation),
    };
    let signature = reader.fixed()?;
    reader.finish()?;
    Ok(ParsedAuthorityResponseV1 {
        operation,
        binding,
        call,
        operation_digest,
        request_digest,
        body,
        signature,
    })
}

fn encode_request_header(
    encoded: &mut Vec<u8>,
    operation: u8,
    binding: &AuthorityBindingV1,
    call: &AuthorityCallV1,
) {
    encoded.extend_from_slice(REQUEST_MAGIC_V1);
    put_u16(encoded, AUTHORITY_WIRE_VERSION_V1);
    encoded.push(operation);
    encoded.extend_from_slice(binding.authority_instance_id());
    encoded.extend_from_slice(binding.namespace());
    encoded.extend_from_slice(binding.client_key_id());
    encoded.extend_from_slice(call.call_nonce());
    encoded.extend_from_slice(call.operation_id());
}

fn operation_digest_v1(
    operation: u8,
    binding: &AuthorityBindingV1,
    operation_id: &[u8; AUTHORITY_OPERATION_ID_BYTES_V1],
    operation_body: &[u8],
) -> [u8; AUTHORITY_OPERATION_DIGEST_BYTES_V1] {
    let mut stable = Zeroizing::new(Vec::with_capacity(
        REQUEST_MAGIC_V1.len() + 2 + 1 + 4 * 32 + 8 + operation_body.len(),
    ));
    stable.extend_from_slice(REQUEST_MAGIC_V1);
    put_u16(&mut stable, AUTHORITY_WIRE_VERSION_V1);
    stable.push(operation);
    stable.extend_from_slice(binding.authority_instance_id());
    stable.extend_from_slice(binding.namespace());
    stable.extend_from_slice(binding.client_key_id());
    stable.extend_from_slice(operation_id);
    put_u64(&mut stable, operation_body.len() as u64);
    stable.extend_from_slice(operation_body);
    domain_hash_v1(OPERATION_DIGEST_DOMAIN_V1, &stable)
}

fn encode_response_header(encoded: &mut Vec<u8>, request: &VerifiedAuthorityRequestV1) {
    encoded.extend_from_slice(RESPONSE_MAGIC_V1);
    put_u16(encoded, AUTHORITY_WIRE_VERSION_V1);
    encoded.push(request.operation_code());
    encoded.extend_from_slice(request.binding.authority_instance_id());
    encoded.extend_from_slice(request.binding.namespace());
    encoded.extend_from_slice(request.binding.client_key_id());
    encoded.extend_from_slice(request.call.call_nonce());
    encoded.extend_from_slice(request.call.operation_id());
    encoded.extend_from_slice(&request.operation_digest);
    encoded.extend_from_slice(&request.request_digest);
}

fn append_signature(encoded: &mut Vec<u8>, domain: &[u8], signing_key: &SigningKey) {
    let signature_message = domain_hash_v1(domain, encoded);
    let signature: Signature = signing_key.sign(&signature_message);
    encoded.extend_from_slice(&signature.to_bytes());
}

fn verify_signature(
    domain: &[u8],
    signed_payload: &[u8],
    signature_bytes: &[u8; 64],
    verifying_key: &VerifyingKey,
) -> Result<(), RollbackAuthorityProtocolErrorV1> {
    let signature_message = domain_hash_v1(domain, signed_payload);
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(&signature_message, &signature)
        .map_err(|_| RollbackAuthorityProtocolErrorV1::BadSignature)
}

fn validate_cas_revisions(
    expected: Option<&OpaqueAuthorityRecordV1>,
    desired: &OpaqueAuthorityRecordV1,
) -> Result<(), RollbackAuthorityProtocolErrorV1> {
    if let Some(expected) = expected {
        let next_revision = expected
            .revision()
            .checked_add(1)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidOutcome)?;
        if desired.revision() != next_revision {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum DerivedAuthorityCasOutcomeRefV1<'a> {
    Empty,
    Applied(&'a OpaqueAuthorityRecordV1),
    AlreadyApplied(&'a OpaqueAuthorityRecordV1),
    ConflictCurrent(&'a OpaqueAuthorityRecordV1),
}

fn derive_cas_outcome_ref<'a>(
    request: &VerifiedAuthorityRequestV1,
    resolution: AuthorityCasResolutionRefV1<'a>,
) -> Result<DerivedAuthorityCasOutcomeRefV1<'a>, RollbackAuthorityProtocolErrorV1> {
    let ParsedAuthorityOperationV1::CompareAndSwap(cas) = &request.operation else {
        return Err(RollbackAuthorityProtocolErrorV1::UnexpectedResponse);
    };
    let persisted = resolution.persisted;
    if persisted.authority_instance_id != request.binding.authority_instance_id()
        || persisted.namespace != request.binding.namespace()
        || persisted.client_key_id != request.binding.client_key_id()
        || persisted.operation_id != request.call.operation_id()
        || persisted.operation_digest != request.operation_digest()
    {
        return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome);
    }

    match persisted.first_outcome {
        PersistedAuthorityTerminalOutcomeRefV1::Empty if cas.expected.is_none() => {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome);
        }
        PersistedAuthorityTerminalOutcomeRefV1::Applied(applied) if applied != &cas.desired => {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome);
        }
        PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(first_current) if matches!(cas.expected.as_ref(), Some(expected) if expected == first_current) =>
        {
            return Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome);
        }
        _ => {}
    }

    match (resolution.disposition, persisted.first_outcome) {
        (
            AuthorityCasDispositionV1::NewlyLinearized,
            PersistedAuthorityTerminalOutcomeRefV1::Empty,
        ) if resolution.observed_current.is_none() => Ok(DerivedAuthorityCasOutcomeRefV1::Empty),
        (
            AuthorityCasDispositionV1::NewlyLinearized,
            PersistedAuthorityTerminalOutcomeRefV1::Applied(applied),
        ) if resolution.observed_current == Some(applied) => {
            Ok(DerivedAuthorityCasOutcomeRefV1::Applied(applied))
        }
        (
            AuthorityCasDispositionV1::NewlyLinearized,
            PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(first_current),
        ) if resolution.observed_current == Some(first_current) => Ok(
            DerivedAuthorityCasOutcomeRefV1::ConflictCurrent(first_current),
        ),
        (
            AuthorityCasDispositionV1::ExactOperationReplay,
            PersistedAuthorityTerminalOutcomeRefV1::Empty,
        ) => match resolution.observed_current {
            None => Ok(DerivedAuthorityCasOutcomeRefV1::Empty),
            Some(live) => Ok(DerivedAuthorityCasOutcomeRefV1::ConflictCurrent(live)),
        },
        (
            AuthorityCasDispositionV1::ExactOperationReplay,
            PersistedAuthorityTerminalOutcomeRefV1::Applied(applied),
        ) => match resolution.observed_current {
            Some(live) if live == applied => {
                Ok(DerivedAuthorityCasOutcomeRefV1::AlreadyApplied(live))
            }
            Some(live) => Ok(DerivedAuthorityCasOutcomeRefV1::ConflictCurrent(live)),
            None => Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome),
        },
        (
            AuthorityCasDispositionV1::ExactOperationReplay,
            PersistedAuthorityTerminalOutcomeRefV1::ConflictCurrent(_),
        ) => resolution
            .observed_current
            .map(DerivedAuthorityCasOutcomeRefV1::ConflictCurrent)
            .ok_or(RollbackAuthorityProtocolErrorV1::InvalidOutcome),
        _ => Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome),
    }
}

fn validate_parsed_response_body(
    operation: &ParsedAuthorityOperationV1,
    body: &ParsedAuthorityResponseBodyV1,
) -> Result<(), RollbackAuthorityProtocolErrorV1> {
    match (operation, body) {
        (ParsedAuthorityOperationV1::Read, ParsedAuthorityResponseBodyV1::Read { .. }) => Ok(()),
        (
            ParsedAuthorityOperationV1::CompareAndSwap(cas),
            ParsedAuthorityResponseBodyV1::CompareAndSwap(outcome),
        ) => match outcome {
            VerifiedAuthorityCasOutcomeV1::Empty if cas.expected.is_some() => Ok(()),
            VerifiedAuthorityCasOutcomeV1::Applied(current)
            | VerifiedAuthorityCasOutcomeV1::AlreadyApplied(current)
                if current == &cas.desired =>
            {
                Ok(())
            }
            VerifiedAuthorityCasOutcomeV1::ConflictCurrent(_) => Ok(()),
            _ => Err(RollbackAuthorityProtocolErrorV1::InvalidOutcome),
        },
        _ => Err(RollbackAuthorityProtocolErrorV1::UnexpectedResponse),
    }
}

fn random_nonzero_32() -> Result<[u8; 32], RollbackAuthorityProtocolErrorV1> {
    let mut bytes = [0_u8; 32];
    loop {
        getrandom::getrandom(&mut bytes)
            .map_err(|_| RollbackAuthorityProtocolErrorV1::RandomnessUnavailable)?;
        if !is_all_zero(&bytes) {
            return Ok(bytes);
        }
    }
}
