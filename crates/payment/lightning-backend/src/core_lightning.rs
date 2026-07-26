//! Core Lightning adapter over the local Unix JSON-RPC socket.
//!
//! The adapter opens a fresh socket for every request and uses CLN's unique
//! private `label` as the durable idempotency key. It always checks
//! `listinvoices` before attempting `invoice`, and treats a lost mutating RPC
//! response as outcome-unknown. It never returns or logs a payment preimage.

use core::fmt;
use std::str::FromStr;

use bitcoin::hashes::Hash as _;
use lightning_invoice::Bolt11Invoice;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    invoice_currency, is_canonical_backend_label, settlement_evidence_digest,
    CreateInvoiceRequestV1, CreatedInvoiceV1, InvoiceObservationStateV1, InvoiceObservationV1,
    LightningBackendErrorV1, LightningInvoiceBackendV1,
};

pub const ANONYMOUS_INVOICE_DESCRIPTION_V1: &str = "BitcoinPIR anonymous service capability v1";
const MAX_CLN_RPC_REQUEST_BYTES_V1: usize = 64 * 1024;
const MAX_CLN_RPC_RESPONSE_BYTES_V1: usize = 256 * 1024;

pub fn anonymous_invoice_description_hash_v1() -> [u8; 32] {
    Sha256::digest(ANONYMOUS_INVOICE_DESCRIPTION_V1.as_bytes()).into()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClnRpcTransportErrorV1 {
    /// No request bytes were successfully written to CLN.
    UnavailableBeforeWrite,
    /// Some or all request bytes were written, so a mutating call may have
    /// committed even though no authentic response was recovered.
    ResponseLostAfterWrite,
    InvalidResponse,
}

/// Secret-bearing raw RPC response. CLN's `listinvoices` may include a paid
/// invoice preimage even though this adapter does not deserialize that field.
/// The backing allocation is therefore zeroized when parsing completes.
pub struct ClnRpcResponseV1 {
    bytes: Zeroizing<Vec<u8>>,
}

impl ClnRpcResponseV1 {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ClnRpcTransportErrorV1> {
        if bytes.is_empty() || bytes.len() > MAX_CLN_RPC_RESPONSE_BYTES_V1 {
            return Err(ClnRpcTransportErrorV1::InvalidResponse);
        }
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl fmt::Debug for ClnRpcResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClnRpcResponseV1")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Narrow transport seam used by the production Unix socket and deterministic
/// tests. Request bytes contain no preimage, payer, query, result, or token.
pub trait ClnRpcTransportV1: Send + Sync + 'static {
    fn call(&self, request: &[u8]) -> Result<ClnRpcResponseV1, ClnRpcTransportErrorV1>;
}

/// Fixed-policy Core Lightning invoice backend. Its `Debug` output never
/// prints the socket path or transport state.
pub struct CoreLightningBackendV1<T> {
    transport: T,
}

impl<T> CoreLightningBackendV1<T> {
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T> fmt::Debug for CoreLightningBackendV1<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CoreLightningBackendV1")
            .field("transport", &"[redacted]")
            .finish()
    }
}

impl<T> LightningInvoiceBackendV1 for CoreLightningBackendV1<T>
where
    T: ClnRpcTransportV1,
{
    fn create_or_get_invoice(
        &self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        request.validate()?;
        if request.description_hash != anonymous_invoice_description_hash_v1() {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }

        if let Some(invoice) = self.list_invoice(&request.backend_label)? {
            return invoice.created_for_request(request);
        }

        let params = InvoiceParamsV1 {
            amount_msat: request.amount_msat,
            label: &request.backend_label,
            description: ANONYMOUS_INVOICE_DESCRIPTION_V1,
            expiry: request.expiry_seconds,
            exposeprivatechannels: false,
            deschashonly: true,
        };
        match self.rpc_call::<_, InvoiceResultV1>("invoice", &params, true) {
            Ok(result) => created_from_invoice_parts(
                result.bolt11,
                &result.payment_hash,
                Some(result.expires_at),
            )?
            .verify_for_request(request)
            .map(|verified| verified.created().clone()),
            Err(RpcCallErrorV1::Remote(900)) => self
                .list_invoice(&request.backend_label)?
                .ok_or(LightningBackendErrorV1::OutcomeUnknown)?
                .created_for_request(request),
            Err(RpcCallErrorV1::Backend(error)) => Err(error),
            Err(RpcCallErrorV1::Remote(_)) => Err(LightningBackendErrorV1::InvoiceCreationFailed),
        }
    }

    fn lookup_invoice(
        &self,
        backend_label: &str,
        observed_at: u64,
    ) -> Result<InvoiceObservationV1, LightningBackendErrorV1> {
        if !is_canonical_backend_label(backend_label) || observed_at == 0 {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let invoice = self
            .list_invoice(backend_label)?
            .ok_or(LightningBackendErrorV1::InvoiceNotFound)?;
        let created = invoice.parsed_created()?;
        let state = match invoice.status.as_str() {
            "paid" => {
                let settled_at = invoice
                    .paid_at
                    .filter(|value| *value >= created.created_at && *value <= observed_at)
                    .ok_or(LightningBackendErrorV1::BackendUnavailable)?;
                let amount_received_msat = invoice
                    .amount_received_msat
                    .as_ref()
                    .and_then(ClnMsatV1::value)
                    .filter(|value| *value != 0)
                    .ok_or(LightningBackendErrorV1::BackendUnavailable)?;
                InvoiceObservationStateV1::Settled {
                    settled_at,
                    amount_received_msat,
                    settlement_evidence_digest: settlement_evidence_digest(
                        backend_label,
                        &created.payment_hash,
                        amount_received_msat,
                        settled_at,
                    ),
                }
            }
            "expired" => InvoiceObservationStateV1::Expired,
            "unpaid" if observed_at >= created.expires_at => InvoiceObservationStateV1::Expired,
            "unpaid" => InvoiceObservationStateV1::Open,
            _ => return Err(LightningBackendErrorV1::BackendUnavailable),
        };
        Ok(InvoiceObservationV1 { state, observed_at })
    }

    fn existing_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<CreatedInvoiceV1>, LightningBackendErrorV1> {
        self.list_invoice(backend_label)?
            .map(|invoice| invoice.parsed_created())
            .transpose()
    }
}

impl<T> CoreLightningBackendV1<T>
where
    T: ClnRpcTransportV1,
{
    /// Fail closed unless the configured RPC endpoint is the exact CLN node
    /// and network pinned by the signed quote delegation.
    ///
    /// Operators should call this before exposing an HTTP listener.  Without
    /// the preflight, a socket-path mistake would still be detected when the
    /// returned BOLT11 is verified, but only after the wrong node had created
    /// an otherwise anonymous orphan invoice.
    pub fn verify_node_identity(
        &self,
        expected_payee_pubkey: &[u8; 33],
        expected_network: pir_service_protocol::LightningNetworkV1,
    ) -> Result<(), LightningBackendErrorV1> {
        bitcoin::secp256k1::PublicKey::from_slice(expected_payee_pubkey)
            .map_err(|_| LightningBackendErrorV1::InvalidRequest)?;
        let result = self
            .rpc_call::<_, GetInfoResultV1>("getinfo", &EmptyParamsV1 {}, false)
            .map_err(|_| LightningBackendErrorV1::BackendUnavailable)?;
        let actual = parse_lower_hex_33(&result.id)?;
        bitcoin::secp256k1::PublicKey::from_slice(&actual)
            .map_err(|_| LightningBackendErrorV1::BackendUnavailable)?;
        if &actual != expected_payee_pubkey || result.network != cln_network_name(expected_network)
        {
            return Err(LightningBackendErrorV1::RequestConflict);
        }
        Ok(())
    }

    fn list_invoice(
        &self,
        backend_label: &str,
    ) -> Result<Option<ListedInvoiceV1>, LightningBackendErrorV1> {
        if !is_canonical_backend_label(backend_label) {
            return Err(LightningBackendErrorV1::InvalidRequest);
        }
        let params = ListInvoicesParamsV1 {
            label: backend_label,
        };
        let result = match self.rpc_call::<_, ListInvoicesResultV1>("listinvoices", &params, false)
        {
            Ok(result) => result,
            Err(_) => return Err(LightningBackendErrorV1::BackendUnavailable),
        };
        match result.invoices.as_slice() {
            [] => Ok(None),
            [invoice] if invoice.label == backend_label => Ok(Some(invoice.clone())),
            _ => Err(LightningBackendErrorV1::RequestConflict),
        }
    }

    fn rpc_call<P, R>(
        &self,
        method: &'static str,
        params: &P,
        mutating: bool,
    ) -> Result<R, RpcCallErrorV1>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let request = RpcRequestV1 {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };
        let mut encoded = serde_json::to_vec(&request)
            .map_err(|_| RpcCallErrorV1::Backend(LightningBackendErrorV1::InvalidRequest))?;
        if encoded.len() > MAX_CLN_RPC_REQUEST_BYTES_V1 {
            return Err(RpcCallErrorV1::Backend(
                LightningBackendErrorV1::InvalidRequest,
            ));
        }
        encoded.extend_from_slice(b"\n\n");
        let response = self.transport.call(&encoded).map_err(|error| {
            let mapped = if mutating && error != ClnRpcTransportErrorV1::UnavailableBeforeWrite {
                LightningBackendErrorV1::OutcomeUnknown
            } else {
                LightningBackendErrorV1::BackendUnavailable
            };
            RpcCallErrorV1::Backend(mapped)
        })?;
        let post_write_error = || {
            RpcCallErrorV1::Backend(if mutating {
                LightningBackendErrorV1::OutcomeUnknown
            } else {
                LightningBackendErrorV1::BackendUnavailable
            })
        };
        let envelope: RpcResponseV1<R> =
            serde_json::from_slice(response.as_bytes()).map_err(|_| post_write_error())?;
        if envelope.jsonrpc != "2.0" || envelope.id != 1 {
            return Err(post_write_error());
        }
        match (envelope.result, envelope.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(RpcCallErrorV1::Remote(error.code)),
            _ => Err(post_write_error()),
        }
    }
}

#[derive(Debug)]
enum RpcCallErrorV1 {
    Backend(LightningBackendErrorV1),
    Remote(i64),
}

#[derive(Serialize)]
struct RpcRequestV1<'a, P> {
    jsonrpc: &'static str,
    id: u8,
    method: &'static str,
    params: &'a P,
}

#[derive(Deserialize)]
struct RpcResponseV1<R> {
    jsonrpc: String,
    id: Value,
    result: Option<R>,
    error: Option<RpcErrorV1>,
}

#[derive(Deserialize)]
struct RpcErrorV1 {
    code: i64,
}

#[derive(Serialize)]
struct ListInvoicesParamsV1<'a> {
    label: &'a str,
}

#[derive(Serialize)]
struct EmptyParamsV1 {}

#[derive(Deserialize)]
struct GetInfoResultV1 {
    id: String,
    network: String,
}

const fn cln_network_name(network: pir_service_protocol::LightningNetworkV1) -> &'static str {
    match network {
        pir_service_protocol::LightningNetworkV1::Bitcoin => "bitcoin",
        pir_service_protocol::LightningNetworkV1::Testnet => "testnet",
        pir_service_protocol::LightningNetworkV1::Signet => "signet",
        pir_service_protocol::LightningNetworkV1::Regtest => "regtest",
    }
}

#[derive(Deserialize)]
struct ListInvoicesResultV1 {
    invoices: Vec<ListedInvoiceV1>,
}

#[derive(Clone, Deserialize)]
struct ListedInvoiceV1 {
    label: String,
    payment_hash: String,
    status: String,
    expires_at: u64,
    bolt11: Option<String>,
    amount_msat: Option<ClnMsatV1>,
    amount_received_msat: Option<ClnMsatV1>,
    paid_at: Option<u64>,
}

impl ListedInvoiceV1 {
    fn parsed_created(&self) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        let bolt11 = self
            .bolt11
            .clone()
            .ok_or(LightningBackendErrorV1::RequestConflict)?;
        let created =
            created_from_invoice_parts(bolt11, &self.payment_hash, Some(self.expires_at))?;
        if self.amount_msat.as_ref().and_then(ClnMsatV1::value) != Some(created.amount_msat) {
            return Err(LightningBackendErrorV1::RequestConflict);
        }
        Ok(created)
    }

    fn created_for_request(
        self,
        request: &CreateInvoiceRequestV1,
    ) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
        if self.label != request.backend_label {
            return Err(LightningBackendErrorV1::RequestConflict);
        }
        let created = self.parsed_created()?;
        created
            .verify_for_request(request)
            .map(|verified| verified.created().clone())
    }
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum ClnMsatV1 {
    Integer(u64),
    Text(String),
}

impl ClnMsatV1 {
    fn value(&self) -> Option<u64> {
        match self {
            Self::Integer(value) => Some(*value),
            Self::Text(value) => value
                .strip_suffix("msat")
                .filter(|digits| {
                    !digits.is_empty()
                        && digits.bytes().all(|byte| byte.is_ascii_digit())
                        && (*digits == "0" || !digits.starts_with('0'))
                })
                .and_then(|digits| digits.parse().ok()),
        }
    }
}

#[derive(Serialize)]
struct InvoiceParamsV1<'a> {
    amount_msat: u64,
    label: &'a str,
    description: &'static str,
    expiry: u32,
    exposeprivatechannels: bool,
    deschashonly: bool,
}

#[derive(Deserialize)]
struct InvoiceResultV1 {
    bolt11: String,
    payment_hash: String,
    expires_at: u64,
}

fn created_from_invoice_parts(
    invoice: String,
    rpc_payment_hash: &str,
    rpc_expires_at: Option<u64>,
) -> Result<CreatedInvoiceV1, LightningBackendErrorV1> {
    let parsed = Bolt11Invoice::from_str(&invoice)
        .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?;
    if parsed.to_string() != invoice || parsed.check_signature().is_err() {
        return Err(LightningBackendErrorV1::InvoiceCreationFailed);
    }
    let network =
        invoice_currency(&parsed).ok_or(LightningBackendErrorV1::InvoiceCreationFailed)?;
    let amount_msat = parsed
        .amount_milli_satoshis()
        .filter(|amount| *amount != 0)
        .ok_or(LightningBackendErrorV1::InvoiceCreationFailed)?;
    let created_at = parsed.duration_since_epoch().as_secs();
    let expiry_seconds = u32::try_from(parsed.expiry_time().as_secs())
        .map_err(|_| LightningBackendErrorV1::InvoiceCreationFailed)?;
    let expires_at = created_at
        .checked_add(u64::from(expiry_seconds))
        .ok_or(LightningBackendErrorV1::InvoiceCreationFailed)?;
    let payment_hash = parse_lower_hex_32(rpc_payment_hash)?;
    if parsed.payment_hash().to_byte_array() != payment_hash
        || rpc_expires_at.is_some_and(|value| value != expires_at)
    {
        return Err(LightningBackendErrorV1::RequestConflict);
    }
    Ok(CreatedInvoiceV1 {
        invoice,
        payment_hash,
        network,
        payee_pubkey: parsed.get_payee_pub_key().serialize(),
        amount_msat,
        created_at,
        expires_at,
        expiry_seconds,
    })
}

fn parse_lower_hex_32(value: &str) -> Result<[u8; 32], LightningBackendErrorV1> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LightningBackendErrorV1::BackendUnavailable);
    }
    let mut decoded = [0; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let high = decode_hex_nibble(value.as_bytes()[index * 2]);
        let low = decode_hex_nibble(value.as_bytes()[index * 2 + 1]);
        *byte = (high << 4) | low;
    }
    Ok(decoded)
}

fn parse_lower_hex_33(value: &str) -> Result<[u8; 33], LightningBackendErrorV1> {
    if value.len() != 66
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LightningBackendErrorV1::BackendUnavailable);
    }
    let mut decoded = [0; 33];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let high = decode_hex_nibble(value.as_bytes()[index * 2]);
        let low = decode_hex_nibble(value.as_bytes()[index * 2 + 1]);
        *byte = (high << 4) | low;
    }
    Ok(decoded)
}

fn decode_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal"),
    }
}

#[cfg(unix)]
mod unix_transport {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use zeroize::Zeroize;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct UnixClnRpcSocketPolicyV1 {
        pub expected_uid: u32,
        /// `Some(gid)` permits access only for this exact group. `None`
        /// requires an owner-only socket.
        pub expected_gid: Option<u32>,
    }

    pub struct UnixClnRpcTransportV1 {
        socket_path: PathBuf,
        policy: UnixClnRpcSocketPolicyV1,
        timeout: Duration,
    }

    impl UnixClnRpcTransportV1 {
        pub fn new(
            socket_path: PathBuf,
            policy: UnixClnRpcSocketPolicyV1,
            timeout: Duration,
        ) -> Result<Self, ClnRpcTransportErrorV1> {
            if !socket_path.is_absolute() || timeout.is_zero() || timeout > Duration::from_secs(30)
            {
                return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite);
            }
            Ok(Self {
                socket_path,
                policy,
                timeout,
            })
        }

        fn checked_metadata(&self) -> Result<(u64, u64), ClnRpcTransportErrorV1> {
            checked_socket_metadata(&self.socket_path, self.policy)
        }
    }

    impl fmt::Debug for UnixClnRpcTransportV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("UnixClnRpcTransportV1")
                .field("socket_path", &"[redacted]")
                .field("policy", &self.policy)
                .field("timeout", &self.timeout)
                .finish()
        }
    }

    impl ClnRpcTransportV1 for UnixClnRpcTransportV1 {
        fn call(&self, request: &[u8]) -> Result<ClnRpcResponseV1, ClnRpcTransportErrorV1> {
            if request.is_empty()
                || request.len() > MAX_CLN_RPC_REQUEST_BYTES_V1 + 2
                || !request.ends_with(b"\n\n")
            {
                return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite);
            }
            let identity = self.checked_metadata()?;
            let mut stream = UnixStream::connect(&self.socket_path)
                .map_err(|_| ClnRpcTransportErrorV1::UnavailableBeforeWrite)?;
            if self.checked_metadata()? != identity {
                return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite);
            }
            stream
                .set_read_timeout(Some(self.timeout))
                .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
                .map_err(|_| ClnRpcTransportErrorV1::UnavailableBeforeWrite)?;
            stream
                .write_all(request)
                .map_err(|_| ClnRpcTransportErrorV1::ResponseLostAfterWrite)?;
            let mut response = Zeroizing::new(Vec::with_capacity(4_096));
            let mut chunk = Zeroizing::new([0u8; 4_096]);
            loop {
                let read = stream
                    .read(chunk.as_mut())
                    .map_err(|_| ClnRpcTransportErrorV1::ResponseLostAfterWrite)?;
                if read == 0 {
                    return Err(ClnRpcTransportErrorV1::ResponseLostAfterWrite);
                }
                response.extend_from_slice(&chunk[..read]);
                chunk[..read].zeroize();
                if response.len() > MAX_CLN_RPC_RESPONSE_BYTES_V1 + 2 {
                    return Err(ClnRpcTransportErrorV1::InvalidResponse);
                }
                if response.ends_with(b"\n\n") {
                    let message_len = response.len() - 2;
                    response.truncate(message_len);
                    return ClnRpcResponseV1::from_bytes(std::mem::take(&mut *response));
                }
            }
        }
    }

    fn checked_socket_metadata(
        path: &Path,
        policy: UnixClnRpcSocketPolicyV1,
    ) -> Result<(u64, u64), ClnRpcTransportErrorV1> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| ClnRpcTransportErrorV1::UnavailableBeforeWrite)?;
        if !metadata.file_type().is_socket() || metadata.uid() != policy.expected_uid {
            return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite);
        }
        let mode = metadata.mode();
        if mode & 0o600 != 0o600 {
            return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite);
        }
        match policy.expected_gid {
            Some(expected_gid) if metadata.gid() == expected_gid && mode & 0o007 == 0 => {}
            None if mode & 0o077 == 0 => {}
            _ => return Err(ClnRpcTransportErrorV1::UnavailableBeforeWrite),
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    pub use UnixClnRpcSocketPolicyV1 as ExportedUnixClnRpcSocketPolicyV1;
    pub use UnixClnRpcTransportV1 as ExportedUnixClnRpcTransportV1;
}

#[cfg(unix)]
pub use unix_transport::{
    ExportedUnixClnRpcSocketPolicyV1 as UnixClnRpcSocketPolicyV1,
    ExportedUnixClnRpcTransportV1 as UnixClnRpcTransportV1,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeLightningNodeV1;
    use pir_service_protocol::LightningNetworkV1;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    enum ScriptResultV1 {
        Response(Vec<u8>),
        Error(ClnRpcTransportErrorV1),
    }

    struct ScriptStepV1 {
        method: &'static str,
        result: ScriptResultV1,
    }

    struct ScriptedTransportV1 {
        steps: Mutex<VecDeque<ScriptStepV1>>,
        requests: Mutex<Vec<Value>>,
    }

    impl ScriptedTransportV1 {
        fn new(steps: Vec<ScriptStepV1>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<Value> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl ClnRpcTransportV1 for ScriptedTransportV1 {
        fn call(&self, request: &[u8]) -> Result<ClnRpcResponseV1, ClnRpcTransportErrorV1> {
            let request = request
                .strip_suffix(b"\n\n")
                .ok_or(ClnRpcTransportErrorV1::InvalidResponse)?;
            let parsed: Value = serde_json::from_slice(request)
                .map_err(|_| ClnRpcTransportErrorV1::InvalidResponse)?;
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(ClnRpcTransportErrorV1::InvalidResponse)?;
            if parsed.get("method") != Some(&Value::String(step.method.to_owned())) {
                return Err(ClnRpcTransportErrorV1::InvalidResponse);
            }
            self.requests.lock().unwrap().push(parsed);
            match step.result {
                ScriptResultV1::Response(response) => ClnRpcResponseV1::from_bytes(response),
                ScriptResultV1::Error(error) => Err(error),
            }
        }
    }

    struct Fixture {
        request: CreateInvoiceRequestV1,
        created: CreatedInvoiceV1,
    }

    fn fixture() -> Fixture {
        let fake = FakeLightningNodeV1::new(
            LightningNetworkV1::Regtest,
            [61; 32],
            [62; 32],
            1_700_000_000,
        )
        .unwrap();
        let request = CreateInvoiceRequestV1 {
            backend_label: format!("bpir-v1-{}", "cd".repeat(32)),
            network: LightningNetworkV1::Regtest,
            expected_payee_pubkey: fake.payee_pubkey(),
            amount_msat: 44_000,
            expiry_seconds: 600,
            description_hash: anonymous_invoice_description_hash_v1(),
        };
        let created = fake.create_or_get_invoice(&request).unwrap();
        Fixture { request, created }
    }

    fn response(result: Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        }))
        .unwrap()
    }

    fn remote_error(code: i64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": code, "message": "redacted fixture" },
        }))
        .unwrap()
    }

    fn list_empty_step() -> ScriptStepV1 {
        ScriptStepV1 {
            method: "listinvoices",
            result: ScriptResultV1::Response(response(serde_json::json!({ "invoices": [] }))),
        }
    }

    fn create_step(created: &CreatedInvoiceV1) -> ScriptStepV1 {
        ScriptStepV1 {
            method: "invoice",
            result: ScriptResultV1::Response(response(serde_json::json!({
                "bolt11": created.invoice,
                "payment_hash": lower_hex(&created.payment_hash),
                "expires_at": created.expires_at,
            }))),
        }
    }

    fn list_step(
        fixture: &Fixture,
        status: &str,
        received: Option<u64>,
        paid_at: Option<u64>,
    ) -> ScriptStepV1 {
        let mut invoice = serde_json::json!({
            "label": fixture.request.backend_label,
            "payment_hash": lower_hex(&fixture.created.payment_hash),
            "status": status,
            "expires_at": fixture.created.expires_at,
            "bolt11": fixture.created.invoice,
            "amount_msat": fixture.created.amount_msat,
        });
        if let Some(received) = received {
            invoice["amount_received_msat"] = Value::from(received);
            invoice["payment_preimage"] = Value::String("ef".repeat(32));
        }
        if let Some(paid_at) = paid_at {
            invoice["paid_at"] = Value::from(paid_at);
        }
        ScriptStepV1 {
            method: "listinvoices",
            result: ScriptResultV1::Response(response(serde_json::json!({
                "invoices": [invoice],
            }))),
        }
    }

    fn lower_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
    fn node_identity_preflight_accepts_only_the_pinned_cln_key() {
        let fixture = fixture();
        let expected_hex = lower_hex(&fixture.request.expected_payee_pubkey);
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![ScriptStepV1 {
            method: "getinfo",
            result: ScriptResultV1::Response(response(serde_json::json!({
                "id": expected_hex,
                "network": "regtest",
            }))),
        }]));
        backend
            .verify_node_identity(
                &fixture.request.expected_payee_pubkey,
                fixture.request.network,
            )
            .unwrap();

        let other = FakeLightningNodeV1::new(
            LightningNetworkV1::Regtest,
            [71; 32],
            [72; 32],
            1_700_000_000,
        )
        .unwrap();
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![ScriptStepV1 {
            method: "getinfo",
            result: ScriptResultV1::Response(response(serde_json::json!({
                "id": lower_hex(&other.payee_pubkey()),
                "network": "regtest",
            }))),
        }]));
        assert_eq!(
            backend
                .verify_node_identity(
                    &fixture.request.expected_payee_pubkey,
                    fixture.request.network,
                )
                .unwrap_err(),
            LightningBackendErrorV1::RequestConflict
        );

        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![ScriptStepV1 {
            method: "getinfo",
            result: ScriptResultV1::Response(response(serde_json::json!({
                "id": lower_hex(&fixture.request.expected_payee_pubkey),
                "network": "bitcoin",
            }))),
        }]));
        assert_eq!(
            backend
                .verify_node_identity(
                    &fixture.request.expected_payee_pubkey,
                    fixture.request.network,
                )
                .unwrap_err(),
            LightningBackendErrorV1::RequestConflict
        );
    }

    #[test]
    fn node_identity_preflight_rejects_noncanonical_or_invalid_keys() {
        let fixture = fixture();
        for id in [
            lower_hex(&fixture.request.expected_payee_pubkey).to_uppercase(),
            "00".repeat(33),
        ] {
            let backend =
                CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![ScriptStepV1 {
                    method: "getinfo",
                    result: ScriptResultV1::Response(response(serde_json::json!({
                        "id": id,
                        "network": "regtest",
                    }))),
                }]));
            assert_eq!(
                backend
                    .verify_node_identity(
                        &fixture.request.expected_payee_pubkey,
                        fixture.request.network,
                    )
                    .unwrap_err(),
                LightningBackendErrorV1::BackendUnavailable
            );
        }
    }

    #[test]
    fn creates_fixed_anonymous_invoice_after_empty_lookup() {
        let fixture = fixture();
        let transport =
            ScriptedTransportV1::new(vec![list_empty_step(), create_step(&fixture.created)]);
        let backend = CoreLightningBackendV1::new(transport);
        let created = backend.create_or_get_invoice(&fixture.request).unwrap();
        assert!(created == fixture.created);
        let requests = backend.transport.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1]["params"]["deschashonly"], Value::Bool(true));
        assert_eq!(
            requests[1]["params"]["exposeprivatechannels"],
            Value::Bool(false)
        );
        assert_eq!(
            requests[1]["params"]["description"],
            Value::String(ANONYMOUS_INVOICE_DESCRIPTION_V1.to_owned())
        );
    }

    #[test]
    fn existing_invoice_lookup_never_falls_through_to_creation() {
        let fixture = fixture();
        let backend =
            CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![list_empty_step()]));
        assert!(backend
            .existing_invoice(&fixture.request.backend_label)
            .unwrap()
            .is_none());
        let requests = backend.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["method"], Value::String("listinvoices".into()));
    }

    #[test]
    fn exact_existing_invoice_recovers_and_changed_request_conflicts() {
        let fixture = fixture();
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![list_step(
            &fixture, "unpaid", None, None,
        )]));
        assert!(backend.create_or_get_invoice(&fixture.request).unwrap() == fixture.created);

        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![list_step(
            &fixture, "unpaid", None, None,
        )]));
        let mut changed = fixture.request.clone();
        changed.amount_msat += 1;
        assert_eq!(
            expect_backend_error(backend.create_or_get_invoice(&changed)),
            LightningBackendErrorV1::RequestConflict
        );
    }

    #[test]
    fn lost_create_response_is_unknown_then_recovers_by_label() {
        let fixture = fixture();
        let transport = ScriptedTransportV1::new(vec![
            list_empty_step(),
            ScriptStepV1 {
                method: "invoice",
                result: ScriptResultV1::Error(ClnRpcTransportErrorV1::ResponseLostAfterWrite),
            },
            list_step(&fixture, "unpaid", None, None),
        ]);
        let backend = CoreLightningBackendV1::new(transport);
        assert_eq!(
            expect_backend_error(backend.create_or_get_invoice(&fixture.request)),
            LightningBackendErrorV1::OutcomeUnknown
        );
        assert!(backend.create_or_get_invoice(&fixture.request).unwrap() == fixture.created);
    }

    #[test]
    fn duplicate_label_race_rechecks_exact_invoice() {
        let fixture = fixture();
        let transport = ScriptedTransportV1::new(vec![
            list_empty_step(),
            ScriptStepV1 {
                method: "invoice",
                result: ScriptResultV1::Response(remote_error(900)),
            },
            list_step(&fixture, "unpaid", None, None),
        ]);
        let backend = CoreLightningBackendV1::new(transport);
        assert!(backend.create_or_get_invoice(&fixture.request).unwrap() == fixture.created);
    }

    #[test]
    fn unverifiable_post_write_response_is_outcome_unknown() {
        let fixture = fixture();
        let transport = ScriptedTransportV1::new(vec![
            list_empty_step(),
            ScriptStepV1 {
                method: "invoice",
                result: ScriptResultV1::Response(b"{}".to_vec()),
            },
        ]);
        let backend = CoreLightningBackendV1::new(transport);
        assert_eq!(
            expect_backend_error(backend.create_or_get_invoice(&fixture.request)),
            LightningBackendErrorV1::OutcomeUnknown
        );
    }

    #[test]
    fn lookup_reports_exact_received_amount_without_exposing_preimage() {
        let fixture = fixture();
        let paid_at = fixture.created.expires_at + 1;
        let received = fixture.request.amount_msat + 1;
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![list_step(
            &fixture,
            "paid",
            Some(received),
            Some(paid_at),
        )]));
        let observation = backend
            .lookup_invoice(&fixture.request.backend_label, paid_at + 1)
            .unwrap();
        assert_eq!(
            observation.state,
            InvoiceObservationStateV1::Settled {
                settled_at: paid_at,
                amount_received_msat: received,
                settlement_evidence_digest: settlement_evidence_digest(
                    &fixture.request.backend_label,
                    &fixture.created.payment_hash,
                    received,
                    paid_at,
                ),
            }
        );
        let debug = format!(
            "{:?}",
            ClnRpcResponseV1::from_bytes(b"secret response".to_vec()).unwrap()
        );
        assert!(debug.contains("redacted"));
        assert!(!debug.contains("secret response"));
    }

    #[test]
    fn wrong_description_hash_and_noncanonical_msat_fail_closed() {
        let fixture = fixture();
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(Vec::new()));
        let mut wrong = fixture.request.clone();
        wrong.description_hash[0] ^= 1;
        assert_eq!(
            expect_backend_error(backend.create_or_get_invoice(&wrong)),
            LightningBackendErrorV1::InvalidRequest
        );
        assert_eq!(ClnMsatV1::Text("44000msat".into()).value(), Some(44_000));
        assert_eq!(ClnMsatV1::Text("044000msat".into()).value(), None);
        assert_eq!(ClnMsatV1::Text("44sat".into()).value(), None);
    }

    #[test]
    fn lookup_rejects_future_paid_time_and_bolt11_side_field_mismatch() {
        let fixture = fixture();
        let future_paid_at = fixture.created.created_at + 100;
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![list_step(
            &fixture,
            "paid",
            Some(fixture.request.amount_msat),
            Some(future_paid_at),
        )]));
        assert_eq!(
            backend
                .lookup_invoice(&fixture.request.backend_label, future_paid_at - 1)
                .unwrap_err(),
            LightningBackendErrorV1::BackendUnavailable
        );

        let mut mismatched = list_step(&fixture, "unpaid", None, None);
        if let ScriptResultV1::Response(bytes) = &mut mismatched.result {
            let mut envelope: Value = serde_json::from_slice(bytes).unwrap();
            envelope["result"]["invoices"][0]["payment_hash"] = Value::String("00".repeat(32));
            *bytes = serde_json::to_vec(&envelope).unwrap();
        }
        let backend = CoreLightningBackendV1::new(ScriptedTransportV1::new(vec![mismatched]));
        assert_eq!(
            backend
                .lookup_invoice(
                    &fixture.request.backend_label,
                    fixture.created.created_at + 1
                )
                .unwrap_err(),
            LightningBackendErrorV1::RequestConflict
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_transport_checks_socket_and_double_newline_framing() {
        use std::fs;
        use std::io::{Read, Write};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::thread;
        use std::time::Duration;

        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "bitcoinpir-cln-rpc-test-{}-{id}.sock",
            std::process::id()
        ));
        assert!(!path.exists());
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::symlink_metadata(&path).unwrap().uid();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\n\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert_eq!(request, b"{\"ping\":1}\n\n");
            stream.write_all(b"{\"pong\":1}\n\n").unwrap();
        });
        let transport = UnixClnRpcTransportV1::new(
            path.clone(),
            UnixClnRpcSocketPolicyV1 {
                expected_uid: uid,
                expected_gid: None,
            },
            Duration::from_secs(1),
        )
        .unwrap();
        let response = transport.call(b"{\"ping\":1}\n\n").unwrap();
        assert_eq!(response.as_bytes(), b"{\"pong\":1}");
        server.join().unwrap();
        fs::remove_file(path).unwrap();
    }
}
