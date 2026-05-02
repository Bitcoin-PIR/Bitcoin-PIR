//! Client-side attestation: send REQ_ATTEST, decode RESP_ATTEST, and
//! recompute the REPORT_DATA preimage to verify the server's response.
//!
//! ## What this module does
//!
//! - Frames a 32-byte client nonce as a REQ_ATTEST message and sends it
//!   over any [`PirTransport`].
//! - Decodes the response into a typed [`AttestResponse`] (the wire
//!   format mirrors `pir_runtime_core::protocol::AttestResult`).
//! - Recomputes `sha256("BPIR-ATTEST-V1" || nonce || combined_root ||
//!   binary_sha256 || git_rev)` and checks that the SEV-SNP report's
//!   REPORT_DATA field (if present) carries that value.
//!
//! ## What this module does NOT do
//!
//! - **AMD VCEK chain verification.** The cert chain (ARK → ASK → VCEK
//!   → report) needs the AMD KDS endpoint and a TLS-validated PEM chain;
//!   the `bpir-admin attest` CLI tool (Slice 4) is the right place for
//!   that since it can shell out to `snpguest verify` or use the `sev`
//!   crate. This module returns the raw SEV bytes; callers are
//!   responsible for cert-chain validation.
//! - **Cross-checking binary_sha256 / git_rev / manifest_roots against
//!   operator-published expected values.** That comparison is operator-
//!   policy, not a wire-protocol concern.

use crate::protocol::encode_request;
use crate::transport::PirTransport;
use pir_core::attest::{build_report_data, extract_report_data};
use pir_core::merkle::Hash256;
use pir_sdk::{PirError, PirResult};

/// REQ_ATTEST opcode (mirrors `pir_runtime_core::protocol::REQ_ATTEST`).
pub(crate) const REQ_ATTEST: u8 = 0x05;
/// RESP_ATTEST opcode.
pub(crate) const RESP_ATTEST: u8 = 0x05;
/// Generic server-side error envelope.
const RESP_ERROR: u8 = 0xff;

/// Decoded body of a `RESP_ATTEST` message.
#[derive(Clone, Debug)]
pub struct AttestResponse {
    /// Raw signed SEV-SNP attestation report bytes (~1184 for v5).
    /// Empty if the server isn't running on a SEV-SNP guest.
    pub sev_snp_report: Vec<u8>,
    /// Per-DB manifest roots in db_id order. The all-zero hash means
    /// that DB has no `MANIFEST.toml` (legacy / un-verified state).
    pub manifest_roots: Vec<Hash256>,
    /// SHA-256 of the running binary (cached at server startup).
    pub binary_sha256: Hash256,
    /// Git commit baked into the running binary. May be suffixed with
    /// `-dirty` if the working tree had local changes at build time, or
    /// be the literal `"unknown"` for non-git builds.
    pub git_rev: String,
}

/// Outcome of an attest call: server response + locally-recomputed
/// expected REPORT_DATA + status of the SEV-SNP report binding check.
#[derive(Clone, Debug)]
pub struct AttestVerification {
    /// The 32-byte nonce the caller supplied — echoed for convenience
    /// so callers can correlate concurrent attest calls.
    pub nonce: [u8; 32],
    /// Decoded server response.
    pub response: AttestResponse,
    /// REPORT_DATA preimage hash the client recomputed locally. For
    /// the binding to be valid, the SEV report's REPORT_DATA[0..32]
    /// must equal this value.
    pub expected_report_data_hash: Hash256,
    /// Status of the REPORT_DATA binding check.
    pub sev_status: SevStatus,
}

/// SEV-SNP report binding status. `ReportDataMatch` is the only state
/// where the operator's claims (binary_sha256, manifest_roots, git_rev)
/// have *any* hardware backing — anything else is unsigned data the
/// server self-reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SevStatus {
    /// Server isn't on a SEV-SNP host (e.g. Hetzner i7-8700, dev laptop).
    /// `binary_sha256` / `manifest_roots` / `git_rev` are self-reported,
    /// not hardware-backed.
    NoSevHost,
    /// SEV-SNP report present, its REPORT_DATA matches our recomputation.
    /// Caller still needs to validate the AMD VCEK chain to anchor the
    /// signature in real silicon.
    ReportDataMatch,
    /// SEV-SNP report present but REPORT_DATA doesn't match. Either the
    /// server is lying about its manifest_roots / binary / git_rev, or
    /// there's a wire format bug. **Do not trust the self-reported
    /// fields in this case.**
    ReportDataMismatch,
    /// SEV-SNP report bytes present but too short to contain REPORT_DATA.
    /// Almost certainly a wire bug or a malformed report.
    MalformedReport,
}

/// Send REQ_ATTEST and verify the REPORT_DATA binding.
///
/// `transport` can be a [`crate::WsConnection`], a
/// [`crate::WasmWebSocketTransport`], or any test mock — the trait
/// abstracts over native and wasm32 sockets. The trait method
/// `roundtrip` already strips the outer 4-byte length prefix.
pub async fn attest<T: PirTransport + ?Sized>(
    transport: &mut T,
    nonce: [u8; 32],
) -> PirResult<AttestVerification> {
    let request = encode_request(REQ_ATTEST, &nonce);
    let response = transport.roundtrip(&request).await?;

    if response.is_empty() {
        return Err(PirError::Protocol("empty attest response".into()));
    }
    match response[0] {
        RESP_ATTEST => { /* fall through */ }
        RESP_ERROR => {
            let msg = String::from_utf8_lossy(&response[1..]).to_string();
            return Err(PirError::ServerError(msg));
        }
        v => {
            return Err(PirError::Protocol(format!(
                "unexpected response variant 0x{:02x} for attest",
                v
            )));
        }
    }

    let parsed = decode_attest_response(&response[1..])?;
    let expected = build_report_data(
        nonce,
        &parsed.manifest_roots,
        parsed.binary_sha256,
        &parsed.git_rev,
    );
    let mut expected_low = [0u8; 32];
    expected_low.copy_from_slice(&expected[..32]);

    let sev_status = if parsed.sev_snp_report.is_empty() {
        SevStatus::NoSevHost
    } else {
        match extract_report_data(&parsed.sev_snp_report) {
            None => SevStatus::MalformedReport,
            Some(actual) if actual == expected.as_slice() => SevStatus::ReportDataMatch,
            Some(_) => SevStatus::ReportDataMismatch,
        }
    };

    Ok(AttestVerification {
        nonce,
        response: parsed,
        expected_report_data_hash: expected_low,
        sev_status,
    })
}

/// Mirror of `pir_runtime_core::protocol::decode_attest_result`. Kept
/// here so pir-sdk-client doesn't need to depend on pir-runtime-core
/// (which pulls in libdpf, memmap2, and other server-side deps).
fn decode_attest_response(data: &[u8]) -> PirResult<AttestResponse> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(PirError::Protocol(
            "attest response missing sev_report length".into(),
        ));
    }
    let sev_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + sev_len > data.len() {
        return Err(PirError::Protocol("truncated sev_snp_report".into()));
    }
    let sev_snp_report = data[pos..pos + sev_len].to_vec();
    pos += sev_len;

    if pos >= data.len() {
        return Err(PirError::Protocol(
            "attest response missing manifest count".into(),
        ));
    }
    let n_roots = data[pos] as usize;
    pos += 1;
    if pos + n_roots * 32 > data.len() {
        return Err(PirError::Protocol("truncated manifest roots".into()));
    }
    let mut manifest_roots = Vec::with_capacity(n_roots);
    for _ in 0..n_roots {
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[pos..pos + 32]);
        manifest_roots.push(root);
        pos += 32;
    }

    if pos + 32 > data.len() {
        return Err(PirError::Protocol("truncated binary_sha256".into()));
    }
    let mut binary_sha256 = [0u8; 32];
    binary_sha256.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    if pos + 2 > data.len() {
        return Err(PirError::Protocol("truncated git_rev length".into()));
    }
    let git_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if pos + git_len > data.len() {
        return Err(PirError::Protocol("truncated git_rev bytes".into()));
    }
    let git_rev = String::from_utf8_lossy(&data[pos..pos + git_len]).to_string();

    Ok(AttestResponse {
        sev_snp_report,
        manifest_roots,
        binary_sha256,
        git_rev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pir_core::attest::SEV_SNP_REPORT_DATA_OFFSET;
    use std::sync::Mutex;

    /// Test transport that returns a canned reply and records the request.
    struct MockTransport {
        reply: Vec<u8>,
        last_request: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl PirTransport for MockTransport {
        async fn send(&mut self, _data: Vec<u8>) -> PirResult<()> {
            Ok(())
        }
        async fn recv(&mut self) -> PirResult<Vec<u8>> {
            Ok(self.reply.clone())
        }
        async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
            *self.last_request.lock().unwrap() = request.to_vec();
            // Strip the outer length prefix (server's reply doesn't include it
            // by the time we reach the trait method — see the doc on
            // PirTransport::roundtrip).
            Ok(self.reply.clone())
        }
        async fn close(&mut self) -> PirResult<()> {
            Ok(())
        }
        fn url(&self) -> &str {
            "mock://test"
        }
    }

    /// Build the wire bytes of a RESP_ATTEST message body (after the
    /// 4-byte outer length prefix would be stripped by transport.roundtrip).
    fn build_response_payload(r: &AttestResponse) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&(r.sev_snp_report.len() as u32).to_le_bytes());
        payload.extend_from_slice(&r.sev_snp_report);
        payload.push(r.manifest_roots.len() as u8);
        for root in &r.manifest_roots {
            payload.extend_from_slice(root);
        }
        payload.extend_from_slice(&r.binary_sha256);
        let g = r.git_rev.as_bytes();
        payload.extend_from_slice(&(g.len() as u16).to_le_bytes());
        payload.extend_from_slice(g);
        payload
    }

    #[tokio::test]
    async fn no_sev_host_returns_no_sev_status() {
        let nonce = [0x42u8; 32];
        let resp = AttestResponse {
            sev_snp_report: Vec::new(), // empty → NoSevHost
            manifest_roots: vec![[0xAAu8; 32]],
            binary_sha256: [0xBBu8; 32],
            git_rev: "abc".into(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::NoSevHost);
        assert_eq!(v.nonce, nonce);
        assert_eq!(v.response.git_rev, "abc");
        // Sanity-check the request is REQ_ATTEST + 32-byte nonce
        let req = mock.last_request.lock().unwrap().clone();
        assert_eq!(req.len(), 4 + 1 + 32);
        assert_eq!(req[4], REQ_ATTEST);
        assert_eq!(&req[5..37], &nonce);
    }

    #[tokio::test]
    async fn matching_sev_report_returns_match() {
        let nonce = [0x10u8; 32];
        let manifest_roots = vec![[0xAAu8; 32], [0xBBu8; 32]];
        let binary_sha256 = [0xCCu8; 32];
        let git_rev = "deadbeef".to_string();

        // Construct a SEV report blob whose REPORT_DATA field at offset 0x50
        // contains the expected preimage hash.
        let expected = build_report_data(nonce, &manifest_roots, binary_sha256, &git_rev);
        let mut sev_blob = vec![0xFFu8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&expected);

        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256,
            git_rev,
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMatch);
    }

    #[tokio::test]
    async fn lying_server_returns_mismatch() {
        let nonce = [0x10u8; 32];

        // Report claims binary_sha256 = [0xCCu8; 32] but the embedded
        // REPORT_DATA was computed with a different binary hash — server
        // is lying.
        let claimed_binary = [0xCCu8; 32];
        let actual_binary = [0xDDu8; 32];
        let manifest_roots = vec![[0xAAu8; 32]];
        let git_rev = "v1".to_string();
        let dishonest_preimage =
            build_report_data(nonce, &manifest_roots, actual_binary, &git_rev);

        let mut sev_blob = vec![0u8; 1184];
        sev_blob[SEV_SNP_REPORT_DATA_OFFSET..SEV_SNP_REPORT_DATA_OFFSET + 64]
            .copy_from_slice(&dishonest_preimage);

        let resp = AttestResponse {
            sev_snp_report: sev_blob,
            manifest_roots,
            binary_sha256: claimed_binary, // ≠ actual_binary used in REPORT_DATA
            git_rev,
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::ReportDataMismatch);
    }

    #[tokio::test]
    async fn truncated_sev_report_returns_malformed() {
        let nonce = [0x10u8; 32];
        let resp = AttestResponse {
            sev_snp_report: vec![0u8; 50], // < 0x50 + 64
            manifest_roots: vec![],
            binary_sha256: [0u8; 32],
            git_rev: "x".into(),
        };
        let mut mock = MockTransport {
            reply: build_response_payload(&resp),
            last_request: Mutex::new(Vec::new()),
        };
        let v = attest(&mut mock, nonce).await.unwrap();
        assert_eq!(v.sev_status, SevStatus::MalformedReport);
    }

    #[tokio::test]
    async fn server_error_envelope_propagates_as_pirerror_server() {
        // Server replied with RESP_ERROR (0xff) + msg
        let mut reply = vec![RESP_ERROR];
        reply.extend_from_slice(b"attest unsupported");
        let mut mock = MockTransport {
            reply,
            last_request: Mutex::new(Vec::new()),
        };
        let err = attest(&mut mock, [0u8; 32]).await.unwrap_err();
        match err {
            PirError::ServerError(msg) => assert!(msg.contains("attest unsupported")),
            _ => panic!("expected PirError::ServerError, got {:?}", err),
        }
    }

    #[tokio::test]
    async fn unknown_response_variant_is_decode_error() {
        let mock_reply = vec![0x99]; // not RESP_ATTEST or RESP_ERROR
        let mut mock = MockTransport {
            reply: mock_reply,
            last_request: Mutex::new(Vec::new()),
        };
        let err = attest(&mut mock, [0u8; 32]).await.unwrap_err();
        assert!(matches!(err, PirError::Protocol(_)), "got {:?}", err);
    }
}
