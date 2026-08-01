//! `bpir-admin channel-test` — end-to-end smoke test of the encrypted
//! channel against a running unified_server.
//!
//! Sequence:
//!   1. Connect raw WSS to the server.
//!   2. REQ_ATTEST → recover `server_static_pub` + verify the SEV-SNP
//!      REPORT_DATA binding (V2 layout). Fail if the binding is broken
//!      or the server reports no channel pubkey.
//!   3. Wrap the connection with `pir_sdk_client::channel::establish`
//!      — this runs REQ_HANDSHAKE and derives the session key.
//!   4. Send a REQ_PING through the now-encrypted channel and confirm
//!      the response decrypts to RESP_PONG (0x00).
//!   5. Send a REQ_GET_INFO through the channel and confirm the
//!      response decrypts to a valid RESP_INFO frame.
//!
//! The test exits 0 on success, non-zero with a diagnostic on failure.
//!
//! ## What this proves (after Slice E deploys)
//!
//! - The handshake protocol works against the production server.
//! - The session key derivation agrees on both sides.
//! - Per-frame AEAD seal/open work bidirectionally.
//! - cloudflared between us and unified_server saw only ciphertext for
//!   frames 2+ — the only cleartext frames were the attest, the
//!   handshake itself, and the response to handshake. (Verifying
//!   cloudflared blindness from outside requires packet capture; this
//!   test verifies the protocol.)
//!
//! ## What this does NOT prove
//!
//! - Without `--expect-ark-fingerprint`, that the AMD VCEK chain validates
//!   the SEV-SNP report. With the flag, chain + report signature are checked.
//! - That the browser-side wiring works (Slice C.2).
//! - That cloudflared can't be exploited to MITM (out of scope —
//!   that's the AMD-attested chip's job).

use clap::Args;
use ed25519_dalek::VerifyingKey;
use pir_sdk_client::attest::{attest, SevStatus};
use pir_sdk_client::channel::establish;
use pir_sdk_client::service::{
    dangerous_unpaired_authorize_service_operation_v1,
    dangerous_unpaired_build_authorization_proof_v1, fetch_verified_service_policy_v1,
    ServicePolicyCheckpointV1,
};
// `roundtrip` is a trait method on PirTransport — bring it into scope
// so we can call it on the SecureChannelTransport returned by `establish`.
use pir_sdk_client::PirTransport;
use pir_sdk_client::WsConnection;
use pir_service_protocol::{AuthScheme, BackendId, FreeModeV1, OperationStartV1, WorkloadId};

#[derive(Args, Debug)]
pub struct ChannelTestArgs {
    /// Server WebSocket URL (e.g. `wss://weikeng2.bitcoinpir.org`).
    pub server_url: String,
    /// Operator-pinned 64-hex-char SHA-256 fingerprint of the AMD ARK
    /// (Root Key) certificate. When set + the server bundles a VCEK
    /// chain, runs full Slice D chain validation
    /// (ARK→ASK→VCEK + report-sig). Skip to test only V2 binding.
    #[arg(long = "expect-ark-fingerprint", value_name = "HEX64")]
    pub expect_ark_fingerprint: Option<String>,
    /// Fetch the signed service policy and present one Free DPF admission after
    /// the encrypted-channel smoke. This neither executes a PIR query nor
    /// consumes a paid capability.
    #[arg(
        long = "service-free-dpf-admission",
        requires_all = ["service_provider_id_hex", "service_policy_signing_key_hex"]
    )]
    pub service_free_dpf_admission: bool,
    /// Pinned 64-hex-char provider ID expected in the signed service policy.
    #[arg(
        long = "service-provider-id-hex",
        value_name = "HEX64",
        requires = "service_free_dpf_admission"
    )]
    pub service_provider_id_hex: Option<String>,
    /// Pinned 64-hex-char Ed25519 public key which signs the service policy.
    #[arg(
        long = "service-policy-signing-key-hex",
        value_name = "HEX64",
        requires = "service_free_dpf_admission"
    )]
    pub service_policy_signing_key_hex: Option<String>,
    /// Database ID bound into the harmless Free DPF admission operation.
    #[arg(
        long = "service-dpf-db-id",
        default_value_t = 0,
        requires = "service_free_dpf_admission"
    )]
    pub service_dpf_db_id: u8,
}

pub async fn run(args: ChannelTestArgs) -> Result<(), i32> {
    let url = &args.server_url;
    println!("Server URL:     {}", url);

    // ── Step 1: connect raw ─────────────────────────────────────────
    let mut conn = match WsConnection::connect(url).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("connect: {}", e);
            return Err(1);
        }
    };

    // ── Step 2: attest + extract server_static_pub ──────────────────
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS RNG must work");
    let v = match attest(&mut conn, nonce).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("attest: {}", e);
            return Err(2);
        }
    };
    println!("attest:         {:?}", v.sev_status);
    if v.sev_status != SevStatus::ReportDataMatch && v.sev_status != SevStatus::NoSevHost {
        eprintln!("attest binding broken: {:?}", v.sev_status);
        return Err(3);
    }
    let server_static_pub = v.response.server_static_pub;
    if server_static_pub == [0u8; 32] {
        eprintln!(
            "server has no X25519 channel key (server_static_pub is all-zero) — \
             upgrade unified_server to enable the encrypted channel"
        );
        return Err(4);
    }
    println!("server channel pubkey: {}", hex::encode(server_static_pub));

    // ── Optional Slice D chain validation ──────────────────────────
    let chain_present = !v.response.ark_pem.is_empty()
        && !v.response.ask_pem.is_empty()
        && !v.response.vcek_pem.is_empty();
    match (&args.expect_ark_fingerprint, chain_present) {
        (None, false) => {
            println!("vcek chain:     <none> (skipped, no --expect-ark-fingerprint)");
        }
        (None, true) => {
            println!(
                "vcek chain:     bundled but UNVERIFIED (pass --expect-ark-fingerprint to validate)"
            );
        }
        (Some(_), false) => {
            eprintln!(
                "--expect-ark-fingerprint set but server didn't bundle a chain — \
                 deploy `--vcek-dir` on the server first"
            );
            return Err(10);
        }
        (Some(hex_str), true) => {
            let pin: [u8; 32] = match hex::decode(hex_str.trim()) {
                Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                _ => {
                    eprintln!("--expect-ark-fingerprint must be 64 hex chars (32 bytes)");
                    return Err(11);
                }
            };
            match pir_attest_verify::verify_chain(
                &v.response.ark_pem,
                &v.response.ask_pem,
                &v.response.vcek_pem,
                Some(pin),
            ) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("chain validation failed: {}", e);
                    return Err(12);
                }
            }
            match pir_attest_verify::verify_report_against_vcek(
                &v.response.sev_snp_report,
                &v.response.vcek_pem,
            ) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("report-sig validation failed: {}", e);
                    return Err(13);
                }
            }
            println!(
                "vcek chain:     ✓ verified (ARK→ASK→VCEK + report sig validate; ARK fingerprint matches pin)"
            );
        }
    }

    // ── Step 3: handshake ───────────────────────────────────────────
    let mut eph_seed = [0u8; 32];
    getrandom::getrandom(&mut eph_seed).expect("OS RNG must work");
    let mut hs_nonce = [0u8; 32];
    getrandom::getrandom(&mut hs_nonce).expect("OS RNG must work");

    let mut secure = match establish(conn, server_static_pub, eph_seed, hs_nonce).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("handshake: {}", e);
            return Err(5);
        }
    };
    println!("handshake:      ok (channel established)");

    // ── Step 4: encrypted REQ_PING → RESP_PONG ──────────────────────
    // REQ_PING = 0x00, no body.
    // Wire: [4B len=1][REQ_PING=0x00]
    let ping_req = {
        let mut r = Vec::with_capacity(5);
        r.extend_from_slice(&1u32.to_le_bytes());
        r.push(0x00);
        r
    };
    let pong = match secure.roundtrip(&ping_req).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ping (encrypted): {}", e);
            return Err(6);
        }
    };
    if pong.is_empty() || pong[0] != 0x00 {
        eprintln!(
            "expected RESP_PONG (0x00) inside encrypted reply, got {:02x?}",
            pong.first()
        );
        return Err(7);
    }
    println!("ping/pong:      ok (encrypted roundtrip)");

    // ── Step 5: encrypted REQ_GET_INFO → RESP_INFO ──────────────────
    // REQ_GET_INFO = 0x01, no body.
    let info_req = {
        let mut r = Vec::with_capacity(5);
        r.extend_from_slice(&1u32.to_le_bytes());
        r.push(0x01);
        r
    };
    let info_resp = match secure.roundtrip(&info_req).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("get_info (encrypted): {}", e);
            return Err(8);
        }
    };
    if info_resp.is_empty() || info_resp[0] != 0x01 {
        eprintln!(
            "expected RESP_INFO (0x01) inside encrypted reply, got {:02x?}",
            info_resp.first()
        );
        return Err(9);
    }
    println!(
        "get_info:       ok (encrypted, payload {} bytes after variant)",
        info_resp.len() - 1
    );

    if args.service_free_dpf_admission {
        let expected_provider_id = match decode_hex_32(
            args.service_provider_id_hex
                .as_deref()
                .expect("clap requires --service-provider-id-hex"),
            "--service-provider-id-hex",
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("service admission: {error}");
                return Err(14);
            }
        };
        let policy_signing_key = match decode_hex_32(
            args.service_policy_signing_key_hex
                .as_deref()
                .expect("clap requires --service-policy-signing-key-hex"),
            "--service-policy-signing-key-hex",
        )
        .and_then(|value| {
            VerifyingKey::from_bytes(&value)
                .map_err(|_| "--service-policy-signing-key-hex is not Ed25519".to_owned())
        }) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("service admission: {error}");
                return Err(15);
            }
        };
        let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(value) if value.as_secs() != 0 => value.as_secs(),
            _ => {
                eprintln!("service admission: trusted wall clock is unavailable");
                return Err(16);
            }
        };
        let accepted = match fetch_verified_service_policy_v1(
            &mut secure,
            expected_provider_id,
            &policy_signing_key,
            now_unix,
            &ServicePolicyCheckpointV1::initial(),
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                eprintln!("service policy: {error}");
                return Err(17);
            }
        };
        let dpf_scope = match accepted.policy().scopes.iter().find(|scope| {
            scope.scope.backend == BackendId::DpfPirV1
                && scope.scope.workload == WorkloadId::DpfEvaluateJobV1
        }) {
            Some(value) => value,
            None => {
                eprintln!("service admission: signed policy has no DPF query scope");
                return Err(18);
            }
        };
        let free_offer_id = match dpf_scope.offers.iter().find(|offer| {
            offer.authorization == AuthScheme::FreeV1
                && offer.free_mode == FreeModeV1::OpenBestEffort
        }) {
            Some(value) => value.offer_id,
            None => {
                eprintln!("service admission: DPF scope has no open-best-effort Free offer");
                return Err(19);
            }
        };
        let scope_id = dpf_scope.scope.scope_id();
        let operation = OperationStartV1::DpfQuery {
            db_id: args.service_dpf_db_id,
        };
        let proof = match dangerous_unpaired_build_authorization_proof_v1(
            &accepted,
            &scope_id,
            free_offer_id,
            &[],
        ) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("service admission: {error}");
                return Err(20);
            }
        };
        let grant = match dangerous_unpaired_authorize_service_operation_v1(
            &mut secure,
            &accepted,
            scope_id,
            free_offer_id,
            operation,
            proof,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                eprintln!("service admission: {error}");
                return Err(21);
            }
        };
        println!(
            "service policy: ok (epoch={}, DPF Free offer={})",
            accepted.policy().policy_epoch,
            free_offer_id,
        );
        println!(
            "service admission: granted (enforced_profile={}, expires_in_ms={})",
            grant.enforced_profile, grant.expires_in_ms
        );
    }

    println!();
    println!("✓ end-to-end encrypted channel works against {}", url);
    Ok(())
}

fn decode_hex_32(value: &str, flag: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(|_| format!("{flag} must be 64 lowercase hex chars"))?;
    if bytes.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{flag} must be 64 lowercase hex chars"));
    }
    bytes
        .try_into()
        .map_err(|_| format!("{flag} must be 64 lowercase hex chars"))
}

#[cfg(test)]
mod tests {
    use super::decode_hex_32;

    #[test]
    fn pinned_values_require_exact_lowercase_hex() {
        assert_eq!(
            decode_hex_32(&"0a".repeat(32), "--value").unwrap(),
            [0x0a; 32]
        );
        assert!(decode_hex_32(&"0A".repeat(32), "--value").is_err());
        assert!(decode_hex_32("00", "--value").is_err());
    }
}
