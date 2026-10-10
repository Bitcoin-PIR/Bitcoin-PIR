//! `bpir-admin channel-test` — end-to-end smoke test of the encrypted
//! channel against a running unified_server.
//!
//! 1. REQ_ATTEST: recover `server_static_pub` and check the SEV-SNP
//!    REPORT_DATA binding (V2 layout). With `--expect-ark-fingerprint`,
//!    also verify ARK→ASK→VCEK and the report signature.
//! 2. REQ_HANDSHAKE via `pir_sdk_client::channel::establish`, which
//!    derives the session key.
//! 3. REQ_PING and REQ_GET_INFO through the encrypted channel.
//!
//! This checks the protocol. That cloudflared only ever sees ciphertext
//! after the handshake would take a packet capture to show.

use clap::Args;
use pir_sdk_client::attest::{attest, SevStatus};
use pir_sdk_client::channel::establish;
// `roundtrip` is a trait method on PirTransport — bring it into scope
// so we can call it on the SecureChannelTransport returned by `establish`.
use pir_sdk_client::PirTransport;
use pir_sdk_client::WsConnection;

#[derive(Args, Debug)]
pub struct ChannelTestArgs {
    /// Server WebSocket URL (e.g. `wss://bitcoin-pir-weikeng-laptop.chenweikeng.com`).
    pub server_url: String,
    /// Operator-pinned 64-hex-char SHA-256 fingerprint of the AMD ARK
    /// (Root Key) certificate. When set, also verify ARK→ASK→VCEK and
    /// the report signature.
    #[arg(long = "expect-ark-fingerprint", value_name = "HEX64")]
    pub expect_ark_fingerprint: Option<String>,
}

pub async fn run(args: ChannelTestArgs) -> Result<(), String> {
    let url = &args.server_url;
    println!("Server URL:     {}", url);
    let ark_pin = args
        .expect_ark_fingerprint
        .as_deref()
        .map(|value| crate::attest::parse_hex_array::<32>(value, "--expect-ark-fingerprint"))
        .transpose()?;

    let mut conn = WsConnection::connect(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    // ── Step 1: attest + extract server_static_pub ──────────────────
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).expect("OS RNG must work");
    let v = attest(&mut conn, nonce)
        .await
        .map_err(|e| format!("attest: {e}"))?;
    println!("attest:         {:?}", v.sev_status);
    if v.sev_status != SevStatus::ReportDataMatch && v.sev_status != SevStatus::NoSevHost {
        return Err(format!("attest binding broken: {:?}", v.sev_status));
    }
    let server_static_pub = v.response.server_static_pub;
    println!("server channel pubkey: {}", hex::encode(server_static_pub));
    match ark_pin {
        Some(pin) => {
            crate::attest::verify_vcek_chain(&v.response, pin)?;
            println!(
                "vcek chain:     ✓ verified (ARK→ASK→VCEK + report sig validate; ARK fingerprint matches pin)"
            );
        }
        None => println!("vcek chain:     not checked (no --expect-ark-fingerprint)"),
    }

    // ── Step 2: handshake ───────────────────────────────────────────
    let mut eph_seed = [0u8; 32];
    getrandom::getrandom(&mut eph_seed).expect("OS RNG must work");
    let mut hs_nonce = [0u8; 32];
    getrandom::getrandom(&mut hs_nonce).expect("OS RNG must work");
    let mut secure = establish(conn, server_static_pub, eph_seed, hs_nonce)
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    println!("handshake:      ok (channel established)");

    // ── Step 3: encrypted requests ──────────────────────────────────
    // Wire: [4B len=1][opcode]. REQ_PING = 0x00 → RESP_PONG = 0x00.
    let pong = secure
        .roundtrip(&[1, 0, 0, 0, 0x00])
        .await
        .map_err(|e| format!("ping (encrypted): {e}"))?;
    if pong.first() != Some(&0x00) {
        return Err(format!(
            "expected RESP_PONG (0x00) inside encrypted reply, got {:02x?}",
            pong.first()
        ));
    }
    println!("ping/pong:      ok (encrypted roundtrip)");

    // REQ_GET_INFO = 0x01 → RESP_INFO = 0x01.
    let info = secure
        .roundtrip(&[1, 0, 0, 0, 0x01])
        .await
        .map_err(|e| format!("get_info (encrypted): {e}"))?;
    if info.first() != Some(&0x01) {
        return Err(format!(
            "expected RESP_INFO (0x01) inside encrypted reply, got {:02x?}",
            info.first()
        ));
    }
    println!(
        "get_info:       ok (encrypted, payload {} bytes after variant)",
        info.len() - 1
    );
    Ok(())
}
