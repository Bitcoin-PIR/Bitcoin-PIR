//! `bpir-admin pir2-sealed-receipt-fetch` — copy a serving sealed pir2
//! guest's Ready evidence out over its public WebSocket endpoint: the Ready
//! preflight receipt, the Ready runtime receipt, and the preflight
//! inert-success marker of the guest's current boot.
//!
//! This replaces the Flow F data-disk window that used to be the only way
//! to retrieve Ready receipts (Ready N → window → Ready N+1, a full ORAM
//! rebuild). The requests are cleartext and read-only; the guest answers
//! `RESP_PIR2_SEALED_RECEIPT` with the persisted bytes verbatim, or
//! `RESP_ERROR` when it is not a sealed Ready build (older images: use the
//! Flow F window).
//!
//! Nothing fetched here is trusted by this command. It only checks that the
//! three replies name one boot ID (and the expected one, when given) and
//! writes them under `--out-dir` with the run script's file names, refusing
//! to overwrite, so `pir2-sealed-receipt-verify` can accept each receipt
//! offline against the operator-signed release.

use std::path::PathBuf;

use clap::Args;
use pir_runtime_core::protocol::{
    Request, Response, PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT,
    PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER, PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
};
use pir_sdk_client::WsConnection;
use sha2::{Digest, Sha256};

#[derive(Args, Debug)]
pub struct Pir2SealedReceiptFetchArgs {
    /// WebSocket URL of the serving pir2 guest, e.g.
    /// `wss://weikeng2.bitcoinpir.org`.
    pub server: String,

    /// Existing directory that receives `ready-preflight-BOOT.bin`,
    /// `ready-runtime-BOOT.bin`, and `ready-preflight-BOOT.env`. None of
    /// the three may exist yet.
    #[arg(long)]
    pub out_dir: PathBuf,

    /// Boot ID (32 lowercase hex) every reply must carry. Without it the
    /// three replies only have to agree with each other; the accepted value
    /// is printed as `boot_id_hex=` for the receipt verifier.
    #[arg(long)]
    pub expected_boot_id_hex: Option<String>,
}

/// Fetch order and the names the run script gives the same files on the
/// guest's data disk (`receipts/` and `markers/`).
const KINDS: [u8; 3] = [
    PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT,
    PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
    PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER,
];

pub async fn run(args: Pir2SealedReceiptFetchArgs) -> Result<(), String> {
    let expected_boot_id = args
        .expected_boot_id_hex
        .as_deref()
        .map(parse_boot_id_hex)
        .transpose()?;
    if !args.out_dir.is_dir() {
        return Err(format!(
            "--out-dir is not an existing directory: {}",
            args.out_dir.display()
        ));
    }

    let mut conn = WsConnection::connect(&args.server)
        .await
        .map_err(|error| format!("connect to {}: {error}", args.server))?;
    let mut boot_id = expected_boot_id;
    let mut fetched: Vec<(u8, Vec<u8>)> = Vec::with_capacity(KINDS.len());
    for kind in KINDS {
        let request = Request::Pir2SealedReceiptGet { kind }.encode();
        let reply = conn
            .roundtrip(&request)
            .await
            .map_err(|error| format!("{}: request failed: {error}", kind_label(kind)))?;
        let (reply_boot_id, bytes) = decode_reply(kind, &reply)?;
        match boot_id {
            Some(expected) if expected != reply_boot_id => {
                return Err(format!(
                    "{} names boot {} but {} was expected",
                    kind_label(kind),
                    hex::encode(reply_boot_id),
                    hex::encode(expected)
                ));
            }
            Some(_) => {}
            None => boot_id = Some(reply_boot_id),
        }
        fetched.push((kind, bytes));
    }
    let _ = conn.close().await;
    let boot_id_hex = hex::encode(boot_id.expect("three replies set the boot id"));

    // Evidence directories are append-only: refuse every target before
    // writing any of them so a rerun into a used directory changes nothing.
    let targets: Vec<PathBuf> = fetched
        .iter()
        .map(|(kind, _)| args.out_dir.join(artifact_file_name(*kind, &boot_id_hex)))
        .collect();
    for target in &targets {
        if target.symlink_metadata().is_ok() {
            return Err(format!("refusing to overwrite {}", target.display()));
        }
    }
    for ((kind, bytes), target) in fetched.iter().zip(&targets) {
        pir_private_files::write_atomic_noreplace_private_file_v1(
            target,
            bytes,
            false,
            kind_label(*kind),
        )?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        println!(
            "{}={} sha256={} bytes={}",
            kind_key(*kind),
            target.display(),
            hex::encode(digest),
            bytes.len()
        );
    }
    println!(
        "PASS pir2_sealed_receipt_fetch boot_id_hex={boot_id_hex} out_dir={}",
        args.out_dir.display()
    );
    println!(
        "NEXT_STEP=accept ready-preflight-{boot_id_hex}.bin and ready-runtime-{boot_id_hex}.bin \
         offline with scripts/pir2-sealed-ceremony.sh receipt --expected-phase ready \
         --expected-boot-id-hex {boot_id_hex} (the marker is context only; nothing fetched \
         here is verified yet)"
    );
    Ok(())
}

/// Decode one reply for `kind`: the artifact bytes and the boot ID the
/// guest says they belong to. A `RESP_ERROR` is reported with the server's
/// message; anything else is malformed.
fn decode_reply(kind: u8, reply: &[u8]) -> Result<([u8; 16], Vec<u8>), String> {
    let label = kind_label(kind);
    match Response::decode(reply).map_err(|error| format!("{label}: malformed reply: {error}"))? {
        Response::Pir2SealedReceipt {
            kind: reply_kind,
            boot_id,
            bytes,
        } => {
            if reply_kind != kind {
                return Err(format!(
                    "{label}: reply carries kind {reply_kind} instead of {kind}"
                ));
            }
            if bytes.is_empty() {
                return Err(format!("{label}: reply carries no bytes"));
            }
            Ok((boot_id, bytes))
        }
        Response::Error(message) => Err(format!(
            "{label}: server refused: {message} (a guest without this opcode needs the Flow F \
             data-disk window instead)"
        )),
        _ => Err(format!("{label}: unexpected reply variant")),
    }
}

/// Exact lowercase hex, 16 bytes, not all zero — the sealed CLI's contract.
fn parse_boot_id_hex(value: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(value)
        .map_err(|_| "--expected-boot-id-hex must be exact lowercase hex".to_owned())?;
    if hex::encode(&bytes) != value {
        return Err("--expected-boot-id-hex must use canonical lowercase hex".to_owned());
    }
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| "--expected-boot-id-hex must be 32 hex characters".to_owned())?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("--expected-boot-id-hex must not be all zero".to_owned());
    }
    Ok(bytes)
}

fn artifact_file_name(kind: u8, boot_id_hex: &str) -> String {
    match kind {
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT => format!("ready-preflight-{boot_id_hex}.bin"),
        PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME => format!("ready-runtime-{boot_id_hex}.bin"),
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER => {
            format!("ready-preflight-{boot_id_hex}.env")
        }
        other => unreachable!("kind {other} is never requested"),
    }
}

fn kind_label(kind: u8) -> &'static str {
    match kind {
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT => "Ready preflight receipt",
        PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME => "Ready runtime receipt",
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER => "Ready preflight marker",
        _ => "pir2 sealed artifact",
    }
}

fn kind_key(kind: u8) -> &'static str {
    match kind {
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT => "ready_preflight_receipt",
        PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME => "ready_runtime_receipt",
        PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER => "ready_preflight_marker",
        _ => "pir2_sealed_artifact",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(kind: u8, boot_id: [u8; 16], bytes: &[u8]) -> Vec<u8> {
        // `WsConnection::roundtrip` hands back the record without its
        // 4-byte length prefix, which is what `Response::decode` expects.
        Response::Pir2SealedReceipt {
            kind,
            boot_id,
            bytes: bytes.to_vec(),
        }
        .encode()[4..]
            .to_vec()
    }

    #[test]
    fn decode_reply_accepts_the_requested_kind_and_returns_boot_and_bytes() {
        let boot_id = [0x5au8; 16];
        let (got_boot, got_bytes) = decode_reply(
            PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
            &reply(PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME, boot_id, b"receipt"),
        )
        .unwrap();
        assert_eq!(got_boot, boot_id);
        assert_eq!(got_bytes, b"receipt");
    }

    #[test]
    fn decode_reply_rejects_kind_mismatch_empty_bytes_errors_and_garbage() {
        let boot_id = [0x5au8; 16];
        let error = decode_reply(
            PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
            &reply(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT, boot_id, b"x"),
        )
        .unwrap_err();
        assert!(error.contains("carries kind 1 instead of 2"), "{error}");
        let error = decode_reply(
            PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
            &reply(PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME, boot_id, b""),
        )
        .unwrap_err();
        assert!(error.contains("no bytes"), "{error}");
        let refused =
            Response::Error("not a sealed Ready pir2 guest".into()).encode()[4..].to_vec();
        let error =
            decode_reply(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER, &refused).unwrap_err();
        assert!(
            error.contains("server refused: not a sealed Ready pir2 guest"),
            "{error}"
        );
        assert!(error.contains("Flow F"), "{error}");
        let pong = Response::Pong.encode()[4..].to_vec();
        let error = decode_reply(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT, &pong).unwrap_err();
        assert!(error.contains("unexpected reply variant"), "{error}");
        assert!(decode_reply(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT, &[0xee, 1]).is_err());
    }

    #[test]
    fn boot_id_parsing_matches_the_sealed_cli_contract() {
        let hex_value = "93f3a6dd0123456789abcdef00112233";
        assert_eq!(
            hex::encode(parse_boot_id_hex(hex_value).unwrap()),
            hex_value
        );
        for bad in [
            "93F3A6DD0123456789ABCDEF00112233",
            "93f3a6dd",
            &"00".repeat(16),
            "zz".repeat(16).as_str(),
        ] {
            assert!(parse_boot_id_hex(bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn artifact_file_names_follow_the_run_script_layout() {
        let boot = "93f3a6dd0123456789abcdef00112233";
        assert_eq!(
            artifact_file_name(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT, boot),
            format!("ready-preflight-{boot}.bin")
        );
        assert_eq!(
            artifact_file_name(PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME, boot),
            format!("ready-runtime-{boot}.bin")
        );
        assert_eq!(
            artifact_file_name(PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER, boot),
            format!("ready-preflight-{boot}.env")
        );
    }
}
