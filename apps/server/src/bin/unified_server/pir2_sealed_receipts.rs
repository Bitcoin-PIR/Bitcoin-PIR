//! Read-only Ready evidence service for a sealed pir2 guest
//! (`REQ_PIR2_SEALED_RECEIPT_GET`; wire layout in `runtime::protocol`).
//!
//! A Ready boot persists two receipts for its own boot before the final
//! server listens — `ready-preflight-BOOT.bin` (Ready preflight, before any
//! ORAM access) and `ready-runtime-BOOT.bin` (the final server opening the
//! sealed keys) — plus the preflight inert-success marker
//! `ready-preflight-BOOT.env`. Unlike Observe, Enroll, and Probe, Ready has
//! no recovery HTTP window, so until this opcode those files could only be
//! copied out in a later Flow F data-disk window, which costs a full ORAM
//! rebuild (Ready N → window → Ready N+1).
//!
//! The three files are read once at startup, with bounded reads and names
//! derived from the flags `unified-server-run.sh` already passes, and served
//! verbatim in cleartext to any client. They are public audit evidence:
//! acceptance stays with `bpir-admin pir2-sealed-receipt-verify`, which
//! checks the AMD chain, the release binding, and the boot ID offline.
//! Nothing here reads a secret, and a load failure only disables this
//! opcode (`RESP_ERROR`); it never changes whether the server serves.

use std::path::{Path, PathBuf};

use runtime::protocol::*;

use crate::io::read_regular_file_bounded_v1;
use crate::unified_server_pir2_sealed::Pir2SealedCliV1;

/// One persisted receipt is exactly the canonical receipt file length.
const MAX_RECEIPT_BYTES: usize =
    pir_runtime_core::snp_sealed_secrets::MAX_SEALED_RECEIPT_FILE_LEN_V1;
/// The inert-success marker is five short `key=value` lines.
const MAX_MARKER_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct Pir2SealedReadyReceiptsV1 {
    boot_id: [u8; 16],
    ready_preflight_receipt: Vec<u8>,
    ready_runtime_receipt: Vec<u8>,
    ready_preflight_marker: Vec<u8>,
}

impl Pir2SealedReadyReceiptsV1 {
    /// Load this boot's Ready artifacts from the paths the sealed CLI names:
    /// `--pir2-snp-sealed-receipt` is the runtime receipt this process wrote
    /// during sealed startup, and the preflight receipt and marker are
    /// siblings of the runtime receipt and marker named by the boot ID,
    /// exactly as `unified-server-run.sh` lays them out.
    pub(crate) fn load(cli: &Pir2SealedCliV1) -> Result<Self, String> {
        let boot_id_hex = cli
            .current_boot_id_hex
            .as_deref()
            .ok_or("--pir2-snp-sealed-current-boot-id-hex is required")?;
        let boot_id = decode_boot_id_hex(boot_id_hex)?;
        let runtime_receipt_path = cli
            .receipt_path
            .as_deref()
            .ok_or("--pir2-snp-sealed-receipt is required")?;
        let runtime_marker_path = cli
            .marker_path
            .as_deref()
            .ok_or("--pir2-snp-sealed-marker is required")?;
        let preflight_receipt_path = sibling(
            runtime_receipt_path,
            &format!("ready-preflight-{boot_id_hex}.bin"),
            "--pir2-snp-sealed-receipt",
        )?;
        let preflight_marker_path = sibling(
            runtime_marker_path,
            &format!("ready-preflight-{boot_id_hex}.env"),
            "--pir2-snp-sealed-marker",
        )?;
        let ready_runtime_receipt = read_regular_file_bounded_v1(
            runtime_receipt_path,
            MAX_RECEIPT_BYTES,
            "Ready runtime receipt",
        )?;
        let ready_preflight_receipt = read_regular_file_bounded_v1(
            &preflight_receipt_path,
            MAX_RECEIPT_BYTES,
            "Ready preflight receipt",
        )?;
        let ready_preflight_marker = read_regular_file_bounded_v1(
            &preflight_marker_path,
            MAX_MARKER_BYTES,
            "Ready preflight marker",
        )?;
        if ready_runtime_receipt.is_empty() || ready_preflight_receipt.is_empty() {
            return Err("a Ready receipt file is empty".to_owned());
        }
        require_marker_names_this_boot(&ready_preflight_marker, boot_id_hex)?;
        Ok(Self {
            boot_id,
            ready_preflight_receipt,
            ready_runtime_receipt,
            ready_preflight_marker,
        })
    }

    pub(crate) fn startup_log_line(&self) -> String {
        format!(
            "pir2 sealed Ready receipts: serving preflight receipt ({} bytes), runtime receipt \
             ({} bytes), and preflight marker ({} bytes) for boot {} via REQ_PIR2_SEALED_RECEIPT_GET",
            self.ready_preflight_receipt.len(),
            self.ready_runtime_receipt.len(),
            self.ready_preflight_marker.len(),
            hex::encode(self.boot_id),
        )
    }

    fn artifact(&self, kind: u8) -> Option<&[u8]> {
        match kind {
            PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT => Some(&self.ready_preflight_receipt),
            PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME => Some(&self.ready_runtime_receipt),
            PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER => Some(&self.ready_preflight_marker),
            _ => None,
        }
    }
}

/// Same contract as the sealed CLI flag: exact lowercase hex, 16 bytes, not
/// all zero. The hex string also becomes part of the derived file names.
fn decode_boot_id_hex(value: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(value).map_err(|_| "boot ID must be exact lowercase hex".to_owned())?;
    if hex::encode(&bytes) != value {
        return Err("boot ID must use canonical lowercase hex".to_owned());
    }
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| "boot ID has the wrong length".to_owned())?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("boot ID must not be all zero".to_owned());
    }
    Ok(bytes)
}

fn sibling(path: &Path, file_name: &str, flag: &str) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| format!("{flag} has no parent directory: {}", path.display()))?;
    Ok(parent.join(file_name))
}

/// The marker is the preflight run's inert-success record; refuse to serve
/// one that names another boot or phase (the receipt file names alone are
/// operator-controlled paths, the marker body is what the guest wrote).
fn require_marker_names_this_boot(marker: &[u8], boot_id_hex: &str) -> Result<(), String> {
    let text = std::str::from_utf8(marker)
        .map_err(|_| "Ready preflight marker is not UTF-8".to_owned())?;
    let boot_line = format!("boot_id={boot_id_hex}");
    if !text.lines().any(|line| line == boot_line) {
        return Err("Ready preflight marker does not name this boot".to_owned());
    }
    if !text.lines().any(|line| line == "phase=ready") {
        return Err("Ready preflight marker is not a Ready marker".to_owned());
    }
    Ok(())
}

/// Build the wire reply for one `REQ_PIR2_SEALED_RECEIPT_GET` body. This is
/// the seam the dispatch arm and the unit tests share; booting the full
/// binary needs a multi-GB checkpoint.
pub(crate) fn build_pir2_sealed_receipt_response(
    source: Option<&Pir2SealedReadyReceiptsV1>,
    body: &[u8],
) -> Response {
    let [kind] = body else {
        return Response::Error(
            "malformed REQ_PIR2_SEALED_RECEIPT_GET: expected exactly one kind byte".into(),
        );
    };
    let Some(source) = source else {
        return Response::Error(
            "pir2 sealed Ready receipts not available: this server is not a sealed Ready pir2 guest"
                .into(),
        );
    };
    match source.artifact(*kind) {
        Some(bytes) => Response::Pir2SealedReceipt {
            kind: *kind,
            boot_id: source.boot_id,
            bytes: bytes.to_vec(),
        },
        None => Response::Error(format!(
            "unknown pir2 sealed receipt kind {kind}: expected 1 (Ready preflight receipt), \
             2 (Ready runtime receipt), or 3 (Ready preflight marker)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT_HEX: &str = "93f3a6dd0123456789abcdef00112233";

    struct Fixture {
        _directory: tempfile::TempDir,
        cli: Pir2SealedCliV1,
        preflight_receipt: PathBuf,
        preflight_marker: PathBuf,
    }

    fn marker_text(boot_id_hex: &str, phase: &str) -> String {
        format!(
            "schema=bitcoinpir-pir2-sealed-inert-success-v1\nphase={phase}\nboot_id={boot_id_hex}\n\
             receipt_digest={}\nexit_code=97\n",
            "11".repeat(32)
        )
    }

    /// Lay the files out exactly as `unified-server-run.sh` does:
    /// `<root>/receipts/ready-*-BOOT.bin` and `<root>/markers/ready-*-BOOT.env`.
    fn make_fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let receipts = directory.path().join("receipts");
        let markers = directory.path().join("markers");
        std::fs::create_dir_all(&receipts).unwrap();
        std::fs::create_dir_all(&markers).unwrap();
        let runtime_receipt = receipts.join(format!("ready-runtime-{BOOT_HEX}.bin"));
        let preflight_receipt = receipts.join(format!("ready-preflight-{BOOT_HEX}.bin"));
        let preflight_marker = markers.join(format!("ready-preflight-{BOOT_HEX}.env"));
        std::fs::write(&runtime_receipt, b"runtime-receipt-bytes").unwrap();
        std::fs::write(&preflight_receipt, b"preflight-receipt-bytes").unwrap();
        std::fs::write(&preflight_marker, marker_text(BOOT_HEX, "ready")).unwrap();
        let cli = Pir2SealedCliV1 {
            receipt_path: Some(runtime_receipt),
            // The runtime marker is written only by preflight-only runs; the
            // final server never creates it, so the loader must not need it.
            marker_path: Some(markers.join(format!("ready-runtime-{BOOT_HEX}.env"))),
            current_boot_id_hex: Some(BOOT_HEX.to_owned()),
            ..Pir2SealedCliV1::default()
        };
        Fixture {
            _directory: directory,
            cli,
            preflight_receipt,
            preflight_marker,
        }
    }

    fn expect_artifact(resp: Response, kind: u8) -> Vec<u8> {
        match resp {
            Response::Pir2SealedReceipt {
                kind: got_kind,
                boot_id,
                bytes,
            } => {
                assert_eq!(got_kind, kind);
                assert_eq!(hex::encode(boot_id), BOOT_HEX);
                bytes
            }
            other => panic!("expected Pir2SealedReceipt, got {:?}", other),
        }
    }

    fn expect_error(resp: Response) -> String {
        match resp {
            Response::Error(message) => message,
            other => panic!("expected Error, got {:?}", other),
        }
    }

    #[test]
    fn load_serves_all_three_artifacts_of_this_boot() {
        let fixture = make_fixture();
        let receipts = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap();
        assert_eq!(
            expect_artifact(
                build_pir2_sealed_receipt_response(
                    Some(&receipts),
                    &[PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT]
                ),
                PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT,
            ),
            b"preflight-receipt-bytes"
        );
        assert_eq!(
            expect_artifact(
                build_pir2_sealed_receipt_response(
                    Some(&receipts),
                    &[PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME]
                ),
                PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
            ),
            b"runtime-receipt-bytes"
        );
        assert_eq!(
            expect_artifact(
                build_pir2_sealed_receipt_response(
                    Some(&receipts),
                    &[PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER]
                ),
                PIR2_SEALED_RECEIPT_KIND_READY_PREFLIGHT_MARKER,
            ),
            marker_text(BOOT_HEX, "ready").as_bytes()
        );
        assert!(receipts.startup_log_line().contains("for boot "));
    }

    #[test]
    fn response_wire_round_trips_through_the_protocol_decoder() {
        let fixture = make_fixture();
        let receipts = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap();
        let wire = build_pir2_sealed_receipt_response(
            Some(&receipts),
            &[PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME],
        )
        .encode();
        // Wire layout: [u32 LE outer len][RESP_PIR2_SEALED_RECEIPT]...;
        // `Response::decode` consumes everything after the outer length.
        let bytes = expect_artifact(
            Response::decode(&wire[4..]).unwrap(),
            PIR2_SEALED_RECEIPT_KIND_READY_RUNTIME,
        );
        assert_eq!(bytes, b"runtime-receipt-bytes");
    }

    #[test]
    fn malformed_body_unknown_kind_and_unconfigured_server_answer_errors() {
        let fixture = make_fixture();
        let receipts = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap();
        assert!(
            expect_error(build_pir2_sealed_receipt_response(Some(&receipts), &[]))
                .contains("exactly one kind byte")
        );
        assert!(
            expect_error(build_pir2_sealed_receipt_response(Some(&receipts), &[1, 2]))
                .contains("exactly one kind byte")
        );
        assert!(
            expect_error(build_pir2_sealed_receipt_response(Some(&receipts), &[0]))
                .contains("unknown pir2 sealed receipt kind 0")
        );
        assert!(
            expect_error(build_pir2_sealed_receipt_response(Some(&receipts), &[4]))
                .contains("unknown pir2 sealed receipt kind 4")
        );
        assert!(expect_error(build_pir2_sealed_receipt_response(None, &[1]))
            .contains("not a sealed Ready pir2 guest"));
    }

    #[test]
    fn load_requires_the_preflight_receipt_of_this_boot() {
        let fixture = make_fixture();
        std::fs::remove_file(&fixture.preflight_receipt).unwrap();
        let error = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap_err();
        assert!(error.contains("Ready preflight receipt"), "{error}");
    }

    #[test]
    fn load_rejects_a_marker_for_another_boot_or_phase() {
        let fixture = make_fixture();
        std::fs::write(
            &fixture.preflight_marker,
            marker_text(&"ab".repeat(16), "ready"),
        )
        .unwrap();
        let error = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap_err();
        assert!(error.contains("does not name this boot"), "{error}");
        std::fs::write(&fixture.preflight_marker, marker_text(BOOT_HEX, "probe")).unwrap();
        let error = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap_err();
        assert!(error.contains("not a Ready marker"), "{error}");
    }

    #[test]
    fn load_rejects_oversized_and_empty_files() {
        let fixture = make_fixture();
        std::fs::write(&fixture.preflight_marker, vec![b'x'; MAX_MARKER_BYTES + 1]).unwrap();
        let error = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap_err();
        assert!(error.contains("above the"), "{error}");
        std::fs::write(&fixture.preflight_marker, marker_text(BOOT_HEX, "ready")).unwrap();
        std::fs::write(&fixture.preflight_receipt, b"").unwrap();
        let error = Pir2SealedReadyReceiptsV1::load(&fixture.cli).unwrap_err();
        assert!(error.contains("is empty"), "{error}");
    }

    #[test]
    fn load_rejects_non_canonical_boot_ids_and_missing_flags() {
        for bad in [
            "93F3A6DD0123456789ABCDEF00112233",
            "93f3a6dd",
            &"00".repeat(16),
            "zz".repeat(16).as_str(),
        ] {
            let mut fixture = make_fixture();
            fixture.cli.current_boot_id_hex = Some(bad.to_owned());
            assert!(
                Pir2SealedReadyReceiptsV1::load(&fixture.cli).is_err(),
                "boot id {bad} must be rejected"
            );
        }
        let mut fixture = make_fixture();
        fixture.cli.receipt_path = None;
        assert!(Pir2SealedReadyReceiptsV1::load(&fixture.cli)
            .unwrap_err()
            .contains("--pir2-snp-sealed-receipt"));
        let mut fixture = make_fixture();
        fixture.cli.marker_path = None;
        assert!(Pir2SealedReadyReceiptsV1::load(&fixture.cli)
            .unwrap_err()
            .contains("--pir2-snp-sealed-marker"));
        let mut fixture = make_fixture();
        fixture.cli.current_boot_id_hex = None;
        assert!(Pir2SealedReadyReceiptsV1::load(&fixture.cli)
            .unwrap_err()
            .contains("--pir2-snp-sealed-current-boot-id-hex"));
    }
}
