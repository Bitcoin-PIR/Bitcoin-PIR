//! `bpir-admin pir2-sealed-observe-fields` — print the public claim fields of
//! a pre-release Observe receipt (`BPIRPRO1`, codec 2) as `key=value` lines.
//!
//! Input extraction only: nothing here verifies the receipt. The values feed
//! `pir2-sealed-release` (which does verify it against the AMD chain and the
//! exact UKI/OVMF measurement) and the client pin update
//! (`report_measurement_hex`). Replaces the session-local
//! `observe-receipt-fields.py` (docs/history/PIR2_DEPLOYMENT_PAIN_POINTS_2026-09.md #9).

use std::path::PathBuf;

use clap::Args;
use pir_attest_verify::SNP_REPORT_LEN;

/// Wire layout of a codec-2 pre-release Observe receipt.
const MAGIC: &[u8; 8] = b"BPIRPRO1";
const CODEC_V2: u16 = 2;
const HEADER_LEN: usize = 8 + 2 + 8 + 32 + 32 + 16;
const RECEIPT_LEN: usize = HEADER_LEN + SNP_REPORT_LEN;

#[derive(Args, Debug)]
pub struct Pir2SealedObserveFieldsArgs {
    /// Observe receipt file downloaded from the recovery root
    /// (`scripts/pir2-sealed-recovery-receipt.sh`).
    #[arg(long)]
    pub receipt: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ObserveFields {
    pub codec: u16,
    pub ordinal: u64,
    pub verifier_nonce: [u8; 32],
    pub current_channel_pubkey: [u8; 32],
    pub boot_id: [u8; 16],
    pub measurement: [u8; 48],
}

pub fn run(args: Pir2SealedObserveFieldsArgs) -> Result<(), String> {
    let bytes = std::fs::read(&args.receipt)
        .map_err(|error| format!("read {}: {error}", args.receipt.display()))?;
    let fields = parse_observe_receipt(&bytes)?;
    print!("{}", render(&fields));
    Ok(())
}

pub fn parse_observe_receipt(bytes: &[u8]) -> Result<ObserveFields, String> {
    if bytes.len() != RECEIPT_LEN {
        return Err(format!(
            "observe receipt has a non-canonical length {} (expected {RECEIPT_LEN})",
            bytes.len()
        ));
    }
    if &bytes[..8] != MAGIC {
        return Err("observe receipt magic is not BPIRPRO1".to_owned());
    }
    let codec = u16::from_le_bytes([bytes[8], bytes[9]]);
    if codec != CODEC_V2 {
        return Err(format!("observe receipt codec {codec} is not {CODEC_V2}"));
    }
    let ordinal = u64::from_le_bytes(bytes[10..18].try_into().expect("8 bytes"));
    let mut verifier_nonce = [0u8; 32];
    verifier_nonce.copy_from_slice(&bytes[18..50]);
    let mut current_channel_pubkey = [0u8; 32];
    current_channel_pubkey.copy_from_slice(&bytes[50..82]);
    let mut boot_id = [0u8; 16];
    boot_id.copy_from_slice(&bytes[82..98]);
    // MEASUREMENT lives at byte 0x90 of the SNP attestation report (AMD SEV-SNP
    // ABI, ATTESTATION_REPORT). Read by offset: this tool extracts, the release
    // command parses and verifies the whole report.
    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(&bytes[HEADER_LEN + 0x90..HEADER_LEN + 0x90 + 48]);
    Ok(ObserveFields {
        codec,
        ordinal,
        verifier_nonce,
        current_channel_pubkey,
        boot_id,
        measurement,
    })
}

pub fn render(fields: &ObserveFields) -> String {
    format!(
        "codec={}\nordinal={}\nverifier_nonce_hex={}\ncurrent_channel_pubkey_hex={}\nboot_id_hex={}\nreport_measurement_hex={}\n",
        fields.codec,
        fields.ordinal,
        hex::encode(fields.verifier_nonce),
        hex::encode(fields.current_channel_pubkey),
        hex::encode(fields.boot_id),
        hex::encode(fields.measurement),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(ordinal: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECEIPT_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&CODEC_V2.to_le_bytes());
        bytes.extend_from_slice(&ordinal.to_le_bytes());
        bytes.extend_from_slice(&[0x11u8; 32]);
        bytes.extend_from_slice(&[0x22u8; 32]);
        bytes.extend_from_slice(&[0x33u8; 16]);
        // A zeroed report with only the version and measurement set; the
        // extractor reads the layout, it does not parse or verify the report.
        let mut report = vec![0u8; SNP_REPORT_LEN];
        report[0] = 2;
        report[0x90..0x90 + 48].copy_from_slice(&[0x44u8; 48]);
        bytes.extend_from_slice(&report);
        bytes
    }

    #[test]
    fn extracts_every_public_field_and_renders_key_value_lines() {
        let fields = parse_observe_receipt(&receipt(56)).unwrap();
        assert_eq!(fields.ordinal, 56);
        assert_eq!(fields.verifier_nonce, [0x11; 32]);
        assert_eq!(fields.current_channel_pubkey, [0x22; 32]);
        assert_eq!(fields.boot_id, [0x33; 16]);
        assert_eq!(fields.measurement, [0x44; 48]);
        let text = render(&fields);
        assert!(text.contains("ordinal=56\n"));
        assert!(text.contains(&format!("boot_id_hex={}\n", "33".repeat(16))));
        assert!(text.contains(&format!("report_measurement_hex={}\n", "44".repeat(48))));
    }

    #[test]
    fn rejects_wrong_length_magic_and_codec() {
        let mut short = receipt(1);
        short.pop();
        assert!(parse_observe_receipt(&short)
            .unwrap_err()
            .contains("non-canonical length"));
        let mut magic = receipt(1);
        magic[0] = b'X';
        assert!(parse_observe_receipt(&magic).unwrap_err().contains("magic"));
        let mut codec = receipt(1);
        codec[8] = 1;
        assert!(parse_observe_receipt(&codec)
            .unwrap_err()
            .contains("codec 1"));
    }
}
