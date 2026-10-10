//! `bpir-admin attest` — fetch and verify a server's SEV-SNP report.
//!
//! Drives `pir_sdk_client::attest::attest()` and presents the result.
//! Optional pin flags cross-check the server's values against
//! operator-published expectations. When `--expect-ark-fingerprint` is
//! supplied, the same response is also verified through ARK→ASK→VCEK and
//! its SNP report signature, atomically binding the pinned binary and
//! MEASUREMENT checks to an AMD-signed report.

use clap::Args;
use pir_sdk_client::attest::{attest, AttestResponse, SevStatus};
use pir_sdk_client::WsConnection;

#[derive(Args, Debug)]
pub struct AttestArgs {
    /// WebSocket URL of the server to attest, e.g.
    /// `wss://bitcoin-pir-weikeng-laptop.chenweikeng.com` or `ws://localhost:8092`.
    pub server: String,

    /// Expected hex of the server binary's SHA-256. If set, exit
    /// non-zero unless the server's self-reported `binary_sha256`
    /// matches.
    #[arg(long)]
    pub expect_binary: Option<String>,

    /// Expected SEV-SNP launch MEASUREMENT (96-char hex = 48 bytes).
    /// This is the value the operator publishes after uploading a UKI
    /// via VPSBG's Measured Boot UI and rebooting — it covers OVMF +
    /// the entire UKI bytes (kernel + initrd + cmdline). If set, exit
    /// non-zero on any mismatch. Implies the SEV report must be
    /// present (i.e., we're attesting against a SEV-SNP host, not a
    /// stock-Linux Hetzner-style fallback).
    #[arg(long)]
    pub expect_measurement: Option<String>,

    /// Operator-pinned 64-hex-character SHA-256 fingerprint of the AMD
    /// ARK certificate. When set, verify ARK→ASK→VCEK and the SNP report
    /// signature from this same attestation response. This makes the
    /// binary and MEASUREMENT comparisons silicon-rooted instead of
    /// treating the report fields as unsigned input.
    #[arg(long = "expect-ark-fingerprint", value_name = "HEX64")]
    pub expect_ark_fingerprint: Option<String>,
}

pub async fn run(args: AttestArgs) -> Result<(), String> {
    let ark_pin = args
        .expect_ark_fingerprint
        .as_deref()
        .map(|value| parse_hex_array::<32>(value, "--expect-ark-fingerprint"))
        .transpose()?;

    let mut conn = WsConnection::connect(&args.server)
        .await
        .map_err(|e| format!("connect to {} failed: {e}", args.server))?;
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("getrandom: {e}"))?;
    let v = attest(&mut conn, nonce)
        .await
        .map_err(|e| format!("server returned error: {e}"))?;
    let measurement = v.response.sev_snp_report.get(MEASUREMENT).map(hex::encode);

    println!("Server URL:        {}", args.server);
    println!("Nonce sent:        {}", hex::encode(nonce));
    println!();
    println!("== Self-reported (server-side) ==");
    println!(
        "binary_sha256:     {}",
        hex::encode(v.response.binary_sha256)
    );
    println!("git_rev:           {}", v.response.git_rev);
    println!(
        "channel pubkey:    {}  (X25519, V2-bound to REPORT_DATA)",
        hex::encode(v.response.server_static_pub)
    );
    println!(
        "manifest roots ({} DB{}):",
        v.response.manifest_roots.len(),
        if v.response.manifest_roots.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    for (i, root) in v.response.manifest_roots.iter().enumerate() {
        println!("  db_id={}: {}", i, hex::encode(root));
    }
    let chain_present = !v.response.ark_pem.is_empty()
        && !v.response.ask_pem.is_empty()
        && !v.response.vcek_pem.is_empty();
    if chain_present {
        println!(
            "vcek chain:        bundled (ark={}B ask={}B vcek={}B)",
            v.response.ark_pem.len(),
            v.response.ask_pem.len(),
            v.response.vcek_pem.len(),
        );
    } else {
        println!(
            "vcek chain:        <none> (server has no VCEK chain loaded — \
             configure --vcek-dir on the server to enable browser-side \
             AMD-rooted chain validation)"
        );
    }
    println!();
    println!("== SEV-SNP attestation ==");
    println!("Report bytes:      {}", v.response.sev_snp_report.len());
    println!("Status:            {:?}", v.sev_status);
    println!(
        "Expected REPORT_DATA[..32]: {}",
        hex::encode(v.expected_report_data_hash)
    );
    if let Some(m) = &measurement {
        println!("Launch MEASUREMENT: {m}");
    }

    let mut mismatch = false;

    // Cross-check sev status
    match v.sev_status {
        SevStatus::ReportDataMatch => {
            println!();
            println!("✓ SEV-SNP REPORT_DATA binding verified.");
        }
        SevStatus::NoSevHost => {
            println!();
            println!("⚠ Server is not running on a SEV-SNP host —");
            println!("   self-reported metadata is NOT hardware-backed.");
        }
        SevStatus::ReportDataMismatch => {
            println!();
            println!("✗ REPORT_DATA does not match recomputation —");
            println!("   server may be lying about its self-reported state.");
            mismatch = true;
        }
        SevStatus::MalformedReport => {
            println!();
            println!("✗ SEV report is malformed (too short for REPORT_DATA field).");
            mismatch = true;
        }
    }

    // Validate the AMD certificate chain and report signature against the
    // exact same AttestResult used for REPORT_DATA, binary, and MEASUREMENT
    // checks below. Keeping these checks on one response avoids a split-view
    // endpoint satisfying pin checks and signature checks on different reports.
    if let Some(ark_pin) = ark_pin {
        println!();
        match verify_vcek_chain(&v.response, ark_pin) {
            Ok(()) => println!(
                "✓ AMD ARK→ASK→VCEK chain and this attestation report's signature verified."
            ),
            Err(e) => {
                println!("✗ {e}");
                mismatch = true;
            }
        }
    }

    // Cross-check expected binary hash
    if let Some(expected_hex) = args.expect_binary {
        let actual_hex = hex::encode(v.response.binary_sha256);
        if !expected_hex.eq_ignore_ascii_case(&actual_hex) {
            println!();
            println!("✗ binary_sha256 mismatch:");
            println!("    expected: {}", expected_hex);
            println!("    got:      {}", actual_hex);
            mismatch = true;
        } else {
            println!();
            println!("✓ binary_sha256 matches expected.");
        }
    }

    // Cross-check expected MEASUREMENT (the operator-published launch
    // digest from the chip-signed report, NOT a recomputation).
    if let Some(expected_hex) = args.expect_measurement {
        println!();
        match &measurement {
            None => {
                println!("✗ --expect-measurement set but server returned no SEV report");
                println!("    (host is not running on a SEV-SNP guest, or report is malformed)");
                mismatch = true;
            }
            Some(actual_hex) if !expected_hex.eq_ignore_ascii_case(actual_hex) => {
                println!("✗ MEASUREMENT mismatch:");
                println!("    expected: {}", expected_hex);
                println!("    got:      {}", actual_hex);
                println!("    (different UKI loaded, or VPSBG OVMF version changed)");
                mismatch = true;
            }
            Some(_) => println!("✓ Launch MEASUREMENT matches expected."),
        }
    }

    if mismatch {
        return Err("the attestation does not match the expectations above".into());
    }
    Ok(())
}

/// The launch MEASUREMENT's bytes in an SNP report (AMD SEV-SNP ABI,
/// report v2/v5 layout).
const MEASUREMENT: std::ops::Range<usize> = 0x90..0x90 + 48;

/// Verify ARK→ASK→VCEK against the pinned ARK fingerprint, then the
/// report's signature against that VCEK.
pub(crate) fn verify_vcek_chain(r: &AttestResponse, ark_pin: [u8; 32]) -> Result<(), String> {
    if r.ark_pem.is_empty() || r.ask_pem.is_empty() || r.vcek_pem.is_empty() {
        return Err("the server returned no complete ARK/ASK/VCEK chain".into());
    }
    pir_attest_verify::verify_chain(&r.ark_pem, &r.ask_pem, &r.vcek_pem, Some(ark_pin))
        .map_err(|e| format!("AMD certificate-chain validation failed: {e}"))?;
    pir_attest_verify::verify_report_against_vcek(&r.sev_snp_report, &r.vcek_pem)
        .map_err(|e| format!("SEV-SNP report-signature validation failed: {e}"))?;
    Ok(())
}

pub(crate) fn parse_hex_array<const N: usize>(value: &str, flag: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value.trim()).map_err(|e| format!("{flag} must be valid hex: {e}"))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        format!(
            "{flag} must be {} hex characters, got {}",
            N * 2,
            v.len() * 2
        )
    })
}
