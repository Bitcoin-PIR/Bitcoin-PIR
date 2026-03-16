//! Shared utility functions for build_db tools.

use std::fs::File;
use std::path::Path;

use crate::mpfh::Mphf;

/// Format duration in seconds to a human-readable string (e.g., "2h 15m 30s").
pub fn format_duration(secs: f64) -> String {
    if secs.is_infinite() || secs.is_nan() {
        return "calculating...".to_string();
    }

    let total_secs = secs as u64;
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

/// Format byte count to a human-readable string (e.g., "1.23 GB").
pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.2} MB", b / MB)
    } else if b >= KB {
        format!("{:.2} KB", b / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// TXID that caused issues during MPHF construction and must be skipped.
/// 68b45f58b674e94eb881cd67b04c2cba07fe5552dbf1d5385637b0d4073dbfe3
pub const SKIP_TXID_1: [u8; 32] = [
    0x68, 0xb4, 0x5f, 0x58, 0xb6, 0x74, 0xe9, 0x4e, 0xb8, 0x81, 0xcd, 0x67, 0xb0, 0x4c, 0x2c, 0xba,
    0x07, 0xfe, 0x55, 0x52, 0xdb, 0xf1, 0xd5, 0x38, 0x56, 0x37, 0xb0, 0xd4, 0x07, 0x3d, 0xbf, 0xe3,
];

/// TXID that caused issues during MPHF construction and must be skipped.
/// 9985d82954e10f2233a08905dc7b490eb444660c8759e324c7dfa3d28779d2d5
pub const SKIP_TXID_2: [u8; 32] = [
    0x99, 0x85, 0xd8, 0x29, 0x54, 0xe1, 0x0f, 0x22, 0x33, 0xa0, 0x89, 0x05, 0xdc, 0x7b, 0x49, 0x0e,
    0xb4, 0x44, 0x66, 0x0c, 0x87, 0x59, 0xe3, 0x24, 0xc7, 0xdf, 0xa3, 0xd2, 0x87, 0x79, 0xd2, 0xd5,
];

/// Returns true if the TXID should be skipped during processing.
#[inline]
pub fn should_skip(txid: &[u8; 32]) -> bool {
    txid == &SKIP_TXID_1 || txid == &SKIP_TXID_2
}

/// Read a progress counter (u64) from a file. Returns 0 if the file is missing or unparseable.
pub fn get_progress(path: &str) -> u64 {
    match std::fs::read_to_string(path) {
        Ok(s) => s.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Write a progress counter (u64) to a file.
pub fn save_progress(path: &str, value: u64) {
    if let Err(e) = std::fs::write(path, value.to_string()) {
        eprintln!("Warning: Failed to save progress to {}: {}", path, e);
    }
}

/// Load MPHF from a bincode-serialized file.
pub fn load_mphf(path: &Path) -> Result<Mphf<[u8; 32]>, String> {
    println!("Loading MPHF from {}...", path.display());

    let file = File::open(path).map_err(|e| format!("Failed to open MPHF file: {}", e))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Failed to read MPHF metadata: {}", e))?;
    println!(
        "MPHF file size: {} bytes ({:.2} GB)",
        metadata.len(),
        metadata.len() as f64 / 1e9
    );

    let mphf: Mphf<[u8; 32]> = bincode::deserialize_from(file)
        .map_err(|e| format!("Failed to deserialize MPHF: {}", e))?;

    println!("MPHF loaded successfully!");
    Ok(mphf)
}
