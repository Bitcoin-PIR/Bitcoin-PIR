//! Attestation helpers shared by server and client.
//!
//! The pure-crypto pieces of the BPIR attestation flow live here so both
//! the server (which fetches the SEV-SNP report) and the client (which
//! verifies it) compute the same canonical REPORT_DATA preimage. Anything
//! platform-specific (the `/dev/sev-guest` ioctl, AMD VCEK chain
//! verification) lives in the consuming crates.
//!
//! ## REPORT_DATA layout
//!
//! SEV-SNP attestation reports include 64 bytes of attester-supplied
//! "user data". BPIR uses the first 32 bytes for a SHA-256 commitment,
//! leaving the trailing 32 bytes zero so the layout can be extended
//! later without re-keying the verifier:
//!
//! ```text
//! report_data[ 0..32] = sha256(BPIR-ATTEST-V1
//!                              || nonce              (32 B)
//!                              || combined_root      (32 B)  // sha256(root_0 || root_1 || ...)
//!                              || binary_sha256      (32 B)
//!                              || git_rev_utf8)
//! report_data[32..64] = 0x00 * 32
//! ```
//!
//! The domain tag `BPIR-ATTEST-V1` ensures collisions with unrelated
//! protocols (or other BPIR features that may want their own
//! REPORT_DATA derivation) cannot be confused for valid attestations.

use crate::merkle::{sha256, Hash256};

/// Domain-separation tag prefixed to the REPORT_DATA preimage.
pub const REPORT_DATA_DOMAIN_TAG: &[u8] = b"BPIR-ATTEST-V1";

/// Concatenate per-DB manifest roots and hash, producing the single
/// "combined manifest root" that goes into REPORT_DATA. Empty input
/// returns the all-zero hash so a server with no manifests still has
/// a deterministic value.
///
/// Order matters: this hashes `roots[0] || roots[1] || ...`. Callers
/// must agree on iteration order (BPIR uses db_id order).
pub fn combine_manifest_roots(roots: &[Hash256]) -> Hash256 {
    if roots.is_empty() {
        return [0u8; 32];
    }
    let mut concat = Vec::with_capacity(roots.len() * 32);
    for r in roots {
        concat.extend_from_slice(r);
    }
    sha256(&concat)
}

/// Build the 64-byte REPORT_DATA payload that gets passed into
/// `/dev/sev-guest`'s SNP_GET_REPORT ioctl.
///
/// See module docs for the exact layout. The high 32 bytes are zero
/// today; clients verify the low 32 bytes match a fresh recomputation.
pub fn build_report_data(
    nonce: [u8; 32],
    manifest_roots: &[Hash256],
    binary_sha256: Hash256,
    git_rev: &str,
) -> [u8; 64] {
    let combined_root = combine_manifest_roots(manifest_roots);

    let mut preimage = Vec::with_capacity(
        REPORT_DATA_DOMAIN_TAG.len() + 32 + 32 + 32 + git_rev.len(),
    );
    preimage.extend_from_slice(REPORT_DATA_DOMAIN_TAG);
    preimage.extend_from_slice(&nonce);
    preimage.extend_from_slice(&combined_root);
    preimage.extend_from_slice(&binary_sha256);
    preimage.extend_from_slice(git_rev.as_bytes());

    let h = sha256(&preimage);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h);
    out
}

/// Offset of the REPORT_DATA field inside an SEV-SNP attestation
/// report (version 2 / version 5; the field's position is stable
/// across both). Use this to extract the 64-byte field from a raw
/// report blob for verification.
pub const SEV_SNP_REPORT_DATA_OFFSET: usize = 0x50;

/// Length of REPORT_DATA in the SEV-SNP report.
pub const SEV_SNP_REPORT_DATA_LEN: usize = 64;

/// Extract the REPORT_DATA field from a raw SEV-SNP report.
/// Returns `None` if the report is too short to contain the field.
pub fn extract_report_data(report: &[u8]) -> Option<&[u8]> {
    let end = SEV_SNP_REPORT_DATA_OFFSET + SEV_SNP_REPORT_DATA_LEN;
    if report.len() < end {
        return None;
    }
    Some(&report[SEV_SNP_REPORT_DATA_OFFSET..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_manifest_roots_empty_is_zero() {
        assert_eq!(combine_manifest_roots(&[]), [0u8; 32]);
    }

    #[test]
    fn combine_manifest_roots_single_is_sha256_of_root() {
        let root = [7u8; 32];
        assert_eq!(combine_manifest_roots(&[root]), sha256(&root));
    }

    #[test]
    fn combine_manifest_roots_order_matters() {
        let a = combine_manifest_roots(&[[1u8; 32], [2u8; 32]]);
        let b = combine_manifest_roots(&[[2u8; 32], [1u8; 32]]);
        assert_ne!(a, b);
    }

    #[test]
    fn build_report_data_changes_with_nonce() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], "abc");
        let h2 = build_report_data([3u8; 32], &[], [2u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_manifest_roots() {
        let h1 = build_report_data([1u8; 32], &[[7u8; 32]], [2u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[[8u8; 32]], [2u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_binary_hash() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[], [3u8; 32], "abc");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_changes_with_git_rev() {
        let h1 = build_report_data([1u8; 32], &[], [2u8; 32], "abc");
        let h2 = build_report_data([1u8; 32], &[], [2u8; 32], "xyz");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_report_data_high_32_bytes_zero() {
        let h = build_report_data([1u8; 32], &[], [2u8; 32], "abc");
        assert_eq!(&h[32..], &[0u8; 32]);
    }

    #[test]
    fn build_report_data_low_32_bytes_match_manual_sha256() {
        // Recompute the preimage by hand and check it matches.
        let nonce = [0xAAu8; 32];
        let root = [0xBBu8; 32];
        let binary = [0xCCu8; 32];
        let git = "deadbeef";
        let combined = combine_manifest_roots(&[root]);

        let mut p = Vec::new();
        p.extend_from_slice(b"BPIR-ATTEST-V1");
        p.extend_from_slice(&nonce);
        p.extend_from_slice(&combined);
        p.extend_from_slice(&binary);
        p.extend_from_slice(git.as_bytes());
        let manual = sha256(&p);

        let out = build_report_data(nonce, &[root], binary, git);
        assert_eq!(&out[..32], &manual);
    }

    #[test]
    fn extract_report_data_short_returns_none() {
        assert!(extract_report_data(&[0u8; 100]).is_none());
    }

    #[test]
    fn extract_report_data_full_report_returns_64b_at_offset() {
        let mut report = vec![0u8; 1184];
        for (i, b) in report
            .iter_mut()
            .enumerate()
            .skip(SEV_SNP_REPORT_DATA_OFFSET)
            .take(64)
        {
            *b = ((i - SEV_SNP_REPORT_DATA_OFFSET) as u8).wrapping_add(1);
        }
        let extracted = extract_report_data(&report).unwrap();
        assert_eq!(extracted.len(), 64);
        assert_eq!(extracted[0], 1);
        assert_eq!(extracted[63], 64);
    }
}
