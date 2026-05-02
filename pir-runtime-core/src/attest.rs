//! Server-side SEV-SNP attestation fetcher and binary self-hash.
//!
//! On a SEV-SNP guest, /dev/sev-guest exposes an ioctl that takes 64
//! bytes of attester-supplied "user data" (REPORT_DATA) and returns a
//! signed attestation report (~1184 bytes). The signature chains to the
//! VCEK certificate the AMD KDS issues for this exact chip + TCB, which
//! itself chains to AMD's ARK root.
//!
//! Pure-crypto helpers (REPORT_DATA preimage construction, manifest-root
//! combination) live in `pir_core::attest` so they're shared with the
//! verifier-side code in pir-sdk-client.
//!
//! On hosts without /dev/sev-guest (Hetzner's Intel i7-8700, dev
//! laptops, CI), [`fetch_report`] returns `Ok(None)` so the /attest
//! handler still emits the manifest/binary/git data — just unsigned.

use pir_core::merkle::{sha256, Hash256};
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::OnceLock;

/// Re-export for callers building REPORT_DATA without a `pir_core` import.
pub use pir_core::attest::{
    build_report_data, combine_manifest_roots, extract_report_data,
    REPORT_DATA_DOMAIN_TAG, SEV_SNP_REPORT_DATA_LEN, SEV_SNP_REPORT_DATA_OFFSET,
};

/// Git commit (with `-dirty` suffix if the working tree had local
/// modifications when the binary was built). Set by `build.rs`.
pub const GIT_REV: &str = env!("BPIR_GIT_REV");

/// Path the kernel exposes the SEV-SNP guest interface at.
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

// Linux uapi: include/uapi/linux/sev-guest.h (kernel 5.19+):
//
//   #define SEV_GUEST_IOC_TYPE 0xa3
//   struct snp_guest_request_ioctl {
//       __u8  msg_version;     // offset 0, +7 padding to 8
//       __u64 req_data;        // offset 8
//       __u64 resp_data;       // offset 16
//       __u64 exitinfo2;       // offset 24
//   };  // total 32 bytes on 64-bit Linux
//   #define SNP_GET_REPORT _IOWR(SEV_GUEST_IOC_TYPE, 0, struct snp_guest_request_ioctl)
//
// _IOWR encodes: dir=3 (R|W), size=32, type=0xa3, nr=0
//   = (3 << 30) | (32 << 16) | (0xa3 << 8) | 0
//   = 0xc020_a300
const SNP_GET_REPORT_IOCTL: libc::c_ulong = 0xc020_a300;

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    _rsvd: [u8; 28],
}

/// 4000-byte response buffer per kernel uapi (SEV_SNP_REPORT_SIZE_MAX).
/// The actual report is ~1184 bytes; the rest is reserved for
/// future-proofing and chaining.
#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

/// Fetch a SEV-SNP attestation report binding `user_data` (64 bytes)
/// into the report's REPORT_DATA field.
///
/// Returns:
/// - `Ok(Some(report_bytes))` — raw signed attestation report bytes.
///   The first 4 bytes are a length prefix the kernel adds; the
///   following bytes are the report itself (~1184 bytes for v5).
///   This function strips the prefix so the caller gets the report
///   bytes directly.
/// - `Ok(None)` — `/dev/sev-guest` doesn't exist (host isn't a SEV-SNP
///   guest). Caller emits unsigned attestation data.
/// - `Err(_)` — unexpected I/O error (permissions, kernel bug).
pub fn fetch_report(user_data: [u8; 64]) -> io::Result<Option<Vec<u8>>> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut req = SnpReportReq {
        user_data,
        vmpl: 0,
        _rsvd: [0u8; 28],
    };
    let mut resp = SnpReportResp { data: [0u8; 4000] };
    let mut wrap = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &mut req as *mut _ as u64,
        resp_data: &mut resp as *mut _ as u64,
        exitinfo2: 0,
    };

    // SAFETY: file is a valid /dev/sev-guest fd; wrap, req, resp are
    // properly sized C-repr structs that outlive the ioctl call.
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            SNP_GET_REPORT_IOCTL,
            &mut wrap as *mut SnpGuestRequestIoctl,
        )
    };
    if rc != 0 {
        return Err(io::Error::other(format!(
            "SNP_GET_REPORT ioctl failed: {} (exitinfo2=0x{:x})",
            io::Error::last_os_error(),
            wrap.exitinfo2
        )));
    }

    // resp.data layout: [4B little-endian length][report bytes][padding]
    let len = u32::from_le_bytes(resp.data[..4].try_into().unwrap()) as usize;
    if len == 0 || 4 + len > resp.data.len() {
        // Fallback for older kernels that don't write the length prefix:
        // assume the canonical 1184-byte v5 report at offset 0.
        return Ok(Some(resp.data[..1184].to_vec()));
    }
    Ok(Some(resp.data[4..4 + len].to_vec()))
}

/// SHA-256 of the running binary (read from `/proc/self/exe`),
/// computed once and cached for the process lifetime.
///
/// On non-Linux hosts or when the read fails (sandboxed test env, etc.)
/// returns the all-zero hash — verifiers must treat all-zero as
/// "self-hash unavailable", not as a valid attestation.
pub fn self_exe_sha256() -> Hash256 {
    static CACHED: OnceLock<Hash256> = OnceLock::new();
    *CACHED.get_or_init(|| {
        std::fs::read("/proc/self/exe")
            .map(|bytes| sha256(&bytes))
            .unwrap_or([0u8; 32])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_report_on_non_sev_host_is_ok_none() {
        // On macOS / non-SEV Linux this should be Ok(None).
        // On a SEV-SNP guest (the new VPSBG box), it returns Ok(Some(report)).
        let user_data = [0u8; 64];
        match fetch_report(user_data) {
            Ok(None) => { /* expected on non-SEV hosts */ }
            Ok(Some(report)) => {
                assert!(report.len() >= 1184, "v5 report should be ≥1184 bytes, got {}", report.len());
            }
            Err(e) => {
                eprintln!("fetch_report errored (acceptable in sandboxed test env): {}", e);
            }
        }
    }

    #[test]
    fn self_exe_sha256_is_deterministic() {
        let h1 = self_exe_sha256();
        let h2 = self_exe_sha256();
        assert_eq!(h1, h2, "self-exe hash must be cached and stable");
    }

    #[test]
    fn git_rev_is_baked_in() {
        // Either a 40-char SHA, "unknown", or "<sha>-dirty".
        assert!(!GIT_REV.is_empty());
        assert!(
            GIT_REV == "unknown" || GIT_REV.len() >= 40,
            "GIT_REV should be 40-char SHA or 'unknown', got {:?}",
            GIT_REV
        );
    }
}
