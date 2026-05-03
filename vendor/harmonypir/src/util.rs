//! Utility functions for HarmonyPIR.
//!
//! Primarily XOR operations on variable-length byte entries.

/// XOR `src` into `dst` in place: `dst[i] ^= src[i]` for all i.
///
/// # Panics
/// Panics if `dst` and `src` have different lengths.
pub fn xor_bytes_into(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "XOR operands must have equal length");

    // Fixed-bound 32-byte inner loop autovectorizes to AVX2 (vpxor on ymm),
    // SSE2 (2x pxor on xmm), or NEON (2x veor on qreg) without cfg gating.
    const CHUNK: usize = 32;
    let mut d_iter = dst.chunks_exact_mut(CHUNK);
    let mut s_iter = src.chunks_exact(CHUNK);
    for (d, s) in (&mut d_iter).zip(&mut s_iter) {
        for i in 0..CHUNK {
            d[i] ^= s[i];
        }
    }
    for (d, s) in d_iter.into_remainder().iter_mut().zip(s_iter.remainder()) {
        *d ^= *s;
    }
}

/// Return the XOR of two byte slices as a new Vec.
///
/// # Panics
/// Panics if the slices have different lengths.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "XOR operands must have equal length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// A zero entry of `w` bytes, used as the identity for XOR.
pub fn zero_entry(w: usize) -> Vec<u8> {
    vec![0u8; w]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_bytes_into() {
        let mut a = vec![0xFF, 0x00, 0xAA];
        let b = vec![0x0F, 0xF0, 0x55];
        xor_bytes_into(&mut a, &b);
        assert_eq!(a, vec![0xF0, 0xF0, 0xFF]);
    }

    #[test]
    fn test_xor_self_is_zero() {
        let a = vec![1, 2, 3, 4];
        let result = xor_bytes(&a, &a);
        assert_eq!(result, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_xor_bytes_into_chunked_and_tail() {
        // Cover sizes that exercise <chunk, exactly chunk, multi-chunk + tail.
        for &n in &[0usize, 1, 7, 31, 32, 33, 63, 64, 65, 168, 352, 1000] {
            let a: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31)).collect();
            let b: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(17).wrapping_add(11)).collect();
            let mut out = a.clone();
            xor_bytes_into(&mut out, &b);
            let expected: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
            assert_eq!(out, expected, "mismatch at n={n}");
        }
    }
}
