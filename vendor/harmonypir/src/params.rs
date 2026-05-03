//! Parameter computation for HarmonyPIR.
//!
//! # Key parameters
//!
//! Given a database of `N` entries each of `w` bytes:
//!
//! - **T** (segment size): controls communication and computation per query.
//! - **M** = 2N / T: number of segments (hint parities the client stores).
//! - The client can make at most **M/2** queries before re-running offline.
//! - **r**: number of PRP rounds for HarmonyPIR0 (Hoang et al. shuffle).
//! - **β = 4**: phase size for the optimized Hoang PRP (Algorithm 5).
//!
//! The natural balanced choice is T ≈ M ≈ √(2N), which gives
//! √(2N) communication/computation per query and √(2N) client storage.
//!
//! For HarmonyPIR1 (FF1), the permutation domain 2N must be ≥ 10^6,
//! so N ≥ 500,000.

use crate::error::{HarmonyPirError, Result};

/// Phase size for the optimized Hoang PRP (Algorithm 5).
/// Each phase uses a single AES call to derive round functions for β rounds.
/// With β = 4, the phase group has 2^4 = 16 positions, each needing 4 bits,
/// fitting within a single 128-bit AES output (16 * 4 = 64 bits used).
pub const BETA: usize = 4;

/// HarmonyPIR parameters, fully derived from (N, w, T).
#[derive(Debug, Clone, Copy)]
pub struct Params {
    /// Number of database entries.
    pub n: usize,
    /// Size of each database entry in bytes.
    pub w: usize,
    /// Segment size (T). Each segment of the hint row has T cells.
    /// Communication and computation per query are O(T).
    pub t: usize,
    /// Number of segments: M = 2N / T.
    /// This is also the number of hint parities the client stores.
    pub m: usize,
    /// Maximum number of queries before the offline phase must be re-run.
    /// Equal to M / 2 = N / T.
    pub max_queries: usize,
    /// Number of PRP rounds for HarmonyPIR0.
    /// r = Θ(log(2N) − log(ε)), where ε is the PRP distinguishing advantage.
    /// We use r such that ε ≈ 2^{-40} (conservative).
    pub r: usize,
}

impl Params {
    /// Create parameters with explicit T.
    ///
    /// Requirements:
    /// - N > 0
    /// - T > 0
    /// - T must divide 2N evenly (so segments partition the hint row exactly).
    /// - w > 0
    pub fn new(n: usize, w: usize, t: usize) -> Result<Self> {
        if n == 0 {
            return Err(HarmonyPirError::InvalidParams("N must be > 0"));
        }
        if w == 0 {
            return Err(HarmonyPirError::InvalidParams("w must be > 0"));
        }
        if t == 0 {
            return Err(HarmonyPirError::InvalidParams("T must be > 0"));
        }
        let two_n = 2 * n;
        if two_n % t != 0 {
            return Err(HarmonyPirError::InvalidParams("T must divide 2N evenly"));
        }

        let m = two_n / t;
        let max_queries = m / 2; // = N / T

        // PRP rounds for HarmonyPIR0 (Hoang et al.):
        // We need (N'/2, ε)-secure PRP where N' = 2N (the domain size).
        // From Theorem 6.2: r = Θ(log(N') − log(ε)).
        // With N' = 2N and targeting ε ≈ 2^{-40}:
        //   r = ceil(log2(2N)) + 40
        // Rounded up to a multiple of BETA for clean phase boundaries.
        let log_domain = (two_n as f64).log2().ceil() as usize;
        let r_raw = log_domain + 40;
        let r = ((r_raw + BETA - 1) / BETA) * BETA; // round up to multiple of β

        Ok(Params {
            n,
            w,
            t,
            m,
            max_queries,
            r,
        })
    }

    /// Create parameters with the balanced default: T = floor(√(2N)),
    /// adjusted so T divides 2N.
    ///
    /// This gives roughly equal communication/computation (O(√N)) and
    /// client storage (O(√N)).
    pub fn with_balanced_t(n: usize, w: usize) -> Result<Self> {
        if n == 0 {
            return Err(HarmonyPirError::InvalidParams("N must be > 0"));
        }
        let two_n = 2 * n;
        let t_approx = (two_n as f64).sqrt() as usize;

        // Search near t_approx for a divisor of 2N.
        let t = find_nearby_divisor(two_n, t_approx);
        Self::new(n, w, t)
    }

    /// The permutation domain size: 2N.
    pub fn domain(&self) -> usize {
        2 * self.n
    }
}

/// Find a divisor of `n` close to `target`.
/// Searches outward from `target` in both directions.
pub fn find_nearby_divisor(n: usize, target: usize) -> usize {
    if target == 0 {
        return 1;
    }
    if n % target == 0 {
        return target;
    }
    for delta in 1..target {
        if target + delta <= n && n % (target + delta) == 0 {
            return target + delta;
        }
        if target > delta && n % (target - delta) == 0 {
            return target - delta;
        }
    }
    // Fallback: T = 1 always divides 2N.
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_params() {
        // N=8, T=4 as in Figure 1 of the paper
        let p = Params::new(8, 32, 4).unwrap();
        assert_eq!(p.n, 8);
        assert_eq!(p.t, 4);
        assert_eq!(p.m, 4); // 2*8/4 = 4
        assert_eq!(p.max_queries, 2); // 4/2 = 2
        assert_eq!(p.domain(), 16);
    }

    #[test]
    fn test_balanced_t() {
        let p = Params::with_balanced_t(1 << 20, 32).unwrap();
        // 2N = 2^21, sqrt(2^21) ≈ 1448. T should divide 2^21.
        assert_eq!((2 * p.n) % p.t, 0);
        // T and M should be roughly equal (balanced).
        let ratio = (p.t as f64) / (p.m as f64);
        assert!(ratio > 0.1 && ratio < 10.0);
    }

    #[test]
    fn test_r_rounds_multiple_of_beta() {
        let p = Params::new(8, 32, 4).unwrap();
        assert_eq!(p.r % BETA, 0);
    }

    #[test]
    fn test_invalid_params() {
        assert!(Params::new(0, 32, 4).is_err());
        assert!(Params::new(8, 32, 3).is_err()); // 16 % 3 != 0
    }
}
