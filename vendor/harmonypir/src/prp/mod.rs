//! Pseudorandom permutation (PRP) implementations.
//!
//! HarmonyPIR requires a random permutation over a domain [2N] (the integers 0..2N-1).
//! This is instantiated via a small-domain PRP, which maps inputs in [2N] to
//! pseudorandom outputs in [2N] using a secret key.
//!
//! Four implementations are provided:
//!
//! - **[`hoang::HoangPrp`]** (HarmonyPIR0): Based on the card-shuffle construction of
//!   Hoang, Morris, and Rogaway (Crypto 2012), with the 4× AES optimization from
//!   the HarmonyPIR paper (Algorithm 5). Security is provably reduced to AES.
//!
//! - **[`ff1::Ff1Prp`]** (HarmonyPIR1): Uses the FF1 Format-Preserving Encryption
//!   standard (NIST SP 800-38G). Faster in practice but requires domain ≥ 10^6.
//!
//! - **[`fast::FastPrpWrapper`]**: Stefanov & Shi (2012) recursive bitstring PRP.
//!   Slower per-element (~53 us at 6M) but has O(N log N) `batch_permute()` for
//!   full-domain table generation. Supports cache persistence for fast reconstruction.
//!
//! - **[`alf::AlfPrp`]**: ALF format-preserving encryption using AES round functions.
//!   Very fast per-element (~83 ns single). Requires domain ≥ 65536. Native tweak
//!   support for per-PBC-group differentiation.

#[cfg(feature = "alf")]
pub mod alf;
#[cfg(feature = "fastprp-prp")]
pub mod fast;
pub mod ff1;
pub mod hoang;

/// Trait for a pseudorandom permutation over a small domain [N'].
///
/// Both `forward` and `inverse` must be deterministic for a given key.
/// `forward(inverse(x)) == x` and `inverse(forward(x)) == x` for all x in [domain].
pub trait Prp: Send + Sync {
    /// Evaluate the permutation: P_k(x).
    fn forward(&self, x: usize) -> usize;

    /// Evaluate the inverse permutation: P_k^{-1}(y).
    fn inverse(&self, y: usize) -> usize;

    /// The domain size N'. Valid inputs are 0..N'-1.
    fn domain(&self) -> usize;

    /// Evaluate forward on 4 inputs simultaneously (AES-NI pipelining).
    /// Default: sequential. Override for backends with 4-way support.
    fn forward_4(&self, xs: [usize; 4]) -> [usize; 4] {
        [self.forward(xs[0]), self.forward(xs[1]), self.forward(xs[2]), self.forward(xs[3])]
    }

    /// Evaluate inverse on 4 inputs simultaneously (AES-NI pipelining).
    /// Default: sequential. Override for backends with 4-way support.
    fn inverse_4(&self, ys: [usize; 4]) -> [usize; 4] {
        [self.inverse(ys[0]), self.inverse(ys[1]), self.inverse(ys[2]), self.inverse(ys[3])]
    }
}

/// Extended PRP trait for batch full-domain permutation table generation.
///
/// Used during the offline phase to generate the full permutation table
/// in one shot, instead of calling `forward()` N times sequentially.
///
/// - [`fast::FastPrpWrapper`] uses the native O(N log N) `batch_permute()`.
/// - [`hoang::HoangPrp`] and [`alf::AlfPrp`] use rayon parallel iteration.
pub trait BatchPrp: Prp {
    /// Compute the full permutation table: `result[x] = forward(x)` for all x in [0, domain()).
    fn batch_forward(&self) -> Vec<usize>;
}
