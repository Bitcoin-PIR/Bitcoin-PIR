//! Restricted relocation data structure DS' (Section 4 + Algorithm 6).
//!
//! # Overview
//!
//! DS' stores a conceptual array of 2N' cells. Each of the N' values in [N']
//! appears in exactly one cell, and the remaining N' cells are "empty" (⊥).
//! The initial assignment is determined by a random permutation P of size 2N':
//!
//! - Cell P(v) contains value v, for v ∈ [N'].
//! - Cell P(N' + j) is empty (the j-th "empty slot"), for j ∈ [N'].
//!
//! ## Operations
//!
//! - **Access(c) → v**: Return the value currently in cell c (or ⊥ if empty).
//! - **Locate(v) → c**: Return the cell currently containing value v.
//! - **RelocateSegment(s)**: Move all T values in segment s to random empty cells.
//!
//! ## How relocation works
//!
//! The i-th Relocate operation on any cell c moves the value in c to the cell
//! that originally held the i-th empty value (i.e., cell P(N' + i)).
//! This is tracked by the history data structure Hist'.
//!
//! Access and Locate perform **chain-walking**: following the chain of relocations
//! through the history until reaching a cell that hasn't been relocated from.
//!
//! ## Cycle detection
//!
//! When P(N' + j) = Hist[j] for some j (a fixed point in the relocation mapping),
//! the chain-walk can cycle. This occurs when the permutation maps an empty-slot
//! destination back to the same cell. We detect this by checking if the chain
//! revisits a cell, and treat the value as residing at that cell.
//!
//! ## Memory efficiency
//!
//! DS' never materializes the 2N' cells. Instead, it stores only:
//! - The PRP P (which can evaluate P(x) and P^{-1}(y) on demand).
//! - The history Hist' (O(number_of_relocated_segments) entries).
//!
//! Total client storage for the DS' is O(M) words, not O(N).

use crate::error::{HarmonyPirError, Result};
use crate::hist::HistPrime;
use crate::prp::Prp;

/// The "empty" sentinel value, analogous to ⊥ in the paper.
pub const EMPTY: usize = usize::MAX;

/// Restricted relocation data structure DS'.
///
/// Parameterized by the PRP that defines the initial permutation.
pub struct RelocationDS {
    /// N': number of real values. The domain of P is [2N'].
    n_prime: usize,
    /// T: segment size.
    t: usize,
    /// The pseudorandom permutation P over [2N'].
    prp: Box<dyn Prp>,
    /// Segment-level history tracking.
    hist: HistPrime,
}

impl RelocationDS {
    /// Initialize DS' with 2*n_prime cells and segment size t.
    ///
    /// - `n_prime`: number of real values (N' in the paper; equals N for HarmonyPIR).
    /// - `t`: segment size T.
    /// - `prp`: a PRP over domain [2*n_prime].
    ///
    /// After initialization:
    /// - Cell P(v) holds value v for v in [N'].
    /// - Cell P(N'+j) is empty for j in [N'].
    /// - Segments partition the 2N' cells into chunks of T.
    pub fn new(n_prime: usize, t: usize, prp: Box<dyn Prp>) -> Result<Self> {
        let domain = 2 * n_prime;
        if prp.domain() != domain {
            return Err(HarmonyPirError::InvalidParams(
                "PRP domain must equal 2 * n_prime",
            ));
        }
        if domain % t != 0 {
            return Err(HarmonyPirError::InvalidParams(
                "T must divide 2 * n_prime",
            ));
        }

        Ok(RelocationDS {
            n_prime,
            t,
            prp,
            hist: HistPrime::new(t),
        })
    }

    /// Access: return the value currently in cell `c`.
    ///
    /// Returns the database index (in [N']) stored at cell c, or EMPTY if the cell
    /// is logically empty.
    ///
    /// # Algorithm (Algorithm 6, lines 4-11)
    ///
    /// Chain-walk from cell c. If P^{-1}(c) >= N' (originally empty slot) and
    /// the history says a value was relocated into it, follow to the source cell.
    /// Repeat until reaching a cell with P^{-1}(c) < N' (original real value)
    /// or an empty slot with no relocation.
    pub fn access(&self, c: usize) -> Result<usize> {
        let domain = 2 * self.n_prime;
        if c >= domain {
            return Err(HarmonyPirError::InvalidIndex {
                index: c,
                max: domain - 1,
            });
        }

        let mut cell = c;
        let max_steps = self.n_prime + 1;

        for _ in 0..max_steps {
            let inv = self.prp.inverse(cell);
            if inv < self.n_prime {
                return Ok(inv);
            }
            // inv >= N': cell was originally an empty slot.
            let empty_idx = inv - self.n_prime;
            match self.hist.index_lookup(empty_idx) {
                Some(source_cell) => {
                    if source_cell == cell {
                        // Fixed point: P(N' + pos) maps back to the same cell.
                        // The value that was relocated here came from this cell itself;
                        // the original value at this cell is P^{-1}(cell).
                        // Since P^{-1}(cell) >= N', this cell is empty.
                        return Ok(EMPTY);
                    }
                    cell = source_cell;
                }
                None => {
                    return Ok(EMPTY);
                }
            }
        }

        Err(HarmonyPirError::ChainWalkExceeded { max_steps })
    }

    /// Locate: find the cell currently containing value `v` (for v in [N']).
    ///
    /// # Algorithm (Algorithm 6, lines 12-16)
    ///
    /// Start at cell P(v). If that cell was relocated, the value moved to
    /// P(N' + Hist'^{-1}[cell]). Repeat until reaching an un-relocated cell.
    pub fn locate(&self, v: usize) -> Result<usize> {
        if v >= self.n_prime {
            return Err(HarmonyPirError::InvalidIndex {
                index: v,
                max: self.n_prime - 1,
            });
        }
        self.locate_impl(v)
    }

    /// Locate a value in the extended domain [2N'].
    ///
    /// This is the modified Locate from Section 10 that supports finding cells
    /// containing even "empty values" (values N'..2N'-1), used for the
    /// optimized hint relocation (Algorithm 7).
    pub fn locate_extended(&self, v: usize) -> Result<usize> {
        let domain = 2 * self.n_prime;
        if v >= domain {
            return Err(HarmonyPirError::InvalidIndex {
                index: v,
                max: domain - 1,
            });
        }
        self.locate_impl(v)
    }

    /// Shared implementation for Locate and Locate-extended.
    ///
    /// Chain-walks from P(v) following relocation history until reaching
    /// a cell not in the relocated set.
    fn locate_impl(&self, v: usize) -> Result<usize> {
        let mut cell = self.prp.forward(v);
        let max_steps = self.n_prime + 1;

        for _ in 0..max_steps {
            match self.hist.value_lookup(cell) {
                Some(pos) => {
                    let new_cell = self.prp.forward(self.n_prime + pos);
                    if new_cell == cell {
                        // Fixed point: P(N' + pos) = cell. The value relocated
                        // from this cell ended up back in the same cell (via the
                        // empty-slot mapping). The value is at this cell.
                        return Ok(cell);
                    }
                    cell = new_cell;
                }
                None => {
                    return Ok(cell);
                }
            }
        }

        Err(HarmonyPirError::ChainWalkExceeded { max_steps })
    }

    /// RelocateSegment: relocate all T values in segment `s` to random empty cells.
    ///
    /// This simply records the segment in the history. The actual "movement" is
    /// implicit: subsequent Access/Locate calls will follow the chain through
    /// the history to find the new locations.
    pub fn relocate_segment(&mut self, s: usize) -> Result<()> {
        let num_segments = (2 * self.n_prime) / self.t;
        if s >= num_segments {
            return Err(HarmonyPirError::InvalidIndex {
                index: s,
                max: num_segments - 1,
            });
        }
        self.hist.append(s);
        Ok(())
    }

    /// The segment size T.
    pub fn segment_size(&self) -> usize {
        self.t
    }

    /// Total number of segments: 2N'/T.
    pub fn num_segments(&self) -> usize {
        (2 * self.n_prime) / self.t
    }

    /// N' (number of real values).
    pub fn n_prime(&self) -> usize {
        self.n_prime
    }

    /// Number of segments that have been relocated so far.
    pub fn relocated_segment_count(&self) -> usize {
        self.hist.len()
    }

    /// Number of cells that have been relocated (= relocated_segments * T).
    pub fn relocated_cell_count(&self) -> usize {
        self.hist.relocated_cell_count()
    }

    /// Check if a cell belongs to a relocated segment.
    pub fn is_cell_in_relocated_segment(&self, c: usize) -> bool {
        self.hist.is_cell_relocated(c)
    }

    /// Batch Access: return the value in each cell, using round-based 4-way PRP.
    ///
    /// Round 1: batch `inverse_4` on all cells.
    /// Most cells resolve immediately (inv < N').
    /// Cells needing chain-walk are collected for subsequent rounds.
    pub fn batch_access(&self, cells: &[usize]) -> Result<Vec<usize>> {
        let n = cells.len();
        let mut results = vec![EMPTY; n];
        // Pending chain-walks: (result_index, current_cell)
        let mut pending: Vec<(usize, usize)> = Vec::with_capacity(n);

        // ── Round 1: batch inverse on all input cells ──
        let mut i = 0;
        while i + 4 <= n {
            let invs = self.prp.inverse_4([cells[i], cells[i+1], cells[i+2], cells[i+3]]);
            for k in 0..4 {
                self.classify_access(cells[i+k], invs[k], i+k, &mut results, &mut pending);
            }
            i += 4;
        }
        // Remainder (< 4 elements)
        for k in i..n {
            let inv = self.prp.inverse(cells[k]);
            self.classify_access(cells[k], inv, k, &mut results, &mut pending);
        }

        // ── Subsequent rounds: resolve chain-walks in batches ──
        let max_rounds = self.n_prime + 1;
        for _ in 0..max_rounds {
            if pending.is_empty() { break; }
            let mut next: Vec<(usize, usize)> = Vec::with_capacity(pending.len());

            let mut j = 0;
            while j + 4 <= pending.len() {
                let invs = self.prp.inverse_4([
                    pending[j].1, pending[j+1].1, pending[j+2].1, pending[j+3].1,
                ]);
                for k in 0..4 {
                    self.classify_access(pending[j+k].1, invs[k], pending[j+k].0, &mut results, &mut next);
                }
                j += 4;
            }
            for k in j..pending.len() {
                let inv = self.prp.inverse(pending[k].1);
                self.classify_access(pending[k].1, inv, pending[k].0, &mut results, &mut next);
            }

            pending = next;
        }

        Ok(results)
    }

    /// Classify an inverse result: real value, empty, or needs chain-walk.
    #[inline(always)]
    fn classify_access(
        &self,
        cell: usize,
        inv: usize,
        result_idx: usize,
        results: &mut [usize],
        pending: &mut Vec<(usize, usize)>,
    ) {
        if inv < self.n_prime {
            results[result_idx] = inv;
        } else {
            let empty_idx = inv - self.n_prime;
            match self.hist.index_lookup(empty_idx) {
                Some(source_cell) if source_cell != cell => {
                    pending.push((result_idx, source_cell));
                }
                _ => {
                    // EMPTY — stays as initialized.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prp::hoang::HoangPrp;

    /// Create a small DS' for testing: N'=8, T=4, domain=16.
    fn make_test_ds() -> RelocationDS {
        let key = [0x42u8; 16];
        let n_prime = 8;
        let t = 4;
        let domain = 2 * n_prime; // 16
        let r = 44;
        let prp = Box::new(HoangPrp::new(domain, r, &key));
        RelocationDS::new(n_prime, t, prp).unwrap()
    }

    #[test]
    fn test_initial_state() {
        let ds = make_test_ds();

        // Every value in [N'] should be locatable.
        let mut found_values = vec![false; ds.n_prime];
        for v in 0..ds.n_prime {
            let c = ds.locate(v).unwrap();
            assert!(c < 2 * ds.n_prime, "Locate({v}) = {c} out of range");

            // Access at that cell should return v.
            let accessed = ds.access(c).unwrap();
            assert_eq!(accessed, v, "Access(Locate({v})) = {accessed} != {v}");
            found_values[v] = true;
        }
        assert!(found_values.iter().all(|&f| f));
    }

    #[test]
    fn test_locate_access_inverse() {
        let ds = make_test_ds();

        for v in 0..ds.n_prime {
            let c = ds.locate(v).unwrap();
            let v2 = ds.access(c).unwrap();
            assert_eq!(v, v2);
        }
    }

    #[test]
    fn test_relocate_segment_preserves_invariants() {
        let mut ds = make_test_ds();

        ds.relocate_segment(0).unwrap();

        for v in 0..ds.n_prime {
            let c = ds.locate(v).unwrap();
            let v2 = ds.access(c).unwrap();
            assert_eq!(v, v2, "After relocating segment 0: Access(Locate({v})) = {v2}");
        }
    }

    #[test]
    fn test_multiple_relocations() {
        let mut ds = make_test_ds();

        ds.relocate_segment(0).unwrap();
        ds.relocate_segment(1).unwrap();

        for v in 0..ds.n_prime {
            let c = ds.locate(v).unwrap();
            let v2 = ds.access(c).unwrap();
            assert_eq!(v, v2, "After 2 relocations: Access(Locate({v})) = {v2}");
        }
    }

    #[test]
    fn test_relocated_values_move_to_new_cells() {
        let mut ds = make_test_ds();

        let initial_cells: Vec<usize> = (0..ds.n_prime)
            .map(|v| ds.locate(v).unwrap())
            .collect();

        ds.relocate_segment(0).unwrap();

        for v in 0..ds.n_prime {
            let new_cell = ds.locate(v).unwrap();
            let old_cell = initial_cells[v];
            let old_segment = old_cell / ds.segment_size();
            if old_segment == 0 {
                assert_ne!(
                    new_cell, old_cell,
                    "Value {v} should have relocated from cell {old_cell}"
                );
            }
        }
    }
}
