//! History data structures for tracking relocations.
//!
//! # Algorithm 1: `Hist` (cell-level history)
//!
//! Tracks individual cell relocations. Supports:
//! - `append(c)`: record that cell `c` was relocated.
//! - `index_lookup(p)`: given a position p in the history, return the cell at that position.
//! - `value_lookup(c)`: given a cell c, return its position in the history (if it was relocated).
//!
//! # Algorithm 2: `HistPrime` (segment-level history)
//!
//! Tracks segment relocations for the restricted relocation data structure DS'.
//! When a segment is relocated, all T cells in that segment are implicitly relocated.
//! The segment-aware indexing maps between cell-level positions and the segment history.
//!
//! Key formulas from Algorithm 2:
//! - `index_lookup(p)`: segment index = ⌊p/T⌋, returns `S[segment_index] * T + (p mod T)`
//! - `value_lookup(c)`: segment = ⌊c/T⌋, returns `M[segment] * T + (c mod T)`

use std::collections::HashMap;

/// Cell-level history data structure (Algorithm 1).
///
/// Stores the list of relocated cells and provides bidirectional lookup.
#[derive(Debug, Clone)]
pub struct Hist {
    /// L: ordered list of relocated cells.
    l: Vec<usize>,
    /// M: map from cell → position in L.
    m: HashMap<usize, usize>,
}

impl Hist {
    pub fn new() -> Self {
        Hist {
            l: Vec::new(),
            m: HashMap::new(),
        }
    }

    /// Record that cell `c` was relocated.
    pub fn append(&mut self, c: usize) {
        let pos = self.l.len();
        self.l.push(c);
        self.m.insert(c, pos);
    }

    /// Number of relocations recorded.
    pub fn len(&self) -> usize {
        self.l.len()
    }

    /// Index-based lookup: return the cell at position `p` in the history.
    /// Corresponds to `Hist[p]` in Algorithm 1.
    /// Returns None if p is out of range.
    pub fn index_lookup(&self, p: usize) -> Option<usize> {
        self.l.get(p).copied()
    }

    /// Value-based lookup: return the position of cell `c` in the history.
    /// Corresponds to `Hist^{-1}[c]` in Algorithm 1.
    /// Returns None if cell `c` was never relocated.
    pub fn value_lookup(&self, c: usize) -> Option<usize> {
        self.m.get(&c).copied()
    }
}

/// Segment-level history data structure (Algorithm 2).
///
/// Adapted for the restricted relocation data structure DS' that only supports
/// `RelocateSegment` (not individual `Relocate`). Cells within a segment are
/// relocated in deterministic order, so we only need to track which segments
/// have been relocated.
#[derive(Debug, Clone)]
pub struct HistPrime {
    /// S: ordered list of relocated segment indices.
    s: Vec<usize>,
    /// M: map from segment index → position in S.
    m: HashMap<usize, usize>,
    /// T: segment size (number of cells per segment).
    t: usize,
}

impl HistPrime {
    pub fn new(t: usize) -> Self {
        HistPrime {
            s: Vec::new(),
            m: HashMap::new(),
            t,
        }
    }

    /// Record that segment `seg` was relocated.
    /// This implicitly relocates cells [seg*T, seg*T+1, ..., seg*T+T-1].
    pub fn append(&mut self, seg: usize) {
        let pos = self.s.len();
        self.s.push(seg);
        self.m.insert(seg, pos);
    }

    /// Number of segment relocations recorded.
    pub fn len(&self) -> usize {
        self.s.len()
    }

    /// Segment-aware index lookup: given a cell-level position `p` in the
    /// history (treating all T cells of each relocated segment as consecutive),
    /// return the actual cell number.
    ///
    /// Formula: segment_pos = ⌊p/T⌋, cell_offset = p mod T.
    /// The segment at position segment_pos is S[segment_pos].
    /// The cell is S[segment_pos] * T + cell_offset.
    ///
    /// Corresponds to `Hist'[p]` in Algorithm 2.
    pub fn index_lookup(&self, p: usize) -> Option<usize> {
        let seg_pos = p / self.t;
        let cell_offset = p % self.t;
        self.s.get(seg_pos).map(|&seg| seg * self.t + cell_offset)
    }

    /// Segment-aware value lookup: given a cell `c`, return its position in
    /// the cell-level history.
    ///
    /// Formula: segment = ⌊c/T⌋, cell_offset = c mod T.
    /// The position of this segment in S is M[segment].
    /// The cell-level position is M[segment] * T + cell_offset.
    ///
    /// Corresponds to `Hist'^{-1}[c]` in Algorithm 2.
    /// Returns None if the segment containing `c` was never relocated.
    pub fn value_lookup(&self, c: usize) -> Option<usize> {
        let seg = c / self.t;
        let cell_offset = c % self.t;
        self.m.get(&seg).map(|&pos| pos * self.t + cell_offset)
    }

    /// Check whether a specific segment has been relocated.
    pub fn is_segment_relocated(&self, seg: usize) -> bool {
        self.m.contains_key(&seg)
    }

    /// Check whether a specific cell's segment has been relocated.
    pub fn is_cell_relocated(&self, c: usize) -> bool {
        self.is_segment_relocated(c / self.t)
    }

    /// The set of all relocated cells (C in the paper).
    /// Used for rejection sampling during query construction.
    pub fn relocated_cell_count(&self) -> usize {
        self.s.len() * self.t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hist_basic() {
        let mut h = Hist::new();
        h.append(10);
        h.append(20);
        h.append(30);

        assert_eq!(h.len(), 3);
        assert_eq!(h.index_lookup(0), Some(10));
        assert_eq!(h.index_lookup(1), Some(20));
        assert_eq!(h.index_lookup(2), Some(30));
        assert_eq!(h.index_lookup(3), None);

        assert_eq!(h.value_lookup(10), Some(0));
        assert_eq!(h.value_lookup(20), Some(1));
        assert_eq!(h.value_lookup(99), None);
    }

    #[test]
    fn test_hist_prime_with_t4() {
        // T = 4. Relocate segment 2, then segment 0.
        let mut hp = HistPrime::new(4);
        hp.append(2); // position 0 in S: cells 8,9,10,11
        hp.append(0); // position 1 in S: cells 0,1,2,3

        // index_lookup: position 0..3 → segment 2's cells 8..11
        assert_eq!(hp.index_lookup(0), Some(8));
        assert_eq!(hp.index_lookup(1), Some(9));
        assert_eq!(hp.index_lookup(2), Some(10));
        assert_eq!(hp.index_lookup(3), Some(11));
        // position 4..7 → segment 0's cells 0..3
        assert_eq!(hp.index_lookup(4), Some(0));
        assert_eq!(hp.index_lookup(5), Some(1));

        // value_lookup: cell 8 → segment 2 at pos 0 → 0*4 + 0 = 0
        assert_eq!(hp.value_lookup(8), Some(0));
        assert_eq!(hp.value_lookup(9), Some(1));
        // cell 0 → segment 0 at pos 1 → 1*4 + 0 = 4
        assert_eq!(hp.value_lookup(0), Some(4));
        assert_eq!(hp.value_lookup(1), Some(5));

        // cell 4 (segment 1) → not relocated
        assert_eq!(hp.value_lookup(4), None);
    }
}
