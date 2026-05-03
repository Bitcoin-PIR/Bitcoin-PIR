//! HarmonyPIR client protocol (Algorithm 3 + Algorithm 7).
//!
//! # Protocol overview
//!
//! ## Offline phase (PIR.Offline)
//!
//! 1. Initialize the restricted relocation data structure DS' with 2N cells
//!    and segment size T. The permutation P determines the initial layout.
//! 2. Compute M = 2N/T hint parities. Hint parity H[i] is the XOR of all
//!    database entries whose indices appear in segment i of DS'.
//!    - Stream the database entry by entry.
//!    - For each entry DB[k], find its cell via Locate(k), determine its
//!      segment s = ⌊cell/T⌋, and XOR DB[k] into H[s].
//!
//! ## Online phase (PIR.Online) — one query
//!
//! Given a query index q:
//!
//! ### Request construction (Algorithm 3, lines 4-10)
//! 1. Locate q in DS': cell c = Locate(q), segment s = ⌊c/T⌋, position r = c mod T.
//! 2. Build request Q of size T:
//!    - For each position i ≠ r: Q[i] = Access(s·T + i) (the values in segment s).
//!    - For position r: sample a random cell l not in the relocated set C and not in
//!      segment s, and set Q[r] = Access(l).
//!    - This hides which position in the segment contains the query.
//!
//! ### Response + answer (line 11-12)
//! 3. Send Q to the server. Receive response R = [DB[Q[0]], DB[Q[1]], ...].
//! 4. Compute the answer: A = H[s] ⊕ XOR_{i≠r} R[i].
//!    Since H[s] = XOR of all DB entries at indices in segment s, and R gives us
//!    all of them except DB[q], the result A = DB[q].
//!
//! ### Relocation + hint update (Algorithm 7)
//! 5. RelocateSegment(s): the T values in segment s move to random empty cells.
//! 6. Update hint parities: for each relocated value, find its new segment
//!    and XOR the corresponding DB entry into the new segment's hint.
//!    Algorithm 7 optimizes this by locating the destination empty-value cells
//!    rather than re-locating each original value.
//!
//! After M/2 queries, all empty cells are used up. Re-run the offline phase.

use rand::Rng;

use crate::error::{HarmonyPirError, Result};
use crate::params::Params;
use crate::prp::Prp;
use crate::relocation::{RelocationDS, EMPTY};
use crate::server::Server;
use crate::util::{xor_bytes_into, zero_entry};

/// The HarmonyPIR client.
///
/// Holds the relocation data structure DS' and the hint parities H.
pub struct Client {
    /// Protocol parameters.
    params: Params,
    /// The restricted relocation data structure.
    ds: RelocationDS,
    /// Hint parities: M entries, each of w bytes.
    /// H[i] = XOR of DB[v] for all values v in segment i of DS'.
    hints: Vec<Vec<u8>>,
    /// Number of queries executed since the last offline phase.
    query_count: usize,
}

impl Client {
    /// Run the offline phase: initialize DS' and compute hint parities by
    /// streaming the database from the server.
    ///
    /// # Arguments
    /// - `params`: protocol parameters (N, w, T, etc.).
    /// - `prp`: a PRP over domain [2N], used to initialize DS'.
    /// - `server`: the server holding the database.
    pub fn offline(params: Params, prp: Box<dyn Prp>, server: &Server) -> Result<Self> {
        // Step 1: Initialize DS' with 2N cells and segment size T.
        let ds = RelocationDS::new(params.n, params.t, prp)?;

        // Step 2: Initialize M hint parities to zero.
        let mut hints: Vec<Vec<u8>> = (0..params.m).map(|_| zero_entry(params.w)).collect();

        // Step 3: Stream the database and compute hint parities.
        // For each entry DB[k], find its cell, determine its segment, XOR into hint.
        server.stream_db(|k, entry| {
            let cell = ds.locate(k).expect("Locate should succeed during offline");
            let segment = cell / params.t;
            xor_bytes_into(&mut hints[segment], entry);
        });

        Ok(Client {
            params,
            ds,
            hints,
            query_count: 0,
        })
    }

    /// Execute a single online query for database index `q`.
    ///
    /// Returns the retrieved database entry DB[q].
    pub fn query(&mut self, q: usize, server: &Server, rng: &mut impl Rng) -> Result<Vec<u8>> {
        if q >= self.params.n {
            return Err(HarmonyPirError::InvalidIndex {
                index: q,
                max: self.params.n - 1,
            });
        }
        if self.query_count >= self.params.max_queries {
            return Err(HarmonyPirError::NoMoreQueries);
        }

        let t = self.params.t;

        // === Request construction (Algorithm 3, lines 4-10) ===

        // Locate q: find its cell, segment, and position within the segment.
        let c = self.ds.locate(q)?;
        let s = c / t; // segment index
        let r = c % t; // position within segment

        // Build request Q of size T.
        let mut request = vec![EMPTY; t];

        // For i ≠ r: Q[i] = Access(s·T + i), the other values in segment s.
        for i in 0..t {
            if i != r {
                request[i] = self.ds.access(s * t + i)?;
            }
        }

        // For position r: sample a random cell NOT in relocated set C and NOT in segment s.
        // Use rejection sampling.
        let l = self.sample_random_cell(s, rng)?;
        request[r] = self.ds.access(l)?;

        // === Send request to server and receive response (line 11) ===
        let response = server.answer(&request);

        // === Compute the answer (line 12) ===
        // A = H[s] ⊕ XOR_{i ∈ [T]\{r}} R[i]
        let mut answer = self.hints[s].clone();
        for i in 0..t {
            if i != r {
                xor_bytes_into(&mut answer, &response[i]);
            }
        }
        // `answer` now equals DB[q].

        // === Relocation + hint update (Algorithm 7) ===
        self.relocate_and_update_hints(s, r, &response, &answer)?;

        self.query_count += 1;
        Ok(answer)
    }

    /// Algorithm 7: Optimized hint relocation.
    ///
    /// After querying segment s, relocate its values to random empty cells
    /// and update the hint parities accordingly.
    ///
    /// Instead of calling Locate on each value in Q to find its new segment,
    /// we use the knowledge that the j-th cell relocated from segment s goes to
    /// cell Locate(N + m·T + j), where m is the count of previously relocated segments.
    fn relocate_and_update_hints(
        &mut self,
        s: usize,
        r: usize,
        response: &[Vec<u8>],
        answer: &[u8],
    ) -> Result<()> {
        let t = self.params.t;
        let n = self.params.n;

        // m = number of segments relocated before this one.
        let m = self.ds.relocated_segment_count();

        // Step 1: RelocateSegment(s).
        self.ds.relocate_segment(s)?;

        // Step 2: Update hint parities.
        // The i-th cell of segment s has relocated to cell Locate(N + m·T + i).
        for i in 0..t {
            // Find the destination segment for the i-th cell of segment s.
            let empty_value = n + m * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)?;
            let d_i = dest_cell / t;

            if i != r {
                // This cell held a request value Q[i]. The DB entry is response[i].
                xor_bytes_into(&mut self.hints[d_i], &response[i]);
            } else {
                // This cell held the query index q. The DB entry is `answer` (= DB[q]).
                xor_bytes_into(&mut self.hints[d_i], answer);
            }
        }

        Ok(())
    }

    /// Sample a random cell that is:
    /// - Not in the relocated set C.
    /// - Not in segment s (except we exclude only non-r positions, but for simplicity
    ///   we exclude the entire segment s).
    ///
    /// Uses rejection sampling. Expected O(1) attempts since at most half the cells
    /// are relocated after M/2 queries.
    fn sample_random_cell(
        &self,
        excluded_segment: usize,
        rng: &mut impl Rng,
    ) -> Result<usize> {
        let domain = 2 * self.params.n;
        let t = self.params.t;

        for _ in 0..10_000 {
            let cell = rng.gen_range(0..domain);
            let cell_segment = cell / t;

            // Skip if in the excluded segment.
            if cell_segment == excluded_segment {
                continue;
            }

            // Skip if the cell's segment has been relocated.
            if self.ds.is_cell_in_relocated_segment(cell) {
                continue;
            }

            return Ok(cell);
        }

        // Should never happen with correct parameters.
        Err(HarmonyPirError::InvalidParams(
            "rejection sampling failed to find a valid cell",
        ))
    }

    /// Handle a database modification at index `i`.
    ///
    /// The server sends `diff = DB_old[i] ⊕ DB_new[i]`.
    /// The client updates the hint parity of the segment containing index i.
    pub fn apply_modification(&mut self, i: usize, diff: &[u8]) -> Result<()> {
        let cell = self.ds.locate(i)?;
        let segment = cell / self.params.t;
        xor_bytes_into(&mut self.hints[segment], diff);
        Ok(())
    }

    /// Number of queries executed since the last offline phase.
    pub fn queries_used(&self) -> usize {
        self.query_count
    }

    /// Number of queries remaining before the offline phase must be re-run.
    pub fn queries_remaining(&self) -> usize {
        self.params.max_queries - self.query_count
    }

    /// The protocol parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "alf")]
    use crate::prp::alf::AlfPrp;
    #[cfg(feature = "fastprp-prp")]
    use crate::prp::fast::FastPrpWrapper;
    use crate::prp::hoang::HoangPrp;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Create a test database of N entries, each w bytes.
    fn make_test_db(n: usize, w: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                // Deterministic but distinct entries.
                let mut entry = vec![0u8; w];
                let bytes = (i as u64).to_le_bytes();
                let copy_len = bytes.len().min(w);
                entry[..copy_len].copy_from_slice(&bytes[..copy_len]);
                // Add some variation.
                if w > 8 {
                    entry[8] = (i * 37) as u8;
                    entry[w - 1] = (i * 53) as u8;
                }
                entry
            })
            .collect()
    }

    #[test]
    fn test_single_query_correctness() {
        let n = 64;
        let w = 32;
        let t = 8; // 2*64/8 = 16 segments, max_queries = 8
        let key = [0x42u8; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(123);

        // Query index 0.
        let result = client.query(0, &server, &mut rng).unwrap();
        assert_eq!(result, db[0], "query(0) returned wrong entry");
    }

    #[test]
    fn test_multiple_queries_correctness() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0xAB; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(456);

        // Query several different indices.
        let queries = [0, 10, 63, 1, 32, 7, 50, 20];
        for &q in &queries[..client.params().max_queries.min(queries.len())] {
            let result = client.query(q, &server, &mut rng).unwrap();
            assert_eq!(result, db[q], "query({q}) returned wrong entry");
        }
    }

    #[test]
    fn test_repeated_queries_same_index() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0xCD; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let max_q = params.max_queries;
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(789);

        // Query the same index repeatedly.
        for _ in 0..max_q {
            let result = client.query(5, &server, &mut rng).unwrap();
            assert_eq!(result, db[5]);
        }
    }

    #[test]
    fn test_no_more_queries_error() {
        let n = 8;
        let w = 4;
        let t = 4; // max_queries = 8/4 = 2
        let key = [0xEF; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let server = Server::new(db);
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(0);

        // Use all queries.
        for _ in 0..2 {
            client.query(0, &server, &mut rng).unwrap();
        }

        // Next query should fail.
        let result = client.query(0, &server, &mut rng);
        assert!(matches!(result, Err(HarmonyPirError::NoMoreQueries)));
    }

    #[test]
    fn test_database_modification() {
        let n = 64;
        let w = 32;
        let t = 8;
        let key = [0x11; 16];
        let r = 44;

        let db = make_test_db(n, w);
        let mut server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let prp = Box::new(HoangPrp::new(2 * n, r, &key));
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(999);

        // Modify entry 10.
        let new_entry = vec![0xFF; w];
        let diff = server.modify_entry(10, new_entry.clone());
        client.apply_modification(10, &diff).unwrap();

        // Query index 10 should return the new entry.
        let result = client.query(10, &server, &mut rng).unwrap();
        assert_eq!(result, new_entry);
    }

    // ================================================================
    // End-to-end protocol tests for all PRP implementations
    // ================================================================

    /// Helper: run full protocol (offline + multiple queries) with any PRP.
    fn run_protocol_test(prp: Box<dyn crate::prp::Prp>, n: usize, w: usize, t: usize) {
        let db = make_test_db(n, w);
        let server = Server::new(db.clone());
        let params = Params::new(n, w, t).unwrap();
        let mut client = Client::offline(params, prp, &server).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let max_q = client.params().max_queries;

        // Query every index we can (up to max_queries), cycling through the database.
        for i in 0..max_q {
            let q = i % n;
            let result = client.query(q, &server, &mut rng).unwrap();
            assert_eq!(
                result, db[q],
                "query({q}) returned wrong entry on iteration {i}"
            );
        }
    }

    // --- FastPRP protocol tests ---

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_small() {
        // N=64, domain=128
        let n = 64;
        let prp = Box::new(FastPrpWrapper::new(&[0x42u8; 16], 2 * n));
        run_protocol_test(prp, n, 32, 8);
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_medium() {
        // N=1024, domain=2048, 40-byte entries
        let n = 1024;
        let w = 40;
        let t = 32; // sqrt(1024) = 32
        let prp = Box::new(FastPrpWrapper::new(&[0xABu8; 16], 2 * n));
        run_protocol_test(prp, n, w, t);
    }

    #[cfg(feature = "fastprp-prp")]
    #[test]
    fn test_fastprp_protocol_with_group_key() {
        let n = 512;
        let prp = Box::new(FastPrpWrapper::with_group(&[0x42u8; 16], 7, 2 * n));
        run_protocol_test(prp, n, 32, 16);
    }

    // --- ALF protocol tests ---

    #[cfg(feature = "alf")]
    #[test]
    fn test_alf_protocol() {
        // ALF minimum domain is 65536, so N >= 32768.
        let n = 32768;
        let w = 40;
        let t = 128; // ~sqrt(32768) ≈ 181, use 128 for clean segments
        let domain = 2 * n; // 65536
        let prp = Box::new(AlfPrp::new(&[0x42u8; 16], domain, &[0u8; 16], 0));
        run_protocol_test(prp, n, w, t);
    }

    #[cfg(feature = "alf")]
    #[test]
    fn test_alf_protocol_different_tweaks() {
        // Two different tweaks produce valid but different protocol runs.
        let n = 32768;
        let w = 32;
        let t = 128;
        let domain = 2 * n;
        let key = [0x42u8; 16];

        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        for tweak_byte in [0u8, 1u8, 2u8] {
            let mut tweak = [0u8; 16];
            tweak[0] = tweak_byte;
            let prp = Box::new(AlfPrp::new(&key, domain, &tweak, 0));
            let params = Params::new(n, w, t).unwrap();
            let mut client = Client::offline(params, prp, &server).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(100 + tweak_byte as u64);

            // Each tweak should still produce correct query results.
            for q in [0, 1, 100, 1000, n - 1] {
                let result = client.query(q, &server, &mut rng).unwrap();
                assert_eq!(result, db[q], "tweak={tweak_byte} query({q}) wrong");
            }
        }
    }

    // --- Hoang protocol test at larger size ---

    #[test]
    fn test_hoang_protocol_medium() {
        let n = 1024;
        let w = 40;
        let t = 32;
        let r = 44;
        let prp = Box::new(HoangPrp::new(2 * n, r, &[0xCDu8; 16]));
        run_protocol_test(prp, n, w, t);
    }

    // --- Cross-PRP consistency test ---

    #[test]
    fn test_all_prps_produce_correct_queries() {
        // Same database, available PRPs should return correct results.
        let n = 512;
        let w = 32;
        let t = 16;
        let db = make_test_db(n, w);
        let server = Server::new(db.clone());

        let prps: Vec<(&str, Box<dyn crate::prp::Prp>)> = vec![
            ("Hoang", Box::new(HoangPrp::new(2 * n, 44, &[1u8; 16]))),
            #[cfg(feature = "fastprp-prp")]
            ("FastPRP", Box::new(FastPrpWrapper::new(&[2u8; 16], 2 * n))),
            // ALF skipped — domain 1024 < 65536 minimum.
        ];

        for (name, prp) in prps {
            let params = Params::new(n, w, t).unwrap();
            let mut client = Client::offline(params, prp, &server).unwrap();
            let mut rng = ChaCha20Rng::seed_from_u64(77);

            for q in [0, 1, n / 2, n - 1] {
                let result = client.query(q, &server, &mut rng).unwrap();
                assert_eq!(result, db[q], "{name}: query({q}) returned wrong entry");
            }
        }
    }
}
