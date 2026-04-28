(* ---------------------------------------------------------------------- *
 * Simulator.ec — `Sim(L, $)`: a transcript generator that has access
 * only to L(q) and uniform randomness, NOT to q itself.
 *
 * The construction:
 *
 *   1. Read the admitted leakage record `L(q)` — that's the only
 *      query-dependent input.
 *   2. Sample fresh uniform bytes for every cryptographic envelope
 *      (DPF keys, FHE ciphertexts, PRP outputs). These are the same
 *      distributions the ideal primitives would produce.
 *   3. Emit a transcript whose round-sequence shape is deterministic
 *      per backend (matches `Real(b).query` step-for-step) and whose
 *      payload bytes are the fresh uniform samples from (2).
 *
 * The simulator-property theorem (Theorem.ec) shows
 *   Real(b).query(q) ≡  Sim(b, L q)
 * as distributions, in the ideal-primitives world. So a server-side
 * adversary observing the transcript can compute at most L(q) — any
 * additional information would distinguish Real from Sim.
 *
 * Crucially, the simulator does NOT receive q. If we accidentally
 * encoded a query-dependent axis in the transcript that L doesn't
 * admit, the simulator can't reproduce it from L(q) alone — the
 * `equiv` lemma fails and we know the protocol leaks more than the
 * spec admits. This is the *completeness* check no other tool gives
 * us.
 * --------------------------------------------------------------------- *)

require import Common Leakage Protocol.
require import AllCore List Distr Int.

module Sim : ProtocolRunner = {
  proc query(b : backend, q : query) : transcript = {
    var t : transcript;
    var leak : leakage;
    (* The simulator extracts the leakage record. The proof obligation
     * is that everything that follows is a function of `leak` and
     * uniform randomness — the simulator must NEVER re-read `q`. *)
    leak <- L q;
    (* TODO: emit the same round-sequence shape as Real(b).query(q),
     * with payload bytes drawn fresh from `dunifin` (the uniform
     * distribution over byte-strings of the appropriate length).
     *
     * Per the modelling discussion in Protocol.ec:
     *   - Info / OnionKeyRegister: deterministic shape, fixed bytes
     *     (catalog content is public).
     *   - Index: K groups × index_items_per_group, each item is a
     *     fresh uniform key.
     *   - Chunk: K_chunk groups, fresh uniform per slot. The number
     *     of Chunk rounds depends on `leak.chunk_merkle_item_count`
     *     ONLY for the *Merkle* sibling-rounds — the PIR Chunk
     *     round-count is fixed by CHUNK Round-Presence Symmetry.
     *   - MerkleTreeTops: deterministic, public bytes.
     *   - IndexMerkleSiblings × number-of-levels: each pass is K
     *     queries, fresh uniform. Number of passes is a function of
     *     INDEX_CUCKOO_NUM_HASHES (= 2 by invariant) — therefore a
     *     function of L(q) (specifically, L(q) is constant across
     *     queries on this axis, so the passes count is L-independent
     *     too).
     *   - ChunkMerkleSiblings × number-of-levels: number of items
     *     equals leak.chunk_merkle_item_count (the admitted leak),
     *     so the simulator gets this right by construction. *)
    t <- empty_transcript;
    return t;
  }
}.
