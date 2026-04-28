(* ---------------------------------------------------------------------- *
 * Protocol.ec — the `Real` model: an abstract description of what
 * the BitcoinPIR client emits on the wire for a single query, in the
 * ideal-primitives world.
 *
 * Modelling choices:
 *
 *  - Cryptographic primitives (DPF.gen, FHE.encrypt, PRP.eval) are
 *    treated as black boxes producing fresh uniformly-random bytes
 *    of fixed length. The protocol invokes them at well-defined
 *    points; we do not reason about their internals. This matches
 *    the user's stated preference ("I tend to avoid verifying
 *    actual cryptography but prefer to treat them as black boxes").
 *
 *  - The protocol is parameterised by a backend tag
 *    (BDpf / BHarmony / BOnion) because the round-sequence shape
 *    differs (DPF emits per-server x2; OnionPIR is single-server;
 *    Harmony has a hint-server side band). The simulator argument
 *    is run once per backend.
 *
 *  - The `Real` module's `query(q)` procedure returns the wire
 *    transcript a server-side observer sees. Privacy reduces to
 *    "the distribution of this transcript depends only on L(q)".
 * --------------------------------------------------------------------- *)

require import Common Leakage.
require import AllCore List Distr Int.

(* ---------- Round-shape primitives ---------- *
 * Each procedure returns a `round_profile` whose request_bytes and
 * response_bytes are determined by the protocol's encoding, and
 * whose `items` Vec is the per-group / per-query count we've already
 * proven structurally invariant in Kani.
 *
 * Implementation as `op` rather than `module` because the round-shape
 * is a deterministic function of the protocol params; only the byte
 * *content* varies (and that's randomised by the underlying
 * primitives, modelled as fresh uniform samples below).
 *)

(* ---------- Index round shape ---------- *
 * For DPF, each query produces TWO Index rounds (server 0 + server 1).
 * For OnionPIR, ONE Index round (single server). For Harmony, ONE
 * Index round on the query server.
 * Items: K entries, each = INDEX_CUCKOO_NUM_HASHES (= 2 for DPF/Onion,
 * T-1 for Harmony). The integration tests pin the per-backend value
 * empirically; this proof treats it as an axiom.
 *)
op index_request_bytes : backend -> int.
op index_response_bytes : backend -> int.
op index_items_per_group : backend -> int.

axiom index_items_per_group_pos :
  forall (b : backend), 1 <= index_items_per_group b.

(* ---------- Chunk round shape ---------- *
 * The CHUNK Round-Presence Symmetry invariant says: every query
 * (found OR not-found OR whale) emits at least one Chunk round.
 * For not-found, the round is fully synthetic dummies; for found,
 * one item per chunk_id. Wire-byte sizes are FIXED-length per group
 * (DPF/FHE encoding pads to a fixed envelope), so request_bytes and
 * response_bytes don't depend on which groups have real queries.
 *)
op chunk_request_bytes : backend -> int.
op chunk_response_bytes : backend -> int.
op chunk_items_per_group : backend -> int.

(* ---------- Merkle round shape ---------- *
 * The Merkle INDEX item-count symmetry invariant: every query
 * contributes exactly INDEX_CUCKOO_NUM_HASHES = 2 INDEX Merkle items.
 * Each sibling-pass round has K (or K_merkle for OnionPIR) groups
 * with one DPF/FHE key per group.
 *)
op merkle_index_pass_bytes_in : backend -> int.
op merkle_index_pass_bytes_out : backend -> int.
op merkle_chunk_pass_bytes_in : backend -> int.
op merkle_chunk_pass_bytes_out : backend -> int.

(* ---------- The Real protocol module ---------- *
 * `Real(b).query(q)` runs a full PIR query and returns the
 * server-observable transcript. The body is split out so the
 * simulator can replicate the same control-flow structure with
 * ideal-primitive samples replaced by fresh uniform bytes.
 *
 * For now we declare the module abstractly; the per-backend body is
 * a separate file (Protocol_DPF.ec etc.) to avoid one giant file.
 *)
module type ProtocolRunner = {
  proc query(b : backend, q : query) : transcript
}.

module Real : ProtocolRunner = {
  proc query(b : backend, q : query) : transcript = {
    var t : transcript;
    (* TODO: per-backend implementation. The shape is determined by
     * the round_kind sequence pinned in
     * pir-sdk-client/tests/leakage_integration_test.rs (per-backend
     * empirically-verified profiles) and by the structural
     * invariants in Common.ec.
     *
     * The procedure must:
     *   1. Emit Info / OnionKeyRegister rounds (deterministic shape).
     *   2. Emit Index round(s) — items = [index_items_per_group b; K]
     *      sampled uniformly because DPF.gen produces fresh keys per
     *      call.
     *   3. Emit one or more Chunk rounds (CHUNK Round-Presence
     *      invariant), each with items = [chunk_items_per_group b;
     *      K_chunk].
     *   4. Emit MerkleTreeTops + per-level IndexMerkleSiblings +
     *      ChunkMerkleSiblings rounds.
     *
     * Per the modelling discussion above, the bytes within each round
     * are uniform fresh samples; only the structural shape is
     * deterministic. *)
    t <- empty_transcript;
    return t;
  }
}.
