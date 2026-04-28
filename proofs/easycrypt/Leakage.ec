(* ---------------------------------------------------------------------- *
 * Leakage.ec — the leakage function L : query -> leakage.
 *
 * `L(q)` enumerates every axis the protocol *admits* to leak. The
 * security theorem in `Theorem.ec` says: any two queries q1, q2 with
 * L(q1) = L(q2) produce indistinguishable transcripts. So the more
 * `L` admits, the weaker the privacy claim — and any axis missing
 * from `L` becomes an unprovable lemma later (catching it at proof
 * time is the irreducible benefit of formal verification we couldn't
 * get from Kani / integration tests / cross-language diff alone).
 *
 * Current admitted axes (cf. CLAUDE.md "What the Server Learns"):
 *
 *   1. chunk_merkle_item_count : number of CHUNK Merkle items the
 *      query contributes. Reveals approximate UTXO count for found
 *      queries (a not-found query contributes 0 — but the client
 *      always emits at least one CHUNK PIR round per the
 *      "CHUNK Round-Presence Symmetry" invariant, so found-vs-not-
 *      found is *not* leaked at the round-presence level).
 *      Closing this axis would require padding CHUNK Merkle items
 *      to a fixed M per query.
 *
 *   2. timing_bucket : timing patterns across rounds. We do not
 *      model the wall-clock dimension here; the wire-shape proof
 *      below is timing-oblivious. A timing-aware extension would
 *      annotate each `round_profile` with a duration bucket.
 *
 * Axes the protocol does NOT leak (these are the obligations the
 * proof must discharge):
 *   - the script-hash bytes
 *   - found-vs-not-found at the round-presence level (closed by
 *     CHUNK Round-Presence Symmetry, 2026)
 *   - the cuckoo position of a match (closed by Merkle INDEX
 *     Item-Count Symmetry, 2026)
 *   - which PBC group contains the real query (closed by K-padding)
 * --------------------------------------------------------------------- *)

require import Common.

(* ---------- Leakage record ---------- *
 * The simulator gets exactly this; nothing else.
 *)
type leakage = {
  chunk_merkle_item_count : int;
  (* timing_bucket : int;  — declared in spec, not modelled here *)
}.

(* The leakage function. We declare it abstractly: the proof obligation
 * is "for any concrete L satisfying the constraints below, the
 * simulator argument holds". The wire-level invariants we've already
 * codified in Rust (K-padding, INDEX_CUCKOO_NUM_HASHES, T-1, CHUNK
 * round-presence) are encoded here as preconditions on the protocol's
 * abstract behaviour, not on `L` itself. `L` is just the projection
 * of "what the wire reveals" onto the admitted axes.
 *)
op L : query -> leakage.

(* ---------- Range axiom for chunk_merkle_item_count ---------- *
 * Bounded by the maximum number of UTXOs a single scripthash can have
 * in a database (loosely; the actual cap is higher than any realistic
 * Bitcoin address would hit). Modelled as a non-negative integer.
 *)
axiom L_chunk_count_nonneg :
  forall (q : query), 0 <= (L q).`chunk_merkle_item_count.

(* ---------- Equivalence relation on leakage ---------- *
 * Two queries are L-equivalent iff their leakage records are equal.
 * The simulator argument's quantification: forall q1 q2,
 * L_eq q1 q2 ==> Real(q1) ~= Real(q2).
 *)
op L_eq (q1 q2 : query) : bool =
  (L q1) = (L q2).

lemma L_eq_refl (q : query) : L_eq q q
proof.
  by rewrite /L_eq.
qed.

lemma L_eq_sym (q1 q2 : query) : L_eq q1 q2 => L_eq q2 q1
proof.
  by rewrite /L_eq.
qed.

lemma L_eq_trans (q1 q2 q3 : query) :
  L_eq q1 q2 => L_eq q2 q3 => L_eq q1 q3
proof.
  by rewrite /L_eq => -> ->.
qed.
