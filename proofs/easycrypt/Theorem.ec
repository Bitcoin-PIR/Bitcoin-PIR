(* ---------------------------------------------------------------------- *
 * Theorem.ec — main simulator-property statement.
 *
 *   ∀ b : backend, q1 q2 : query.
 *     L_eq q1 q2  ⇒
 *     Real(b).query(q1)  ≡_dist  Real(b).query(q2)
 *
 * This is the wire-shape simulator argument: any two queries with the
 * same admitted leakage produce identically-distributed transcripts in
 * the ideal-primitives world. Equivalent statement:
 *
 *   Real(b).query(q)  ≡_dist  Sim.query(b, L q)
 *
 * (a transcript indistinguishable from one a simulator could produce
 * given only the admitted leakage).
 *
 * The proof discharges one obligation per axis NOT in `L`. For each
 * axis we informally argue why it's structural (provable by the
 * existing per-message invariants verified in Kani / Rust) and then
 * stub the EasyCrypt tactic — actual proof closure is the Phase 3
 * follow-up.
 *
 * # Status
 *
 * All proofs below are `admit`-stubbed. The scaffolding nails down
 * the proof obligations precisely; closing them is multi-month work
 * that requires EasyCrypt fluency we do not currently have in-house.
 *
 * # Run
 *
 * Install (macOS):
 *   brew install opam
 *   opam init && opam switch create easycrypt 4.14.1
 *   opam install easycrypt alt-ergo z3
 *   easycrypt why3config
 *
 * Verify:
 *   easycrypt -I . Theorem.ec
 *
 * The `admit`-stubbed proofs typecheck but emit warnings. A successful
 * run with all admits closed would print no errors. This file is
 * gitignored from CI for now (proof closure is multi-month, see plan
 * doc); commit and PR-review of the *spec* (Common.ec, Leakage.ec,
 * Protocol.ec, Simulator.ec, the lemma statements here) is what's
 * meaningful at this stage.
 * --------------------------------------------------------------------- *)

require import Common Leakage Protocol Simulator.
require import AllCore List Distr Int.

(* ---------------------------------------------------------------------- *
 * Lemma 1 (per-backend, per-query): wire transcript depends only on L.
 *
 * For a single non-batched query, the transcript distribution is
 * identical across L-equivalent queries. This is the headline
 * simulator-property.
 * --------------------------------------------------------------------- *)
lemma simulator_property_per_query :
  forall (b : backend) (q1 q2 : query),
    L_eq q1 q2 =>
    equiv [
      Real.query ~ Real.query :
      ={glob Real} /\ b{1} = b /\ b{2} = b /\ q{1} = q1 /\ q{2} = q2
      ==>
      ={res}
    ].
proof.
  (* TODO: per-backend induction on the round-sequence structure.
   *
   * For each backend, the proof discharges:
   *
   *   (a) Info / OnionKeyRegister rounds: deterministic, identical
   *       across queries.
   *
   *   (b) Index round: items vector is K-padded with INDEX_CUCKOO
   *       per group (Kani-verified; cite in proof). Bytes are fresh
   *       uniform — sampled identically distributed in both runs.
   *
   *   (c) Chunk round: items vector is K_CHUNK-padded
   *       (Kani-verified). Bytes are fresh uniform. Round-presence
   *       fixed by CHUNK Round-Presence Symmetry — both queries
   *       emit at least one Chunk round.
   *
   *   (d) MerkleTreeTops: deterministic, identical bytes.
   *
   *   (e) IndexMerkleSiblings: pass count depends on
   *       INDEX_CUCKOO_NUM_HASHES (= 2, fixed). Items per pass = K.
   *       Bytes uniform.
   *
   *   (f) ChunkMerkleSiblings: pass count depends on the chunk
   *       Merkle item count, which IS in L (admitted leak). So
   *       L_eq q1 q2 ==> chunk_merkle_item_count agrees ==> same
   *       number of passes ==> same transcript shape on this axis.
   *
   * The proof reduces to a uniform-coupling argument: at each
   * randomized step, both runs sample from the same distribution,
   * so an identity coupling is admissible. Closure requires
   * EasyCrypt's `rnd` / `auto` / `swap` / `wp` tactics applied
   * carefully per backend.
   *)
  admit.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 2: simulator construction. Anything Real reveals, Sim
 * reveals — and Sim has only L(q) plus uniform randomness.
 *
 * Statement: `Real(b, q)` and `Sim(b, q)` produce indistinguishable
 * distributions, where `Sim` reads `L q` but otherwise sees only
 * fresh randomness.
 * --------------------------------------------------------------------- *)
lemma simulator_property_constructive :
  forall (b : backend) (q : query),
    equiv [
      Real.query ~ Sim.query :
      ={glob Real, glob Sim} /\ b{1} = b /\ b{2} = b /\ q{1} = q /\ q{2} = q
      ==>
      ={res}
    ].
proof.
  (* TODO: factor through Lemma 1. The Sim's body is identical to
   * Real's per-backend body except (a) it reads L(q) instead of q,
   * and (b) all crypto-primitive outputs come from fresh uniform
   * samples instead of "ideal-primitive evaluations" (which by
   * hypothesis are uniformly distributed).
   *
   * This Lemma is what lets us state security in the simulator
   * style: an adversary observing the transcript cannot distinguish
   * "real implementation" from "fake transcript constructed from
   * L(q) alone" — so any computation it does on the transcript is a
   * function of L(q) alone.
   *)
  admit.
qed.

(* ---------------------------------------------------------------------- *
 * Lemma 3 (adaptive, multi-query): batched / sequential queries.
 *
 * Real privacy claims need the multi-query analog: an adversary
 * issuing a sequence of queries q1, q2, ... and observing transcripts
 * t1, t2, ... learns at most (L q1, L q2, ...) plus uniform randomness.
 *
 * For DPF and OnionPIR this follows from per-query independence
 * (each query uses fresh DPF keys / FHE keys, no cross-query state).
 *
 * For HarmonyPIR the argument is more subtle: the hint state evolves
 * across queries, so Lemma 3 must be conditioned on the hint refresh
 * not having happened mid-batch (or the proof has to handle the
 * refresh as a state transition explicitly).
 * --------------------------------------------------------------------- *)
lemma simulator_property_multi_query :
  forall (b : backend) (qs1 qs2 : query list),
    size qs1 = size qs2 =>
    (forall i, 0 <= i < size qs1 => L_eq (nth witness qs1 i) (nth witness qs2 i)) =>
    (* TODO: state the equiv on the multi-query procedure once Real
     * has a `query_batch` extension. *)
    true.
proof.
  admit.
qed.
