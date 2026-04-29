(* ---------------------------------------------------------------------- *
 * Protocol_DPF.ec — DPF-specific instantiation of the abstract
 * `Protocol.ec` interface.
 *
 * The shared `Protocol.ec` declares all per-round-shape parameters as
 * `op X : backend -> ...` plus the abstract `pir_server_ids : backend
 * -> int list` op. Each backend's per-backend axiom (the concrete
 * binding for `b = BDpf` etc.) lives in its own file so:
 *
 *   - Adding a new round to (say) Harmony only touches
 *     `Protocol_Harmony.ec` and the abstract op declarations in
 *     `Protocol.ec`. The DPF / Onion files are unaffected.
 *
 *   - Per-backend specialisation lemmas (e.g. "DPF emits two INDEX
 *     rounds because pir_server_ids BDpf = [0; 1]") read as standalone
 *     witnesses in the per-backend file, rather than being scattered
 *     across the abstract spec.
 *
 *   - Future backend-specific cryptographic primitive reductions
 *     (when we drop the black-box hypothesis) will land in the
 *     matching per-backend file.
 *
 * Required by Theorem.ec via `require import` so all three
 * `pir_server_ids_*` axioms are in scope wherever the simulator-
 * property statements need them.
 * --------------------------------------------------------------------- *)

require import Common Protocol.
require import AllCore List Int.

(* ---------- DPF concrete bindings ---------- *
 * The two-server DPF protocol: server 0 + server 1, no key-register,
 * no hint-refresh side band. INDEX and CHUNK rounds emit per-server
 * for an XOR-combined response.
 *)
axiom pir_server_ids_dpf : pir_server_ids BDpf = [0; 1].

(* ---------- DPF specialisation lemmas ---------- *
 * Concrete witnesses for what `Real(BDpf).query` emits. These are
 * direct instantiations of the abstract `index_segment`,
 * `chunk_segment`, `onion_key_register_segment`,
 * `harmony_hint_refresh_segment` ops at `b = BDpf`, plus the
 * `pir_server_ids_dpf` axiom. They exist as documentation:
 * a reviewer who wants to know "what does DPF emit?" reads this file
 * and gets the per-section answer without having to walk the
 * abstract ops.
 *)

(* DPF INDEX phase emits exactly 2 rounds (one per server). *)
lemma dpf_index_segment_size (db : db_id) :
  size (index_segment BDpf db) = 2.
proof.
  by rewrite /index_segment size_map pir_server_ids_dpf.
qed.

(* DPF CHUNK phase emits exactly 2 rounds (one per server). *)
lemma dpf_chunk_segment_size (db : db_id) :
  size (chunk_segment BDpf db) = 2.
proof.
  by rewrite /chunk_segment size_map pir_server_ids_dpf.
qed.

(* DPF emits no Onion key-register round. *)
lemma dpf_no_onion_key_register (db : db_id) :
  onion_key_register_segment BDpf db = [].
proof.
  by rewrite /onion_key_register_segment.
qed.

(* DPF emits no Harmony hint-refresh round, regardless of session
 * position. *)
lemma dpf_no_harmony_hint_refresh (db : db_id) (sess_idx : int) :
  harmony_hint_refresh_segment BDpf db sess_idx = [].
proof.
  by rewrite /harmony_hint_refresh_segment.
qed.
