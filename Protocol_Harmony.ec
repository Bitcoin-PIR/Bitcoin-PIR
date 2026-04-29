(* ---------------------------------------------------------------------- *
 * Protocol_Harmony.ec — HarmonyPIR-specific instantiation of the
 * abstract `Protocol.ec` interface. See `Protocol_DPF.ec` for the
 * split rationale.
 *
 * HarmonyPIR is single-server (the query-server fan-in) plus a
 * separate hint-server side band that emits a `RHarmonyHintRefresh`
 * round when the per-group `query_count` reaches `max_queries`.
 * The session-position dependency is captured by the `harmony_refresh_due`
 * op (declared in Protocol.ec) which the abstract
 * `harmony_hint_refresh_segment` op consults.
 * --------------------------------------------------------------------- *)

require import Common Protocol.
require import AllCore List Int.

(* ---------- HarmonyPIR concrete bindings ---------- *)
axiom pir_server_ids_harmony : pir_server_ids BHarmony = [0].

(* ---------- HarmonyPIR specialisation lemmas ---------- *)

(* Harmony INDEX phase emits exactly 1 round (single query server). *)
lemma harmony_index_segment_size (db : db_id) :
  size (index_segment BHarmony db) = 1.
proof.
  by rewrite /index_segment size_map pir_server_ids_harmony.
qed.

(* Harmony CHUNK phase emits exactly 1 round. *)
lemma harmony_chunk_segment_size (db : db_id) :
  size (chunk_segment BHarmony db) = 1.
proof.
  by rewrite /chunk_segment size_map pir_server_ids_harmony.
qed.

(* Harmony emits no Onion key-register round. *)
lemma harmony_no_onion_key_register (db : db_id) :
  onion_key_register_segment BHarmony db = [].
proof.
  by rewrite /onion_key_register_segment.
qed.

(* Harmony emits the hint-refresh round IFF `harmony_refresh_due` says
 * so. The session-position dependency is the only reason
 * `query_session_query_index q` is admitted as a leakage axis (see
 * `proofs/easycrypt/Leakage.ec` axis 3). This lemma pins the wire
 * shape under the refresh-not-due case. *)
lemma harmony_no_hint_refresh_when_not_due (db : db_id) (sess_idx : int) :
  ! harmony_refresh_due sess_idx =>
  harmony_hint_refresh_segment BHarmony db sess_idx = [].
proof.
  by rewrite /harmony_hint_refresh_segment => ->.
qed.
