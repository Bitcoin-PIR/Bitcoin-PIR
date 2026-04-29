(* ---------------------------------------------------------------------- *
 * Protocol_Onion.ec — OnionPIR-specific instantiation of the abstract
 * `Protocol.ec` interface. See `Protocol_DPF.ec` for the split
 * rationale.
 *
 * OnionPIR is single-server with FHE (BFV/SEAL); each session begins
 * with a one-shot `ROnionKeyRegister` round per database to upload
 * the relinearisation / Galois keys. Subsequent INDEX and CHUNK
 * rounds carry FHE-encrypted queries and per-bin decryption proceeds
 * client-side from the recovered ciphertext.
 * --------------------------------------------------------------------- *)

require import Common Protocol.
require import AllCore List Int.

(* ---------- OnionPIR concrete bindings ---------- *)
axiom pir_server_ids_onion : pir_server_ids BOnion = [0].

(* ---------- OnionPIR specialisation lemmas ---------- *)

(* Onion INDEX phase emits exactly 1 round (single FHE server). *)
lemma onion_index_segment_size (db : db_id) :
  size (index_segment BOnion db) = 1.
proof.
  by rewrite /index_segment size_map pir_server_ids_onion.
qed.

(* Onion CHUNK phase emits exactly 1 round. *)
lemma onion_chunk_segment_size (db : db_id) :
  size (chunk_segment BOnion db) = 1.
proof.
  by rewrite /chunk_segment size_map pir_server_ids_onion.
qed.

(* Onion always emits exactly one `ROnionKeyRegister` round per
 * (session, database). The protocol amortises the FHE key upload
 * across the session — a per-DB one-shot sufficient because the
 * OnionPIR server's KeyStore caches by client_id × db_id. *)
lemma onion_emits_key_register (db : db_id) :
  size (onion_key_register_segment BOnion db) = 1.
proof.
  by rewrite /onion_key_register_segment.
qed.

(* Onion emits no Harmony hint-refresh round. *)
lemma onion_no_harmony_hint_refresh (db : db_id) (sess_idx : int) :
  harmony_hint_refresh_segment BOnion db sess_idx = [].
proof.
  by rewrite /harmony_hint_refresh_segment.
qed.
