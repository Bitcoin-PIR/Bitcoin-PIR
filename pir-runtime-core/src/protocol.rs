//! Simple binary protocol for two-level Batch PIR.
//!
//! All integers are little-endian. Messages are length-prefixed:
//!   [4B total_len][1B variant][payload...]
//!
//! The outer 4-byte length includes the variant byte.

use std::io;

// ─── Request variants ───────────────────────────────────────────────────────

pub const REQ_PING: u8 = 0x00;
pub const REQ_GET_INFO: u8 = 0x01;
pub const REQ_INDEX_BATCH: u8 = 0x11;
pub const REQ_CHUNK_BATCH: u8 = 0x21;
// 0x31 (REQ_MERKLE_SIBLING_BATCH) and 0x32 (REQ_MERKLE_TREE_TOP) are
// RETIRED. They served the legacy global N-ary tree Merkle, superseded by
// the per-bucket bin Merkle (0x33/0x34). Do not reuse these opcode values:
// pre-removal clients may still probe them, and the OnionPIR codes were
// deliberately placed at 0x50+ to avoid this range (see runtime/onionpir.rs).
pub const REQ_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const REQ_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;

// ─── HarmonyPIR request variants ────────────────────────────────────────────

pub const REQ_HARMONY_GET_INFO: u8 = 0x40;
pub const REQ_HARMONY_HINTS: u8 = 0x41;
pub const REQ_HARMONY_QUERY: u8 = 0x42;
pub const REQ_HARMONY_BATCH_QUERY: u8 = 0x43;
/// V2 hint request: server generates the PRP key (client does not send one).
pub const REQ_HARMONY_HINTS_V2: u8 = 0x44;
/// HarmonyPIR V2 half-stream hint request.
///
/// Lets a client split the V2 main hint download across two TCP sockets:
/// one fetches the INDEX half, the other fetches the CHUNK half. Both
/// halves share the same PRP key — the server pairs the two requests
/// by `session_token` and serves both halves from the same pool entry.
/// This breaks the single-stream bandwidth-delay-product cap on the
/// ~20 MB V2 stream without changing per-half wire shape: each half
/// is structurally identical to the corresponding portion of the
/// existing `REQ_HARMONY_HINTS_V2` response.
///
/// Wire: [16B session_token][1B side: 0=INDEX 1=CHUNK]
///       [optional trailing 1B db_id, only when non-zero —
///        backward compatible]
pub const REQ_HARMONY_HINTS_V2_HALF: u8 = 0x46;

// ─── TEE ORAM request variants ─────────────────────────────────────────────

/// Native TEE + ORAM lookup over the existing INDEX + CHUNK cuckoo tables.
///
/// This request carries plaintext scripthashes and therefore must be sent only
/// inside the attested encrypted channel (`REQ_HANDSHAKE` first, then an
/// encrypted frame). The server rejects cleartext ORAM lookup frames.
///
/// Wire: [1B db_id][2B count LE][count × 20B scripthash]
pub const REQ_ORAM_LOOKUP: u8 = 0x60;

// ─── Extended request variants (multi-database) ────────────────────────────

pub const REQ_GET_DB_CATALOG: u8 = 0x02;

// ─── Monitoring ────────────────────────────────────────────────────────────

pub const REQ_RESIDENCY: u8 = 0x04;

// ─── Attestation ───────────────────────────────────────────────────────────
//
// Slice 2 of the attestation work. Client sends a 32-byte nonce; server
// returns the SEV-SNP attestation report (if available), the per-DB
// manifest roots from MANIFEST.toml verification, the SHA-256 of the
// running binary, and the build's git rev. The client recomputes the
// REPORT_DATA preimage and matches it against the field embedded in the
// signed report.

pub const REQ_ATTEST: u8 = 0x05;

// ─── Anonymous credential (ARC) ────────────────────────────────────────────

/// Client presents an ARC credential before a PIR query batch.
/// Server verifies it and responds 0x00 (valid) or an error code.
pub const REQ_CREDENTIAL_PRESENT: u8 = 0x08;
/// Response: ARC credential presentation accepted.
pub const RESP_CREDENTIAL_OK: u8 = 0x08;

/// Client presents a Cashu Blind Auth Token (BAT) before a PIR query batch.
/// Server verifies the BDHKE signature and checks the spent-set.
pub const REQ_CASHU_BAT_PRESENT: u8 = 0x09;
/// Response: Cashu BAT accepted.
pub const RESP_CASHU_BAT_OK: u8 = 0x09;

// ─── Encrypted channel handshake (Slice B) ─────────────────────────────────
//
// One-round X25519 handshake before any traffic-bearing requests on a
// connection. After the handshake completes, every subsequent frame is
// AEAD-wrapped per `pir_channel::Session::seal` — the wire layout starts
// with `pir_channel::ENCRYPTED_FRAME_MAGIC` (= 0xfe), a sequence number,
// and a ChaCha20-Poly1305 ciphertext of the inner request/response.
//
// Sequence:
//   client → server:  REQ_HANDSHAKE { client_eph_pub: [u8;32], nonce: [u8;32] }
//   server → client:  RESP_HANDSHAKE { server_eph_pub: [u8;32] }
//
// The client must already know the server's long-lived static pubkey
// (via REQ_ATTEST + verifying REPORT_DATA — the V2 layout binds the
// pubkey to the chip-signed attestation). With both pubkeys + the
// nonce, both sides derive a session key via HKDF-SHA256.
//
// Cleartext requests (PING, GET_INFO, ATTEST, the handshake itself)
// remain available pre-handshake. Once the server processes a
// REQ_HANDSHAKE, the connection enters encrypted mode and any
// cleartext frame after that is a protocol error.
pub const REQ_HANDSHAKE: u8 = 0x06;

// ─── Operator-signed identity announce ─────────────────────────────────────
//
// One-shot query: client asks "who are you?" and gets a two-tier
// signed bundle:
//
//   client → server:  REQ_ANNOUNCE   (no payload)
//   server → client:  RESP_ANNOUNCE  { AnnouncementBundle bytes }
//
// where the bundle is `pir_identity::AnnouncementBundle::encode()` —
// `[cert_len:u32 LE][cert][manifest_len:u32 LE][manifest]`.
//
// The two layers it carries:
// * IdentityCert  — operator's offline Ed25519 key signs (server_id,
//                    identity_pubkey, valid_from, valid_until). Operator
//                    key is published out-of-band (eventually Nostr).
// * ChannelManifest — server's on-disk identity key signs the current
//                    boot's channel_pub (X25519, from
//                    `ChannelKeypair::generate`) + binary_sha256 +
//                    git_rev + manifest_roots + issued_at.
//
// Servers that lack the identity-key file or operator-cert file at
// startup serve attest/handshake but reject REQ_ANNOUNCE with
// RESP_ERROR; existing flows are unaffected. Clients use the bundle to
// authenticate `server_static_pub` on hosts that lack SEV-SNP (pir1),
// and as defense-in-depth on hosts that do (pir2).
pub const REQ_ANNOUNCE: u8 = 0x07;

// ─── Admin auth (Slice 3a) ─────────────────────────────────────────────────
//
// Challenge/response with ed25519. The server holds the admin's public
// key (loaded once at startup from a CLI flag or env var, eventually
// from the UKI cmdline in tier 3). The client holds the matching
// private key on the operator's laptop.
//
//   client → server:  REQ_ADMIN_AUTH_CHALLENGE
//   server → client:  RESP_ADMIN_AUTH_CHALLENGE { nonce: [u8; 32] }
//   client signs `b"BPIR-ADMIN-AUTH-V1" || nonce` with their ed25519 sk
//   client → server:  REQ_ADMIN_AUTH_RESPONSE { signature: [u8; 64] }
//   server verifies → marks the connection authenticated.
//
// Auth state lives per-WebSocket-connection on the server. Disconnecting
// is logging out. Nothing in the wire protocol persists auth across
// connections.

pub const REQ_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub const REQ_ADMIN_AUTH_RESPONSE: u8 = 0x81;

/// Domain-separation tag for admin-auth signatures. Must match between
/// client and server.
pub const ADMIN_AUTH_DOMAIN_TAG: &[u8] = b"BPIR-ADMIN-AUTH-V1";

// ─── Admin DB upload (Slice 3b) ────────────────────────────────────────────
//
// Streaming DB upload over the authenticated admin channel. After
// `REQ_ADMIN_AUTH_RESPONSE` succeeds, the client runs:
//
//   BEGIN { name, manifest_toml }     - server creates /data/.staging/<name>/
//                                        and writes MANIFEST.toml
//   CHUNK { name, file_path, offset,  - server appends bytes to the staged
//           data } × N                  file (one per file × chunk)
//   FINALIZE { name }                 - server verifies all files against
//                                        the manifest hashes; returns the
//                                        manifest_root (sha256 of MANIFEST)
//   ACTIVATE { name, target_path }    - server atomically renames
//                                        .staging/<name>/ → <target_path>/
//                                        (relative to data_root). The
//                                        operator restarts unified_server
//                                        to load the new DB (no hot-reload
//                                        in this slice).
//
// All operations require the connection to be authenticated; otherwise
// the server returns a RESP_ERROR envelope.

pub const REQ_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub const REQ_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub const REQ_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub const REQ_ADMIN_DB_ACTIVATE: u8 = 0x85;

// ─── Response variants ──────────────────────────────────────────────────────

pub const RESP_PONG: u8 = 0x00;
pub const RESP_INFO: u8 = 0x01;
pub const RESP_DB_CATALOG: u8 = 0x02;
pub const RESP_ATTEST: u8 = 0x05;
pub const RESP_HANDSHAKE: u8 = 0x06;
pub const RESP_ANNOUNCE: u8 = 0x07;
pub const RESP_ADMIN_AUTH_CHALLENGE: u8 = 0x80;
pub const RESP_ADMIN_AUTH_RESPONSE: u8 = 0x81;
pub const RESP_ADMIN_DB_UPLOAD_BEGIN: u8 = 0x82;
pub const RESP_ADMIN_DB_UPLOAD_CHUNK: u8 = 0x83;
pub const RESP_ADMIN_DB_UPLOAD_FINALIZE: u8 = 0x84;
pub const RESP_ADMIN_DB_ACTIVATE: u8 = 0x85;
pub const RESP_INDEX_BATCH: u8 = 0x11;
pub const RESP_CHUNK_BATCH: u8 = 0x21;
// 0x31 / 0x32 RETIRED (legacy N-ary tree Merkle) — see REQ section above.
pub const RESP_BUCKET_MERKLE_SIB_BATCH: u8 = 0x33;
pub const RESP_BUCKET_MERKLE_TREE_TOPS: u8 = 0x34;
pub const RESP_RESIDENCY: u8 = 0x04;
pub const RESP_ERROR: u8 = 0xFF;

// ─── HarmonyPIR response variants ──────────────────────────────────────────

pub const RESP_HARMONY_INFO: u8 = 0x40;
pub const RESP_HARMONY_HINTS: u8 = 0x41;
pub const RESP_HARMONY_QUERY: u8 = 0x42;
pub const RESP_HARMONY_BATCH_QUERY: u8 = 0x43;
/// Key preamble sent before per-group hint frames in V2 protocol.
pub const RESP_HARMONY_HINTS_KEY: u8 = 0x44;
pub const RESP_ORAM_LOOKUP: u8 = 0x60;

// ─── Request types ──────────────────────────────────────────────────────────

/// A batch of DPF keys for one level.
/// Each group has N DPF keys (one per cuckoo hash function).
#[derive(Clone, Debug)]
pub struct BatchQuery {
    /// 0 for index, 1 for chunk
    pub level: u8,
    /// Round ID (only meaningful for chunk level; 0 for index)
    pub round_id: u16,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
    /// Per-group: list of DPF keys. Length = K (75) or K_CHUNK (80).
    /// Inner Vec length = number of cuckoo hash functions (2 for index, 3 for chunks).
    pub keys: Vec<Vec<Vec<u8>>>,
}

/// HarmonyPIR hint request: client asks Hint Server to compute hints.
///
/// Wire: [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyHintRequest {
    pub prp_key: [u8; 16],
    pub prp_backend: u8,
    pub level: u8,
    pub group_ids: Vec<u8>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR V2 hint request: server generates the PRP key.
///
/// Wire: [1B level_sentinel=0xFF][1B reserved=0x00]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
///
/// The server always returns ALL groups for both INDEX and CHUNK levels.
/// The level sentinel 0xFF signals "both levels."
#[derive(Clone, Debug)]
pub struct HarmonyHintRequestV2 {
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    pub db_id: u8,
}

/// HarmonyPIR V2 half-stream hint request.
///
/// Pairs with [`HarmonyHintRequestV2`] but only emits one of the two
/// trees (INDEX = side 0, CHUNK = side 1). The server matches two
/// requests carrying the same `session_token` against the same pool
/// entry — both halves therefore expose the same PRP key in their
/// preambles.
///
/// Wire: [16B session_token][1B side: 0=INDEX, 1=CHUNK]
///       [optional trailing 1B db_id, only when non-zero —
///        backward compatible]
///
/// Response wire shape per side is identical to the corresponding
/// portion of a [`HarmonyHintRequestV2`] response:
///   `[KEY_PREAMBLE] + [INDEX or CHUNK frames] + [SENTINEL]`
///
/// The server's pending-pool map keeps a token-to-entry mapping with
/// a short TTL (~30 s). The first arriving half allocates a fresh
/// pool entry; the second matching half consumes its other side
/// from the same entry. Lone tokens (one half arrives, the other
/// never does) expire and release their pool entries to be re-used.
#[derive(Clone, Debug)]
pub struct HarmonyHintRequestV2Half {
    /// 16-byte client-generated random token. Both halves of a logical
    /// session carry the same token; the server uses it as the key
    /// into its pending pool entry map.
    pub session_token: [u8; 16],
    /// Which half this request is for: 0 = INDEX, 1 = CHUNK.
    pub side: u8,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    pub db_id: u8,
}

/// HarmonyPIR query: client sends T indices for one group to Query Server.
///
/// Wire: [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE indices]
///       [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyQuery {
    pub level: u8,
    pub group_id: u8,
    pub round_id: u16,
    pub indices: Vec<u32>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

/// HarmonyPIR query result: server returns T entries for one group.
#[derive(Clone, Debug)]
pub struct HarmonyQueryResult {
    pub group_id: u8,
    pub round_id: u16,
    pub data: Vec<u8>,
}

/// HarmonyPIR batch query: client sends queries for multiple groups in one message.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_queries_per_group]
///   per group:
///     [1B group_id]
///     per sub_query (× sub_queries_per_group):
///       [4B count LE][count × 4B u32 LE indices]
///   [optional trailing 1B db_id, only when non-zero — backward compatible]
#[derive(Clone, Debug)]
pub struct HarmonyBatchQuery {
    pub level: u8,
    pub round_id: u16,
    pub sub_queries_per_group: u8,
    /// Per-group items.  Each item has `sub_queries_per_group` sub-queries.
    pub items: Vec<HarmonyBatchItem>,
    /// Database ID (0 = main UTXO, 1+ = delta databases).
    /// Defaults to 0 for backward compatibility.
    pub db_id: u8,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchItem {
    pub group_id: u8,
    /// Each sub-query is a Vec of sorted u32 indices.
    pub sub_queries: Vec<Vec<u32>>,
}

/// HarmonyPIR batch result.
///
/// Wire format:
///   [1B level][2B round_id LE][2B num_groups LE][1B sub_results_per_group]
///   per group:
///     [1B group_id]
///     per sub_result (× sub_results_per_group):
///       [4B data_len LE][data_len bytes]
#[derive(Clone, Debug)]
pub struct HarmonyBatchResult {
    pub level: u8,
    pub round_id: u16,
    pub sub_results_per_group: u8,
    pub items: Vec<HarmonyBatchResultItem>,
}

#[derive(Clone, Debug)]
pub struct HarmonyBatchResultItem {
    pub group_id: u8,
    pub sub_results: Vec<Vec<u8>>,
}

/// Maximum scripthashes accepted in one native ORAM lookup request.
///
/// This is a request-memory and response-size guard, not a privacy parameter.
/// The ORAM leakage model admits `batch_len`; callers that need fixed batches
/// can pad at the client layer before using this opcode.
pub const MAX_ORAM_LOOKUP_SCRIPTHASHES: usize = 256;

#[derive(Clone, Debug)]
pub struct OramLookupRequest {
    pub db_id: u8,
    pub script_hashes: Vec<[u8; pir_core::params::SCRIPT_HASH_SIZE]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OramLookupItem {
    pub found: bool,
    pub whale: bool,
    pub start_chunk_id: u32,
    pub num_chunks: u8,
    /// Raw concatenated 40-byte chunk payloads in chunk-id order. Empty for
    /// not-found and whale results.
    pub raw_chunk_data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OramLookupResult {
    pub db_id: u8,
    pub items: Vec<OramLookupItem>,
}

#[derive(Clone, Debug)]
pub enum Request {
    Ping,
    GetInfo,
    GetDbCatalog,
    /// Attestation request — 32-byte client-supplied nonce gets folded
    /// into REPORT_DATA so the response is anti-replay.
    Attest { nonce: [u8; 32] },
    /// Encrypted-channel handshake — sent in cleartext as the first
    /// channel-establishing message. After the server replies with its
    /// `server_eph_pub`, both sides derive a session key per
    /// `pir_channel`'s ECDH+HKDF construction. Subsequent client→server
    /// frames are AEAD-wrapped with `pir_channel::ENCRYPTED_FRAME_MAGIC`
    /// as the leading byte.
    Handshake {
        /// Client's per-session X25519 ephemeral pubkey.
        client_eph_pub: [u8; 32],
        /// Random 32-byte salt for HKDF-SHA256 session-key derivation.
        nonce: [u8; 32],
    },
    /// Admin auth step 1 — client asks the server for a challenge nonce.
    AdminAuthChallenge,
    /// Admin auth step 2 — client returns ed25519 signature over
    /// `ADMIN_AUTH_DOMAIN_TAG || nonce`.
    AdminAuthResponse { signature: [u8; 64] },
    /// Start a new DB upload — server creates `data_root/.staging/<name>/`
    /// and writes `MANIFEST.toml` from `manifest_toml`.
    AdminDbUploadBegin {
        name: String,
        manifest_toml: Vec<u8>,
    },
    /// Append `data` to `staging/<name>/<file_path>` at byte `offset`.
    AdminDbUploadChunk {
        name: String,
        file_path: String,
        offset: u64,
        data: Vec<u8>,
    },
    /// Verify the staged dir against its manifest. Returns the manifest root.
    AdminDbUploadFinalize {
        name: String,
    },
    /// Atomic-rename `staging/<name>/` → `data_root/<target_path>/`.
    /// Operator restarts unified_server to load the new DB.
    AdminDbActivate {
        name: String,
        target_path: String,
    },
    IndexBatch(BatchQuery),
    ChunkBatch(BatchQuery),
    BucketMerkleSibBatch(BatchQuery),
    HarmonyGetInfo,
    HarmonyHints(HarmonyHintRequest),
    HarmonyHintsV2(HarmonyHintRequestV2),
    HarmonyHintsV2Half(HarmonyHintRequestV2Half),
    HarmonyQuery(HarmonyQuery),
    HarmonyBatchQuery(HarmonyBatchQuery),
    OramLookup(OramLookupRequest),
    /// Operator-signed identity announce. Body is empty — the server
    /// returns its cached, pre-encoded `pir_identity::AnnouncementBundle`
    /// in `Response::Announce`. Servers that lack the on-disk identity
    /// material reply with `Response::Error`.
    Announce,
}

// ─── Response types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ServerInfo {
    pub index_bins_per_table: u32,
    pub chunk_bins_per_table: u32,
    pub index_k: u8,
    pub chunk_k: u8,
    pub tag_seed: u64,
    /// INDEX/CHUNK cuckoo master seeds (read from the main DB header).
    /// Appended after `tag_seed` in the v2 RESP_INFO; older clients that
    /// stop after `tag_seed` ignore them.
    pub index_master_seed: u64,
    pub chunk_master_seed: u64,
    /// Chain anchor of the main DB, if it carries a v2 header.
    pub anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

/// Info about a single database in the server's catalog.
#[derive(Clone, Debug)]
pub struct DatabaseCatalogEntry {
    /// Database ID (index into the server's database list).
    pub db_id: u8,
    /// 0 = full UTXO snapshot, 1 = delta between two heights.
    pub db_type: u8,
    /// Human-readable name (e.g. "main", "delta_940611_944000").
    pub name: String,
    /// Base height (0 for full snapshots, start height for deltas).
    pub base_height: u32,
    /// Tip height (snapshot height for full, end height for deltas).
    pub height: u32,
    /// INDEX-level bins_per_table.
    pub index_bins_per_table: u32,
    /// CHUNK-level bins_per_table.
    pub chunk_bins_per_table: u32,
    /// INDEX-level group count.
    pub index_k: u8,
    /// CHUNK-level group count.
    pub chunk_k: u8,
    /// Tag seed for INDEX-level fingerprints.
    pub tag_seed: u64,
    /// DPF domain exponent for INDEX level.
    pub dpf_n_index: u8,
    /// DPF domain exponent for CHUNK level.
    pub dpf_n_chunk: u8,
    /// Whether this database has per-bucket bin Merkle verification data.
    pub has_bucket_merkle: bool,
    /// INDEX cuckoo master seed (read from the DB header). Delivered so
    /// the client computes placements with the server's actual seed
    /// rather than a hardcoded constant — required since the build-side
    /// const was zeroed in favour of chain-derived seeds.
    pub index_master_seed: u64,
    /// CHUNK cuckoo master seed (read from the DB header).
    pub chunk_master_seed: u64,
    /// Chain anchor the seeds were derived from, if the DB carries a v2
    /// header. `None` for legacy databases. Lets the client recompute
    /// `derive_seed(anchor)` and confirm it matches the master/tag seeds,
    /// and surface the block hash to the user for independent checking.
    pub anchor: Option<pir_core::cuckoo::HeaderAnchor>,
}

/// Server's database catalog listing all available databases.
#[derive(Clone, Debug)]
pub struct DatabaseCatalog {
    pub databases: Vec<DatabaseCatalogEntry>,
}

/// Server response to a `REQ_ADMIN_AUTH_CHALLENGE`. The 32-byte
/// `nonce` is what the client must sign (prefixed by
/// `ADMIN_AUTH_DOMAIN_TAG`) and return as a `REQ_ADMIN_AUTH_RESPONSE`.
#[derive(Clone, Debug)]
pub struct AdminAuthChallenge {
    pub nonce: [u8; 32],
}

/// Server response to a `REQ_ADMIN_AUTH_RESPONSE`. `ok = true` means
/// the connection is now authenticated; subsequent admin requests on
/// the same connection are accepted. `msg` is a short status string
/// (e.g. "ok", "no challenge issued", "bad signature").
#[derive(Clone, Debug)]
pub struct AdminAuthResult {
    pub ok: bool,
    pub msg: String,
}

/// Generic ack used by BEGIN, CHUNK, ACTIVATE.
#[derive(Clone, Debug)]
pub struct AdminAck {
    pub ok: bool,
    pub msg: String,
}

/// Reply to `REQ_ADMIN_DB_UPLOAD_FINALIZE`. On success, `manifest_root`
/// is the SHA-256 of the staged `MANIFEST.toml` — the same value
/// `MappedDatabase::load()` would expose if the staging dir were
/// activated and the server reloaded.
#[derive(Clone, Debug)]
pub struct AdminFinalizeResult {
    pub ok: bool,
    pub msg: String,
    pub manifest_root: [u8; 32],
}

/// Result of an attestation request.
///
/// Wire format (encoded after the `RESP_ATTEST` variant byte):
///
///   [4B sev_report_len LE][sev_report_bytes]   (len=0 if not on SEV-SNP)
///   [1B num_manifest_roots][num × 32B]          (per-DB roots in db_id order)
///   [32B binary_sha256]
///   [2B git_rev_len LE][git_rev_bytes UTF-8]
///
/// Per-DB manifest roots are zero (`[0u8; 32]`) for DBs that don't have
/// a `MANIFEST.toml` (back-compat with legacy DBs).
/// Server's response to a `REQ_HANDSHAKE`. Carries the per-session
/// X25519 ephemeral public key. The client combines this with the
/// server's long-lived static pubkey (verified via attestation) and
/// its own ephemeral secret to derive the session key — see
/// `pir_channel::ClientHandshake::complete_handshake`.
///
/// Wire format (after the `RESP_HANDSHAKE` variant byte):
/// `[u8; 32] server_eph_pub`
#[derive(Clone, Debug)]
pub struct HandshakeResult {
    /// Per-session X25519 ephemeral pubkey. Different for every
    /// handshake even within the same boot of the server (provides
    /// forward secrecy).
    pub server_eph_pub: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct AttestResult {
    /// Raw signed SEV-SNP attestation report bytes (~1184 for v5).
    /// Empty if /dev/sev-guest unavailable on the host.
    pub sev_snp_report: Vec<u8>,
    /// Per-DB manifest roots in db_id order. Length matches catalog.
    pub manifest_roots: Vec<[u8; 32]>,
    /// SHA-256 of `/proc/self/exe` captured at server startup.
    pub binary_sha256: [u8; 32],
    /// Long-lived X25519 public key the server generated inside the
    /// SEV-SNP guest at boot. Bound into REPORT_DATA via
    /// `pir_core::attest::build_report_data` (V2 layout) so a chip-
    /// signed report authenticates this exact key. Used by clients
    /// to establish an end-to-end encrypted channel that cloudflared
    /// (and Cloudflare's edge) can't read. All-zero on servers that
    /// don't yet have a channel key (transitional).
    pub server_static_pub: [u8; 32],
    /// Git commit baked in at build time (40-char SHA, optionally
    /// suffixed with `-dirty`, or "unknown" for non-git builds).
    pub git_rev: String,
    /// PEM-encoded AMD ARK (Root Key) certificate. Empty if the server
    /// doesn't have the cert chain loaded (operator hasn't run the
    /// fetch-vcek-chain step). The browser's pir-attest-verify uses
    /// it (combined with `ask_pem` + `vcek_pem`) to chain-validate
    /// the SEV-SNP report's signature back to AMD's known root.
    pub ark_pem: Vec<u8>,
    /// PEM-encoded AMD ASK (SEV Signing Key) certificate, per
    /// SoC family (Milan / Genoa / Turin). Empty if not loaded.
    pub ask_pem: Vec<u8>,
    /// PEM-encoded VCEK (Versioned Chip Endorsement Key) certificate
    /// for THIS chip + TCB. Empty if not loaded. The chip ID + TCB
    /// in the SNP report determine the AMD KDS URL the operator
    /// fetched this from.
    pub vcek_pem: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BatchResult {
    pub level: u8,
    pub round_id: u16,
    /// Per-group: list of results. Same structure as request keys.
    pub results: Vec<Vec<Vec<u8>>>,
}

#[derive(Clone, Debug)]
pub enum Response {
    Pong,
    Info(ServerInfo),
    DbCatalog(DatabaseCatalog),
    Attest(AttestResult),
    /// Server's reply to `Request::Handshake`. Carries the per-session
    /// X25519 ephemeral pubkey. After this exchange both sides have the
    /// same session key derived via `pir_channel`'s ECDH+HKDF.
    Handshake(HandshakeResult),
    /// Server's reply to `Request::Announce`. Body is the raw bytes of
    /// `pir_identity::AnnouncementBundle::encode()` — the wire format
    /// is opaque to this enum so a future bundle version bump doesn't
    /// require touching the protocol layer.
    Announce(Vec<u8>),
    AdminAuthChallenge(AdminAuthChallenge),
    AdminAuthResponse(AdminAuthResult),
    AdminDbUploadBegin(AdminAck),
    AdminDbUploadChunk(AdminAck),
    AdminDbUploadFinalize(AdminFinalizeResult),
    AdminDbActivate(AdminAck),
    IndexBatch(BatchResult),
    ChunkBatch(BatchResult),
    BucketMerkleSibBatch(BatchResult),
    Error(String),
    HarmonyInfo(ServerInfo),
    HarmonyQueryResult(HarmonyQueryResult),
    HarmonyBatchResult(HarmonyBatchResult),
    OramLookupResult(OramLookupResult),
    /// ARC credential presentation verified (status=0x00).
    ArcCredentialOk,
    /// Cashu BAT presentation verified.
    CashuBatOk,
}

// ─── Encoding ───────────────────────────────────────────────────────────────

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Request::Ping => {
                payload.push(REQ_PING);
            }
            Request::GetInfo => {
                payload.push(REQ_GET_INFO);
            }
            Request::GetDbCatalog => {
                payload.push(REQ_GET_DB_CATALOG);
            }
            Request::Attest { nonce } => {
                payload.push(REQ_ATTEST);
                payload.extend_from_slice(nonce);
            }
            Request::Handshake { client_eph_pub, nonce } => {
                payload.push(REQ_HANDSHAKE);
                payload.extend_from_slice(client_eph_pub);
                payload.extend_from_slice(nonce);
            }
            Request::AdminAuthChallenge => {
                payload.push(REQ_ADMIN_AUTH_CHALLENGE);
            }
            Request::AdminAuthResponse { signature } => {
                payload.push(REQ_ADMIN_AUTH_RESPONSE);
                payload.extend_from_slice(signature);
            }
            Request::AdminDbUploadBegin { name, manifest_toml } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_BEGIN);
                encode_lp_string(&mut payload, name);
                payload.extend_from_slice(&(manifest_toml.len() as u32).to_le_bytes());
                payload.extend_from_slice(manifest_toml);
            }
            Request::AdminDbUploadChunk { name, file_path, offset, data } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_CHUNK);
                encode_lp_string(&mut payload, name);
                encode_lp_string(&mut payload, file_path);
                payload.extend_from_slice(&offset.to_le_bytes());
                payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
                payload.extend_from_slice(data);
            }
            Request::AdminDbUploadFinalize { name } => {
                payload.push(REQ_ADMIN_DB_UPLOAD_FINALIZE);
                encode_lp_string(&mut payload, name);
            }
            Request::AdminDbActivate { name, target_path } => {
                payload.push(REQ_ADMIN_DB_ACTIVATE);
                encode_lp_string(&mut payload, name);
                encode_lp_string(&mut payload, target_path);
            }
            Request::IndexBatch(q) => {
                payload.push(REQ_INDEX_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::ChunkBatch(q) => {
                payload.push(REQ_CHUNK_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::BucketMerkleSibBatch(q) => {
                payload.push(REQ_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_query(&mut payload, q);
            }
            Request::HarmonyGetInfo => {
                payload.push(REQ_HARMONY_GET_INFO);
            }
            Request::HarmonyHints(h) => {
                payload.push(REQ_HARMONY_HINTS);
                payload.extend_from_slice(&h.prp_key);
                payload.push(h.prp_backend);
                payload.push(h.level);
                payload.push(h.group_ids.len() as u8);
                payload.extend_from_slice(&h.group_ids);
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyHintsV2(h) => {
                payload.push(REQ_HARMONY_HINTS_V2);
                payload.push(0xFFu8); // level_sentinel: all levels
                payload.push(0x00u8); // reserved
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyHintsV2Half(h) => {
                payload.push(REQ_HARMONY_HINTS_V2_HALF);
                payload.extend_from_slice(&h.session_token);
                payload.push(h.side);
                if h.db_id != 0 {
                    payload.push(h.db_id);
                }
            }
            Request::HarmonyQuery(q) => {
                payload.push(REQ_HARMONY_QUERY);
                payload.push(q.level);
                payload.push(q.group_id);
                payload.extend_from_slice(&q.round_id.to_le_bytes());
                payload.extend_from_slice(&(q.indices.len() as u32).to_le_bytes());
                for idx in &q.indices {
                    payload.extend_from_slice(&idx.to_le_bytes());
                }
                // Trailing db_id byte: only appended when non-zero for backward compatibility.
                if q.db_id != 0 {
                    payload.push(q.db_id);
                }
            }
            Request::HarmonyBatchQuery(q) => {
                payload.push(REQ_HARMONY_BATCH_QUERY);
                encode_harmony_batch_query(&mut payload, q);
            }
            Request::OramLookup(q) => {
                payload.push(REQ_ORAM_LOOKUP);
                encode_oram_lookup_request(&mut payload, q);
            }
            Request::Announce => {
                payload.push(REQ_ANNOUNCE);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty request"));
        }
        match data[0] {
            REQ_PING => Ok(Request::Ping),
            REQ_GET_INFO => Ok(Request::GetInfo),
            REQ_GET_DB_CATALOG => Ok(Request::GetDbCatalog),
            REQ_ATTEST => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "attest request must carry a 32-byte nonce",
                    ));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[1..33]);
                Ok(Request::Attest { nonce })
            }
            REQ_HANDSHAKE => {
                // Wire layout: [variant:1][client_eph_pub:32][nonce:32]
                if data.len() < 1 + 32 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake request must carry 32-byte client_eph_pub + 32-byte nonce",
                    ));
                }
                let mut client_eph_pub = [0u8; 32];
                client_eph_pub.copy_from_slice(&data[1..33]);
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[33..65]);
                Ok(Request::Handshake { client_eph_pub, nonce })
            }
            REQ_ADMIN_AUTH_CHALLENGE => Ok(Request::AdminAuthChallenge),
            REQ_ADMIN_AUTH_RESPONSE => {
                if data.len() < 1 + 64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "admin auth response must carry a 64-byte signature",
                    ));
                }
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&data[1..65]);
                Ok(Request::AdminAuthResponse { signature })
            }
            REQ_ADMIN_DB_UPLOAD_BEGIN => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                if pos + 4 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing manifest len"));
                }
                let mlen = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                if pos + mlen > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated manifest_toml"));
                }
                let manifest_toml = data[pos..pos+mlen].to_vec();
                Ok(Request::AdminDbUploadBegin { name, manifest_toml })
            }
            REQ_ADMIN_DB_UPLOAD_CHUNK => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                let file_path = decode_lp_string(data, &mut pos)?;
                if pos + 8 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing offset"));
                }
                let offset = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
                pos += 8;
                if pos + 4 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "missing data len"));
                }
                let dlen = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
                pos += 4;
                if pos + dlen > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated chunk data"));
                }
                let data_bytes = data[pos..pos+dlen].to_vec();
                Ok(Request::AdminDbUploadChunk { name, file_path, offset, data: data_bytes })
            }
            REQ_ADMIN_DB_UPLOAD_FINALIZE => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                Ok(Request::AdminDbUploadFinalize { name })
            }
            REQ_ADMIN_DB_ACTIVATE => {
                let mut pos = 1;
                let name = decode_lp_string(data, &mut pos)?;
                let target_path = decode_lp_string(data, &mut pos)?;
                Ok(Request::AdminDbActivate { name, target_path })
            }
            REQ_INDEX_BATCH => {
                // INDEX groups must carry both cuckoo-position keys.
                let q = decode_batch_query(
                    &data[1..],
                    pir_core::params::INDEX_CUCKOO_NUM_HASHES,
                )?;
                Ok(Request::IndexBatch(q))
            }
            REQ_CHUNK_BATCH => {
                let q = decode_batch_query(&data[1..], 0)?;
                Ok(Request::ChunkBatch(q))
            }
            REQ_BUCKET_MERKLE_SIB_BATCH => {
                let q = decode_batch_query(&data[1..], 0)?;
                Ok(Request::BucketMerkleSibBatch(q))
            }
            REQ_HARMONY_GET_INFO => Ok(Request::HarmonyGetInfo),
            REQ_HARMONY_HINTS => {
                let h = decode_harmony_hint_request(&data[1..])?;
                Ok(Request::HarmonyHints(h))
            }
            REQ_HARMONY_HINTS_V2 => {
                let h = decode_harmony_hint_request_v2(&data[1..])?;
                Ok(Request::HarmonyHintsV2(h))
            }
            REQ_HARMONY_HINTS_V2_HALF => {
                let h = decode_harmony_hint_request_v2_half(&data[1..])?;
                Ok(Request::HarmonyHintsV2Half(h))
            }
            REQ_HARMONY_QUERY => {
                let q = decode_harmony_query(&data[1..])?;
                Ok(Request::HarmonyQuery(q))
            }
            REQ_HARMONY_BATCH_QUERY => {
                let q = decode_harmony_batch_query(&data[1..])?;
                Ok(Request::HarmonyBatchQuery(q))
            }
            REQ_ORAM_LOOKUP => {
                let q = decode_oram_lookup_request(&data[1..])?;
                Ok(Request::OramLookup(q))
            }
            REQ_ANNOUNCE => Ok(Request::Announce),
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown request variant: 0x{:02x}", v),
            )),
        }
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Response::Pong => {
                payload.push(RESP_PONG);
            }
            Response::Info(info) => {
                payload.push(RESP_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
                // v2 trailing fields (older clients stop after tag_seed).
                payload.extend_from_slice(&info.index_master_seed.to_le_bytes());
                payload.extend_from_slice(&info.chunk_master_seed.to_le_bytes());
                encode_anchor_ext(&mut payload, &info.anchor);
            }
            Response::DbCatalog(cat) => {
                payload.push(RESP_DB_CATALOG);
                encode_db_catalog(&mut payload, cat);
            }
            Response::Attest(r) => {
                payload.push(RESP_ATTEST);
                encode_attest_result(&mut payload, r);
            }
            Response::Handshake(r) => {
                payload.push(RESP_HANDSHAKE);
                payload.extend_from_slice(&r.server_eph_pub);
            }
            Response::Announce(bundle_bytes) => {
                payload.push(RESP_ANNOUNCE);
                payload.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bundle_bytes);
            }
            Response::AdminAuthChallenge(c) => {
                payload.push(RESP_ADMIN_AUTH_CHALLENGE);
                payload.extend_from_slice(&c.nonce);
            }
            Response::AdminAuthResponse(r) => {
                payload.push(RESP_ADMIN_AUTH_RESPONSE);
                encode_admin_ack_payload(&mut payload, r.ok, &r.msg);
            }
            Response::AdminDbUploadBegin(a) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_BEGIN);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::AdminDbUploadChunk(a) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_CHUNK);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::AdminDbUploadFinalize(r) => {
                payload.push(RESP_ADMIN_DB_UPLOAD_FINALIZE);
                payload.push(if r.ok { 1 } else { 0 });
                let mb = r.msg.as_bytes();
                payload.extend_from_slice(&(mb.len() as u16).to_le_bytes());
                payload.extend_from_slice(mb);
                payload.extend_from_slice(&r.manifest_root);
            }
            Response::AdminDbActivate(a) => {
                payload.push(RESP_ADMIN_DB_ACTIVATE);
                encode_admin_ack_payload(&mut payload, a.ok, &a.msg);
            }
            Response::IndexBatch(r) => {
                payload.push(RESP_INDEX_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::ChunkBatch(r) => {
                payload.push(RESP_CHUNK_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::BucketMerkleSibBatch(r) => {
                payload.push(RESP_BUCKET_MERKLE_SIB_BATCH);
                encode_batch_result(&mut payload, r);
            }
            Response::Error(msg) => {
                payload.push(RESP_ERROR);
                let bytes = msg.as_bytes();
                payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                payload.extend_from_slice(bytes);
            }
            Response::HarmonyInfo(info) => {
                payload.push(RESP_HARMONY_INFO);
                payload.extend_from_slice(&info.index_bins_per_table.to_le_bytes());
                payload.extend_from_slice(&info.chunk_bins_per_table.to_le_bytes());
                payload.push(info.index_k);
                payload.push(info.chunk_k);
                payload.extend_from_slice(&info.tag_seed.to_le_bytes());
                // v2 trailing fields (older clients stop after tag_seed).
                payload.extend_from_slice(&info.index_master_seed.to_le_bytes());
                payload.extend_from_slice(&info.chunk_master_seed.to_le_bytes());
                encode_anchor_ext(&mut payload, &info.anchor);
            }
            Response::HarmonyQueryResult(r) => {
                payload.push(RESP_HARMONY_QUERY);
                payload.push(r.group_id);
                payload.extend_from_slice(&r.round_id.to_le_bytes());
                payload.extend_from_slice(&r.data);
            }
            Response::HarmonyBatchResult(r) => {
                payload.push(RESP_HARMONY_BATCH_QUERY);
                encode_harmony_batch_result(&mut payload, r);
            }
            Response::OramLookupResult(r) => {
                payload.push(RESP_ORAM_LOOKUP);
                encode_oram_lookup_result(&mut payload, r);
            }
            Response::ArcCredentialOk => {
                payload.push(RESP_CREDENTIAL_OK);
                payload.push(0x00u8); // status = valid
            }
            Response::CashuBatOk => {
                payload.push(RESP_CASHU_BAT_OK);
                payload.push(0x00u8);
            }
        }
        let mut msg = Vec::with_capacity(4 + payload.len());
        msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        msg.extend_from_slice(&payload);
        msg
    }

    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty response"));
        }
        match data[0] {
            RESP_PONG => Ok(Response::Pong),
            RESP_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "info too short"));
                }
                // v2 trailing fields: index/chunk master seeds + anchor.
                // Absent (len == 19) when talking to a pre-ext server.
                let (index_master_seed, chunk_master_seed, anchor) = if data.len() >= 35 {
                    let ims = u64::from_le_bytes(data[19..27].try_into().unwrap());
                    let cms = u64::from_le_bytes(data[27..35].try_into().unwrap());
                    let mut pos = 36;
                    let anchor = if data.len() >= 36 {
                        decode_anchor_ext(data[35], data, &mut pos)?
                    } else {
                        None
                    };
                    (ims, cms, anchor)
                } else {
                    (0, 0, None)
                };
                Ok(Response::Info(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                    index_master_seed,
                    chunk_master_seed,
                    anchor,
                }))
            }
            RESP_DB_CATALOG => {
                let cat = decode_db_catalog(&data[1..])?;
                Ok(Response::DbCatalog(cat))
            }
            RESP_ATTEST => {
                let r = decode_attest_result(&data[1..])?;
                Ok(Response::Attest(r))
            }
            RESP_HANDSHAKE => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "handshake response missing 32-byte server_eph_pub",
                    ));
                }
                let mut server_eph_pub = [0u8; 32];
                server_eph_pub.copy_from_slice(&data[1..33]);
                Ok(Response::Handshake(HandshakeResult { server_eph_pub }))
            }
            RESP_ANNOUNCE => {
                if data.len() < 1 + 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "announce response missing 4-byte bundle length",
                    ));
                }
                let blen = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                if 5 + blen > data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "announce response: bundle length exceeds buffer",
                    ));
                }
                Ok(Response::Announce(data[5..5 + blen].to_vec()))
            }
            RESP_ADMIN_AUTH_CHALLENGE => {
                if data.len() < 1 + 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "admin auth challenge response missing nonce",
                    ));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&data[1..33]);
                Ok(Response::AdminAuthChallenge(AdminAuthChallenge { nonce }))
            }
            RESP_ADMIN_AUTH_RESPONSE => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminAuthResponse(AdminAuthResult { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_BEGIN => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbUploadBegin(AdminAck { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_CHUNK => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbUploadChunk(AdminAck { ok, msg }))
            }
            RESP_ADMIN_DB_UPLOAD_FINALIZE => {
                if data.len() < 1 + 1 + 2 + 32 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "finalize result too short"));
                }
                let ok = data[1] != 0;
                let msg_len = u16::from_le_bytes(data[2..4].try_into().unwrap()) as usize;
                if 4 + msg_len + 32 > data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "finalize result truncated"));
                }
                let msg = String::from_utf8_lossy(&data[4..4 + msg_len]).to_string();
                let mut manifest_root = [0u8; 32];
                manifest_root.copy_from_slice(&data[4 + msg_len..4 + msg_len + 32]);
                Ok(Response::AdminDbUploadFinalize(AdminFinalizeResult { ok, msg, manifest_root }))
            }
            RESP_ADMIN_DB_ACTIVATE => {
                let (ok, msg) = decode_admin_ack_payload(&data[1..])?;
                Ok(Response::AdminDbActivate(AdminAck { ok, msg }))
            }
            RESP_INDEX_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::IndexBatch(r))
            }
            RESP_CHUNK_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::ChunkBatch(r))
            }
            RESP_BUCKET_MERKLE_SIB_BATCH => {
                let r = decode_batch_result(&data[1..])?;
                Ok(Response::BucketMerkleSibBatch(r))
            }
            RESP_ERROR => {
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                let msg = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                Ok(Response::Error(msg))
            }
            RESP_HARMONY_INFO => {
                if data.len() < 19 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony info too short"));
                }
                let (index_master_seed, chunk_master_seed, anchor) = if data.len() >= 35 {
                    let ims = u64::from_le_bytes(data[19..27].try_into().unwrap());
                    let cms = u64::from_le_bytes(data[27..35].try_into().unwrap());
                    let mut pos = 36;
                    let anchor = if data.len() >= 36 {
                        decode_anchor_ext(data[35], data, &mut pos)?
                    } else {
                        None
                    };
                    (ims, cms, anchor)
                } else {
                    (0, 0, None)
                };
                Ok(Response::HarmonyInfo(ServerInfo {
                    index_bins_per_table: u32::from_le_bytes(data[1..5].try_into().unwrap()),
                    chunk_bins_per_table: u32::from_le_bytes(data[5..9].try_into().unwrap()),
                    index_k: data[9],
                    chunk_k: data[10],
                    tag_seed: u64::from_le_bytes(data[11..19].try_into().unwrap()),
                    index_master_seed,
                    chunk_master_seed,
                    anchor,
                }))
            }
            RESP_HARMONY_QUERY => {
                if data.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query result too short"));
                }
                Ok(Response::HarmonyQueryResult(HarmonyQueryResult {
                    group_id: data[1],
                    round_id: u16::from_le_bytes(data[2..4].try_into().unwrap()),
                    data: data[4..].to_vec(),
                }))
            }
            RESP_HARMONY_BATCH_QUERY => {
                let r = decode_harmony_batch_result(&data[1..])?;
                Ok(Response::HarmonyBatchResult(r))
            }
            RESP_ORAM_LOOKUP => {
                let r = decode_oram_lookup_result(&data[1..])?;
                Ok(Response::OramLookupResult(r))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown response variant: 0x{:02x}", v),
            )),
        }
    }
}

// ─── Batch encoding helpers ─────────────────────────────────────────────────

/// Bounds on the declared DPF domain exponent (`n`, byte 0 of a
/// serialized key) accepted from clients.
///
/// libdpf keys structurally require `n ≥ 7`: `DpfKey::from_bytes`
/// computes `max_layer = n - 7` in u8 arithmetic, which underflows
/// below that (a panic in debug builds, a bogus 200+-layer key in
/// release). The upper bound caps the tree depth a client can make
/// the server walk and keeps the `1 << (n - 7)` domain-size shifts
/// in libdpf's eval sound. Real tables use `compute_dpf_n` ≈ 20–21;
/// 32 (a 2^32-bin domain) leaves ample headroom for any future table.
pub const MIN_DPF_DOMAIN_N: u8 = 7;
pub const MAX_DPF_DOMAIN_N: u8 = 32;

/// Validate the framing of a client-supplied serialized DPF key
/// without constructing a `DpfKey`.
///
/// Mirrors the layout checks of `libdpf::DpfKey::from_bytes`
/// (`[1B n][16B s0][1B t0][18B × (n−7) layers][16B final]`) plus the
/// domain bounds above, so downstream `from_bytes` + `eval_partial`
/// calls on an accepted blob cannot panic. Key *content* (seeds and
/// correction words) is necessarily opaque — any value is a valid PRG
/// seed.
pub fn validate_dpf_key_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 18 {
        return Err(format!("key too short: {} bytes", bytes.len()));
    }
    let n = bytes[0];
    if !(MIN_DPF_DOMAIN_N..=MAX_DPF_DOMAIN_N).contains(&n) {
        return Err(format!(
            "domain n={} outside [{}, {}]",
            n, MIN_DPF_DOMAIN_N, MAX_DPF_DOMAIN_N
        ));
    }
    let max_layer = (n - 7) as usize; // safe: n ≥ MIN_DPF_DOMAIN_N = 7
    let expected_size = 1 + 16 + 1 + 18 * max_layer + 16;
    if bytes.len() < expected_size {
        return Err(format!(
            "key length {} below expected {} for n={}",
            bytes.len(),
            expected_size,
            n
        ));
    }
    Ok(())
}

/// Wire format:
///   [2B round_id][1B num_groups][1B keys_per_group]
///   For each group:
///     For each key (keys_per_group times):
///       [2B key_len][key_data]
fn encode_batch_query(buf: &mut Vec<u8>, q: &BatchQuery) {
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.push(q.keys.len() as u8);
    let keys_per_group = q.keys.first().map_or(0, |k| k.len()) as u8;
    buf.push(keys_per_group);
    for group_keys in &q.keys {
        for k in group_keys {
            buf.extend_from_slice(&(k.len() as u16).to_le_bytes());
            buf.extend_from_slice(k);
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

/// `min_keys_per_group` lets the opcode-aware caller enforce a per-level
/// floor: INDEX batches must carry both cuckoo-position keys per group
/// (`INDEX_CUCKOO_NUM_HASHES = 2`), or the eval path would index
/// `key_refs[0]`/`key_refs[1]` out of bounds. CHUNK and Merkle sibling
/// batches pass 0 (any count up to the cap is processable).
fn decode_batch_query(data: &[u8], min_keys_per_group: usize) -> io::Result<BatchQuery> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch query too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let keys_per_group = data[pos] as usize;
    pos += 1;
    // Cap the attacker-controlled keys_per_group at decode time (S2/S3):
    // the DPF eval fast path tracks per-key bits in a fixed
    // [bool; MAX_KEYS_PER_GROUP] array, so larger counts are unsound
    // downstream. Legitimate clients send 2 keys per group (INDEX/CHUNK
    // cuckoo hashes) or 1 (Merkle sibling batches). `num_groups` needs
    // no extra cap: it is a single wire byte (≤ 255) and handlers clamp
    // it to the table's k.
    if keys_per_group > crate::eval::MAX_KEYS_PER_GROUP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "keys_per_group {} exceeds maximum {}",
                keys_per_group,
                crate::eval::MAX_KEYS_PER_GROUP
            ),
        ));
    }
    if num_groups > 0 && keys_per_group < min_keys_per_group {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "keys_per_group {} below required {}",
                keys_per_group, min_keys_per_group
            ),
        ));
    }
    let mut keys = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_keys = Vec::with_capacity(keys_per_group);
        for _ in 0..keys_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated key data"));
            }
            let key = &data[pos..pos + len];
            // Reject malformed DPF key blobs at decode time (S1):
            // `DpfKey::from_bytes` is not panic-safe on adversarial
            // bytes, and the eval layer assumes well-framed keys.
            validate_dpf_key_bytes(key).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("bad DPF key: {}", e))
            })?;
            group_keys.push(key.to_vec());
            pos += len;
        }
        keys.push(group_keys);
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(BatchQuery {
        level: 0,
        round_id,
        db_id,
        keys,
    })
}

fn encode_batch_result(buf: &mut Vec<u8>, r: &BatchResult) {
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.push(r.results.len() as u8);
    let results_per_group = r.results.first().map_or(0, |r| r.len()) as u8;
    buf.push(results_per_group);
    for group_results in &r.results {
        for res in group_results {
            buf.extend_from_slice(&(res.len() as u16).to_le_bytes());
            buf.extend_from_slice(res);
        }
    }
}

fn decode_batch_result(data: &[u8]) -> io::Result<BatchResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "batch result too short"));
    }
    let round_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
    pos += 2;
    let num_groups = data[pos] as usize;
    pos += 1;
    let results_per_group = data[pos] as usize;
    pos += 1;
    let mut results = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        let mut group_results = Vec::with_capacity(results_per_group);
        for _ in 0..results_per_group {
            if pos + 2 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result"));
            }
            let len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated result data"));
            }
            group_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        results.push(group_results);
    }
    Ok(BatchResult {
        level: 0,
        round_id,
        results,
    })
}

// ─── HarmonyPIR encoding helpers ────────────────────────────────────────────

fn decode_harmony_hint_request(data: &[u8]) -> io::Result<HarmonyHintRequest> {
    // [16B prp_key][1B prp_backend][1B level][1B num_groups][per group: 1B id]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 19 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony hint request too short"));
    }
    let mut prp_key = [0u8; 16];
    prp_key.copy_from_slice(&data[0..16]);
    let prp_backend = data[16];
    let level = data[17];
    let num_groups = data[18] as usize;
    let pos = 19 + num_groups;
    if data.len() < pos {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated group list"));
    }
    let group_ids = data[19..pos].to_vec();
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyHintRequest {
        prp_key,
        prp_backend,
        level,
        group_ids,
        db_id,
    })
}

/// V2 hint request wire format:
/// [1B level_sentinel=0xFF][1B reserved=0x00]
/// [optional trailing 1B db_id]
fn decode_harmony_hint_request_v2(data: &[u8]) -> io::Result<HarmonyHintRequestV2> {
    // Minimum: level_sentinel (1) + reserved (1)
    if data.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 hint request too short",
        ));
    }
    let level_sentinel = data[0];
    if level_sentinel != 0xFF {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("V2 hint request expected level_sentinel 0xFF, got 0x{:02x}", level_sentinel),
        ));
    }
    // data[1] is reserved, ignored.
    let db_id = if data.len() > 2 { data[2] } else { 0 };
    Ok(HarmonyHintRequestV2 { db_id })
}

/// V2 half-stream hint request wire format:
/// [16B session_token][1B side: 0=INDEX, 1=CHUNK]
/// [optional trailing 1B db_id]
fn decode_harmony_hint_request_v2_half(data: &[u8]) -> io::Result<HarmonyHintRequestV2Half> {
    // Minimum: session_token (16) + side (1)
    if data.len() < 17 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "V2 half hint request too short",
        ));
    }
    let mut session_token = [0u8; 16];
    session_token.copy_from_slice(&data[..16]);
    let side = data[16];
    if side != 0 && side != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("V2 half hint request side must be 0 or 1, got {}", side),
        ));
    }
    let db_id = if data.len() > 17 { data[17] } else { 0 };
    Ok(HarmonyHintRequestV2Half {
        session_token,
        side,
        db_id,
    })
}

// ─── HarmonyPIR batch encoding helpers ─────────────────────────────────────

/// Encode a `HarmonyBatchQuery` *payload* (no [4B length][1B opcode]
/// envelope — the envelope is owned by `Request::encode`). Exposed as
/// `pub` so out-of-crate callers (notably the WASM wire-explorer
/// decoder in `pir-sdk-wasm`) have a single source-of-truth encoder
/// to test their mirrored decoder against.
pub fn encode_harmony_batch_query(buf: &mut Vec<u8>, q: &HarmonyBatchQuery) {
    buf.push(q.level);
    buf.extend_from_slice(&q.round_id.to_le_bytes());
    buf.extend_from_slice(&(q.items.len() as u16).to_le_bytes());
    buf.push(q.sub_queries_per_group);
    for item in &q.items {
        buf.push(item.group_id);
        for sq in &item.sub_queries {
            buf.extend_from_slice(&(sq.len() as u32).to_le_bytes());
            for &idx in sq {
                buf.extend_from_slice(&idx.to_le_bytes());
            }
        }
    }
    // Trailing db_id byte: only appended when non-zero for backward compatibility.
    if q.db_id != 0 {
        buf.push(q.db_id);
    }
}

/// Decode a `HarmonyBatchQuery` *payload* (no [4B length][1B opcode]
/// envelope — pass `&data[1..]` from a `[opcode][payload]` frame, or
/// just `&payload` from a stripped frame). Exposed as `pub` so
/// out-of-crate callers (the WASM wire-explorer in `pir-sdk-wasm`)
/// share one parser definition with the server side.
pub fn decode_harmony_batch_query(data: &[u8]) -> io::Result<HarmonyBatchQuery> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch query too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_queries_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_queries = Vec::with_capacity(sub_queries_per_group as usize);
        for _ in 0..sub_queries_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch sub-query count"));
            }
            let count = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + count * 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch indices"));
            }
            let mut indices = Vec::with_capacity(count);
            for i in 0..count {
                let off = pos + i * 4;
                indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
            }
            pos += count * 4;
            sub_queries.push(indices);
        }
        items.push(HarmonyBatchItem { group_id, sub_queries });
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if pos < data.len() { data[pos] } else { 0 };
    Ok(HarmonyBatchQuery { level, round_id, sub_queries_per_group, items, db_id })
}

fn encode_harmony_batch_result(buf: &mut Vec<u8>, r: &HarmonyBatchResult) {
    buf.push(r.level);
    buf.extend_from_slice(&r.round_id.to_le_bytes());
    buf.extend_from_slice(&(r.items.len() as u16).to_le_bytes());
    buf.push(r.sub_results_per_group);
    for item in &r.items {
        buf.push(item.group_id);
        for sr in &item.sub_results {
            buf.extend_from_slice(&(sr.len() as u32).to_le_bytes());
            buf.extend_from_slice(sr);
        }
    }
}

fn decode_harmony_batch_result(data: &[u8]) -> io::Result<HarmonyBatchResult> {
    if data.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony batch result too short"));
    }
    let level = data[0];
    let round_id = u16::from_le_bytes(data[1..3].try_into().unwrap());
    let num_groups = u16::from_le_bytes(data[3..5].try_into().unwrap()) as usize;
    let sub_results_per_group = data[5];
    let mut pos = 6;
    let mut items = Vec::with_capacity(num_groups);
    for _ in 0..num_groups {
        if pos >= data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result group"));
        }
        let group_id = data[pos];
        pos += 1;
        let mut sub_results = Vec::with_capacity(sub_results_per_group as usize);
        for _ in 0..sub_results_per_group {
            if pos + 4 > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result len"));
            }
            let len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + len > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated batch result data"));
            }
            sub_results.push(data[pos..pos + len].to_vec());
            pos += len;
        }
        items.push(HarmonyBatchResultItem { group_id, sub_results });
    }
    Ok(HarmonyBatchResult { level, round_id, sub_results_per_group, items })
}

// ─── TEE ORAM encoding helpers ─────────────────────────────────────────────

fn encode_oram_lookup_request(buf: &mut Vec<u8>, q: &OramLookupRequest) {
    debug_assert!(q.script_hashes.len() <= u16::MAX as usize);
    buf.push(q.db_id);
    buf.extend_from_slice(&(q.script_hashes.len() as u16).to_le_bytes());
    for sh in &q.script_hashes {
        buf.extend_from_slice(sh);
    }
}

fn decode_oram_lookup_request(data: &[u8]) -> io::Result<OramLookupRequest> {
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ORAM lookup request too short"));
    }
    let db_id = data[0];
    let count = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
    if count > MAX_ORAM_LOOKUP_SCRIPTHASHES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ORAM lookup request count {} exceeds maximum {}",
                count, MAX_ORAM_LOOKUP_SCRIPTHASHES
            ),
        ));
    }
    let expected = 3 + count * pir_core::params::SCRIPT_HASH_SIZE;
    if data.len() < expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ORAM scripthash list"));
    }
    let mut script_hashes = Vec::with_capacity(count);
    let mut pos = 3;
    for _ in 0..count {
        let mut sh = [0u8; pir_core::params::SCRIPT_HASH_SIZE];
        sh.copy_from_slice(&data[pos..pos + pir_core::params::SCRIPT_HASH_SIZE]);
        script_hashes.push(sh);
        pos += pir_core::params::SCRIPT_HASH_SIZE;
    }
    Ok(OramLookupRequest { db_id, script_hashes })
}

fn encode_oram_lookup_result(buf: &mut Vec<u8>, r: &OramLookupResult) {
    debug_assert!(r.items.len() <= u16::MAX as usize);
    buf.push(r.db_id);
    buf.extend_from_slice(&(r.items.len() as u16).to_le_bytes());
    for item in &r.items {
        let mut flags = 0u8;
        if item.found {
            flags |= 0x01;
        }
        if item.whale {
            flags |= 0x02;
        }
        buf.push(flags);
        buf.extend_from_slice(&item.start_chunk_id.to_le_bytes());
        buf.push(item.num_chunks);
        buf.extend_from_slice(&(item.raw_chunk_data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&item.raw_chunk_data);
    }
}

fn decode_oram_lookup_result(data: &[u8]) -> io::Result<OramLookupResult> {
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ORAM lookup result too short"));
    }
    let db_id = data[0];
    let count = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
    let mut pos = 3;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        if pos + 10 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated ORAM lookup item"));
        }
        let flags = data[pos];
        pos += 1;
        let start_chunk_id = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let num_chunks = data[pos];
        pos += 1;
        let data_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + data_len > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated ORAM lookup chunk data",
            ));
        }
        items.push(OramLookupItem {
            found: flags & 0x01 != 0,
            whale: flags & 0x02 != 0,
            start_chunk_id,
            num_chunks,
            raw_chunk_data: data[pos..pos + data_len].to_vec(),
        });
        pos += data_len;
    }
    Ok(OramLookupResult { db_id, items })
}

// ─── Database catalog encoding helpers ─────────────────────────────────────

/// Marker that begins the v1 trailing "ext" section appended after all
/// catalog entries. A decoder that doesn't know about the section parses
/// the entries and stops; one that does sees this byte and reads the
/// per-entry master seeds + chain anchors.
const CATALOG_EXT_V1: u8 = 0x01;

/// Anchor-kind discriminator inside the ext section.
const ANCHOR_KIND_NONE: u8 = 0;
const ANCHOR_KIND_SNAPSHOT: u8 = 1;
const ANCHOR_KIND_DELTA: u8 = 2;

/// Wire format:
///   [1B num_databases]
///   Per database (v1 entry):
///     [1B db_id][1B db_type][1B name_len][name bytes][4B base_height][4B height]
///     [4B index_bins][4B chunk_bins][1B index_k][1B chunk_k]
///     [8B tag_seed][1B dpf_n_index][1B dpf_n_chunk][1B has_bucket_merkle]
///   Trailing ext section (appended after ALL entries; older decoders
///   stop after the entries above and ignore it):
///     [1B CATALOG_EXT_V1]
///     Per database, in the same order:
///       [8B index_master_seed][8B chunk_master_seed][1B anchor_kind]
///       anchor_kind 1 → [36B ChainAnchor]; 2 → [72B DeltaAnchor]; 0 → none
fn encode_db_catalog(buf: &mut Vec<u8>, cat: &DatabaseCatalog) {
    buf.push(cat.databases.len() as u8);
    for entry in &cat.databases {
        buf.push(entry.db_id);
        buf.push(entry.db_type);
        let name_bytes = entry.name.as_bytes();
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&entry.base_height.to_le_bytes());
        buf.extend_from_slice(&entry.height.to_le_bytes());
        buf.extend_from_slice(&entry.index_bins_per_table.to_le_bytes());
        buf.extend_from_slice(&entry.chunk_bins_per_table.to_le_bytes());
        buf.push(entry.index_k);
        buf.push(entry.chunk_k);
        buf.extend_from_slice(&entry.tag_seed.to_le_bytes());
        buf.push(entry.dpf_n_index);
        buf.push(entry.dpf_n_chunk);
        buf.push(if entry.has_bucket_merkle { 1 } else { 0 });
    }
    // Trailing ext section: per-entry master seeds + chain anchor.
    buf.push(CATALOG_EXT_V1);
    for entry in &cat.databases {
        buf.extend_from_slice(&entry.index_master_seed.to_le_bytes());
        buf.extend_from_slice(&entry.chunk_master_seed.to_le_bytes());
        encode_anchor_ext(buf, &entry.anchor);
    }
}

fn decode_db_catalog(data: &[u8]) -> io::Result<DatabaseCatalog> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "catalog too short"));
    }
    let num_dbs = data[0] as usize;
    let mut pos = 1;
    let mut databases = Vec::with_capacity(num_dbs);
    for _ in 0..num_dbs {
        if pos + 3 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog entry"));
        }
        let db_id = data[pos];
        pos += 1;
        let db_type = data[pos];
        pos += 1;
        let name_len = data[pos] as usize;
        pos += 1;
        if pos + name_len > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog name"));
        }
        let name = String::from_utf8_lossy(&data[pos..pos + name_len]).to_string();
        pos += name_len;
        // base_height(4) + height(4) + index_bins(4) + chunk_bins(4) + index_k(1) + chunk_k(1) + tag_seed(8) + dpf_n_index(1) + dpf_n_chunk(1) = 28
        // + has_bucket_merkle(1) = 29 (optional for backward compat)
        if pos + 28 > data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated catalog fields"));
        }
        let base_height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let height = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let chunk_bins_per_table = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let index_k = data[pos];
        pos += 1;
        let chunk_k = data[pos];
        pos += 1;
        let tag_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let dpf_n_index = data[pos];
        pos += 1;
        let dpf_n_chunk = data[pos];
        pos += 1;
        // has_bucket_merkle: always present in current wire format (1 byte, 0 or 1)
        let has_bucket_merkle = if pos < data.len() {
            let v = data[pos] != 0;
            pos += 1;
            v
        } else {
            false
        };
        databases.push(DatabaseCatalogEntry {
            db_id,
            db_type,
            name,
            base_height,
            height,
            index_bins_per_table,
            chunk_bins_per_table,
            index_k,
            chunk_k,
            tag_seed,
            dpf_n_index,
            dpf_n_chunk,
            has_bucket_merkle,
            // Filled from the trailing ext section below (defaults for a
            // legacy server that doesn't emit it).
            index_master_seed: 0,
            chunk_master_seed: 0,
            anchor: None,
        });
    }

    // Trailing ext section (CATALOG_EXT_V1): per-entry master seeds + anchor.
    // Absent when talking to a pre-ext server — leave the defaults above.
    if pos < data.len() && data[pos] == CATALOG_EXT_V1 {
        pos += 1;
        for entry in databases.iter_mut() {
            if pos + 17 > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated catalog ext entry",
                ));
            }
            entry.index_master_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            entry.chunk_master_seed = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            pos += 8;
            let anchor_kind = data[pos];
            pos += 1;
            entry.anchor = decode_anchor_ext(anchor_kind, data, &mut pos)?;
        }
    }
    Ok(DatabaseCatalog { databases })
}

/// Encode one anchor record (kind byte + 0/36/72 bytes) into `buf`.
fn encode_anchor_ext(buf: &mut Vec<u8>, anchor: &Option<pir_core::cuckoo::HeaderAnchor>) {
    match anchor {
        None => buf.push(ANCHOR_KIND_NONE),
        Some(pir_core::cuckoo::HeaderAnchor::Snapshot(c)) => {
            buf.push(ANCHOR_KIND_SNAPSHOT);
            buf.extend_from_slice(&c.to_bytes());
        }
        Some(pir_core::cuckoo::HeaderAnchor::Delta(d)) => {
            buf.push(ANCHOR_KIND_DELTA);
            buf.extend_from_slice(&d.to_bytes());
        }
    }
}

/// Decode one anchor record from the catalog ext section, advancing `pos`.
fn decode_anchor_ext(
    kind: u8,
    data: &[u8],
    pos: &mut usize,
) -> io::Result<Option<pir_core::cuckoo::HeaderAnchor>> {
    use pir_core::seeds::{ChainAnchor, DeltaAnchor, CHAIN_ANCHOR_BYTES, DELTA_ANCHOR_BYTES};
    match kind {
        ANCHOR_KIND_NONE => Ok(None),
        ANCHOR_KIND_SNAPSHOT => {
            if *pos + CHAIN_ANCHOR_BYTES > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated snapshot anchor"));
            }
            let a = ChainAnchor::from_bytes(&data[*pos..*pos + CHAIN_ANCHOR_BYTES])?;
            *pos += CHAIN_ANCHOR_BYTES;
            Ok(Some(pir_core::cuckoo::HeaderAnchor::Snapshot(a)))
        }
        ANCHOR_KIND_DELTA => {
            if *pos + DELTA_ANCHOR_BYTES > data.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated delta anchor"));
            }
            let a = DeltaAnchor::from_bytes(&data[*pos..*pos + DELTA_ANCHOR_BYTES])?;
            *pos += DELTA_ANCHOR_BYTES;
            Ok(Some(pir_core::cuckoo::HeaderAnchor::Delta(a)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown catalog anchor kind {}", other),
        )),
    }
}

// ─── Attestation encoding helpers ──────────────────────────────────────────

fn encode_attest_result(buf: &mut Vec<u8>, r: &AttestResult) {
    buf.extend_from_slice(&(r.sev_snp_report.len() as u32).to_le_bytes());
    buf.extend_from_slice(&r.sev_snp_report);
    // Manifest-roots count fits in u8 because db_id is u8 (≤255 DBs).
    let n = r.manifest_roots.len();
    debug_assert!(n <= u8::MAX as usize, "too many manifest roots");
    buf.push(n as u8);
    for root in &r.manifest_roots {
        buf.extend_from_slice(root);
    }
    buf.extend_from_slice(&r.binary_sha256);
    // V2 wire layout: server_static_pub immediately after binary_sha256.
    // Bumped together with REPORT_DATA's BPIR-ATTEST-V2 tag.
    buf.extend_from_slice(&r.server_static_pub);
    let git_bytes = r.git_rev.as_bytes();
    debug_assert!(git_bytes.len() <= u16::MAX as usize, "git_rev too long");
    buf.extend_from_slice(&(git_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(git_bytes);
    // V3 cert chain extension: ARK + ASK + VCEK PEMs. Each prefixed
    // with a u32 LE length (PEMs are ~2 KB each — well below 2 GiB).
    // Empty if the operator hasn't loaded the cert chain on the
    // server; the verifier falls back to V2-binding-only mode in
    // that case.
    encode_lp_bytes_u32(buf, &r.ark_pem);
    encode_lp_bytes_u32(buf, &r.ask_pem);
    encode_lp_bytes_u32(buf, &r.vcek_pem);
}

/// Length-prefixed bytes write helper (u32 LE length + body). Mirrors
/// the existing `encode_lp_string` but without the UTF-8 assumption,
/// for binary blobs like PEM bytes.
fn encode_lp_bytes_u32(buf: &mut Vec<u8>, body: &[u8]) {
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(body);
}

fn decode_attest_result(data: &[u8]) -> io::Result<AttestResult> {
    let mut pos = 0;
    if data.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attest result missing sev_report length",
        ));
    }
    let sev_len = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if pos + sev_len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated sev_snp_report",
        ));
    }
    let sev_snp_report = data[pos..pos + sev_len].to_vec();
    pos += sev_len;

    if pos >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "attest result missing manifest count",
        ));
    }
    let n_roots = data[pos] as usize;
    pos += 1;
    if pos + n_roots * 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated manifest roots",
        ));
    }
    let mut manifest_roots = Vec::with_capacity(n_roots);
    for _ in 0..n_roots {
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[pos..pos + 32]);
        manifest_roots.push(root);
        pos += 32;
    }

    if pos + 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated binary_sha256",
        ));
    }
    let mut binary_sha256 = [0u8; 32];
    binary_sha256.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    // V2 wire layout: server_static_pub right after binary_sha256.
    if pos + 32 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated server_static_pub (V2 wire layout)",
        ));
    }
    let mut server_static_pub = [0u8; 32];
    server_static_pub.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    if pos + 2 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated git_rev length",
        ));
    }
    let git_len = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
    pos += 2;
    if pos + git_len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated git_rev bytes",
        ));
    }
    let git_rev = String::from_utf8_lossy(&data[pos..pos + git_len]).to_string();
    pos += git_len;

    // V3 cert chain extension. Trailing empty for back-compat with
    // V2-only servers (which stop emitting after git_rev — those
    // verifiers fall back to V2-binding-only mode).
    let ark_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ark_pem: {}", e)))?;
    let ask_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("ask_pem: {}", e)))?;
    let vcek_pem = decode_lp_bytes_u32_or_empty(data, &mut pos)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("vcek_pem: {}", e)))?;

    Ok(AttestResult {
        sev_snp_report,
        manifest_roots,
        binary_sha256,
        server_static_pub,
        git_rev,
        ark_pem,
        ask_pem,
        vcek_pem,
    })
}

/// Read a length-prefixed binary blob. If `pos` is at end-of-buffer
/// returns empty (back-compat with older servers that don't emit the
/// trailing fields). If `pos` is mid-buffer but the length prefix is
/// truncated or the body would overrun, returns an error.
fn decode_lp_bytes_u32_or_empty(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    if *pos == data.len() {
        return Ok(Vec::new());
    }
    if *pos + 4 > data.len() {
        return Err(format!(
            "truncated u32 length prefix at pos {} (len={})",
            *pos,
            data.len()
        ));
    }
    let n = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + n > data.len() {
        return Err(format!("body truncated: claimed {} bytes, have {}", n, data.len() - *pos));
    }
    let body = data[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(body)
}

// ─── Admin upload encoding helpers ─────────────────────────────────────────

/// Encode a length-prefixed UTF-8 string with a 4-byte LE length.
fn encode_lp_string(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    buf.extend_from_slice(&(b.len() as u32).to_le_bytes());
    buf.extend_from_slice(b);
}

/// Decode a `[4B len LE][bytes]` UTF-8 string starting at `*pos`,
/// advancing `*pos` past it. Lossy UTF-8 conversion.
fn decode_lp_string(data: &[u8], pos: &mut usize) -> io::Result<String> {
    if *pos + 4 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing length-prefixed string len",
        ));
    }
    let len = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    if *pos + len > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated length-prefixed string body",
        ));
    }
    let s = String::from_utf8_lossy(&data[*pos..*pos + len]).to_string();
    *pos += len;
    Ok(s)
}

/// Common AdminAck wire body: `[1B ok][2B msg_len LE][msg_bytes]`.
fn encode_admin_ack_payload(buf: &mut Vec<u8>, ok: bool, msg: &str) {
    buf.push(if ok { 1 } else { 0 });
    let mb = msg.as_bytes();
    buf.extend_from_slice(&(mb.len() as u16).to_le_bytes());
    buf.extend_from_slice(mb);
}

fn decode_admin_ack_payload(data: &[u8]) -> io::Result<(bool, String)> {
    if data.len() < 3 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "admin ack too short"));
    }
    let ok = data[0] != 0;
    let msg_len = u16::from_le_bytes(data[1..3].try_into().unwrap()) as usize;
    if 3 + msg_len > data.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "admin ack truncated msg"));
    }
    Ok((ok, String::from_utf8_lossy(&data[3..3 + msg_len]).to_string()))
}

fn decode_harmony_query(data: &[u8]) -> io::Result<HarmonyQuery> {
    // [1B level][1B group_id][2B round_id][4B count][count × 4B u32 LE]
    // [optional trailing 1B db_id, only when non-zero — backward compatible]
    if data.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "harmony query too short"));
    }
    let level = data[0];
    let group_id = data[1];
    let round_id = u16::from_le_bytes(data[2..4].try_into().unwrap());
    let count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let expected = 8 + count * 4;
    if data.len() < expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated harmony query indices"));
    }
    let mut indices = Vec::with_capacity(count);
    for i in 0..count {
        let off = 8 + i * 4;
        indices.push(u32::from_le_bytes(data[off..off + 4].try_into().unwrap()));
    }
    // Read trailing db_id if present (backward compatible: old clients don't send it).
    let db_id = if expected < data.len() { data[expected] } else { 0 };
    Ok(HarmonyQuery {
        level,
        group_id,
        round_id,
        indices,
        db_id,
    })
}

#[cfg(test)]
mod attest_wire_tests {
    use super::*;

    #[test]
    fn attest_request_roundtrip() {
        let nonce = [0xAAu8; 32];
        let req = Request::Attest { nonce };
        let encoded = req.encode();
        // [4B len LE][1B variant][32B nonce] = 4 + 33
        assert_eq!(encoded.len(), 4 + 33);
        let payload_len = u32::from_le_bytes(encoded[..4].try_into().unwrap()) as usize;
        assert_eq!(payload_len, 33);
        // skip the 4B length prefix when decoding the payload
        let decoded = Request::decode(&encoded[4..]).unwrap();
        match decoded {
            Request::Attest { nonce: n } => assert_eq!(n, nonce),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_request_truncated_nonce_fails() {
        // Missing the last byte of the nonce.
        let mut bad = vec![REQ_ATTEST];
        bad.extend_from_slice(&[0u8; 31]);
        let err = Request::decode(&bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn sample_entry(db_id: u8, anchor: Option<pir_core::cuckoo::HeaderAnchor>) -> DatabaseCatalogEntry {
        DatabaseCatalogEntry {
            db_id,
            db_type: 0,
            name: format!("db{}", db_id),
            base_height: 0,
            height: 850_000,
            index_bins_per_table: 1000,
            chunk_bins_per_table: 2000,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0xAABB_CCDD_EEFF_0011,
            dpf_n_index: 20,
            dpf_n_chunk: 21,
            has_bucket_merkle: true,
            index_master_seed: 0x1111_2222_3333_4444,
            chunk_master_seed: 0x5555_6666_7777_8888,
            anchor,
        }
    }

    #[test]
    fn db_catalog_ext_roundtrip_mixed_snapshot_and_legacy() {
        use pir_core::cuckoo::HeaderAnchor;
        use pir_core::seeds::ChainAnchor;
        let snap = HeaderAnchor::Snapshot(ChainAnchor { block_hash: [0x42; 32], block_height: 850_000 });
        let cat = DatabaseCatalog {
            databases: vec![sample_entry(0, Some(snap)), sample_entry(1, None)],
        };
        let mut buf = Vec::new();
        encode_db_catalog(&mut buf, &cat);
        let decoded = decode_db_catalog(&buf).unwrap();
        assert_eq!(decoded.databases.len(), 2);
        // Anchored entry: seeds + anchor survive.
        assert_eq!(decoded.databases[0].index_master_seed, 0x1111_2222_3333_4444);
        assert_eq!(decoded.databases[0].chunk_master_seed, 0x5555_6666_7777_8888);
        assert_eq!(decoded.databases[0].anchor, Some(snap));
        // Legacy-anchor entry: seeds survive, anchor is None.
        assert_eq!(decoded.databases[1].index_master_seed, 0x1111_2222_3333_4444);
        assert_eq!(decoded.databases[1].anchor, None);
    }

    #[test]
    fn db_catalog_without_ext_decodes_with_defaults() {
        // A pre-ext server stops after the entries; the decoder must
        // tolerate the absence and default the seeds/anchor.
        let mut buf = Vec::new();
        encode_db_catalog(&mut buf, &DatabaseCatalog { databases: vec![sample_entry(0, None)] });
        // Truncate the trailing ext section (everything from CATALOG_EXT_V1 on).
        // The legacy entry is fixed-shape: 1 num + (1+1+1+name + 28 + 1).
        let name_len = 3; // "db0"
        let legacy_len = 1 + (1 + 1 + 1 + name_len + 4 + 4 + 4 + 4 + 1 + 1 + 8 + 1 + 1 + 1);
        let decoded = decode_db_catalog(&buf[..legacy_len]).unwrap();
        assert_eq!(decoded.databases.len(), 1);
        assert_eq!(decoded.databases[0].index_master_seed, 0);
        assert_eq!(decoded.databases[0].anchor, None);
    }

    #[test]
    fn server_info_v2_roundtrip() {
        use pir_core::cuckoo::HeaderAnchor;
        use pir_core::seeds::ChainAnchor;
        let info = ServerInfo {
            index_bins_per_table: 100,
            chunk_bins_per_table: 200,
            index_k: 75,
            chunk_k: 80,
            tag_seed: 0xCAFE_F00D,
            index_master_seed: 0x0123_4567_89AB_CDEF,
            chunk_master_seed: 0xFEDC_BA98_7654_3210,
            anchor: Some(HeaderAnchor::Snapshot(ChainAnchor { block_hash: [7; 32], block_height: 42 })),
        };
        let encoded = Response::Info(info.clone()).encode();
        match Response::decode(&encoded[4..]).unwrap() {
            Response::Info(d) => {
                assert_eq!(d.index_master_seed, info.index_master_seed);
                assert_eq!(d.chunk_master_seed, info.chunk_master_seed);
                assert_eq!(d.anchor, info.anchor);
                assert_eq!(d.tag_seed, info.tag_seed);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn oram_lookup_request_and_response_roundtrip() {
        let req = OramLookupRequest {
            db_id: 7,
            script_hashes: vec![[0x11; pir_core::params::SCRIPT_HASH_SIZE], [0x22; pir_core::params::SCRIPT_HASH_SIZE]],
        };
        let encoded = Request::OramLookup(req.clone()).encode();
        assert_eq!(encoded[4], REQ_ORAM_LOOKUP);
        match Request::decode(&encoded[4..]).unwrap() {
            Request::OramLookup(decoded) => {
                assert_eq!(decoded.db_id, req.db_id);
                assert_eq!(decoded.script_hashes, req.script_hashes);
            }
            other => panic!("wrong variant: {:?}", other),
        }

        let result = OramLookupResult {
            db_id: 7,
            items: vec![
                OramLookupItem {
                    found: true,
                    whale: false,
                    start_chunk_id: 42,
                    num_chunks: 2,
                    raw_chunk_data: vec![0xAA; 2 * pir_core::params::CHUNK_SIZE],
                },
                OramLookupItem {
                    found: false,
                    whale: false,
                    start_chunk_id: 0,
                    num_chunks: 0,
                    raw_chunk_data: Vec::new(),
                },
            ],
        };
        let encoded = Response::OramLookupResult(result.clone()).encode();
        assert_eq!(encoded[4], RESP_ORAM_LOOKUP);
        match Response::decode(&encoded[4..]).unwrap() {
            Response::OramLookupResult(decoded) => assert_eq!(decoded, result),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn oram_lookup_rejects_oversized_batch() {
        let mut payload = vec![REQ_ORAM_LOOKUP, 0];
        payload.extend_from_slice(&((MAX_ORAM_LOOKUP_SCRIPTHASHES as u16 + 1).to_le_bytes()));
        let err = Request::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum"), "got: {}", err);
    }

    #[test]
    fn attest_response_roundtrip_with_sev_report() {
        let r = AttestResult {
            sev_snp_report: vec![0xCDu8; 1184],
            manifest_roots: vec![[0x11u8; 32], [0x22u8; 32]],
            binary_sha256: [0x33u8; 32],
            server_static_pub: [0x44u8; 32],
            git_rev: "deadbeef".to_string(),
            ark_pem: b"-----BEGIN ARK-----\nfakebytes\n-----END ARK-----\n".to_vec(),
            ask_pem: b"-----BEGIN ASK-----\nfakebytes\n-----END ASK-----\n".to_vec(),
            vcek_pem: b"-----BEGIN VCEK-----\nfakebytes\n-----END VCEK-----\n".to_vec(),
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert_eq!(r2.sev_snp_report, r.sev_snp_report);
                assert_eq!(r2.manifest_roots, r.manifest_roots);
                assert_eq!(r2.binary_sha256, r.binary_sha256);
                assert_eq!(r2.server_static_pub, r.server_static_pub);
                assert_eq!(r2.git_rev, r.git_rev);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_roundtrip_no_sev_report() {
        // Hetzner case: empty sev_snp_report, still has the rest.
        let r = AttestResult {
            sev_snp_report: vec![],
            manifest_roots: vec![[0u8; 32]],
            binary_sha256: [0xFFu8; 32],
            server_static_pub: [0u8; 32], // no channel key on this server yet
            git_rev: "unknown".to_string(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: Vec::new(),
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert!(r2.sev_snp_report.is_empty());
                assert_eq!(r2.manifest_roots.len(), 1);
                assert_eq!(r2.server_static_pub, [0u8; 32]);
                assert_eq!(r2.git_rev, "unknown");
                assert!(r2.ark_pem.is_empty());
                assert!(r2.ask_pem.is_empty());
                assert!(r2.vcek_pem.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_zero_dbs() {
        let r = AttestResult {
            sev_snp_report: vec![0u8; 50],
            manifest_roots: vec![],
            binary_sha256: [0xAAu8; 32],
            server_static_pub: [0xBBu8; 32],
            git_rev: "abc".into(),
            ark_pem: Vec::new(),
            ask_pem: Vec::new(),
            vcek_pem: vec![0xCCu8; 1500], // simulate ~1.5 KB VCEK PEM
        };
        let encoded = Response::Attest(r.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Attest(r2) => {
                assert!(r2.manifest_roots.is_empty());
                assert_eq!(r2.sev_snp_report.len(), 50);
                assert_eq!(r2.server_static_pub, [0xBBu8; 32]);
                assert_eq!(r2.vcek_pem.len(), 1500);
                assert_eq!(r2.vcek_pem[0], 0xCC);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_decoder_back_compat_no_cert_fields() {
        // Synthesise a wire payload that ends right after git_rev —
        // mimics what a V2-only server (pre-Slice-D.2) would emit.
        // The decoder should fill the cert fields with empty rather
        // than erroring with "truncated".
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&0u32.to_le_bytes()); // sev_snp_report len
        payload.push(0u8); // n_roots
        payload.extend_from_slice(&[0u8; 32]); // binary_sha256
        payload.extend_from_slice(&[0u8; 32]); // server_static_pub
        payload.extend_from_slice(&3u16.to_le_bytes()); // git_rev len
        payload.extend_from_slice(b"abc"); // git_rev
        // INTENTIONALLY no cert fields — pre-D.2 server behavior.

        let decoded = Response::decode(&payload).unwrap();
        match decoded {
            Response::Attest(r) => {
                assert_eq!(r.git_rev, "abc");
                assert!(r.ark_pem.is_empty(), "ark_pem should default empty");
                assert!(r.ask_pem.is_empty(), "ask_pem should default empty");
                assert!(r.vcek_pem.is_empty(), "vcek_pem should default empty");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn attest_response_decoder_rejects_truncated_cert_length() {
        // Build a payload where the ark_pem length prefix starts but
        // is cut short mid-u32 — must error, not silently truncate.
        let mut payload = Vec::new();
        payload.push(RESP_ATTEST);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(0u8);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&0u16.to_le_bytes());
        // Only 2 of the 4 length-prefix bytes for ark_pem.
        payload.extend_from_slice(&[0xCC, 0xDD]);

        let err = Response::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(format!("{}", err).contains("ark_pem"), "got: {}", err);
    }

    // ─── Announce wire round-trips ──────────────────────────────────────

    #[test]
    fn announce_request_roundtrip() {
        let encoded = Request::Announce.encode();
        // [4B len LE][1B variant] = 5 bytes total.
        assert_eq!(encoded.len(), 5);
        assert_eq!(u32::from_le_bytes(encoded[..4].try_into().unwrap()), 1);
        let decoded = Request::decode(&encoded[4..]).unwrap();
        assert!(matches!(decoded, Request::Announce));
    }

    #[test]
    fn announce_response_roundtrip_arbitrary_bundle() {
        // The Response::Announce wraps the bundle bytes verbatim — it
        // doesn't decode them. So this test uses an arbitrary blob to
        // confirm the length-prefix framing is symmetric.
        let bundle_bytes = (0u8..200u8).collect::<Vec<u8>>();
        let encoded = Response::Announce(bundle_bytes.clone()).encode();
        let decoded = Response::decode(&encoded[4..]).unwrap();
        match decoded {
            Response::Announce(bytes) => assert_eq!(bytes, bundle_bytes),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn announce_response_truncated_bundle_length_fails() {
        // [RESP_ANNOUNCE][len = 100][only 50 bytes of payload]
        let mut payload = vec![RESP_ANNOUNCE];
        payload.extend_from_slice(&100u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 50]);
        let err = Response::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn announce_handler_returns_bundle_when_configured() {
        use crate::handler::RequestHandler;
        let bundle_bytes = vec![1u8, 2, 3, 4, 5];
        let handler = RequestHandler::new(vec![])
            .with_announcement_bundle(Some(bundle_bytes.clone()));
        let resp = handler.handle_request(&Request::Announce);
        match resp {
            Response::Announce(bytes) => assert_eq!(bytes, bundle_bytes),
            other => panic!("expected Announce, got {:?}", other),
        }
    }

    #[test]
    fn announce_handler_returns_error_when_unconfigured() {
        use crate::handler::RequestHandler;
        let handler = RequestHandler::new(vec![]); // announcement_bundle = None
        let resp = handler.handle_request(&Request::Announce);
        match resp {
            Response::Error(msg) => assert!(msg.contains("announce not configured")),
            other => panic!("expected Error, got {:?}", other),
        }
    }

    // ─── Batch-query DoS guards (S1–S3) ─────────────────────────────────

    fn valid_key_bytes(n: u8) -> Vec<u8> {
        libdpf::Dpf::with_default_key().gen(1, n).0.to_bytes()
    }

    /// S2: an uncapped keys_per_group used to flow straight into the
    /// eval layer's fixed 8-slot bit array (OOB write).
    #[test]
    fn decode_batch_query_rejects_oversized_keys_per_group() {
        // [variant][2B round_id][1B num_groups = 1][1B keys_per_group = 200]
        let payload = vec![REQ_CHUNK_BATCH, 0, 0, 1, 200];
        let err = Request::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("keys_per_group"), "got: {}", err);
    }

    /// S3: an INDEX batch group with fewer than INDEX_CUCKOO_NUM_HASHES
    /// keys used to panic at key_refs[1] in the handler.
    #[test]
    fn decode_index_batch_rejects_fewer_than_two_keys_per_group() {
        let key = valid_key_bytes(8);
        let mut payload = vec![REQ_INDEX_BATCH, 0, 0, 1, 1];
        payload.extend_from_slice(&(key.len() as u16).to_le_bytes());
        payload.extend_from_slice(&key);
        let err = Request::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("below required"), "got: {}", err);
    }

    /// S1: a garbage key blob (declared domain n = 0) used to reach
    /// `DpfKey::from_bytes(..).expect(..)` in the handler.
    #[test]
    fn decode_batch_query_rejects_garbage_key_blob() {
        let mut payload = vec![REQ_CHUNK_BATCH, 0, 0, 1, 2];
        for _ in 0..2 {
            payload.extend_from_slice(&20u16.to_le_bytes());
            payload.extend_from_slice(&[0u8; 20]);
        }
        let err = Request::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("bad DPF key"), "got: {}", err);
    }

    /// A key whose declared domain implies more bytes than supplied
    /// must be rejected (mirrors from_bytes' length check).
    #[test]
    fn decode_batch_query_rejects_truncated_key_for_domain() {
        // n = 20 needs 1+16+1+18×13+16 = 268 bytes; send only 30.
        let mut blob = vec![20u8];
        blob.extend_from_slice(&[0u8; 29]);
        let mut payload = vec![REQ_CHUNK_BATCH, 0, 0, 1, 1];
        payload.extend_from_slice(&(blob.len() as u16).to_le_bytes());
        payload.extend_from_slice(&blob);
        let err = Request::decode(&payload).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// What the real DPF client sends (2 keys per group, n = 20)
    /// must keep decoding unchanged.
    #[test]
    fn decode_batch_query_accepts_legitimate_index_batch() {
        let g: Vec<Vec<u8>> = vec![valid_key_bytes(20), valid_key_bytes(20)];
        let q = BatchQuery { level: 0, round_id: 0, db_id: 0, keys: vec![g.clone(); 3] };
        let encoded = Request::IndexBatch(q).encode();
        match Request::decode(&encoded[4..]).unwrap() {
            Request::IndexBatch(d) => {
                assert_eq!(d.keys.len(), 3);
                assert_eq!(d.keys[0], g);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    /// Merkle sibling batches legitimately carry 1 key per group — the
    /// INDEX-only minimum must not reject them.
    #[test]
    fn decode_sibling_batch_accepts_single_key_groups() {
        let q = BatchQuery {
            level: 0,
            round_id: 100,
            db_id: 0,
            keys: vec![vec![valid_key_bytes(14)]; 2],
        };
        let encoded = Request::BucketMerkleSibBatch(q).encode();
        assert!(matches!(
            Request::decode(&encoded[4..]).unwrap(),
            Request::BucketMerkleSibBatch(_)
        ));
    }

    /// An empty batch (0 groups) has nothing to process — stays accepted.
    #[test]
    fn decode_index_batch_accepts_empty_batch() {
        let payload = vec![REQ_INDEX_BATCH, 0, 0, 0, 0];
        assert!(matches!(
            Request::decode(&payload).unwrap(),
            Request::IndexBatch(_)
        ));
    }

    #[test]
    fn validate_dpf_key_bytes_bounds() {
        assert!(validate_dpf_key_bytes(&valid_key_bytes(MIN_DPF_DOMAIN_N)).is_ok());
        assert!(validate_dpf_key_bytes(&valid_key_bytes(MAX_DPF_DOMAIN_N)).is_ok());
        // Too short for any key.
        assert!(validate_dpf_key_bytes(&[0u8; 17]).is_err());
        // Domain below the libdpf structural minimum (n − 7 underflow).
        let mut k = valid_key_bytes(8);
        k[0] = MIN_DPF_DOMAIN_N - 1;
        assert!(validate_dpf_key_bytes(&k).is_err());
        // Domain above the cap.
        let mut k = valid_key_bytes(MAX_DPF_DOMAIN_N);
        k[0] = MAX_DPF_DOMAIN_N + 1;
        assert!(validate_dpf_key_bytes(&k).is_err());
    }

    #[test]
    fn announce_end_to_end_with_pir_identity() {
        use crate::handler::RequestHandler;
        use ed25519_dalek::SigningKey;
        // Build a real bundle the SDK client will parse.
        let op_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let id_sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let cert = pir_identity::sign_identity_cert(
            &op_sk,
            "pir-test",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let manifest = pir_identity::sign_channel_manifest(
            &id_sk,
            "pir-test",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "test-rev",
            vec![],
            1_700_000_000,
        );
        let bundle = pir_identity::AnnouncementBundle { cert, manifest };
        let encoded_bundle = bundle.encode();
        let handler = RequestHandler::new(vec![])
            .with_announcement_bundle(Some(encoded_bundle.clone()));

        // Server-side: produce the RESP_ANNOUNCE wire bytes.
        let resp = handler.handle_request(&Request::Announce);
        let wire = resp.encode();

        // Client-side: decode the same wire. Bundle bytes round-trip.
        let parsed = Response::decode(&wire[4..]).unwrap();
        match parsed {
            Response::Announce(b) => {
                assert_eq!(b, encoded_bundle);
                // And the bundle itself decodes + verify_chain passes.
                let bundle2 = pir_identity::AnnouncementBundle::decode(&b).unwrap();
                bundle2.verify_chain().unwrap();
                assert_eq!(bundle2.cert.server_id, "pir-test");
            }
            other => panic!("expected Announce, got {:?}", other),
        }
    }
}
