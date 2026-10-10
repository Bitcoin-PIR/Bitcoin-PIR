/**
 * Constants for the Batch PIR system.
 *
 * Must match tools/db-builder/src/common.rs exactly.
 */

// ─── Index-level constants ────────────────────────────────────────────────────

/** Number of Batch PIR groups (index level) */
export const K = 75;

/** Number of group assignments per entry */
export const NUM_HASHES = 3;

/** Master PRG seed for deriving per-group cuckoo hash function keys */
export const MASTER_SEED = 0x71a2ef38b4c90d15n;

/** Number of cuckoo hash functions for INDEX level */
export const INDEX_CUCKOO_NUM_HASHES = 2;

// ─── Chunk-level constants ────────────────────────────────────────────────────

/** Number of Batch PIR groups for chunks */
export const K_CHUNK = 80;

/** Master PRG seed for chunk-level cuckoo key derivation */
export const CHUNK_MASTER_SEED = 0xa3f7c2d918e4b065n;

// ─── Protocol constants ────────────────────────────────────────────────────

export const REQ_GET_INFO_JSON = 0x03;
export const REQ_GET_DB_CATALOG = 0x02;

// ─── OnionPIR per-bin Merkle constants (arity=120, two trees) ───────────────

export const REQ_ONIONPIR_MERKLE_INDEX_SIBLING = 0x53;
export const RESP_ONIONPIR_MERKLE_INDEX_SIBLING = 0x53;
export const REQ_ONIONPIR_MERKLE_INDEX_TREE_TOP = 0x54;
export const RESP_ONIONPIR_MERKLE_INDEX_TREE_TOP = 0x54;
export const REQ_ONIONPIR_MERKLE_DATA_SIBLING = 0x55;
export const RESP_ONIONPIR_MERKLE_DATA_SIBLING = 0x55;
export const REQ_ONIONPIR_MERKLE_DATA_TREE_TOP = 0x56;
export const RESP_ONIONPIR_MERKLE_DATA_TREE_TOP = 0x56;

// ─── Credits (docs/CREDITS.md) ────────────────────────────────────────────
// 0x08 (ARC), 0x09 (Cashu blind auth) and 0x0b (session grants) are retired;
// never reassign.
// `[kind u8][len u32 LE][payload]` presented inside the encrypted channel;
// the server answers `[gas_added u64 LE][gas_balance i64 LE]`.

export const REQ_CREDIT_PRESENT = 0x12;
export const RESP_CREDIT_OK = 0x12;
/** Largest `REQ_CREDIT_PRESENT` payload a server decodes (256 KiB). */
export const MAX_CREDIT_PRESENT_PAYLOAD_LEN = 256 * 1024;
/**
 * Operator-issued API key (docs/CREDITS.md "API keys"): the key's bytes,
 * presented inside the encrypted channel; the server answers with an empty
 * `RESP_API_KEY_OK` and serves the rest of the connection unmetered.
 */
export const REQ_API_KEY = 0x13;
export const RESP_API_KEY_OK = 0x13;
/** Longest API key a server decodes. */
export const MAX_API_KEY_LEN = 128;
/**
 * Client-side pin of the credit issuer (`docs/CREDITS.md`). The server
 * announces no payment endpoint, so this is the only place the browser
 * learns where to buy credits. Operator-owned; change it here, not at
 * runtime.
 */
export const PRODUCTION_ISSUER_URL = 'https://issuer.bitcoinpir.org';
