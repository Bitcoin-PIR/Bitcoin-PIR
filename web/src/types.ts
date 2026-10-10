/**
 * Result types shared by the DPF, OnionPIR and ORAM clients and the merge
 * utilities. HarmonyPIR has a structurally different result shape
 * (`HarmonyQueryResult`, `HarmonyUtxoEntry` with hex-string txids + `number`
 * amounts) and lives in `harmony-types.ts`.
 */

// ─── UTXO entry ─────────────────────────────────────────────────────────────

/**
 * One unspent transaction output. TXID is stored as raw 32-byte internal byte
 * order (matches what comes out of the PIR chunk decoder and what
 * `sync-merge.ts` keys dedup by).
 */
export interface UtxoEntry {
  /** 32-byte raw TXID (internal byte order) */
  txid: Uint8Array;
  vout: number;
  /** Amount in satoshis */
  amount: bigint;
}

// ─── Query result ───────────────────────────────────────────────────────────

/**
 * Result of a DPF/OnionPIR/ORAM batch query for a single scripthash:
 *   1. **User-facing data** (`entries`, `totalSats`, `isWhale`).
 *   2. **Sync / merge metadata** (`startChunkId`, `numChunks`, `numRounds`,
 *      `rawChunkData`, `scriptHash`, `merkleVerified`, `merkleRootHex`).
 *   3. **OnionPIR per-group Merkle state** (`merkleSuperRoot` onwards),
 *      used by its browser verification flow.
 */
export interface QueryResult {
  entries: UtxoEntry[];
  totalSats: bigint;
  startChunkId: number;
  numChunks: number;
  numRounds: number;
  /** True if this address was excluded from the database due to too many UTXOs */
  isWhale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** Raw chunk data retained for verified sync/merge metadata and audit UI */
  rawChunkData?: Uint8Array;
  /** Script hash used for this query */
  scriptHash?: Uint8Array;
  // ── Per-group OnionPIR Merkle (Phase 3 redesign) ──────────────────
  /**
   * Pinned super-root hex (SHA256 of the 155 per-group roots). The
   * Phase-3 per-group redesign replaced the two flat per-table roots
   * (`merkleIndexRoot` / `merkleDataRoot`) with a single anchor.
   */
  merkleSuperRoot?: string;
  /**
   * SHA256 of the first probed INDEX bin. Retained purely as the UI's
   * "this result is Merkle-verifiable" marker (index.html filters on
   * `indexBinHash !== undefined`); the per-group verifier itself walks
   * `indexBinLeaves`.
   */
  indexBinHash?: Uint8Array;
  /**
   * Every probed INDEX cuckoo bin as a per-group Merkle leaf — always
   * `INDEX_CUCKOO_NUM_HASHES` entries (found / not-found / whale alike,
   * per the INDEX item-count symmetry invariant). `pbcGroup` selects
   * the per-group INDEX tree; `bin` is the leaf index within it.
   */
  indexBinLeaves?: { hash: Uint8Array; pbcGroup: number; bin: number }[];
  /**
   * Each fetched DATA bin as a per-group Merkle leaf — one per real
   * chunk entry_id (so 0 for not-found / whale). `pbcGroup` selects the
   * per-group DATA tree; `bin` is the leaf index within it.
   */
  dataBinLeaves?: { hash: Uint8Array; pbcGroup: number; bin: number }[];
}

// ─── Connection state ───────────────────────────────────────────────────────

/**
 * Connection lifecycle state reported by clients via `onConnectionStateChange`.
 * Shared across DPF, OnionPIR, and (indirectly through the adapter) HarmonyPIR.
 */
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'reconnecting';
