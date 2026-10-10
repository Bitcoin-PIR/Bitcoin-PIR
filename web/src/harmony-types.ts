/**
 * HarmonyPIR-specific types.
 *
 * Shared between the HarmonyPIR adapter and any module that consumes
 * HarmonyPIR results (e.g. sync-merge). Kept in its own module so the
 * underlying implementation (TS client in the past, Rust-backed WASM
 * via HarmonyPirClientAdapter today) can be swapped without rippling
 * import-path changes through the codebase.
 */

// ─── Result shapes (different from DPF/OnionPIR — txid is a hex string
//     and the value is a number rather than a bigint amount). ────────────

export interface HarmonyUtxoEntry {
  txid: string;
  vout: number;
  value: number;
}

export interface HarmonyQueryResult {
  address: string;
  scriptHash: string;
  utxos: HarmonyUtxoEntry[];
  whale: boolean;
  /** Merkle verification result (undefined if not verified yet) */
  merkleVerified?: boolean;
  /** Merkle root hash hex (from server, for display) */
  merkleRootHex?: string;
  /** Raw chunk data (kept for Merkle verification) */
  rawChunkData?: Uint8Array;
  /** Script hash as bytes (for Merkle leaf hash) */
  scriptHashBytes?: Uint8Array;
}
