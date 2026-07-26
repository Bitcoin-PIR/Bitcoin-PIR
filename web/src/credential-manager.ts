/**
 * ARC (Anonymous Rate-limited Credentials) client-side manager.
 *
 * Manages an ARC credential's presentation state: calls into WASM for the
 * cryptographic operations and tracks remaining query budget in memory.
 * Production persistence is owned by `AdmissionCredentialVaultV1`, which
 * encrypts the serialized state in IndexedDB and serializes multi-tab use.
 *
 * ## Usage
 *
 * ```typescript
 * import { ArcCredentialManager } from './credential-manager';
 *
 * // Credential bytes from the payment service (131 bytes).
 * const credBytes = fetchFromPaymentService();
 * // Fresh random 32-byte session ID for this connection.
 * const presCtx = crypto.getRandomValues(new Uint8Array(32));
 *
 * const mgr = new ArcCredentialManager(credBytes, presCtx, 50);
 * await mgr.initialize(); // loads WASM
 *
 * // Before each PIR query batch:
 * const presBytes = await mgr.present();
 * // Send presBytes in REQ_CREDENTIAL_PRESENT to the server
 * console.log(`Remaining: ${mgr.remaining}`);
 *
 * // Production callers persist mgr.serializeState() through
 * // AdmissionCredentialVaultV1; never write ARC state to localStorage.
 * ```
 */

import { requireSdkWasm } from './sdk-bridge';
import { REQ_CREDENTIAL_PRESENT } from './constants';

/** Minimum remaining queries before UI should warn the user to re-issue. */
export const ARC_LOW_WARNING = 5;

export interface ArcCredentialState {
  /** Serialized WasmArcPresentationState bytes. */
  stateBytes: Uint8Array;
  /** Remaining presentations represented by stateBytes. */
  remaining: number;
}

/**
 * Manages an ARC credential's presentation lifecycle.
 *
 * Thin wrapper over `WasmArcPresentationState` — all crypto happens in WASM.
 */
export class ArcCredentialManager {
  private state: unknown; // WasmArcPresentationState (opaque WASM handle)
  private _limit: number;
  private _presCtx: Uint8Array;

  /**
   * Create from credential bytes (received from the payment service).
   *
   * @param credentialBytes 131-byte blob from payment service
   * @param presCtx Presentation context (random session nonce)
   * @param limit Max number of queries this credential authorizes
   */
  constructor(
    credentialBytes: Uint8Array,
    presCtx: Uint8Array,
    limit: number,
  ) {
    const sdk = requireSdkWasm();
    this._presCtx = presCtx;
    this._limit = limit;
    this.state = new sdk.WasmArcPresentationState(
      credentialBytes,
      presCtx,
      BigInt(limit),
    );
  }

  /**
   * Ensure WASM is loaded. Call once before first use.
   */
  static async initialize(): Promise<void> {
    const { initSdkWasm } = await import('./sdk-bridge');
    await initSdkWasm();
  }

  /**
   * Produce the next presentation.
   *
   * @returns Wire-format presentation bytes for REQ_CREDENTIAL_PRESENT.
   * @throws If the credential is exhausted.
   */
  async present(): Promise<Uint8Array> {
    const wasmState = this.state as {
      present(): Uint8Array;
      remaining(): bigint;
      nonce(): bigint;
      serialize(): Uint8Array;
    };
    return wasmState.present();
  }

  /**
   * Build the full REQ_CREDENTIAL_PRESENT wire frame.
   *
   * Format: [4B len LE][1B variant=0x08][1B req_ctx_len][req_ctx]
   *         [1B pres_ctx_len][pres_ctx][8B limit LE][presentation bytes]
   *
   * @param requestContext The context agreed with the payment service (e.g., "bitcoin-pir-v1")
   */
  async buildPresentFrame(requestContext: Uint8Array): Promise<Uint8Array> {
    const presBytes = await this.present();
    const reqCtx = requestContext;
    const presCtx = this._presCtx;
    const limit = BigInt(this._limit);

    // Payload (without 4B length prefix)
    const payload = new Uint8Array(
      1 + 1 + reqCtx.length + 1 + presCtx.length + 8 + presBytes.length,
    );
    let off = 0;
    payload[off] = REQ_CREDENTIAL_PRESENT; off += 1;
    payload[off] = reqCtx.length; off += 1;
    payload.set(reqCtx, off); off += reqCtx.length;
    payload[off] = presCtx.length; off += 1;
    payload.set(presCtx, off); off += presCtx.length;
    // 8-byte limit LE
    const limitView = new DataView(payload.buffer, payload.byteOffset + off, 8);
    // DataView doesn't support bigint well; use 2× u32 LE
    limitView.setUint32(0, Number(limit & 0xFFFFFFFFn), true);
    limitView.setUint32(4, Number(limit >> 32n), true);
    off += 8;
    payload.set(presBytes, off);

    // Prepend 4-byte LE length (includes variant byte)
    const frame = new Uint8Array(4 + payload.length);
    const lenView = new DataView(frame.buffer);
    lenView.setUint32(0, payload.length, true);
    frame.set(payload, 4);
    return frame;
  }

  /** How many presentations remain. */
  get remaining(): number {
    const wasmState = this.state as { remaining(): bigint };
    return Number(wasmState.remaining());
  }

  /** Total presentation limit. */
  get limit(): number {
    return this._limit;
  }

  /** How many presentations already made. */
  get used(): number {
    const wasmState = this.state as { nonce(): bigint };
    return Number(wasmState.nonce());
  }

  /** Whether the credential is exhausted. */
  get exhausted(): boolean {
    return this.remaining <= 0;
  }

  /** Snapshot for encrypted, provider-bound IndexedDB persistence. */
  serializeState(): ArcCredentialState {
    const wasmState = this.state as { serialize(): Uint8Array };
    return {
      stateBytes: wasmState.serialize().slice(),
      remaining: this.remaining,
    };
  }
}
