/**
 * ARC (Anonymous Rate-limited Credentials) client-side manager.
 *
 * Manages an ARC credential's presentation state: calls into WASM for the
 * cryptographic operations, tracks remaining query budget, and persists
 * state to localStorage so the credential survives page reloads.
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
 * // Persist for next page load:
 * mgr.save();
 *
 * // Restore later:
 * const restored = ArcCredentialManager.load(presCtx);
 * ```
 */

import { requireSdkWasm } from './sdk-bridge';
import { REQ_CREDENTIAL_PRESENT } from './constants';

const STORAGE_KEY = 'bitcoinpir.arc.credential';

/** Minimum remaining queries before UI should warn the user to re-issue. */
export const ARC_LOW_WARNING = 5;

export interface ArcCredentialState {
  /** Serialized WasmArcPresentationState bytes. */
  stateBytes: Uint8Array;
  /** When this was last saved (ms since epoch). */
  savedAt: number;
  /** Presentation context used (needed for restoration). */
  presCtx: Uint8Array;
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

  /** Save state to localStorage. */
  save(): void {
    const wasmState = this.state as { serialize(): Uint8Array };
    const entry: ArcCredentialState = {
      stateBytes: wasmState.serialize(),
      savedAt: Date.now(),
      presCtx: this._presCtx,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      stateBytes: arrayBufferToBase64(entry.stateBytes),
      savedAt: entry.savedAt,
      presCtx: arrayBufferToBase64(entry.presCtx),
    }));
  }

  /**
   * Restore from localStorage. Returns null if no saved state exists.
   *
   * @param fallbackPresCtx Used if saved state is missing or corrupted
   */
  static load(fallbackPresCtx?: Uint8Array): ArcCredentialManager | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const data = JSON.parse(raw);
      const stateBytes = base64ToArrayBuffer(data.stateBytes);
      const presCtx = data.presCtx
        ? base64ToArrayBuffer(data.presCtx)
        : fallbackPresCtx;
      if (!presCtx) return null;

      const sdk = requireSdkWasm();
      const wasmState = sdk.WasmArcPresentationState.deserialize(stateBytes);
      const mgr = Object.create(ArcCredentialManager.prototype);
      mgr.state = wasmState;
      mgr._presCtx = presCtx;
      mgr._limit = Number(wasmState.limit());
      return mgr;
    } catch {
      localStorage.removeItem(STORAGE_KEY);
      return null;
    }
  }

  /** Delete saved state. */
  static clear(): void {
    localStorage.removeItem(STORAGE_KEY);
  }
}

function arrayBufferToBase64(buf: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < buf.length; i++) {
    binary += String.fromCharCode(buf[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
