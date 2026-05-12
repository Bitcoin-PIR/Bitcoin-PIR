/**
 * ARC credential presentation for PIR WebSocket connections.
 *
 * Before each PIR query batch, call `sendArcPresentation(ws, credMgr)` to
 * attach an ARC proof. The server verifies it and responds 0x00 (valid) or
 * an error code.
 *
 * Usage in an adapter's queryBatch():
 *
 *   if (this.credMgr) {
 *     await sendArcPresentation(ws, this.credMgr);
 *   }
 *   // ... proceed with normal PIR query ...
 */

import { RESP_CREDENTIAL_OK } from './constants';
import { ArcCredentialManager } from './credential-manager';
import { ManagedWebSocket } from './ws';

/** Fixed request_context agreed with the payment service. */
const REQUEST_CONTEXT = new TextEncoder().encode('bitcoin-pir-v1');

/**
 * Send an ARC credential presentation on the given WebSocket.
 *
 * Returns the response status byte (0x00 = OK).
 * @throws If the presentation fails or the server rejects it.
 */
export async function sendArcPresentation(
  ws: ManagedWebSocket,
  credMgr: ArcCredentialManager,
): Promise<number> {
  const frame = await credMgr.buildPresentFrame(REQUEST_CONTEXT);
  const resp = await ws.sendRaw(frame);

  if (resp.length < 2 || resp[0] !== RESP_CREDENTIAL_OK) {
    throw new Error(
      `ARC presentation: unexpected response byte 0x${resp[0]?.toString(16)}`,
    );
  }

  const status = resp[1];
  if (status !== 0x00) {
    const reasons: Record<number, string> = {
      0x01: 'credential exhausted',
      0x02: 'proof invalid',
      0x03: 'duplicate tag',
    };
    throw new Error(
      `ARC presentation rejected: ${reasons[status] ?? `status 0x${status.toString(16)}`}`,
    );
  }

  return status;
}
