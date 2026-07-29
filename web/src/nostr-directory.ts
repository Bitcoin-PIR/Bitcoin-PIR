/** Complete, query-independent NIP-01 relay refresh for the service directory. */

import {
  DirectoryRollbackVaultV1,
  type SelectableDirectoryCatalogV1,
  type SelectableDirectoryEntryV1,
} from './directory-vault.js';
import { hexToBytes } from './hash.js';
import { requireSdkWasm } from './sdk-bridge.js';
import type { ProviderTrustAnchorV1 } from './service-admission.js';

const DIRECTORY_SUBSCRIPTION_PREFIX = 'bitcoinpir-directory-v1-shard-';
const SHARD_COUNT = 16;
const MAX_RELAYS = 8;
const MAX_EVENTS_PER_SHARD = 1_025;
const MAX_NIP01_MESSAGE_BYTES = 256 * 1024 + 256;
const MAX_RELAY_EVENT_BYTES = 8 * 1024 * 1024;
const MAX_DIRECTORY_EVENT_BYTES_TOTAL = 16 * 1024 * 1024;
const MAX_WASM_DIRECTORY_BATCH_BYTES = 64 * 1024 * 1024;
const UTF8 = new TextEncoder();

export type DirectoryRelayModeV1 =
  | 'strict-multi-relay'
  | 'centralized-single-relay';

export interface DirectoryWebSocketV1 {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'open', listener: (event: Event) => void): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  addEventListener(type: 'error', listener: (event: Event) => void): void;
  addEventListener(type: 'close', listener: (event: CloseEvent) => void): void;
  removeEventListener(type: 'open', listener: (event: Event) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'error', listener: (event: Event) => void): void;
  removeEventListener(type: 'close', listener: (event: CloseEvent) => void): void;
}

export interface NostrDirectoryRefreshOptionsV1 {
  relays: string[];
  /** Defaults to strict. Centralized mode is an explicit, exact-one-relay opt-in. */
  relayMode?: DirectoryRelayModeV1;
  pinnedDirectoryPubkeyHex: string;
  vault: DirectoryRollbackVaultV1;
  timeoutMs?: number;
  webSocketFactory?: (url: string) => DirectoryWebSocketV1;
  /** Development/test only. Production relay URLs must be wss://. */
  allowInsecureLoopback?: boolean;
}

interface CompleteRelayV1 {
  relayId: number;
  eventMessages: string[];
}

class DirectoryRefreshByteBudgetV1 {
  private used = 0;

  reserve(bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes <= 0
        || this.used + bytes > MAX_DIRECTORY_EVENT_BYTES_TOTAL) {
      return false;
    }
    this.used += bytes;
    return true;
  }

  release(bytes: number): void {
    this.used = Math.max(0, this.used - bytes);
  }
}

export interface DirectoryProviderTrustMaterialV1 {
  providerId: Uint8Array;
  operatorSigningKeyEd25519: Uint8Array;
  stableServerId: string;
  policySigningKeyEd25519: Uint8Array;
  policyEpoch: bigint;
  policyDigest: Uint8Array;
}

/**
 * Convert only a Rust-verified, durably selectable entry into the two distinct
 * keys needed by strict identity and service-policy verification. These keys
 * are directory-derived discovery trust unless the user pinned the operator
 * independently; live verification must still close both bindings.
 */
export function directoryProviderTrustMaterialV1(
  entry: SelectableDirectoryEntryV1,
): DirectoryProviderTrustMaterialV1 {
  const providerIdHex = canonicalNonzeroHex32('provider ID', entry.providerIdHex);
  const operatorKeyHex = canonicalNonzeroHex32(
    'operator Ed25519 key',
    entry.operatorPubkeyEd25519Hex,
  );
  const policyKeyHex = canonicalNonzeroHex32(
    'policy Ed25519 key',
    entry.policySigningKeyEd25519Hex,
  );
  const policyDigestHex = canonicalNonzeroHex32('policy digest', entry.policyDigestHex);
  if (operatorKeyHex === policyKeyHex) {
    throw new Error('directory entry reuses its operator key as its policy key');
  }
  if (typeof entry.stableServerId !== 'string' || entry.stableServerId.length === 0
      || !/^[1-9][0-9]*$/.test(entry.policyEpoch)) {
    throw new Error('directory entry trust material is malformed');
  }
  return {
    providerId: hexToBytes(providerIdHex),
    operatorSigningKeyEd25519: hexToBytes(operatorKeyHex),
    stableServerId: entry.stableServerId,
    policySigningKeyEd25519: hexToBytes(policyKeyHex),
    policyEpoch: BigInt(entry.policyEpoch),
    policyDigest: hexToBytes(policyDigestHex),
  };
}

/** Build the exact admission anchor; callers must not drop the assertion fields. */
export function directoryProviderTrustAnchorV1(
  entry: SelectableDirectoryEntryV1,
): ProviderTrustAnchorV1 {
  const material = directoryProviderTrustMaterialV1(entry);
  return {
    providerId: material.providerId.slice(),
    policySigningKey: material.policySigningKeyEd25519.slice(),
    directoryAssertion: {
      operatorSigningKeyEd25519: material.operatorSigningKeyEd25519.slice(),
      stableServerId: material.stableServerId,
      policyEpoch: material.policyEpoch,
      policyDigest: material.policyDigest.slice(),
    },
  };
}

/**
 * Perform one explicit refresh. There is no retry loop and refresh timing is
 * never coupled to an address query, provider choice, or payment event.
 */
export async function refreshNostrDirectoryV1(
  options: NostrDirectoryRefreshOptionsV1,
): Promise<SelectableDirectoryCatalogV1> {
  const relayMode = options.relayMode ?? 'strict-multi-relay';
  if (relayMode !== 'strict-multi-relay' && relayMode !== 'centralized-single-relay') {
    throw new Error('directory relay mode is unsupported');
  }
  const relayUrls = validateRelayUrls(
    options.relays,
    relayMode,
    options.allowInsecureLoopback ?? false,
  );
  const directoryPubkeyHex = canonicalNonzeroHex32(
    'directory pubkey',
    options.pinnedDirectoryPubkeyHex,
  );
  const directoryPubkey = hexToBytes(directoryPubkeyHex);
  const sdk = requireSdkWasm();
  const requests = parseReqMessages(sdk.directoryFullCatalogReqJsonV1(directoryPubkey));
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 10 || timeoutMs > 60_000) {
    throw new Error('directory relay timeout must be between 10 and 60000 ms');
  }
  const factory = options.webSocketFactory ?? ((url: string) => new WebSocket(url));
  const byteBudget = new DirectoryRefreshByteBudgetV1();
  const results = await Promise.allSettled(relayUrls.map((url, relayId) =>
    collectCompleteRelayV1(url, relayId, requests, timeoutMs, factory, byteBudget)));
  const complete = results
    .filter((result): result is PromiseFulfilledResult<CompleteRelayV1> =>
      result.status === 'fulfilled')
    .map((result) => result.value);
  if (relayMode === 'strict-multi-relay' && complete.length < 2) {
    throw new Error(
      'strict directory refresh has fewer than two complete 16-shard EOSE relay catalogs',
    );
  }
  if (relayMode === 'centralized-single-relay' && complete.length !== 1) {
    throw new Error('centralized directory relay did not return one complete 16-shard EOSE catalog');
  }
  const batch = UTF8.encode(JSON.stringify({
    version: 1,
    directoryMode: relayMode,
    relays: complete,
  }));
  if (batch.length > MAX_WASM_DIRECTORY_BATCH_BYTES) {
    throw new Error('complete directory relay batch exceeds the WASM V1 bound');
  }
  const candidate = relayMode === 'centralized-single-relay'
    ? sdk.WasmDirectoryCatalogCandidateV1.verifyCentralizedSingleRelayCatalog(
      batch,
      directoryPubkey,
      trustedNowUnix(),
    )
    : sdk.WasmDirectoryCatalogCandidateV1.verifyRelayCatalogs(
      batch,
      directoryPubkey,
      trustedNowUnix(),
    );
  try {
    return await options.vault.acceptCatalog(candidate);
  } finally {
    candidate.free();
  }
}

async function collectCompleteRelayV1(
  url: string,
  relayId: number,
  requests: string[],
  timeoutMs: number,
  factory: (url: string) => DirectoryWebSocketV1,
  byteBudget: DirectoryRefreshByteBudgetV1,
): Promise<CompleteRelayV1> {
  return new Promise((resolve, reject) => {
    let socket: DirectoryWebSocketV1;
    try {
      socket = factory(url);
    } catch (error) {
      reject(error);
      return;
    }
    const expected = new Set(requests.map(subscriptionIdFromReq));
    const eose = new Set<string>();
    const eventCounts = new Map<string, number>();
    const eventMessages: string[] = [];
    let retainedEventBytes = 0;
    let settled = false;
    const timeout = setTimeout(() => fail('directory relay timed out before complete EOSE'), timeoutMs);

    const cleanup = () => {
      clearTimeout(timeout);
      socket.removeEventListener('open', onOpen);
      socket.removeEventListener('message', onMessage);
      socket.removeEventListener('error', onError);
      socket.removeEventListener('close', onClose);
    };
    const fail = (message: string) => {
      if (settled) return;
      settled = true;
      cleanup();
      byteBudget.release(retainedEventBytes);
      retainedEventBytes = 0;
      eventMessages.length = 0;
      try { socket.close(1000, 'directory refresh rejected'); } catch { /* no-op */ }
      reject(new Error(message));
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      for (const subscription of expected) {
        try { socket.send(JSON.stringify(['CLOSE', subscription])); } catch { /* no-op */ }
      }
      try { socket.close(1000, 'directory refresh complete'); } catch { /* no-op */ }
      resolve({ relayId, eventMessages });
    };
    const onOpen = () => {
      try {
        for (const request of requests) socket.send(request);
      } catch {
        fail('directory relay failed while sending all-shard REQ messages');
      }
    };
    const onMessage = (event: MessageEvent) => {
      if (typeof event.data !== 'string' || event.data.length === 0) {
        fail('directory relay returned non-text or oversized NIP-01 data');
        return;
      }
      const messageBytes = UTF8.encode(event.data).byteLength;
      if (messageBytes > MAX_NIP01_MESSAGE_BYTES) {
        fail('directory relay returned non-text or oversized NIP-01 data');
        return;
      }
      let message: unknown;
      try {
        message = JSON.parse(event.data);
      } catch {
        fail('directory relay returned malformed NIP-01 JSON');
        return;
      }
      if (!Array.isArray(message) || typeof message[0] !== 'string') {
        fail('directory relay returned a malformed NIP-01 envelope');
        return;
      }
      if (message[0] === 'EVENT') {
        if (message.length !== 3 || typeof message[1] !== 'string'
            || !expected.has(message[1]) || eose.has(message[1])) {
          fail('directory relay returned EVENT for an invalid or closed subscription');
          return;
        }
        const count = (eventCounts.get(message[1]) ?? 0) + 1;
        if (count > MAX_EVENTS_PER_SHARD) {
          fail('directory relay exceeded the per-shard event bound');
          return;
        }
        if (retainedEventBytes + messageBytes > MAX_RELAY_EVENT_BYTES
            || !byteBudget.reserve(messageBytes)) {
          fail('directory relay exceeded the bounded refresh byte budget');
          return;
        }
        retainedEventBytes += messageBytes;
        eventCounts.set(message[1], count);
        // Preserve the raw envelope for Rust. Do not stringify the parsed
        // event: that would erase duplicate JSON fields before verification.
        eventMessages.push(event.data);
        return;
      }
      if (message[0] === 'EOSE') {
        if (message.length !== 2 || typeof message[1] !== 'string'
            || !expected.has(message[1]) || eose.has(message[1])) {
          fail('directory relay returned invalid or duplicate EOSE');
          return;
        }
        eose.add(message[1]);
        if (eose.size === SHARD_COUNT) finish();
        return;
      }
      if (message[0] === 'CLOSED') {
        fail('directory relay CLOSED a catalog subscription before acceptance');
        return;
      }
      // NOTICE is informational. AUTH and all unknown messages are ignored;
      // without every EOSE the bounded timeout still rejects the relay.
    };
    const onError = () => fail('directory relay WebSocket error before complete EOSE');
    const onClose = () => fail('directory relay disconnected before complete EOSE');

    socket.addEventListener('open', onOpen);
    socket.addEventListener('message', onMessage);
    socket.addEventListener('error', onError);
    socket.addEventListener('close', onClose);
  });
}

function parseReqMessages(json: string): string[] {
  let values: unknown;
  try {
    values = JSON.parse(json);
  } catch {
    throw new Error('WASM returned malformed directory REQ messages');
  }
  if (!Array.isArray(values) || values.length !== SHARD_COUNT) {
    throw new Error('directory refresh requires exactly 16 Rust-generated REQ messages');
  }
  const requests = values.map((value) => JSON.stringify(value));
  const ids = requests.map(subscriptionIdFromReq);
  if (new Set(ids).size !== SHARD_COUNT
      || ids.some((id, shard) => id !== `${DIRECTORY_SUBSCRIPTION_PREFIX}${shard.toString(16)}`)) {
    throw new Error('directory REQ subscriptions do not cover all ordered shards');
  }
  return requests;
}

function subscriptionIdFromReq(request: string): string {
  const value = JSON.parse(request) as unknown;
  if (!Array.isArray(value) || value.length !== 3 || value[0] !== 'REQ'
      || typeof value[1] !== 'string' || typeof value[2] !== 'object' || value[2] === null) {
    throw new Error('WASM returned an invalid directory REQ message');
  }
  return value[1];
}

function validateRelayUrls(
  values: string[],
  relayMode: DirectoryRelayModeV1,
  allowInsecureLoopback: boolean,
): string[] {
  if (!Array.isArray(values)) {
    throw new Error('directory relay URLs must be an array');
  }
  if (relayMode === 'centralized-single-relay' && values.length !== 1) {
    throw new Error(
      'centralized single-relay mode requires exactly one relay URL and never downgrades strict mode',
    );
  }
  if (relayMode === 'strict-multi-relay'
      && (values.length < 2 || values.length > MAX_RELAYS)) {
    throw new Error('strict directory refresh requires two to eight relay URLs');
  }
  const canonical = values.map((value) => {
    let parsed: URL;
    try { parsed = new URL(value); } catch { throw new Error('directory relay URL is invalid'); }
    const loopback = parsed.hostname === 'localhost'
      || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
    if (parsed.protocol !== 'wss:'
        && !(allowInsecureLoopback && loopback && parsed.protocol === 'ws:')) {
      throw new Error('directory relays must use wss://');
    }
    if (parsed.username || parsed.password || parsed.hash || parsed.search
        || (parsed.pathname !== '/' && parsed.pathname !== '')) {
      throw new Error('directory relay must be a credential-free WebSocket origin');
    }
    return parsed.origin;
  });
  if (new Set(canonical).size !== canonical.length) {
    throw new Error('directory relay URLs must be distinct');
  }
  return canonical;
}

function canonicalNonzeroHex32(field: string, value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value) || /^0{64}$/.test(value)) {
    throw new Error(`${field} must be non-zero lowercase 32-byte hex`);
  }
  return value;
}

function trustedNowUnix(): bigint {
  const now = Date.now();
  if (!Number.isFinite(now) || now <= 0) throw new Error('trusted wall clock is unavailable');
  return BigInt(Math.floor(now / 1000));
}
