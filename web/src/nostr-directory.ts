/**
 * Nostr service directory client (docs/DIRECTORY_PROTOCOL.md).
 *
 * `refreshNostrDirectoryV1` reads the full 16-shard catalog from the
 * configured relays (NIP-01 `REQ` / `EOSE`), verifies it in WASM
 * against the pinned directory key and the stored rollback floors, stores
 * the advanced floors, and returns the candidate providers per backend.
 * Every relay, shard or event that fails is reported in `rejected`; whether
 * a degraded catalog is good enough is the caller's choice.
 *
 * A candidate is a discovery hint. Connect to it with the usual checks
 * (attestation, operator identity, database proof, server info), then close
 * it against the live server with `directoryBindingMismatchV1`.
 */

import type { StorageLike } from './cashu-wallet.js';
import { resolveAccess, type AccessBackend } from './credits.js';
import { hexToBytes } from './hash.js';
import { requireSdkWasm } from './sdk-bridge.js';
import type { ServerInfoJson } from './server-info.js';
import type { OperatorIdentity, ServerAttestation } from './verification.js';

/** `localStorage` key prefix of the rollback floors, one entry per directory key. */
export const DIRECTORY_FLOORS_STORAGE_PREFIX = 'bitcoinpir.directory-floors.v1.';

const SHARDS = 16;
const MAX_STRICT_RELAYS = 8;
const MAX_RELAY_BYTES = 16 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * `strict-multi-relay`: two to eight distinct relays whose views are
 * compared. `centralized-single-relay`: exactly one relay; its catalog is
 * always reported degraded.
 */
export type DirectoryRelayModeV1 = 'strict-multi-relay' | 'centralized-single-relay';
export type DirectoryAccessClassV1 = 'free' | 'paid' | 'best-effort';
/**
 * How a provider is bound live: its REQ_ANNOUNCE operator identity, or, for
 * an SEV-SNP provider, its attestation against the client's pinned
 * MEASUREMENT.
 */
export type DirectoryTrustTierV1 = 'operator-identity' | 'sev-snp';

export interface NostrDirectoryConfigV1 {
  mode: DirectoryRelayModeV1;
  relays: readonly string[];
  /** The directory publisher's x-only key, lowercase hex; `null` until one is pinned. */
  directoryPubkeyHex: string | null;
}

export interface NostrDirectoryRefreshOptionsV1 {
  /** Where the rollback floors are kept; `localStorage` by default, `null` for none. */
  storage?: StorageLike | null;
  /** Unix seconds the catalog is verified at; the local clock by default. */
  nowUnix?: number;
  /** Per relay, for the whole catalog; 10 s by default. */
  timeoutMs?: number;
  /** Opens one relay connection; `new WebSocket(url)` by default. */
  openSocket?: (url: string) => WebSocket;
}

export interface DirectoryProviderV1 {
  providerIdHex: string;
  /** `server_id` of the operator assertion. */
  serverId: string;
  /** Ed25519 operator key of the assertion, lowercase hex. */
  operatorPubkeyHex: string;
  /** Connection hints only. */
  endpoints: string[];
  role: 'primary' | 'secondary';
  trustTier: DirectoryTrustTierV1;
  /** Access class of every backend the entry lists. */
  backends: Partial<Record<AccessBackend, DirectoryAccessClassV1>>;
  health: 'unknown' | 'available' | 'degraded' | 'unavailable';
  /** Unix seconds; the entry is not valid after it. */
  validUntil: number;
}

export interface DirectoryCandidateV1 {
  provider: DirectoryProviderV1;
  /** The backend's access class on this provider. */
  access: DirectoryAccessClassV1;
}

export interface DirectoryRejectionV1 {
  /** The relay whose view was rejected; `null` for a whole shard. */
  relay: string | null;
  /** The shard; `null` for a relay's whole view. */
  shard: number | null;
  reason: string;
}

export interface NostrDirectoryCatalogV1 {
  mode: DirectoryRelayModeV1;
  /** False only when all 16 shards came from at least two agreeing relays. */
  degraded: boolean;
  /** Earliest expiry (unix seconds) over the accepted shards; 0 when none was accepted. */
  validUntil: number;
  /** Providers listing each backend, by provider id. */
  candidates: Record<AccessBackend, DirectoryCandidateV1[]>;
  rejected: DirectoryRejectionV1[];
}

/** What the client verified about one connected server. */
export interface DirectoryLiveServerV1 {
  /** The REQ_ANNOUNCE check (`checkOperatorIdentity`). */
  identity: OperatorIdentity;
  /** The secure-channel attestation (`summariseAttestation`). */
  attestation: ServerAttestation;
  /** `role` and `credits` of the server's `GET_INFO_JSON`. */
  info: Pick<ServerInfoJson, 'role' | 'credits'>;
}

/** `verifyDirectoryCatalogV1` output (crates/sdk/wasm/src/directory.rs). */
interface VerifiedCatalogV1 {
  validUntil: number;
  shards: Array<{ shard: number; epoch: number; views: number; eventId: string }>;
  entries: Array<{
    providerId: string;
    serverId: string;
    operatorPubkey: string;
    endpoints: string[];
    health: DirectoryProviderV1['health'];
    validUntil: number;
    hints: Array<{
      backend: AccessBackend;
      role: 'primary' | 'secondary';
      access: DirectoryAccessClassV1;
      attestation: 'none' | 'sev-snp';
    }>;
  }>;
  rejected: Array<{ relay: number | null; shard: number | null; reason: string }>;
  state: unknown;
}

/** Read, verify and return the directory catalog; see the module comment. */
export async function refreshNostrDirectoryV1(
  config: NostrDirectoryConfigV1,
  options: NostrDirectoryRefreshOptionsV1 = {},
): Promise<NostrDirectoryCatalogV1> {
  const { mode, relays, directoryPubkeyHex } = config;
  if (!directoryPubkeyHex) throw new Error('no directory key is pinned');
  if (mode === 'centralized-single-relay' && relays.length !== 1) {
    throw new Error('centralized-single-relay takes exactly one relay');
  }
  if (mode === 'strict-multi-relay' && (relays.length < 2 || relays.length > MAX_STRICT_RELAYS
    || new Set(relays).size !== relays.length)) {
    throw new Error('strict-multi-relay takes two to eight distinct relays');
  }
  const sdk = requireSdkWasm();
  const key = hexToBytes(directoryPubkeyHex);
  const requests = sdk.directoryCatalogRequestsV1(key);
  const openSocket = options.openSocket ?? ((url: string) => new WebSocket(url));
  const reads = await Promise.allSettled(relays.map((url) =>
    readCatalog(url, requests, options.timeoutMs ?? DEFAULT_TIMEOUT_MS, openSocket)));

  const rejected: DirectoryRejectionV1[] = [];
  const views: string[][] = [];
  const viewRelays: string[] = [];
  reads.forEach((read, index) => {
    if (read.status === 'fulfilled') {
      views.push(read.value);
      viewRelays.push(relays[index]);
    } else {
      rejected.push({ relay: relays[index], shard: null, reason: errorMessage(read.reason) });
    }
  });

  const storage = options.storage === undefined ? defaultStorage() : options.storage;
  const floorsKey = DIRECTORY_FLOORS_STORAGE_PREFIX + directoryPubkeyHex;
  const verified = JSON.parse(sdk.verifyDirectoryCatalogV1(
    JSON.stringify(views),
    storage?.getItem(floorsKey) ?? undefined,
    key,
    BigInt(options.nowUnix ?? Math.floor(Date.now() / 1000)),
  )) as VerifiedCatalogV1;
  // The advanced floors are stored before anything can use the catalog.
  storage?.setItem(floorsKey, JSON.stringify(verified.state));

  for (const rejection of verified.rejected) {
    rejected.push({
      relay: rejection.relay === null ? null : viewRelays[rejection.relay],
      shard: rejection.shard,
      reason: rejection.reason,
    });
  }
  const candidates: Record<AccessBackend, DirectoryCandidateV1[]> = {
    dpf: [], harmony: [], onion: [], oram: [],
  };
  for (const entry of verified.entries) {
    if (entry.hints.length === 0) continue;
    const provider: DirectoryProviderV1 = {
      providerIdHex: entry.providerId,
      serverId: entry.serverId,
      operatorPubkeyHex: entry.operatorPubkey,
      endpoints: entry.endpoints,
      role: entry.hints[0].role,
      trustTier: entry.hints[0].attestation === 'sev-snp' ? 'sev-snp' : 'operator-identity',
      backends: Object.fromEntries(entry.hints.map((hint) => [hint.backend, hint.access])),
      health: entry.health,
      validUntil: entry.validUntil,
    };
    for (const hint of entry.hints) candidates[hint.backend].push({ provider, access: hint.access });
  }
  return {
    mode,
    degraded: mode === 'centralized-single-relay' || verified.shards.length < SHARDS
      || verified.shards.some((shard) => shard.views < 2),
    validUntil: verified.validUntil,
    candidates,
    rejected,
  };
}

/**
 * Close a directory provider against the live server, as the codec's
 * `bind_directory_entry_to_live_identity_v1` does: `null` when the server is
 * the provider the entry describes, otherwise what differs. A verified
 * announce identity must carry the assertion's operator key and `server_id`
 * (which together derive the provider id); a server that announces no
 * identity binds only as an SEV-SNP provider whose report verified to AMD
 * and matched the client's pin. Role, attestation tier and the access class
 * of every listed backend must be what the live server publishes.
 */
export function directoryBindingMismatchV1(
  provider: DirectoryProviderV1,
  live: DirectoryLiveServerV1,
): string | null {
  const sevSnp = live.attestation.state === 'verified-vcek' && live.attestation.pinStatus === 'match';
  const { identity } = live;
  if (identity.state === 'verified') {
    if (identity.operatorPubkeyHex !== provider.operatorPubkeyHex
      || identity.serverId !== provider.serverId) {
      return 'the live operator identity is not the one the directory asserts';
    }
  } else if (identity.state !== 'unconfigured' || provider.trustTier !== 'sev-snp' || !sevSnp) {
    return `operator identity is ${identity.state}; only a pinned SEV-SNP provider binds without one`;
  }
  if (sevSnp !== (provider.trustTier === 'sev-snp')) {
    return `live attestation is ${sevSnp ? 'sev-snp' : 'not a pinned sev-snp'}, the directory says ${provider.trustTier}`;
  }
  if (live.info.role !== provider.role) {
    return `live role is ${live.info.role}, the directory says ${provider.role}`;
  }
  for (const [backend, access] of Object.entries(provider.backends) as Array<[AccessBackend, DirectoryAccessClassV1]>) {
    const served = resolveAccess(live.info.credits, backend).mode;
    if (served !== access) return `live ${backend} access is ${served}, the directory says ${access}`;
  }
  return null;
}

/** Every `EVENT` message one relay returns for `requests`, once each subscription reached `EOSE`. */
function readCatalog(
  url: string,
  requests: string[],
  timeoutMs: number,
  openSocket: (url: string) => WebSocket,
): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const open = new Set(requests.map((request) => JSON.parse(request)[1] as string));
    const events: string[] = [];
    let bytes = 0;
    let socket: WebSocket;
    try {
      socket = openSocket(url);
    } catch (error) {
      reject(error);
      return;
    }
    const finish = (error: string | null) => {
      clearTimeout(timer);
      socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
      // Closing the connection ends every subscription; no CLOSE frames.
      try {
        socket.close();
      } catch {
        // The connection is gone either way.
      }
      if (error === null) resolve(events);
      else reject(new Error(error));
    };
    const timer = setTimeout(() => finish(`no EOSE on every shard within ${timeoutMs} ms`), timeoutMs);
    socket.onopen = () => {
      for (const request of requests) socket.send(request);
    };
    socket.onmessage = (event) => {
      const data: unknown = event.data;
      if (typeof data !== 'string') return finish('relay sent a binary message');
      bytes += data.length;
      if (bytes > MAX_RELAY_BYTES) return finish(`relay sent more than ${MAX_RELAY_BYTES} bytes`);
      let message: unknown;
      try {
        message = JSON.parse(data);
      } catch {
        return finish('relay sent malformed JSON');
      }
      if (!Array.isArray(message)) return finish('relay sent a malformed message');
      const [type, id] = message as unknown[];
      if (type === 'EVENT') {
        if (!open.has(id as string)) return finish('relay sent an EVENT outside an open subscription');
        // The exact message: Rust verifies the event's own JSON text.
        events.push(data);
      } else if (type === 'EOSE') {
        if (!open.delete(id as string)) return finish('relay sent an unexpected EOSE');
        if (open.size === 0) finish(null);
      } else if (type === 'CLOSED') {
        finish(`relay closed a subscription: ${String(message[2] ?? '')}`);
      }
      // NOTICE and anything else carries nothing the catalog needs.
    };
    socket.onerror = () => finish('WebSocket error');
    socket.onclose = () => finish('relay closed the connection before EOSE');
  });
}

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
