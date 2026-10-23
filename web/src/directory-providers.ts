/**
 * Provider selection from the Nostr service directory
 * (docs/DIRECTORY_PROTOCOL.md "Browser client"; C3 in issue #429).
 *
 * `directoryProviderChoicesV1` turns a verified catalog into the connection
 * parameters a backend needs, per server slot: DPF-PIR and HarmonyPIR take a
 * primary (server 0, hint) and a secondary (server 1, query) provider,
 * OnionPIR and Direct ORAM one provider of any role. A candidate that is one
 * of the client's own pinned providers (same operator key and `server_id`)
 * connects with that pin: binary hash or MEASUREMENT and operator key fixed
 * at build time, the endpoint taken from the directory. Any other candidate
 * is trusted at the tier the directory asserts, which the trust model makes
 * the directory key's responsibility: `sev-snp` connects against the
 * client's known-good MEASUREMENT (a provider on another image reports a
 * measurement mismatch and never binds), `operator-identity` connects with
 * the directory-asserted operator key and no binary pin, and is shown as
 * such. Nothing here blocks a candidate; the page decides, and the manual
 * endpoint with the built-in pin stays the bypass when the directory is
 * unavailable. After connecting, `directoryBindingMismatchV1` closes the
 * choice against the live server; `fetchLiveServerInfoV1` reads the `role`
 * and access policy that check needs.
 */

import type { ServerAttestPin } from './attest-pin.js';
import type { AccessBackend } from './credits.js';
import { bytesToHex, hexToBytes } from './hash.js';
import type {
  DirectoryCandidateV1,
  NostrDirectoryCatalogV1,
} from './nostr-directory.js';
import type { ProductionProviderPin } from './production-providers.js';
import { fetchServerInfoJson, type ServerInfoJson } from './server-info.js';
import { ManagedWebSocket } from './ws.js';

/**
 * How a chosen provider is trusted: `pinned-build` is one of the client's
 * own providers (operator key and build pinned here), the other two are the
 * directory's tiers for a provider this client has no pin for.
 */
export type DirectoryProviderTrustV1 = 'pinned-build' | 'sev-snp' | 'operator-identity';

/** The server slot a backend fills from the directory. */
export type DirectorySlotV1 = 'primary' | 'secondary' | 'any';

/** Slots per backend, in connection order. */
export const DIRECTORY_SLOTS_V1: Readonly<Record<AccessBackend, readonly DirectorySlotV1[]>> =
  Object.freeze({
    dpf: Object.freeze(['primary', 'secondary'] as const),
    harmony: Object.freeze(['primary', 'secondary'] as const),
    onion: Object.freeze(['any'] as const),
    oram: Object.freeze(['any'] as const),
  });

/** Connection parameters of a chosen provider, as the adapters take them. */
export interface DirectoryProviderConnectionV1 {
  endpoint: string;
  /** Build pin; absent for an `operator-identity` provider (no binary pin). */
  serverPin?: ServerAttestPin;
  /** Raw 32-byte operator key for the REQ_ANNOUNCE check. */
  operatorPubkey: Uint8Array;
  /** ARK for the VCEK chain check; `null` skips it (no-TEE provider). */
  expectedArkFingerprint: Uint8Array | null;
}

export interface DirectoryProviderChoiceV1 {
  candidate: DirectoryCandidateV1;
  trust: DirectoryProviderTrustV1;
  connection: DirectoryProviderConnectionV1;
  /** One line for a picker: server id, trust, access class, health. */
  label: string;
}

const HEALTH_ORDER = { available: 0, degraded: 1, unknown: 2, unavailable: 3 } as const;
const ACCESS_ORDER = { free: 0, 'best-effort': 1, paid: 2 } as const;
const TRUST_ORDER = { 'pinned-build': 0, 'sev-snp': 1, 'operator-identity': 2 } as const;
const TRUST_LABEL: Record<DirectoryProviderTrustV1, string> = {
  'pinned-build': 'pinned build',
  'sev-snp': 'SEV-SNP',
  'operator-identity': 'operator identity',
};

/**
 * The candidates of `backend` that fit `slot`, as connection choices, best
 * first: the client's pinned providers, then by health, access class
 * (free, best-effort, paid), trust tier and server id. `builtIns` are the
 * client's pinned providers; those with a MEASUREMENT also supply the
 * known-good image for discovered `sev-snp` providers.
 */
export function directoryProviderChoicesV1(
  catalog: Pick<NostrDirectoryCatalogV1, 'candidates'>,
  builtIns: readonly ProductionProviderPin[],
  backend: AccessBackend,
  slot: DirectorySlotV1,
): DirectoryProviderChoiceV1[] {
  const measured = builtIns.find((pin) => pin.serverPin.measurementHex);
  return catalog.candidates[backend]
    .filter((candidate) => slot === 'any' || candidate.provider.role === slot)
    .map((candidate) => choice(candidate, builtIns, measured))
    .sort((left, right) =>
      Number(left.trust !== 'pinned-build') - Number(right.trust !== 'pinned-build')
      || HEALTH_ORDER[left.candidate.provider.health] - HEALTH_ORDER[right.candidate.provider.health]
      || ACCESS_ORDER[left.candidate.access] - ACCESS_ORDER[right.candidate.access]
      || TRUST_ORDER[left.trust] - TRUST_ORDER[right.trust]
      || left.candidate.provider.serverId.localeCompare(right.candidate.provider.serverId));
}

/** The pinned provider a directory entry describes, when the client has one. */
export function builtInProviderForV1(
  provider: Pick<DirectoryCandidateV1['provider'], 'serverId' | 'operatorPubkeyHex'>,
  builtIns: readonly ProductionProviderPin[],
): ProductionProviderPin | undefined {
  return builtIns.find((pin) => pin.serverId !== undefined
    && pin.serverId === provider.serverId
    && bytesToHex(pin.operatorPubkey) === provider.operatorPubkeyHex);
}

function choice(
  candidate: DirectoryCandidateV1,
  builtIns: readonly ProductionProviderPin[],
  measured: ProductionProviderPin | undefined,
): DirectoryProviderChoiceV1 {
  const { provider } = candidate;
  const endpoint = provider.endpoints[0] ?? '';
  const builtIn = builtInProviderForV1(provider, builtIns);
  let trust: DirectoryProviderTrustV1;
  let connection: DirectoryProviderConnectionV1;
  if (builtIn) {
    trust = 'pinned-build';
    connection = {
      endpoint,
      serverPin: builtIn.serverPin,
      operatorPubkey: builtIn.operatorPubkey,
      expectedArkFingerprint: builtIn.expectedArkFingerprint,
    };
  } else if (provider.trustTier === 'sev-snp') {
    trust = 'sev-snp';
    connection = {
      endpoint,
      serverPin: measured?.serverPin,
      operatorPubkey: hexToBytes(provider.operatorPubkeyHex),
      expectedArkFingerprint: measured?.expectedArkFingerprint ?? null,
    };
  } else {
    trust = 'operator-identity';
    connection = {
      endpoint,
      operatorPubkey: hexToBytes(provider.operatorPubkeyHex),
      expectedArkFingerprint: null,
    };
  }
  return {
    candidate,
    trust,
    connection,
    label: `${provider.serverId} · ${TRUST_LABEL[trust]} · ${candidate.access} · ${provider.health}`,
  };
}

/** What a trust tier means for the connection, for the badge. */
export function describeDirectoryTrustV1(trust: DirectoryProviderTrustV1): string {
  switch (trust) {
    case 'pinned-build':
      return 'operator key and build pinned in this client; the directory supplied the endpoint';
    case 'sev-snp':
      return 'operator key asserted by the directory; the server must attest to a MEASUREMENT this client knows';
    case 'operator-identity':
      return 'operator key asserted by the directory, no binary pin: the directory key is the trust boundary for this operator';
  }
}

/** One line on the catalog: providers, mode, expiry. */
export function describeDirectoryCatalogV1(
  catalog: Pick<NostrDirectoryCatalogV1, 'mode' | 'degraded' | 'validUntil' | 'candidates' | 'rejected'>,
): string {
  const providers = new Set<string>();
  for (const candidates of Object.values(catalog.candidates)) {
    for (const candidate of candidates) providers.add(candidate.provider.providerIdHex);
  }
  const mode = catalog.mode === 'centralized-single-relay'
    ? 'one relay (centralized, degraded)'
    : catalog.degraded ? 'relays disagree or are short (degraded)' : 'relays agree';
  const expiry = catalog.validUntil > 0
    ? `valid until ${new Date(catalog.validUntil * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC`
    : 'no shard accepted';
  const rejected = catalog.rejected.length > 0 ? `, ${catalog.rejected.length} rejected` : '';
  return `${providers.size} provider${providers.size === 1 ? '' : 's'} · ${mode} · ${expiry}${rejected}`;
}

/**
 * The live `role` and access policy of a server (`GET_INFO_JSON`, cleartext
 * and unmetered), for `directoryBindingMismatchV1`, over a short connection
 * of its own: the backend adapters keep their server info inside the SDK.
 */
export async function fetchLiveServerInfoV1(
  endpoint: string,
  options: { timeoutMs?: number } = {},
): Promise<Pick<ServerInfoJson, 'role' | 'credits'>> {
  const socket = new ManagedWebSocket({
    url: endpoint,
    label: `${endpoint} (directory check)`,
    requestTimeoutMs: options.timeoutMs ?? 15_000,
  });
  await socket.connect();
  try {
    const info = await fetchServerInfoJson(socket);
    return { role: info.role, credits: info.credits };
  } finally {
    socket.disconnect();
  }
}
