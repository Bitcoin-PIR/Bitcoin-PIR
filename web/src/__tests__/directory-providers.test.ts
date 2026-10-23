import { describe, expect, it } from 'vitest';

import { AMD_MILAN_ARK_FINGERPRINT } from '../attest-pin.js';
import {
  DIRECTORY_SLOTS_V1,
  builtInProviderForV1,
  describeDirectoryCatalogV1,
  describeDirectoryTrustV1,
  directoryProviderChoicesV1,
} from '../directory-providers.js';
import { bytesToHex } from '../hash.js';
import type {
  DirectoryAccessClassV1,
  DirectoryCandidateV1,
  DirectoryProviderV1,
  NostrDirectoryCatalogV1,
} from '../nostr-directory.js';
import type { ProductionProviderPin } from '../production-providers.js';

const key = (fill: number) => new Uint8Array(32).fill(fill);

function provider(
  seed: number,
  serverId: string,
  role: DirectoryProviderV1['role'],
  trustTier: DirectoryProviderV1['trustTier'],
  backends: DirectoryProviderV1['backends'],
  health: DirectoryProviderV1['health'],
): DirectoryProviderV1 {
  return {
    providerIdHex: bytesToHex(key(seed + 100)),
    serverId,
    operatorPubkeyHex: bytesToHex(key(seed)),
    endpoints: [`wss://${serverId}.example`],
    role,
    trustTier,
    backends,
    health,
    validUntil: 1_800_000_000,
  };
}

/** The client's own server 0, listed under its stable id. */
const PINNED_PRIMARY = provider(1, 'pir1-like', 'primary', 'operator-identity',
  { dpf: 'best-effort', harmony: 'best-effort', onion: 'best-effort' }, 'available');
/** The client's own server 1. */
const PINNED_SECONDARY = provider(2, 'pir2-like', 'secondary', 'operator-identity',
  { dpf: 'best-effort', harmony: 'best-effort' }, 'degraded');
/** A discovered SEV-SNP Direct ORAM host. */
const DISCOVERED_ORAM = provider(3, 'oram-elsewhere', 'secondary', 'sev-snp', { oram: 'free' }, 'available');
/** A discovered no-TEE server, currently down. */
const DISCOVERED_DOWN = provider(4, 'down-elsewhere', 'primary', 'operator-identity',
  { dpf: 'paid', onion: 'free' }, 'unavailable');
/** A discovered SEV-SNP server 0 on an image this client does not know. */
const DISCOVERED_SEV = provider(5, 'sev-elsewhere', 'primary', 'sev-snp', { dpf: 'free' }, 'available');

function catalog(...providers: DirectoryProviderV1[]): NostrDirectoryCatalogV1 {
  const candidates: NostrDirectoryCatalogV1['candidates'] = { dpf: [], harmony: [], onion: [], oram: [] };
  for (const entry of providers) {
    for (const [backend, access] of Object.entries(entry.backends) as Array<[keyof typeof candidates, DirectoryAccessClassV1]>) {
      candidates[backend].push({ provider: entry, access });
    }
  }
  return { mode: 'centralized-single-relay', degraded: true, validUntil: 1_790_000_000, candidates, rejected: [] };
}

const PIN_PRIMARY: ProductionProviderPin = {
  endpoint: 'wss://pinned-primary.example',
  serverId: 'pir1-like',
  serverPin: { binarySha256Hex: 'aa'.repeat(32) },
  operatorPubkey: key(1),
  expectedArkFingerprint: null,
};
const PIN_SECONDARY: ProductionProviderPin = {
  endpoint: 'wss://pinned-secondary.example',
  serverId: 'pir2-like',
  serverPin: { binarySha256Hex: 'bb'.repeat(32) },
  operatorPubkey: key(2),
  expectedArkFingerprint: null,
};
/** The client's measured image: a Direct ORAM host with another server id. */
const PIN_MEASURED: ProductionProviderPin = {
  endpoint: 'wss://pinned-oram.example',
  serverId: 'oram-pinned',
  serverPin: { measurementHex: 'cc'.repeat(48), binarySha256Hex: 'dd'.repeat(32) },
  operatorPubkey: key(2),
  expectedArkFingerprint: AMD_MILAN_ARK_FINGERPRINT,
};
const BUILT_INS = [PIN_PRIMARY, PIN_SECONDARY, PIN_MEASURED];
const CATALOG = catalog(PINNED_PRIMARY, PINNED_SECONDARY, DISCOVERED_ORAM, DISCOVERED_DOWN, DISCOVERED_SEV);

const ids = (choices: Array<{ candidate: DirectoryCandidateV1 }>) =>
  choices.map((choice) => choice.candidate.provider.serverId);

describe('directoryProviderChoicesV1', () => {
  it('fills each slot from the candidates of its role, the pinned providers first', () => {
    expect(DIRECTORY_SLOTS_V1.dpf).toEqual(['primary', 'secondary']);
    expect(ids(directoryProviderChoicesV1(CATALOG, BUILT_INS, 'dpf', 'primary')))
      .toEqual(['pir1-like', 'sev-elsewhere', 'down-elsewhere']);
    expect(ids(directoryProviderChoicesV1(CATALOG, BUILT_INS, 'dpf', 'secondary'))).toEqual(['pir2-like']);
    expect(ids(directoryProviderChoicesV1(CATALOG, BUILT_INS, 'harmony', 'secondary'))).toEqual(['pir2-like']);
    expect(ids(directoryProviderChoicesV1(CATALOG, BUILT_INS, 'onion', 'any'))).toEqual(['pir1-like', 'down-elsewhere']);
    expect(ids(directoryProviderChoicesV1(CATALOG, BUILT_INS, 'oram', 'any'))).toEqual(['oram-elsewhere']);
  });

  it('connects a pinned provider with its own pin and the directory endpoint', () => {
    const [choice] = directoryProviderChoicesV1(CATALOG, BUILT_INS, 'dpf', 'primary');
    expect(choice.trust).toBe('pinned-build');
    expect(choice.candidate.access).toBe('best-effort');
    expect(choice.connection).toEqual({
      endpoint: 'wss://pir1-like.example',
      serverPin: PIN_PRIMARY.serverPin,
      operatorPubkey: key(1),
      expectedArkFingerprint: null,
    });
    expect(choice.label).toBe('pir1-like · pinned build · best-effort · available');
    expect(builtInProviderForV1(PINNED_SECONDARY, BUILT_INS)).toBe(PIN_SECONDARY);
    // The same server id under another operator key is another provider.
    expect(builtInProviderForV1({ ...PINNED_SECONDARY, operatorPubkeyHex: bytesToHex(key(9)) }, BUILT_INS))
      .toBeUndefined();
  });

  it('connects a discovered SEV-SNP provider against the known-good image', () => {
    const [choice] = directoryProviderChoicesV1(CATALOG, BUILT_INS, 'oram', 'any');
    expect(choice.trust).toBe('sev-snp');
    expect(choice.connection).toEqual({
      endpoint: 'wss://oram-elsewhere.example',
      serverPin: PIN_MEASURED.serverPin,
      operatorPubkey: key(3),
      expectedArkFingerprint: AMD_MILAN_ARK_FINGERPRINT,
    });
    // Without a measured image the choice stays, unpinned: it will not bind.
    const [unpinned] = directoryProviderChoicesV1(CATALOG, [PIN_PRIMARY], 'oram', 'any');
    expect(unpinned.trust).toBe('sev-snp');
    expect(unpinned.connection.serverPin).toBeUndefined();
    expect(unpinned.connection.expectedArkFingerprint).toBeNull();
  });

  it('connects a discovered no-TEE provider with the asserted operator key and no binary pin', () => {
    const choices = directoryProviderChoicesV1(CATALOG, BUILT_INS, 'onion', 'any');
    const down = choices.find((choice) => choice.candidate.provider.serverId === 'down-elsewhere')!;
    expect(down.trust).toBe('operator-identity');
    expect(down.candidate.access).toBe('free');
    expect(down.connection).toEqual({
      endpoint: 'wss://down-elsewhere.example',
      operatorPubkey: key(4),
      expectedArkFingerprint: null,
    });
    expect(down.connection.serverPin).toBeUndefined();
    expect(down.label).toBe('down-elsewhere · operator identity · free · unavailable');
  });

  it('orders by health, then access class, then trust tier, then server id', () => {
    const a = provider(11, 'a', 'primary', 'operator-identity', { onion: 'paid' }, 'available');
    const b = provider(12, 'b', 'primary', 'operator-identity', { onion: 'free' }, 'available');
    const c = provider(13, 'c', 'primary', 'sev-snp', { onion: 'paid' }, 'available');
    const d = provider(14, 'd', 'primary', 'operator-identity', { onion: 'free' }, 'unknown');
    const e = provider(15, 'e', 'primary', 'operator-identity', { onion: 'paid' }, 'available');
    expect(ids(directoryProviderChoicesV1(catalog(e, d, c, b, a), [], 'onion', 'any')))
      .toEqual(['b', 'c', 'a', 'e', 'd']);
  });
});

describe('describeDirectoryTrustV1 / describeDirectoryCatalogV1', () => {
  it('explains each tier', () => {
    expect(describeDirectoryTrustV1('pinned-build')).toMatch(/pinned in this client/);
    expect(describeDirectoryTrustV1('sev-snp')).toMatch(/MEASUREMENT this client knows/);
    expect(describeDirectoryTrustV1('operator-identity')).toMatch(/no binary pin/);
  });

  it('summarises the catalog in one line', () => {
    expect(describeDirectoryCatalogV1(CATALOG))
      .toBe('5 providers · one relay (centralized, degraded) · valid until 2026-09-21 14:13 UTC');
    expect(describeDirectoryCatalogV1({
      mode: 'strict-multi-relay', degraded: false, validUntil: 0,
      candidates: { dpf: [], harmony: [], onion: [], oram: [] },
      rejected: [{ relay: 'wss://r.example', shard: null, reason: 'timeout' }],
    })).toBe('0 providers · relays agree · no shard accepted, 1 rejected');
  });
});
