import { readFile } from 'node:fs/promises';
import { ed25519 } from '@noble/curves/ed25519.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { beforeAll, describe, expect, it, vi } from 'vitest';

const { requireSdkWasm } = vi.hoisted(() => ({ requireSdkWasm: vi.fn() }));
vi.mock('../sdk-bridge.js', () => ({ requireSdkWasm }));

import { bytesToHex, hexToBytes } from '../hash.js';
import {
  DIRECTORY_FLOORS_STORAGE_PREFIX,
  directoryBindingMismatchV1,
  refreshNostrDirectoryV1,
  type DirectoryLiveServerV1,
  type NostrDirectoryConfigV1,
} from '../nostr-directory.js';
import { PRODUCTION_DIRECTORY } from '../production-providers.js';

const NOW = 1_800_000_000;
const NOT_BEFORE = NOW - 3_600;
const VALID_UNTIL = NOW + 7 * 24 * 3_600;
const UTF8 = new TextEncoder();

beforeAll(async () => {
  const sdk = await import('pir-sdk-wasm');
  sdk.initSync({
    module: await readFile(new URL('../../../crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm', import.meta.url)),
  });
  requireSdkWasm.mockReturnValue(sdk);
});

// ─── A directory publisher (formats of docs/DIRECTORY_PROTOCOL.md) ──────────

const DIRECTORY_SECRET = new Uint8Array(32).fill(51);
const DIRECTORY_KEY = bytesToHex(schnorr.getPublicKey(DIRECTORY_SECRET));
const FLOORS_KEY = DIRECTORY_FLOORS_STORAGE_PREFIX + DIRECTORY_KEY;

interface TestProvider {
  seed: number;
  serverId: string;
  endpoint: string;
  attestation: 'none' | 'sev-snp';
  backends: Array<[string, string]>;
}

/** A no-TEE server with an announce identity, and an SEV-SNP ORAM host. */
const ALPHA: TestProvider = {
  seed: 52,
  serverId: 'alpha',
  endpoint: 'wss://alpha.pir.example/v1',
  attestation: 'none',
  backends: [['dpf', 'best-effort'], ['harmony', 'paid'], ['onion', 'paid']],
};
const BETA: TestProvider = {
  seed: 62,
  serverId: 'beta-oram',
  endpoint: 'wss://beta.pir.example',
  attestation: 'sev-snp',
  backends: [['oram', 'free']],
};

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

function concat(...parts: Array<Uint8Array | number[]>): Uint8Array {
  return Uint8Array.from(parts.flatMap((part) => Array.from(part)));
}

function le(value: number, bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  for (let index = 0, rest = BigInt(value); index < bytes; index += 1, rest >>= 8n) {
    out[index] = Number(rest & 0xffn);
  }
  return out;
}

function operatorKey(provider: TestProvider): Uint8Array {
  return ed25519.getPublicKey(new Uint8Array(32).fill(provider.seed));
}

function providerId(provider: TestProvider): Uint8Array {
  const serverId = UTF8.encode(provider.serverId);
  return sha256(concat(UTF8.encode('BitcoinPIR/provider-id/v1'), operatorKey(provider), le(serverId.length, 4), serverId));
}

function shardOf(provider: TestProvider): number {
  return providerId(provider)[0] >> 4;
}

function signEvent(createdAt: number, d: string, shard: number, content: string): NostrEvent {
  const tags = [['d', d], ['s', `bitcoinpir-service-directory-shard-v1:${shard.toString(16)}`]];
  const id = sha256(UTF8.encode(JSON.stringify([0, DIRECTORY_KEY, createdAt, 30078, tags, content])));
  const sig = schnorr.sign(id, DIRECTORY_SECRET, new Uint8Array(32).fill(shard + 1));
  return { id: bytesToHex(id), pubkey: DIRECTORY_KEY, created_at: createdAt, kind: 30078, tags, content, sig: bytesToHex(sig) };
}

function entryEvent(provider: TestProvider, sequence: number, createdAt: number): NostrEvent {
  const secret = new Uint8Array(32).fill(provider.seed);
  const operator = ed25519.getPublicKey(secret);
  const id = providerId(provider);
  const serverId = UTF8.encode(provider.serverId);
  const url = UTF8.encode(provider.endpoint);
  const signature = ed25519.sign(concat(
    UTF8.encode('BitcoinPIR/directory-operator-assertion/v1'), [1], operator,
    le(serverId.length, 2), serverId, id, le(sequence, 8), le(NOT_BEFORE, 8), le(VALID_UNTIL, 8),
    [1], [1], le(url.length, 2), url,
  ), secret);
  const content = JSON.stringify({
    v: 1,
    provider_id: bytesToHex(id),
    directory_sequence: sequence,
    directory_valid_until: VALID_UNTIL,
    status: 'active',
    operator_assertion: {
      v: 1,
      operator_pubkey_ed25519: bytesToHex(operator),
      stable_server_id: provider.serverId,
      provider_id: bytesToHex(id),
      assertion_epoch: sequence,
      not_before: NOT_BEFORE,
      valid_until: VALID_UNTIL,
      endpoints: [{ transport: 'wss', url: provider.endpoint }],
      signature_ed25519: bytesToHex(signature),
    },
    catalog_hints: provider.backends.map(([backend, access]) =>
      ({ backend, role: 'primary', access, attestation: provider.attestation })),
    health: { class: 'available', observed_bucket: NOW - 900 },
  });
  return signEvent(createdAt, `bitcoinpir-service-directory-v1:${bytesToHex(id)}`, id[0] >> 4, content);
}

/** Both providers' entries at `sequence` and the 16 checkpoints at `epoch`. */
function catalog(sequence: number, epoch: number, createdAt: number): NostrEvent[] {
  const entries = [ALPHA, BETA].map((provider) => entryEvent(provider, sequence, createdAt));
  const checkpoints = Array.from({ length: 16 }, (_, shard) => {
    const rows = entries
      .filter((event) => event.tags[1][1].endsWith(`:${shard.toString(16)}`))
      .map((event) => ({ provider_id: event.tags[0][1].split(':')[1], directory_sequence: sequence, event_id: event.id }))
      .sort((left, right) => (left.provider_id < right.provider_id ? -1 : 1));
    const root = sha256(concat(
      UTF8.encode('BitcoinPIR/directory-catalog-checkpoint-root/v1'), [1, shard],
      le(epoch, 8), le(NOT_BEFORE, 8), le(VALID_UNTIL, 8), le(rows.length, 4),
      ...rows.flatMap((row) => [hexToBytes(row.provider_id), le(sequence, 8), hexToBytes(row.event_id)]),
    ));
    const content = JSON.stringify({
      v: 1, shard, checkpoint_epoch: epoch, not_before: NOT_BEFORE, valid_until: VALID_UNTIL,
      entries: rows, catalog_root: bytesToHex(root),
    });
    return signEvent(createdAt, `bitcoinpir-service-directory-checkpoint-v1:${shard.toString(16)}`, shard, content);
  });
  return [...entries, ...checkpoints];
}

// ─── An in-memory directory relay ───────────────────────────────────────────

/** Answers each catalog `REQ` with its shard's events and `EOSE`; a silent relay never answers. */
class FakeRelay {
  readonly sent: string[] = [];

  constructor(readonly events: NostrEvent[], readonly silent = false) {}

  socket(): WebSocket {
    return new FakeSocket(this) as unknown as WebSocket;
  }
}

class FakeSocket {
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(private readonly relay: FakeRelay) {
    queueMicrotask(() => this.onopen?.());
  }

  send(data: string): void {
    this.relay.sent.push(data);
    const [type, subscription, filter] = JSON.parse(data);
    if (type !== 'REQ' || this.relay.silent) return;
    queueMicrotask(() => {
      for (const event of this.relay.events) {
        if (event.tags[1][1] === filter['#s'][0]) {
          this.onmessage?.({ data: JSON.stringify(['EVENT', subscription, event]) });
        }
      }
      this.onmessage?.({ data: JSON.stringify(['EOSE', subscription]) });
    });
  }

  close(): void {}
}

const RELAY_A = 'wss://relay-a.example';
const RELAY_B = 'wss://relay-b.example';
const STRICT: NostrDirectoryConfigV1 = {
  mode: 'strict-multi-relay',
  relays: [RELAY_A, RELAY_B],
  directoryPubkeyHex: DIRECTORY_KEY,
};
const CENTRAL: NostrDirectoryConfigV1 = {
  mode: 'centralized-single-relay',
  relays: [RELAY_A],
  directoryPubkeyHex: DIRECTORY_KEY,
};

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (key: string) => map.get(key) ?? null,
    setItem: (key: string, value: string) => void map.set(key, value),
  };
}

function refresh(
  config: NostrDirectoryConfigV1,
  relays: Record<string, FakeRelay>,
  storage = memoryStorage(),
) {
  return refreshNostrDirectoryV1(config, {
    storage,
    nowUnix: NOW,
    timeoutMs: 50,
    openSocket: (url) => relays[url].socket(),
  });
}

describe('refreshNostrDirectoryV1', () => {
  it('reads all 16 shards from each relay and returns the candidates per backend', async () => {
    const events = catalog(1, 7, NOW - 600);
    const a = new FakeRelay(events);
    const storage = memoryStorage();
    const result = await refresh(STRICT, { [RELAY_A]: a, [RELAY_B]: new FakeRelay(events) }, storage);

    expect(result).toMatchObject({ mode: 'strict-multi-relay', degraded: false, validUntil: VALID_UNTIL, rejected: [] });
    const requests = a.sent.filter((message) => message.startsWith('["REQ"'));
    expect(requests).toHaveLength(16);
    expect(requests[0]).toBe(JSON.stringify(['REQ', 'bitcoinpir-directory-v1-shard-0', {
      authors: [DIRECTORY_KEY], kinds: [30078], '#s': ['bitcoinpir-service-directory-shard-v1:0'],
    }]));
    expect(a.sent.filter((message) => message.startsWith('["CLOSE"'))).toHaveLength(0);

    const summary = (backend: 'dpf' | 'harmony' | 'onion' | 'oram') => result.candidates[backend]
      .map(({ provider, access }) => [provider.serverId, access, provider.trustTier]);
    expect(summary('dpf')).toEqual([['alpha', 'best-effort', 'operator-identity']]);
    expect(summary('harmony')).toEqual([['alpha', 'paid', 'operator-identity']]);
    expect(summary('onion')).toEqual([['alpha', 'paid', 'operator-identity']]);
    expect(summary('oram')).toEqual([['beta-oram', 'free', 'sev-snp']]);
    expect(result.candidates.dpf[0].provider).toMatchObject({
      providerIdHex: bytesToHex(providerId(ALPHA)),
      operatorPubkeyHex: bytesToHex(operatorKey(ALPHA)),
      endpoints: ['wss://alpha.pir.example/v1'],
      role: 'primary',
      backends: { dpf: 'best-effort', harmony: 'paid', onion: 'paid' },
      health: 'available',
    });
    expect(storage.map.has(FLOORS_KEY)).toBe(true);
  });

  it('flags a centralized catalog, or a strict one short of a relay, as degraded', async () => {
    const events = catalog(1, 7, NOW - 600);
    const central = await refresh(CENTRAL, { [RELAY_A]: new FakeRelay(events) });
    expect(central).toMatchObject({ mode: 'centralized-single-relay', degraded: true, rejected: [] });
    expect(central.candidates.oram).toHaveLength(1);

    const strict = await refresh(STRICT, { [RELAY_A]: new FakeRelay(events), [RELAY_B]: new FakeRelay(events, true) });
    expect(strict.degraded).toBe(true);
    expect(strict.rejected).toEqual([{ relay: RELAY_B, shard: null, reason: expect.stringMatching(/EOSE/) }]);
    expect(strict.candidates.dpf).toHaveLength(1);
  });

  it('rejects and reports a tampered event or signature', async () => {
    const events = catalog(1, 7, NOW - 600);
    const tampered = events.map((event) => {
      if (event.content.includes('"alpha"')) return { ...event, content: event.content.replace('available', 'degraded') };
      if (event.content.includes('"beta-oram"')) return { ...event, sig: `${event.sig.slice(0, -1)}${event.sig.endsWith('0') ? '1' : '0'}` };
      return event;
    });

    const strict = await refresh(STRICT, { [RELAY_A]: new FakeRelay(tampered), [RELAY_B]: new FakeRelay(events) });
    expect(strict.rejected).toEqual([
      { relay: RELAY_A, shard: shardOf(BETA), reason: expect.stringMatching(/signature/) },
      { relay: RELAY_A, shard: shardOf(ALPHA), reason: expect.stringMatching(/event id/) },
    ].sort((left, right) => left.shard - right.shard));
    expect(strict.degraded).toBe(true);
    expect(strict.candidates.dpf).toHaveLength(1);
    expect(strict.candidates.oram).toHaveLength(1);

    const central = await refresh(CENTRAL, { [RELAY_A]: new FakeRelay(tampered) });
    expect(central.candidates.dpf).toEqual([]);
    expect(central.candidates.oram).toEqual([]);
    expect(central.rejected.filter((rejection) => rejection.relay === null).map((rejection) => rejection.shard))
      .toEqual([shardOf(BETA), shardOf(ALPHA)].sort());
  });

  it('rejects an older catalog after a newer one as a rollback and keeps the floors', async () => {
    const storage = memoryStorage();
    const newer = await refresh(CENTRAL, { [RELAY_A]: new FakeRelay(catalog(2, 8, NOW - 300)) }, storage);
    expect(newer.rejected).toEqual([]);
    const floors = storage.map.get(FLOORS_KEY);

    const older = await refresh(CENTRAL, { [RELAY_A]: new FakeRelay(catalog(1, 7, NOW - 600)) }, storage);
    expect(older.validUntil).toBe(0);
    expect(older.candidates.dpf).toEqual([]);
    expect(older.candidates.oram).toEqual([]);
    const relayRejections = older.rejected.filter((rejection) => rejection.relay === RELAY_A);
    expect(relayRejections).toHaveLength(16);
    expect(relayRejections.every((rejection) => /rollback/.test(rejection.reason))).toBe(true);
    expect(storage.map.get(FLOORS_KEY)).toBe(floors);
  });

  it('takes the relay count its mode names and a pinned key', async () => {
    await expect(refresh({ ...CENTRAL, relays: [RELAY_A, RELAY_B] }, {})).rejects.toThrow(/exactly one/);
    await expect(refresh({ ...STRICT, relays: [RELAY_A, RELAY_A] }, {})).rejects.toThrow(/two to eight distinct/);
    await expect(refresh({ ...CENTRAL, directoryPubkeyHex: null }, {})).rejects.toThrow(/no directory key/);
    // The production directory: one relay on pir1 and the publisher key pinned
    // with the first catalog publish (2026-10-19).
    expect(PRODUCTION_DIRECTORY.mode).toBe('centralized-single-relay');
    expect(PRODUCTION_DIRECTORY.relays).toEqual(['wss://directory.bitcoinpir.org']);
    expect(PRODUCTION_DIRECTORY.directoryPubkeyHex).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('directoryBindingMismatchV1', () => {
  it('binds by announce identity, or an SEV-SNP provider by its pinned attestation', async () => {
    const result = await refresh(CENTRAL, { [RELAY_A]: new FakeRelay(catalog(1, 7, NOW - 600)) });
    const alpha = result.candidates.dpf[0].provider;
    const beta = result.candidates.oram[0].provider;

    const noTee: DirectoryLiveServerV1 = {
      identity: { state: 'verified', serverId: 'alpha', operatorPubkeyHex: alpha.operatorPubkeyHex },
      attestation: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
      info: {
        role: 'primary',
        credits: {
          enabled: true,
          required: false,
          access: { dpf: { mode: 'best-effort', free_concurrency: 4 }, harmony: { mode: 'paid' }, onion: { mode: 'paid' } },
        },
      },
    };
    expect(directoryBindingMismatchV1(alpha, noTee)).toBeNull();
    expect(directoryBindingMismatchV1(alpha, { ...noTee, identity: { ...noTee.identity, serverId: 'other' } }))
      .toMatch(/identity/);
    expect(directoryBindingMismatchV1(alpha, { ...noTee, identity: { state: 'unconfigured' } }))
      .toMatch(/unconfigured/);
    expect(directoryBindingMismatchV1(alpha, { ...noTee, info: { role: 'secondary', credits: noTee.info.credits } }))
      .toMatch(/role/);
    expect(directoryBindingMismatchV1(alpha, { ...noTee, info: { role: 'primary', credits: { enabled: true, required: true } } }))
      .toMatch(/dpf access is paid/);

    const sevSnp: DirectoryLiveServerV1 = {
      identity: { state: 'unconfigured' },
      attestation: { state: 'verified-vcek', sevStatus: 'reportDataMatch', vcekChain: 'pass', pinStatus: 'match' },
      info: { role: 'primary', credits: { enabled: false, required: false } },
    };
    expect(directoryBindingMismatchV1(beta, sevSnp)).toBeNull();
    expect(directoryBindingMismatchV1(beta, { ...sevSnp, attestation: { ...sevSnp.attestation, pinStatus: 'no-pin' } }))
      .toMatch(/SEV-SNP/);
    expect(directoryBindingMismatchV1(alpha, sevSnp)).toMatch(/SEV-SNP/);
  });
});
