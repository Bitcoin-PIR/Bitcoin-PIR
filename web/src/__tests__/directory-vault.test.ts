import { webcrypto } from 'node:crypto';
import { indexedDB as fakeIndexedDB } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DirectoryRollbackVaultV1 } from '../directory-vault.js';
import type { WasmDirectoryCatalogCandidateV1 } from '../sdk-bridge.js';

const directory = '11'.repeat(32);
const activeProvider = '33'.repeat(32);
const databaseName = 'bitcoinpir-directory-v1';
let opened: DirectoryRollbackVaultV1[] = [];

class Candidate implements WasmDirectoryCatalogCandidateV1 {
  readonly free = vi.fn();
  readonly acknowledgePersisted = vi.fn((bytes: Uint8Array) => {
    this.acknowledged = JSON.parse(new TextDecoder().decode(bytes));
  });
  seenCurrent: any;
  acknowledged: any;
  selectableCalledAfterAck = false;

  constructor(
    private readonly successorOffset: number,
    private readonly forceNullExpected = false,
    private readonly rollbackProviders: string[] = [],
  ) {}

  stateKeysJson(): string {
    return JSON.stringify({
      version: 1,
      directoryPubkeyHex: directory,
      entries: this.rollbackProviders,
      checkpoints: Array.from({ length: 16 }, (_, shard) => shard),
    });
  }

  prepareRollback(currentStateJson: Uint8Array): string {
    this.seenCurrent = JSON.parse(new TextDecoder().decode(currentStateJson));
    const current = new Map<number, number[]>(
      this.seenCurrent.checkpoints.map((row: any) => [row.shard, row.state]),
    );
    const currentEntries = new Map<string, number[]>(
      this.seenCurrent.entries.map((row: any) => [row.providerIdHex, row.state]),
    );
    return JSON.stringify({
      version: 1,
      directoryPubkeyHex: directory,
      entries: this.rollbackProviders.map((providerIdHex, index) => ({
        providerIdHex,
        expected: this.forceNullExpected ? null : (currentEntries.get(providerIdHex) ?? null),
        successor: [this.successorOffset + 100 + index],
      })),
      checkpoints: Array.from({ length: 16 }, (_, shard) => ({
        shard,
        expected: this.forceNullExpected ? null : (current.get(shard) ?? null),
        successor: [this.successorOffset + shard + 1],
      })),
    });
  }

  selectableCatalogJson(): string {
    this.selectableCalledAfterAck = this.acknowledgePersisted.mock.calls.length === 1;
    return JSON.stringify({
      version: 1,
      directoryPubkeyHex: directory,
      directoryMode: 'strict-multi-relay',
      directoryAssurance: 'multi-origin-split-view-compared',
      catalogValidUntilUnix: '9999999999',
      shards: Array.from({ length: 16 }, (_, shard) => ({
        shard,
        checkpointEpoch: '1',
        checkpointRootHex: '22'.repeat(32),
        checkpointValidUntilUnix: '9999999999',
        entries: [],
      })),
    });
  }
}

beforeEach(async () => {
  Object.defineProperty(globalThis, 'indexedDB', {
    configurable: true,
    value: fakeIndexedDB,
  });
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    value: webcrypto,
  });
  let tail = Promise.resolve<unknown>(undefined);
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      locks: {
        request: <T>(_name: string, _options: unknown, callback: () => Promise<T>) => {
          const result = tail.then(callback, callback);
          tail = result.then(() => undefined, () => undefined);
          return result;
        },
      },
    },
  });
  await deleteDatabase();
  opened = [];
});

afterEach(async () => {
  for (const vault of opened) vault.close();
  opened = [];
  await deleteDatabase();
});

describe('encrypted directory rollback vault', () => {
  it('persists all 16 floors before selection and restores them after restart', async () => {
    const firstVault = await DirectoryRollbackVaultV1.open();
    opened.push(firstVault);
    const first = new Candidate(0);
    const selected = await firstVault.acceptCatalog(first);
    expect(selected.shards).toHaveLength(16);
    expect(JSON.stringify(first.seenCurrent)).not.toMatch(
      /relay|directoryMode|directoryAssurance|invoice|payment|query/i,
    );
    expect(first.acknowledgePersisted).toHaveBeenCalledOnce();
    expect(first.selectableCalledAfterAck).toBe(true);
    firstVault.close();
    opened = opened.filter((vault) => vault !== firstVault);

    const restartedVault = await DirectoryRollbackVaultV1.open();
    opened.push(restartedVault);
    const replay = new Candidate(0);
    await restartedVault.acceptCatalog(replay);
    expect(replay.seenCurrent.checkpoints).toHaveLength(16);
    expect(replay.seenCurrent.checkpoints.map((row: any) => row.state[0]))
      .toEqual(Array.from({ length: 16 }, (_, shard) => shard + 1));
  });

  it('fails closed on a stale CAS expectation and never acknowledges/selects', async () => {
    const vault = await DirectoryRollbackVaultV1.open();
    opened.push(vault);
    await vault.acceptCatalog(new Candidate(0));
    const stale = new Candidate(50, true);
    await expect(vault.acceptCatalog(stale)).rejects.toThrow(/CAS conflict/);
    expect(stale.acknowledgePersisted).not.toHaveBeenCalled();
    expect(stale.selectableCalledAfterAck).toBe(false);
  });

  it('reconstructs and freezes an exact selectable entry instead of returning decoded JSON', async () => {
    const vault = await DirectoryRollbackVaultV1.open();
    opened.push(vault);
    const candidate = new Candidate(0, false, [activeProvider]) as any;
    const original = candidate.selectableCatalogJson.bind(candidate);
    candidate.selectableCatalogJson = () => JSON.stringify(
      withActiveEntry(JSON.parse(original()), activeProvider),
    );
    const selected = await vault.acceptCatalog(candidate, 1_500n);
    const entry = selected.shards[3].entries[0];
    expect(entry.providerIdHex).toBe(activeProvider);
    expect(entry.entry.directory_sequence).toBe(1);
    expect(Object.isFrozen(selected)).toBe(true);
    expect(Object.isFrozen(entry)).toBe(true);
    expect(Object.isFrozen(entry.entry.operator_assertion.endpoints)).toBe(true);
  });

  it('rejects unknown selectable fields, non-conservative expiry, and expired output', async () => {
    const vault = await DirectoryRollbackVaultV1.open();
    opened.push(vault);
    const unknown = new Candidate(0) as any;
    const original = unknown.selectableCatalogJson.bind(unknown);
    unknown.selectableCatalogJson = () => JSON.stringify({
      ...JSON.parse(original()),
      paymentHash: 'forbidden',
    });
    await expect(vault.acceptCatalog(unknown, 1_500n)).rejects.toThrow(/unknown or missing fields/);

    const unknownShard = new Candidate(10) as any;
    const originalUnknownShard = unknownShard.selectableCatalogJson.bind(unknownShard);
    unknownShard.selectableCatalogJson = () => {
      const catalog = JSON.parse(originalUnknownShard());
      catalog.shards[0].invoice = 'forbidden';
      return JSON.stringify(catalog);
    };
    await expect(vault.acceptCatalog(unknownShard, 1_500n))
      .rejects.toThrow(/unknown or missing fields/);

    const unknownEntry = new Candidate(15, false, [activeProvider]) as any;
    const originalUnknownEntry = unknownEntry.selectableCatalogJson.bind(unknownEntry);
    unknownEntry.selectableCatalogJson = () => {
      const catalog = withActiveEntry(JSON.parse(originalUnknownEntry()), activeProvider);
      catalog.shards[3].entries[0].entry.invoice = 'forbidden';
      return JSON.stringify(catalog);
    };
    await expect(vault.acceptCatalog(unknownEntry, 1_500n))
      .rejects.toThrow(/unknown or missing fields/);

    const nonConservative = new Candidate(20) as any;
    const originalNonConservative = nonConservative.selectableCatalogJson.bind(nonConservative);
    nonConservative.selectableCatalogJson = () => JSON.stringify({
      ...JSON.parse(originalNonConservative()),
      catalogValidUntilUnix: '10000000000',
    });
    await expect(vault.acceptCatalog(nonConservative, 1_500n))
      .rejects.toThrow(/extends authenticated validity/);

    const tombstoneConservative = new Candidate(30, false, ['33'.repeat(32)]) as any;
    const originalTombstoneConservative =
      tombstoneConservative.selectableCatalogJson.bind(tombstoneConservative);
    tombstoneConservative.selectableCatalogJson = () => JSON.stringify({
      ...JSON.parse(originalTombstoneConservative()),
      // Rust includes authenticated tombstones in this minimum, while only
      // active entries are exported for selection.
      catalogValidUntilUnix: '9999999998',
    });
    await expect(vault.acceptCatalog(tombstoneConservative, 1_500n)).resolves.toMatchObject({
      catalogValidUntilUnix: '9999999998',
    });

    const expiredTombstoneMinimum = new Candidate(35, false, ['33'.repeat(32)]) as any;
    const originalExpiredTombstoneMinimum =
      expiredTombstoneMinimum.selectableCatalogJson.bind(expiredTombstoneMinimum);
    expiredTombstoneMinimum.selectableCatalogJson = () => JSON.stringify({
      ...JSON.parse(originalExpiredTombstoneMinimum()),
      // Visible active entries/checkpoints can remain current after the
      // authenticated tombstone-aware catalog minimum has expired.
      catalogValidUntilUnix: '1499',
    });
    await expect(vault.acceptCatalog(expiredTombstoneMinimum, 1_500n))
      .rejects.toThrow(/expired/);

    const expired = new Candidate(40);
    await expect(vault.acceptCatalog(expired, 10_000_000_000n)).rejects.toThrow(/expired/);
  });
});

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = fakeIndexedDB.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('test directory database deletion blocked'));
  });
}

function withActiveEntry(catalog: any, providerIdHex: string): any {
  catalog.shards[3].entries.push({
    providerIdHex,
    eventIdHex: '44'.repeat(32),
    directorySequence: '1',
    directoryValidUntil: '9999999999',
    operatorPubkeyEd25519Hex: '55'.repeat(32),
    stableServerId: 'provider-3',
    policySigningKeyEd25519Hex: '66'.repeat(32),
    assertionEpoch: '1',
    policyEpoch: '1',
    policyDigestHex: '77'.repeat(32),
    entry: {
      v: 1,
      provider_id: providerIdHex,
      directory_sequence: 1,
      directory_valid_until: 9_999_999_999,
      status: 'active',
      operator_assertion: {
        v: 1,
        operator_pubkey_ed25519: '55'.repeat(32),
        stable_server_id: 'provider-3',
        provider_id: providerIdHex,
        assertion_epoch: 1,
        not_before: 1,
        valid_until: 9_999_999_999,
        endpoints: [{ transport: 'wss', url: 'wss://provider.example/v1' }],
        policy_signing_key_ed25519: '66'.repeat(32),
        policy_epoch: 1,
        policy_digest: '77'.repeat(32),
        signature_ed25519: '88'.repeat(64),
      },
      catalog_hints: [],
      health: { class: 'available', observed_bucket: 300 },
    },
  });
  return catalog;
}
