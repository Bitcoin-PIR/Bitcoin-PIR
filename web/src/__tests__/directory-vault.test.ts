import { webcrypto } from 'node:crypto';
import { indexedDB as fakeIndexedDB } from 'fake-indexeddb';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DirectoryRollbackVaultV1 } from '../directory-vault.js';
import type { WasmDirectoryCatalogCandidateV1 } from '../sdk-bridge.js';

const directory = '11'.repeat(32);
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
  ) {}

  stateKeysJson(): string {
    return JSON.stringify({
      version: 1,
      directoryPubkeyHex: directory,
      entries: [],
      checkpoints: Array.from({ length: 16 }, (_, shard) => shard),
    });
  }

  prepareRollback(currentStateJson: Uint8Array): string {
    this.seenCurrent = JSON.parse(new TextDecoder().decode(currentStateJson));
    const current = new Map<number, number[]>(
      this.seenCurrent.checkpoints.map((row: any) => [row.shard, row.state]),
    );
    return JSON.stringify({
      version: 1,
      directoryPubkeyHex: directory,
      entries: [],
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
      shards: Array.from({ length: 16 }, (_, shard) => ({
        shard,
        checkpointEpoch: '1',
        checkpointRootHex: '22'.repeat(32),
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
});

function deleteDatabase(): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = fakeIndexedDB.deleteDatabase(databaseName);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('test directory database deletion blocked'));
  });
}
