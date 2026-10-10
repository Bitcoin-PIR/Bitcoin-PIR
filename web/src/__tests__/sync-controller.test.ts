import { afterEach, describe, expect, it, vi } from 'vitest';
import { SyncController } from '../sync-controller.js';
import type { SyncPlan } from '../sync.js';

interface TestResult {
  value: string;
  rawChunkData?: Uint8Array;
}

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
}

const scriptHash = new Uint8Array(32).fill(7);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('SyncController', () => {
  it('merges each delta step onto the snapshot and commits the height', async () => {
    vi.stubGlobal('localStorage', memoryStorage());
    const controller = new SyncController<TestResult>({ storageKey: () => 'sync-height' });
    const trace: string[] = [];
    const plan: SyncPlan = {
      isFreshSync: true,
      targetHeight: 110,
      steps: [
        { dbId: 0, dbType: 'full', name: 'snapshot', baseHeight: 0, tipHeight: 100 },
        { dbId: 1, dbType: 'delta', name: 'delta', baseHeight: 100, tipHeight: 110 },
      ],
    };

    const out = await controller.execute(plan, {
      scriptHashes: [scriptHash],
      queryStep: async (_step, index) => {
        trace.push(`query:${index}`);
        return [{ value: index === 0 ? 'snapshot' : 'delta' }];
      },
      mergeStep: (snapshot, delta) => {
        trace.push('merge:1');
        return { value: `${snapshot?.value}+${delta?.value}` };
      },
    });

    expect(trace).toEqual(['query:0', 'query:1', 'merge:1']);
    expect(out.merged[0]?.value).toBe('snapshot+delta');
    expect(controller.hasSnapshotFor(scriptHash)).toBe(true);
    expect(controller.loadLastSyncedHeight()).toBe(110);
  });

  it('rejects a partial result vector before committing', async () => {
    vi.stubGlobal('localStorage', memoryStorage());
    const controller = new SyncController<TestResult>({ storageKey: () => 'sync-height' });
    const plan: SyncPlan = {
      isFreshSync: true,
      targetHeight: 100,
      steps: [
        { dbId: 0, dbType: 'full', name: 'snapshot', baseHeight: 0, tipHeight: 100 },
      ],
    };

    await expect(controller.execute(plan, {
      scriptHashes: [scriptHash, new Uint8Array(32).fill(8)],
      queryStep: async () => [{ value: 'only one result' }],
      mergeStep: (_snapshot, next) => next,
    })).rejects.toThrow('returned 1 results; expected 2');

    expect(controller.loadLastSyncedHeight()).toBe(0);
    expect(controller.hasSnapshotFor(scriptHash)).toBe(false);
  });
});
