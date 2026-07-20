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

describe('SyncController verification barrier', () => {
  it('verifies each step before merging it', async () => {
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

    await controller.execute(plan, {
      scriptHashes: [scriptHash],
      queryStep: async (_step, index) => {
        trace.push(`query:${index}`);
        return [{ value: index === 0 ? 'snapshot' : 'delta' }];
      },
      verifyStep: async (_step, _results, index) => {
        trace.push(`verify:${index}`);
      },
      mergeStep: (snapshot, delta) => {
        trace.push('merge:1');
        return { value: `${snapshot?.value}+${delta?.value}` };
      },
    });

    expect(trace).toEqual(['query:0', 'verify:0', 'query:1', 'verify:1', 'merge:1']);
    expect(controller.getSnapshot(scriptHash)?.value).toBe('snapshot+delta');
    expect(controller.loadLastSyncedHeight()).toBe(110);
  });

  it('leaves the prior cache and height untouched when verification fails', async () => {
    vi.stubGlobal('localStorage', memoryStorage());
    const controller = new SyncController<TestResult>({ storageKey: () => 'sync-height' });
    const initial: SyncPlan = {
      isFreshSync: true,
      targetHeight: 100,
      steps: [
        { dbId: 0, dbType: 'full', name: 'snapshot', baseHeight: 0, tipHeight: 100 },
      ],
    };
    await controller.execute(initial, {
      scriptHashes: [scriptHash],
      queryStep: async () => [{ value: 'trusted snapshot' }],
      verifyStep: async () => {},
      mergeStep: (_snapshot, next) => next,
    });

    const mergeStep = vi.fn((snapshot: TestResult | null) => snapshot);
    const failing: SyncPlan = {
      isFreshSync: false,
      targetHeight: 110,
      steps: [
        { dbId: 1, dbType: 'delta', name: 'delta', baseHeight: 100, tipHeight: 110 },
      ],
    };

    await expect(controller.execute(failing, {
      scriptHashes: [scriptHash],
      queryStep: async () => [{ value: 'unverified delta' }],
      verifyStep: async () => { throw new Error('Merkle proof rejected'); },
      mergeStep,
    })).rejects.toThrow('Merkle proof rejected');

    expect(mergeStep).not.toHaveBeenCalled();
    expect(controller.getSnapshot(scriptHash)?.value).toBe('trusted snapshot');
    expect(controller.loadLastSyncedHeight()).toBe(100);
  });

  it('rejects a partial result vector before verification or commit', async () => {
    vi.stubGlobal('localStorage', memoryStorage());
    const controller = new SyncController<TestResult>({ storageKey: () => 'sync-height' });
    const verifyStep = vi.fn(async () => {});
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
      verifyStep,
      mergeStep: (_snapshot, next) => next,
    })).rejects.toThrow('returned 1 results; expected 2');

    expect(verifyStep).not.toHaveBeenCalled();
    expect(controller.loadLastSyncedHeight()).toBe(0);
    expect(controller.getSnapshot(scriptHash)).toBeUndefined();
  });
});
