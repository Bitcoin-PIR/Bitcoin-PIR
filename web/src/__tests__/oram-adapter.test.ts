import { describe, expect, it } from 'vitest';

import {
  DEFAULT_ORAM_ACCESS_BUDGET,
  DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH,
  DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
  OramPirClientAdapter,
  oramJsonResultToQueryResult,
  planOramScriptHashBatches,
  resolveOramBatchPlan,
  splitOramScriptHashBatches,
} from '../oram-adapter.js';

describe('ORAM adapter', () => {
  it('advertises direct non-PBC layout', () => {
    expect(OramPirClientAdapter.layout()).toEqual({
      backend: 'oram-direct',
      usesPbc: false,
      serverCount: 1,
      merkleModel: 'server-authenticated-oram',
    });
  });

  it('translates direct ORAM JSON without PBC inspector fields', () => {
    const result = oramJsonResultToQueryResult({
      entries: [
        {
          txid: '11'.repeat(32),
          vout: 2,
          amountSats: 12345,
        },
      ],
      totalBalance: 12345,
      isWhale: false,
      merkleVerified: true,
    });

    expect(result).not.toBeNull();
    expect(result?.entries).toHaveLength(1);
    expect(result?.entries[0].txid).toEqual(new Uint8Array(32).fill(0x11));
    expect(result?.entries[0].amount).toBe(12345n);
    expect(result?.totalSats).toBe(12345n);
    expect(result?.isWhale).toBe(false);
    expect(result?.indexPbcGroup).toBeUndefined();
    expect(result?.allIndexBins).toBeUndefined();
    expect(result?.chunkPbcGroups).toBeUndefined();
  });

  it('keeps not-found as null', () => {
    expect(oramJsonResultToQueryResult(null)).toBeNull();
  });

  it('splits direct ORAM script hashes into conservative fixed-budget requests by default', () => {
    expect(DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST).toBe(1);
    expect(splitOramScriptHashBatches([1, 2, 3]).map((b) => b.length)).toEqual([1, 1, 1]);
  });

  it('allows measured direct ORAM deployments to raise the per-request batch size', () => {
    expect(splitOramScriptHashBatches([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });

  it('plans fixed-budget direct ORAM batches from access counts', () => {
    expect(DEFAULT_ORAM_ACCESS_BUDGET).toBe(50);
    expect(DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH).toBe(2);

    expect(resolveOramBatchPlan()).toMatchObject({
      paddedSlotCount: 25,
      maxScriptHashesPerRequest: 25,
      chunkReadsAvailableAtMax: 0,
    });
    expect(resolveOramBatchPlan({ expectedChunkReadsPerScriptHash: 1 })).toMatchObject({
      paddedSlotCount: 16,
      maxScriptHashesPerRequest: 16,
      chunkReadsAvailableAtMax: 18,
    });
    expect(resolveOramBatchPlan({ chunkReadReserve: 10 })).toMatchObject({
      paddedSlotCount: 20,
      maxScriptHashesPerRequest: 20,
      chunkReadsAvailableAtMax: 10,
    });
    expect(resolveOramBatchPlan({ maxScriptHashesPerRequest: 7 })).toMatchObject({
      paddedSlotCount: 25,
      maxScriptHashesPerRequest: 7,
      chunkReadsAvailableAtMax: 0,
    });
    expect(resolveOramBatchPlan({
      accessBudget: 120,
      paddedSlotCount: 50,
      expectedChunkReadsPerScriptHash: 1,
    })).toMatchObject({
      paddedSlotCount: 50,
      maxScriptHashesPerRequest: 20,
      chunkReadsAvailableAtMax: 20,
    });
  });

  it('splits batches with the fixed-budget planner', () => {
    expect(
      planOramScriptHashBatches(
        Array.from({ length: 41 }, (_, i) => i),
        { expectedChunkReadsPerScriptHash: 1 },
      ).map((b) => b.length),
    ).toEqual([16, 16, 9]);
  });

  it('rejects invalid direct ORAM per-request batch sizes', () => {
    expect(() => splitOramScriptHashBatches([1], 0)).toThrow(/positive integer/);
    expect(() => splitOramScriptHashBatches([1], 1.5)).toThrow(/positive integer/);
    expect(() => resolveOramBatchPlan({ accessBudget: 0 })).toThrow(/positive integer/);
    expect(() => resolveOramBatchPlan({ paddedSlotCount: 50 })).toThrow(/exceeding access budget/);
  });
});
