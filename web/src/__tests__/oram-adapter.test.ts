import { describe, expect, it } from 'vitest';

import {
  DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
  OramPirClientAdapter,
  oramJsonResultToQueryResult,
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

  it('rejects invalid direct ORAM per-request batch sizes', () => {
    expect(() => splitOramScriptHashBatches([1], 0)).toThrow(/positive integer/);
    expect(() => splitOramScriptHashBatches([1], 1.5)).toThrow(/positive integer/);
  });
});
