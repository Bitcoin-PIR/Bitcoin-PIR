import { describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_ORAM_ACCESS_BUDGET,
  DEFAULT_ORAM_INDEX_READS_PER_SCRIPT_HASH,
  DEFAULT_ORAM_SCRIPT_HASHES_PER_REQUEST,
  OramPirClientAdapter,
  oramJsonResultToQueryResult,
  planOramScriptHashBatches,
  requireAtomicOramRequest,
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

  it('requires a product query to fit one authorized ORAM wire request', () => {
    expect(requireAtomicOramRequest([1, 2, 3], 3)).toEqual([1, 2, 3]);
    expect(() => requireAtomicOramRequest([1, 2, 3, 4], 3))
      .toThrow(/one authorization.*reduce the query.*separate capability/i);
  });

  it('sends a multi-input product query as exactly one padded SDK call', async () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      batchPlanner: {
        accessBudget: 12,
        indexReadsPerScriptHash: 2,
        expectedChunkReadsPerScriptHash: 1,
        paddedSlotCount: 4,
        maxScriptHashesPerRequest: 4,
      },
    });
    const calls: Uint8Array[] = [];
    (adapter as any).wasmClient = {
      queryBatchPadded: async (packed: Uint8Array, _dbId: number, paddedSlots: number) => {
        calls.push(packed.slice());
        expect(paddedSlots).toBe(4);
        return [null, null, null];
      },
    };
    const inputs = [
      new Uint8Array(20).fill(1),
      new Uint8Array(20).fill(2),
      new Uint8Array(20).fill(3),
    ];
    await adapter.queryBatch(inputs);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toHaveLength(60);
  });

  it('plans the exact padded ORAM gate counters without SDK wire I/O', () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      batchPlanner: {
        accessBudget: 12,
        indexReadsPerScriptHash: 2,
        expectedChunkReadsPerScriptHash: 1,
        paddedSlotCount: 4,
        maxScriptHashesPerRequest: 4,
      },
    });
    const queryBatchPadded = vi.fn();
    (adapter as any).wasmClient = { queryBatchPadded };

    expect(adapter.planServiceQuery([
      new Uint8Array(20),
      new Uint8Array(20),
      new Uint8Array(20),
    ])).toEqual({
      backend: 'tee-oram',
      workload: 'tee-oram-query',
      lowerBounds: {
        logicalInputs: 4,
        frames: 1,
        concurrentSockets: 1,
        workUnits: '4',
      },
    });
    expect(queryBatchPadded).not.toHaveBeenCalled();
  });

  it('rejects an oversized atomic product query before SDK wire I/O', async () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      maxScriptHashesPerRequest: 2,
    });
    let calls = 0;
    (adapter as any).wasmClient = {
      queryBatch: async () => {
        calls += 1;
        return [];
      },
    };
    await expect(adapter.queryBatch([
      new Uint8Array(20),
      new Uint8Array(20),
      new Uint8Array(20),
    ])).rejects.toThrow(/atomic ORAM query.*at most 2/i);
    expect(calls).toBe(0);
  });

  it('rejects strict queries before the native channel, identity, and proof gate commits', async () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      strictVerification: true,
    });
    const queryBatch = vi.fn().mockResolvedValue([null]);
    const internal = adapter as any;
    internal.wasmClient = { queryBatch, isConnected: true };
    internal.connected = true;
    internal.strictReady = false;

    await expect(adapter.queryBatch([new Uint8Array(20)]))
      .rejects.toThrow('live verified native session');
    expect(queryBatch).not.toHaveBeenCalled();
  });

  it('rejects a late native result after disconnect invalidates its session generation', async () => {
    let releaseQuery!: (value: Array<null>) => void;
    const delayed = new Promise<Array<null>>((resolve) => { releaseQuery = resolve; });
    const native = {
      isConnected: true,
      queryBatch: vi.fn(() => delayed),
      disconnect: vi.fn(async () => {}),
      free: vi.fn(),
    };
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      strictVerification: true,
    });
    const internal = adapter as any;
    internal.wasmClient = native;
    internal.connected = true;
    internal.strictReady = true;
    internal.sessionGeneration = 7;
    internal.databaseProofs.set(0, { state: 'verified' });

    const query = adapter.queryBatch([new Uint8Array(20)]);
    expect(native.queryBatch).toHaveBeenCalledOnce();
    adapter.disconnect();
    releaseQuery([null]);
    await expect(query).rejects.toThrow(/stale ORAM query response result/);
  });

  it('never treats an omitted attested pin claim as a match', () => {
    const binaryAdapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      expectedServerPin: { binarySha256Hex: '11'.repeat(32) },
    });
    const base = {
      serverStaticPub: new Uint8Array(32).fill(1),
      serverStaticPubHex: '01'.repeat(32),
      sevStatus: 'noSevHost',
      binarySha256Hex: '',
      gitRev: '',
      launchMeasurementHex: '',
      hasVcekChain: false,
    };
    expect((binaryAdapter as any).summariseAttestation(base, null, {})).toMatchObject({
      state: 'mismatch',
      pinStatus: 'binary-mismatch',
      pinError: expect.stringMatching(/omitted.*binary/i),
    });

    const measurementAdapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      expectedServerPin: { measurementHex: '22'.repeat(48) },
    });
    expect((measurementAdapter as any).summariseAttestation({
      ...base,
      sevStatus: 'reportDataMatch',
      binarySha256Hex: '11'.repeat(32),
    }, null, {})).toMatchObject({
      state: 'mismatch',
      pinStatus: 'measurement-mismatch',
      pinError: expect.stringMatching(/omitted.*measurement/i),
    });
  });

  it('requires hardware VCEK verification and both runtime pins in strict mode', () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      strictVerification: true,
      expectedServerPin: {
        binarySha256Hex: '11'.repeat(32),
        measurementHex: '22'.repeat(48),
      },
    });
    const base = {
      serverStaticPub: new Uint8Array(32).fill(1),
      serverStaticPubHex: '01'.repeat(32),
      binarySha256Hex: '11'.repeat(32),
      gitRev: 'test',
      launchMeasurementHex: '22'.repeat(48),
      manifestRootsHex: ['33'.repeat(32)],
      verifyFull: vi.fn(),
    };

    expect((adapter as any).summariseAttestation({
      ...base, sevStatus: 'noSevHost', hasVcekChain: false,
    }, new Uint8Array(32), {})).toMatchObject({ state: 'mismatch' });
    expect((adapter as any).summariseAttestation({
      ...base, sevStatus: 'reportDataMatch', hasVcekChain: false,
    }, new Uint8Array(32), {})).toMatchObject({
      state: 'mismatch',
      vcekChain: 'skipped',
    });
    expect((adapter as any).summariseAttestation({
      ...base, sevStatus: 'reportDataMatch', hasVcekChain: true,
    }, new Uint8Array(32), {})).toMatchObject({
      state: 'verified-vcek',
      vcekChain: 'pass',
      pinStatus: 'match',
      manifestRootsHex: ['33'.repeat(32)],
    });
  });

  it('binds each strict database proof to the same attested manifest list', () => {
    const adapter = new OramPirClientAdapter({
      serverUrl: 'wss://oram.example',
      strictVerification: true,
    });
    const internal = adapter as any;
    internal.catalog = { databases: [{ dbId: 0 }, { dbId: 3 }] };
    internal.attestation = {
      state: 'verified-vcek',
      manifestRootsHex: ['11'.repeat(32), '22'.repeat(32)],
    };

    expect(() => internal.assertAttestedManifestRoot(3, '22'.repeat(32))).not.toThrow();
    expect(() => internal.assertAttestedManifestRoot(3, '33'.repeat(32)))
      .toThrow('attested manifest root mismatch');
    internal.attestation.manifestRootsHex = ['11'.repeat(32)];
    expect(() => internal.assertAttestedManifestRoot(0, '11'.repeat(32)))
      .toThrow('complete database catalog');
  });

  it('owns no second clear diagnostic WebSocket and clears strict proof state', () => {
    const adapter = new OramPirClientAdapter({ serverUrl: 'wss://oram.example' });
    const internal = adapter as any;
    expect(internal.ws).toBeUndefined();
    internal.catalog = { databases: [{ dbId: 0 }] };
    internal.databaseProofs.set(0, { state: 'verified', dbId: 0 });
    internal.strictReady = true;
    internal.resetSessionTrust();
    expect(internal.catalog).toBeNull();
    expect(internal.databaseProofs.size).toBe(0);
    expect(internal.strictReady).toBe(false);
  });

  it('rejects invalid direct ORAM per-request batch sizes', () => {
    expect(() => splitOramScriptHashBatches([1], 0)).toThrow(/positive integer/);
    expect(() => splitOramScriptHashBatches([1], 1.5)).toThrow(/positive integer/);
    expect(() => resolveOramBatchPlan({ accessBudget: 0 })).toThrow(/positive integer/);
    expect(() => resolveOramBatchPlan({ paddedSlotCount: 50 })).toThrow(/exceeding access budget/);
  });
});
