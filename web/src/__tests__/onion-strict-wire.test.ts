import { describe, expect, it, vi } from 'vitest';
import {
  assertConsistentOnionMerkleLeaves,
  databaseProofV2Request,
  decodeBatchResult,
  OnionPirWebClient,
  reassembleCompleteOnionChunks,
  responsePayloadFromFrame,
} from '../onionpir_client.js';

function frame(payload: number[]): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, true);
  out.set(payload, 4);
  return out;
}

describe('strict OnionPIR wire parsing', () => {
  it('uses only the v2 database-proof opcode and rejects invalid DB IDs', () => {
    expect([...databaseProofV2Request(1)]).toEqual([2, 0, 0, 0, 0x0c, 1]);
    expect(() => databaseProofV2Request(-1)).toThrow('must be a byte');
    expect(() => databaseProofV2Request(256)).toThrow('must be a byte');
  });

  it('accepts exactly one complete length-prefixed response', () => {
    expect([...responsePayloadFromFrame(frame([0x50, 0xaa]), 0x50)])
      .toEqual([0x50, 0xaa]);
  });

  it('rejects payload-only, truncated, concatenated, and wrong-variant responses', () => {
    expect(() => responsePayloadFromFrame(new Uint8Array([0x50, 0xaa])))
      .toThrow('too short');
    expect(() => responsePayloadFromFrame(new Uint8Array([2, 0, 0, 0, 0x50])))
      .toThrow('length mismatch');
    const concatenated = new Uint8Array([...frame([0x50]), ...frame([0x50])]);
    expect(() => responsePayloadFromFrame(concatenated)).toThrow('length mismatch');
    expect(() => responsePayloadFromFrame(frame([0x51]), 0x50))
      .toThrow('Unexpected response variant');
  });

  it('binds batch results to the requested round/count and rejects trailing bytes', () => {
    const payload = new Uint8Array([
      0x51,
      7, 0,
      1,
      2, 0, 0, 0,
      0xaa, 0xbb,
    ]);
    expect([...decodeBatchResult(payload, 1, 7, 1).results[0]])
      .toEqual([0xaa, 0xbb]);
    expect(() => decodeBatchResult(payload, 1, 8, 1)).toThrow('round mismatch');
    expect(() => decodeBatchResult(payload, 1, 7, 2)).toThrow('group count mismatch');
    expect(() => decodeBatchResult(new Uint8Array([...payload, 0]), 1, 7, 1))
      .toThrow('trailing bytes');
    expect(() => decodeBatchResult(payload.slice(0, -1), 1, 7, 1))
      .toThrow('truncated');
  });
});

describe('strict OnionPIR duplicate Merkle coordinates', () => {
  const a = new Uint8Array(32).fill(1);
  const b = new Uint8Array(32).fill(2);

  it('allows identical duplicates and keeps INDEX/DATA namespaces distinct', () => {
    expect(() => assertConsistentOnionMerkleLeaves([
      { tree: 'index', pbcGroup: 3, bin: 9, hash: a },
      { tree: 'index', pbcGroup: 3, bin: 9, hash: a.slice() },
      { tree: 'data', pbcGroup: 3, bin: 9, hash: b },
    ])).not.toThrow();
  });

  it('rejects conflicting duplicates in either input order', () => {
    const first = { tree: 'index' as const, pbcGroup: 3, bin: 9, hash: a };
    const second = { tree: 'index' as const, pbcGroup: 3, bin: 9, hash: b };
    expect(() => assertConsistentOnionMerkleLeaves([first, second]))
      .toThrow('conflicting hashes');
    expect(() => assertConsistentOnionMerkleLeaves([second, first]))
      .toThrow('conflicting hashes');
  });
});

describe('strict OnionPIR CHUNK completeness', () => {
  it('reassembles every INDEX-declared CHUNK in order', () => {
    const chunks = new Map<number, Uint8Array>([
      [4, new Uint8Array([0, 1, 2])],
      [5, new Uint8Array([3, 4, 5])],
    ]);
    expect([...reassembleCompleteOnionChunks(4, 2, 1, chunks)])
      .toEqual([1, 2, 3, 4, 5]);
  });

  it('rejects omission, inconsistent size, and an out-of-range first offset', () => {
    expect(() => reassembleCompleteOnionChunks(
      4, 2, 0, new Map([[4, new Uint8Array([1, 2])]]),
    )).toThrow('omitted expected CHUNK entry 5');
    expect(() => reassembleCompleteOnionChunks(
      4, 2, 0, new Map([
        [4, new Uint8Array([1, 2])],
        [5, new Uint8Array([3])],
      ]),
    )).toThrow('malformed CHUNK entry 5');
    expect(() => reassembleCompleteOnionChunks(
      4, 1, 2, new Map([[4, new Uint8Array([1, 2])]]),
    )).toThrow('byte offset exceeds');
  });
});

describe('strict OnionPIR session lifecycle', () => {
  function seedStrictQuerySession(client: OnionPirWebClient, socket: any): any {
    const internal = client as any;
    internal.sessionGeneration = 7;
    internal.ws = socket;
    internal.strictReady = true;
    internal.dbId = 0;
    internal.installedOnionRoots.set(0, {
      dbId: 0,
      onionSuperRootHex: 'ab'.repeat(32),
      generation: 7,
      indexK: 75,
      chunkK: 80,
      indexBinsPerTable: 8,
      chunkBinsPerTable: 8,
      tagSeed: 1n,
      indexMasterSeed: 2n,
      chunkMasterSeed: 3n,
      totalPackedEntries: 8,
      indexSlotsPerBin: 1,
      indexSlotSize: 16,
    });
    internal.verifiedTreeTops.set(0, {
      generation: 7,
      rootHex: 'ab'.repeat(32),
      allTops: [],
    });
    internal.serverInfo = {
      onionpir_merkle: {
        arity: 2,
        super_root: 'ab'.repeat(32),
        index: { k: 1, num_pt: 1 },
        data: { k: 1, num_pt: 1 },
      },
    };
    return internal;
  }

  it('cannot install a tree-top response after its socket was disconnected', async () => {
    let release!: (value: Uint8Array) => void;
    const response = new Promise<Uint8Array>((resolve) => { release = resolve; });
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(() => response),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = client as any;
    internal.sessionGeneration = 7;
    internal.ws = socket;
    internal.installedOnionRoots.set(0, {
      dbId: 0,
      onionSuperRootHex: 'ab'.repeat(32),
      generation: 7,
    });
    internal.serverInfo = {
      onionpir_merkle: {
        arity: 2,
        super_root: 'ab'.repeat(32),
        index: { k: 1, num_pt: 1 },
        data: { k: 1, num_pt: 1 },
      },
    };

    const preflight = client.preflightDatabase(0);
    client.disconnect();
    release(new Uint8Array());

    await expect(preflight).rejects.toThrow('stale OnionPIR tree-top response');
    expect((client as any).verifiedTreeTops.size).toBe(0);
  });

  it('rejects a query before any network traffic when no root is installed', async () => {
    const sendRaw = vi.fn();
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = client as any;
    internal.ws = { isOpen: () => true, sendRaw };
    internal.strictReady = true;
    internal.wasmModule = {};

    await expect(client.queryBatch([new Uint8Array(32)]))
      .rejects.toThrow('proof/layout/tree-tops are not ready');
    expect(sendRaw).not.toHaveBeenCalled();
  });

  it('rejects the test-only script-hash override in strict mode', async () => {
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = seedStrictQuerySession(client, socket);
    internal.wasmModule = {};
    client.setScriptHashOverrideForNextQuery([new Uint8Array(20).fill(9)]);

    await expect(client.queryBatch([new Uint8Array(20).fill(1)]))
      .rejects.toThrow('forbids the test-only script-hash override');
    expect(socket.sendRaw).not.toHaveBeenCalled();
  });

  it('plans the exact Onion INDEX round without generating keys or network traffic', () => {
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    seedStrictQuerySession(client, socket);

    expect(client.planServiceQuery([new Uint8Array(20)])).toEqual({
      backend: 'onion-pir',
      workload: 'onion-session',
      lowerBounds: {
        logicalInputs: 1,
        frames: 5,
        concurrentSockets: 1,
        workUnits: '386',
      },
    });
    expect(socket.sendRaw).not.toHaveBeenCalled();
  });

  it('rejects a late query response from a disconnected OnionPIR session', async () => {
    let release!: (value: Uint8Array) => void;
    const response = new Promise<Uint8Array>((resolve) => { release = resolve; });
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(() => response),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = seedStrictQuerySession(client, socket);
    const indexClient = {
      generateQuery: vi.fn(() => new Uint8Array([1])),
      delete: vi.fn(),
    };
    internal.wasmModule = {
      OnionPirClient: class {
        id(): number { return 9; }
        galoisKeys(): Uint8Array { return new Uint8Array([1]); }
        gswKey(): Uint8Array { return new Uint8Array([2]); }
        exportSecretKey(): Uint8Array { return new Uint8Array([3]); }
        delete(): void {}
      },
      createClientFromSecretKey: vi.fn(() => indexClient),
    };

    const pending = client.queryBatch([new Uint8Array(20)]);
    expect(socket.sendRaw).toHaveBeenCalledOnce();
    await expect(client.queryBatch([new Uint8Array(20)]))
      .rejects.toThrow('pipeline is already in flight');
    client.disconnect();
    release(new Uint8Array());

    await expect(pending).rejects.toThrow(/stale OnionPIR key registration/);
    expect(indexClient.delete).toHaveBeenCalledOnce();
  });

  it('scrubs results when an OnionPIR verifier resolves after disconnect', async () => {
    let release!: (value: Map<string, boolean>) => void;
    const response = new Promise<Map<string, boolean>>((resolve) => { release = resolve; });
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = seedStrictQuerySession(client, socket);
    internal.wasmModule = {};
    internal.fheSecretKey = new Uint8Array([3]);
    internal.verifySubTree = vi.fn(() => response);
    const result: any = {
      entries: [{ txid: new Uint8Array(32), vout: 0, amount: 9n }],
      totalSats: 9n,
      startChunkId: 1,
      numChunks: 0,
      numRounds: 1,
      isWhale: false,
      merkleVerified: false,
      rawChunkData: new Uint8Array([7]),
      indexBinLeaves: [
        { hash: new Uint8Array(32).fill(1), pbcGroup: 0, bin: 0 },
        { hash: new Uint8Array(32).fill(2), pbcGroup: 0, bin: 1 },
      ],
      dataBinLeaves: [],
      verifiedDbId: 0,
      verifiedOnionRootHex: 'ab'.repeat(32),
      verificationGeneration: 7,
      scriptHash: new Uint8Array(20).fill(4),
    };
    const [handle] = internal.capturePendingResultBatch(
      [result], [result.scriptHash], 0, 7, internal.resultEpoch,
    );

    const pending = client.verifyMerkleBatch([handle]);
    expect(internal.verifySubTree).toHaveBeenCalledOnce();
    await expect(client.queryBatch([new Uint8Array(20)]))
      .rejects.toThrow('pipeline is already in flight');
    client.disconnect();
    release(new Map([['0:0', true], ['0:1', true]]));

    await expect(pending).rejects.toThrow(/stale OnionPIR/);
    expect(handle).toMatchObject({ entries: [], totalSats: 0n, merkleVerified: false });
    expect(handle.rawChunkData).toBeUndefined();
    expect(handle.indexBinLeaves).toBeUndefined();
  });

  it('verifies an immutable one-shot snapshot and only then releases it', async () => {
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = seedStrictQuerySession(client, socket);
    internal.wasmModule = {};
    internal.fheSecretKey = new Uint8Array([3]);
    internal.verifySubTree = vi.fn(async () => new Map([
      ['0:0', true], ['0:1', true], ['0:2', true],
    ]));
    const expectedScriptHash = new Uint8Array(20).fill(4);
    const trusted: any = {
      entries: [{ txid: new Uint8Array(32).fill(8), vout: 1, amount: 9n }],
      totalSats: 9n,
      startChunkId: 4,
      numChunks: 1,
      numRounds: 1,
      isWhale: false,
      merkleVerified: false,
      rawChunkData: new Uint8Array([7]),
      scriptHash: expectedScriptHash,
      indexBinLeaves: [
        { hash: new Uint8Array(32).fill(1), pbcGroup: 0, bin: 0 },
        { hash: new Uint8Array(32).fill(2), pbcGroup: 0, bin: 1 },
      ],
      dataBinLeaves: [
        { hash: new Uint8Array(32).fill(3), pbcGroup: 0, bin: 2 },
      ],
      verifiedDbId: 0,
      verifiedOnionRootHex: 'ab'.repeat(32),
      verificationGeneration: 7,
    };
    const [handle] = internal.capturePendingResultBatch(
      [trusted], [expectedScriptHash], 0, 7, internal.resultEpoch,
    );
    expect(handle.numRounds).toBe(0);

    // Pre-verification fields are caller-controlled. The verifier must ignore
    // them and restore the private query snapshot only after the whole batch.
    handle.entries = [{ txid: new Uint8Array(32), vout: 99, amount: 1n }];
    handle.rawChunkData = new Uint8Array([0]);
    handle.scriptHash = new Uint8Array(20).fill(9);
    handle.indexBinLeaves = [{ hash: new Uint8Array(32), pbcGroup: 9, bin: 9 }];

    await expect(client.verifyMerkleBatch([handle])).resolves.toEqual([true]);
    expect(handle.merkleVerified).toBe(true);
    expect(handle.verificationPending).toBeUndefined();
    expect(handle.totalSats).toBe(9n);
    expect(handle.entries[0]).toMatchObject({ vout: 1, amount: 9n });
    expect([...handle.entries[0].txid]).toEqual([...new Uint8Array(32).fill(8)]);
    expect([...handle.rawChunkData!]).toEqual([7]);
    expect([...handle.scriptHash!]).toEqual([...expectedScriptHash]);

    await expect(client.verifyMerkleBatch([handle]))
      .rejects.toThrow('no live verification handle');
    expect(handle.entries).toEqual([]);
  });

  it('rejects invented and reordered result handles before proof I/O', async () => {
    const socket = {
      isOpen: () => true,
      sendRaw: vi.fn(),
      disconnect: vi.fn(),
    };
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = seedStrictQuerySession(client, socket);
    internal.wasmModule = {};
    internal.fheSecretKey = new Uint8Array([3]);
    internal.verifySubTree = vi.fn();
    const result = (fill: number): any => ({
      entries: [], totalSats: 0n, startChunkId: 0, numChunks: 0, numRounds: 1,
      isWhale: false, scriptHash: new Uint8Array(20).fill(fill),
      indexBinLeaves: [
        { hash: new Uint8Array(32).fill(1), pbcGroup: 0, bin: 0 },
        { hash: new Uint8Array(32).fill(2), pbcGroup: 0, bin: 1 },
      ],
      dataBinLeaves: [], verifiedDbId: 0,
      verifiedOnionRootHex: 'ab'.repeat(32), verificationGeneration: 7,
    });
    const first = result(1);
    const second = result(2);
    const handles = internal.capturePendingResultBatch(
      [first, second], [first.scriptHash, second.scriptHash], 0, 7, internal.resultEpoch,
    );

    await expect(client.verifyMerkleBatch([handles[1], handles[0]]))
      .rejects.toThrow('not the expected live handle');
    expect(internal.verifySubTree).not.toHaveBeenCalled();

    const invented = result(3);
    await expect(client.verifyMerkleBatch([invented]))
      .rejects.toThrow('no live verification handle');
    expect(invented.entries).toEqual([]);
    expect(internal.verifySubTree).not.toHaveBeenCalled();
  });

  it('consumes the proof handle and clears the installed root on disconnect', () => {
    const free = vi.fn();
    const client = new OnionPirWebClient({
      serverUrl: 'wss://example.invalid',
      strictVerification: true,
    });
    const internal = client as any;
    internal.sessionGeneration = 7;
    internal.wasmModule = { paramsInfo: () => ({ entrySize: 3_328 }) };
    internal.catalog = {
      databases: [{
        dbId: 0,
        baseHeight: 0,
        height: 948_454,
        // Standard proof-catalog bins are DPF geometry and intentionally
        // differ from the proof-backed Onion layout below.
        indexBinsPerTable: 567_558,
        chunkBinsPerTable: 1_066_928,
        indexK: 75,
        chunkK: 80,
        tagSeed: 1n,
        indexMasterSeed: 2n,
        chunkMasterSeed: 3n,
      }],
    };
    internal.serverInfo = {
      onionpir: {
        total_packed_entries: 948_640,
        index_bins_per_table: 10_273,
        chunk_bins_per_table: 37_954,
        index_k: 75,
        chunk_k: 80,
        tag_seed: 1n,
        // Optional legacy diagnostic fields may be absent (parsed as 0);
        // strict query placement still uses the proof-verified catalog seeds.
        index_master_seed: 0n,
        chunk_master_seed: 0n,
        index_slots_per_bin: 221,
        index_slot_size: 15,
      },
      onionpir_merkle: {
        arity: 104,
        super_root: 'ab'.repeat(32),
        index: { k: 75, num_pt: 99 },
        data: { k: 80, num_pt: 365 },
      },
    };

    client.installVerifiedDatabaseProof({
      dbId: 0,
      buildKind: 'snapshot',
      fromHeight: 0,
      height: 948_454,
      onionSuperRootHex: 'ab'.repeat(32),
      onionEntrySize: 3_328,
      proofVersion: 2,
      onionTotalPackedEntries: 948_640,
      onionIndexBinsPerTable: 10_273,
      onionChunkBinsPerTable: 37_954,
      onionIndexSlotsPerBin: 221,
      onionIndexSlotSize: 15,
      free,
    } as any);

    expect(free).toHaveBeenCalledOnce();
    expect(client.getMerkleRootHexForDb(0)).toBe('ab'.repeat(32));
    client.disconnect();
    expect(client.getMerkleRootHexForDb(0)).toBeUndefined();
  });
});
