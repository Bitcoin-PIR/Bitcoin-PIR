import { describe, expect, it, vi } from 'vitest';
import {
  assertConsistentOnionMerkleLeaves,
  databaseProofV2Request,
  decodeBatchResult,
  OnionPirWebClient,
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

describe('strict OnionPIR session lifecycle', () => {
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
