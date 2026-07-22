import { describe, expect, it, vi } from 'vitest';
import {
  assertConsistentOnionMerkleLeaves,
  decodeBatchResult,
  OnionPirWebClient,
  responsePayloadFromFrame,
} from '../onionpir_client.js';
import { PRODUCTION_ONION_QUERY_LAYOUT_PINS } from '../attest-pin.js';

function frame(payload: number[]): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, true);
  out.set(payload, 4);
  return out;
}

describe('strict OnionPIR wire parsing', () => {
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
      onionQueryLayoutPins: PRODUCTION_ONION_QUERY_LAYOUT_PINS,
    });
    const internal = client as any;
    internal.sessionGeneration = 7;
    internal.catalog = {
      databases: [{ dbId: 0, baseHeight: 0, height: 948_454 }],
    };

    client.installVerifiedDatabaseProof({
      dbId: 0,
      buildKind: 'snapshot',
      fromHeight: 0,
      height: 948_454,
      onionSuperRootHex: 'ab'.repeat(32),
      onionEntrySize: 3_328,
      free,
    } as any);

    expect(free).toHaveBeenCalledOnce();
    expect(client.getMerkleRootHexForDb(0)).toBe('ab'.repeat(32));
    client.disconnect();
    expect(client.getMerkleRootHexForDb(0)).toBeUndefined();
  });
});
