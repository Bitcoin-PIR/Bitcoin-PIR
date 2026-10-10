import { describe, expect, it } from 'vitest';
import {
  databaseProofV2Request,
  decodeBatchResult,
  reassembleCompleteOnionChunks,
  responsePayloadFromFrame,
} from '../onionpir_client.js';

function frame(payload: number[]): Uint8Array {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, true);
  out.set(payload, 4);
  return out;
}

describe('OnionPIR wire parsing', () => {
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

describe('OnionPIR CHUNK completeness', () => {
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
