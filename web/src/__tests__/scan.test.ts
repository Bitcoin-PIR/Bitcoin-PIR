import { describe, it, expect } from 'vitest';
import { findEntryInOnionPirIndexResult } from '../scan.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Write a u64 LE into a buffer at the given offset. */
function writeU64LE(buf: Uint8Array, offset: number, val: bigint): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setBigUint64(offset, val, true);
}

/** Write a u32 LE into a buffer at the given offset. */
function writeU32LE(buf: Uint8Array, offset: number, val: number): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setUint32(offset, val, true);
}

/** Write a u16 LE into a buffer at the given offset. */
function writeU16LE(buf: Uint8Array, offset: number, val: number): void {
  const dv = new DataView(buf.buffer, buf.byteOffset);
  dv.setUint16(offset, val, true);
}

// ─── findEntryInOnionPirIndexResult ──────────────────────────────────────────

describe('findEntryInOnionPirIndexResult', () => {
  // OnionPIR layout: 8B tag + 4B entryId + 2B byteOffset + 1B numEntries = 15 bytes
  const SLOT_SIZE = 15;
  const BUCKET_SIZE = 256;

  it('finds matching tag and extracts entryId, byteOffset, numEntries', () => {
    // Use small bin for test
    const testBucketSize = 4;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    const tag = 0xFEDCBA9876543210n;

    // Write to slot 1
    const off = SLOT_SIZE;
    writeU64LE(data, off, tag);
    writeU32LE(data, off + 8, 12345);  // entryId
    writeU16LE(data, off + 12, 320);   // byteOffset
    data[off + 14] = 7;               // numEntries

    const result = findEntryInOnionPirIndexResult(data, tag, testBucketSize, SLOT_SIZE);
    expect(result).toEqual({ entryId: 12345, byteOffset: 320, numEntries: 7 });
  });

  it('skips zero tags', () => {
    const testBucketSize = 2;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    // Slot 0: tag = 0 (should be skipped even if searching for 0)
    // All zeros

    const result = findEntryInOnionPirIndexResult(data, 0n, testBucketSize, SLOT_SIZE);
    expect(result).toBeNull();
  });

  it('returns null when tag not present', () => {
    const testBucketSize = 3;
    const data = new Uint8Array(testBucketSize * SLOT_SIZE);
    writeU64LE(data, 0, 0x1111n);
    writeU64LE(data, SLOT_SIZE, 0x2222n);

    const result = findEntryInOnionPirIndexResult(data, 0x9999n, testBucketSize, SLOT_SIZE);
    expect(result).toBeNull();
  });
});
