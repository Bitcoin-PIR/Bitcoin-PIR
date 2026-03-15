/**
 * Example tests for Bitcoin PIR Web Client
 * 
 * These tests demonstrate the basic functionality of the library
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  hexToBytes,
  bytesToHex,
  cuckooHash1,
  cuckooHash2,
  cuckooLocations,
  CUCKOO_NUM_BUCKETS,
  reverseBytes,
} from '../index.js';

describe('Hash Functions', () => {
  it('should convert hex to bytes correctly', () => {
    const bytes = hexToBytes('deadbeef');
    assert.strictEqual(bytes.length, 4);
    assert.strictEqual(bytes[0], 0xde);
    assert.strictEqual(bytes[1], 0xad);
    assert.strictEqual(bytes[2], 0xbe);
    assert.strictEqual(bytes[3], 0xef);
  });

  it('should convert bytes to hex correctly', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = bytesToHex(bytes);
    assert.strictEqual(hex, 'deadbeef');
  });

  it('should produce different cuckoo hash values', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const h1 = cuckooHash1(key, 1000);
    const h2 = cuckooHash2(key, 1000);
    assert.notStrictEqual(h1, h2);
  });

  it('should produce hash values within bucket range', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const h1 = cuckooHash1(key, CUCKOO_NUM_BUCKETS);
    const h2 = cuckooHash2(key, CUCKOO_NUM_BUCKETS);
    assert.ok(h1 >= 0 && h1 < CUCKOO_NUM_BUCKETS);
    assert.ok(h2 >= 0 && h2 < CUCKOO_NUM_BUCKETS);
  });

  it('should compute both cuckoo locations', () => {
    const key = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
    const [loc1, loc2] = cuckooLocations(key, CUCKOO_NUM_BUCKETS);
    assert.ok(loc1 >= 0 && loc1 < CUCKOO_NUM_BUCKETS);
    assert.ok(loc2 >= 0 && loc2 < CUCKOO_NUM_BUCKETS);
    assert.notStrictEqual(loc1, loc2);
  });

  it('should reverse bytes correctly', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
    const reversed = reverseBytes(bytes);
    assert.strictEqual(reversed[0], 0x04);
    assert.strictEqual(reversed[1], 0x03);
    assert.strictEqual(reversed[2], 0x02);
    assert.strictEqual(reversed[3], 0x01);
  });
});

describe('Hex Round-trip', () => {
  it('should maintain data integrity through hex conversion', () => {
    const original = new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    ]);
    const hex = bytesToHex(original);
    const restored = hexToBytes(hex);
    assert.deepStrictEqual(restored, original);
  });
});