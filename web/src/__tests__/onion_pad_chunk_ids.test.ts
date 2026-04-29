/**
 * `padChunkIdsToM` — TypeScript port of the Rust Kani-verified helper
 * `crate::dpf::pad_chunk_ids_to_m`.
 *
 * The properties asserted below mirror the four Rust harnesses
 * (`pad_chunk_ids_to_m_emits_exactly_m_when_padding_needed`,
 * `pad_chunk_ids_to_m_real_chunks_in_prefix`,
 * `pad_chunk_ids_to_m_synthetics_disjoint_from_real`,
 * `pad_chunk_ids_to_m_zero_m_is_identity`). Cross-language consistency
 * with the Rust reference is what makes the
 * `chunk_max_items_per_group_per_level` axis closure observably
 * equivalent across `OnionClient` (Rust) and `OnionPirWebClient`
 * (this file's home).
 */

import { describe, it, expect } from 'vitest';
import { padChunkIdsToM, CHUNK_MERKLE_ITEMS_PER_QUERY } from '../onionpir_client.js';

describe('padChunkIdsToM (chunk_max axis closure helper)', () => {
  it('exposes M = 16 matching the Rust constant', () => {
    expect(CHUNK_MERKLE_ITEMS_PER_QUERY).toBe(16);
  });

  it('emits exactly m ids when padding needed (empty real-chunks)', () => {
    const padded = padChunkIdsToM([], 4);
    expect(padded.length).toBe(4);
    // Synthetics are deterministic 0..3 when no reals to skip.
    expect(padded).toEqual([0, 1, 2, 3]);
  });

  it('emits exactly m ids when padding needed (one real chunk)', () => {
    const padded = padChunkIdsToM([42], 4);
    expect(padded.length).toBe(4);
    // Real comes first, then synthetics 0..2 (skipping 42 since
    // none of {0, 1, 2} collide).
    expect(padded).toEqual([42, 0, 1, 2]);
  });

  it('preserves real chunks in the prefix verbatim', () => {
    const padded = padChunkIdsToM([100, 200], 4);
    expect(padded[0]).toBe(100);
    expect(padded[1]).toBe(200);
    expect(padded.length).toBe(4);
  });

  it('synthetics never collide with real-chunk list (worst-case [0, 1])', () => {
    const padded = padChunkIdsToM([0, 1], 4);
    expect(padded.length).toBe(4);
    // Synthetic prefix `[2, 3]` because 0 and 1 are both real —
    // the helper's skip branch must reject both.
    expect(padded[2]).toBe(2);
    expect(padded[3]).toBe(3);
  });

  it('is identity when m <= realChunks.length (m=0 case)', () => {
    const padded = padChunkIdsToM([10, 20, 30], 0);
    expect(padded).toEqual([10, 20, 30]);
  });

  it('is identity when m <= realChunks.length (m=N case)', () => {
    const padded = padChunkIdsToM([10, 20, 30], 3);
    expect(padded).toEqual([10, 20, 30]);
  });

  it('is identity when m < realChunks.length (defensive shrink path)', () => {
    // Production callers always pass `m === CHUNK_MERKLE_ITEMS_PER_QUERY = 16`,
    // but the helper must remain total for any (real_chunks, m) pair —
    // including the surprising case `m < real_chunks.length`. Returns
    // the input verbatim (no truncation) so the caller's downstream
    // length-check fires cleanly.
    const padded = padChunkIdsToM([10, 20, 30, 40, 50], 2);
    expect(padded).toEqual([10, 20, 30, 40, 50]);
  });

  it('production M=16 case with N=1 real produces the expected suffix', () => {
    // The realistic shape every found query produces: one or two real
    // entry_ids + 14-15 deterministic synthetics. Pin the full 16-element
    // expected output so a regression in the synthetic loop fires here
    // rather than in a higher-level integration test.
    const padded = padChunkIdsToM([100], CHUNK_MERKLE_ITEMS_PER_QUERY);
    expect(padded.length).toBe(16);
    expect(padded[0]).toBe(100);
    // Synthetics 0..14 fill the remaining 15 slots (none collide with 100).
    for (let i = 1; i < 16; i++) {
      expect(padded[i]).toBe(i - 1);
    }
  });

  it('not-found / whale path: M=16 owned ids are all synthetic 0..15', () => {
    const padded = padChunkIdsToM([], CHUNK_MERKLE_ITEMS_PER_QUERY);
    expect(padded.length).toBe(16);
    for (let i = 0; i < 16; i++) {
      expect(padded[i]).toBe(i);
    }
  });

  it('synthetic suffix shifts when real ids overlap the 0..M-1 range', () => {
    // Worst-case overlap: every real id is in the synthetic search space.
    // The helper must skip all of them; synthetics shift up to
    // [N..N+(M-N)).
    const realChunks = [0, 5, 10];
    const padded = padChunkIdsToM(realChunks, 8);
    expect(padded.length).toBe(8);
    expect(padded.slice(0, 3)).toEqual([0, 5, 10]);
    // Synthetics: skipping 0, 5, 10 → 1, 2, 3, 4, 6 fill positions 3-7.
    expect(padded.slice(3)).toEqual([1, 2, 3, 4, 6]);
  });
});
