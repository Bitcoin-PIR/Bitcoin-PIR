import { describe, expect, it } from 'vitest';

import { prepareQueryInspectorRenderDataV1 } from '../query-inspector-sanitize.js';

function validInspectorData(): Record<string, unknown> {
  return {
    address: 'bc1qexample',
    scriptPubKeyHex: '0014aabb',
    scriptHashHex: '11'.repeat(32),
    candidateIndexGroups: [1, 2, 3],
    assignedIndexGroup: 2,
    indexPlacementRound: 0,
    indexBinIndex: 4,
    indexHashRound: 1,
    indexSegment: 2,
    indexPosition: 3,
    indexSegmentSize: 8,
    tagHex: 'aabbccdd',
    startChunkId: 4,
    numChunks: 1,
    isWhale: false,
    chunkDetails: [{ chunkId: 4, groupId: 2, segment: 1, position: 7 }],
    roundTimings: [{
      phase: 'index',
      roundIdx: 0,
      hashIdx: 1,
      realCount: 1,
      totalCount: 8,
      buildMs: 1.5,
      netMs: 2.5,
      procMs: 3.5,
      relocMs: 4.5,
    }],
    totalMs: 12,
  };
}

describe('Query Inspector renderer boundary', () => {
  it('copies valid data and HTML-escapes the only free-form text field', () => {
    const input = validInspectorData();
    input.address = '\"><img src=x onerror="globalThis.pwned=1">&\'';

    const output = prepareQueryInspectorRenderDataV1(input);

    expect(output.address).toBe(
      '&quot;&gt;&lt;img src=x onerror=&quot;globalThis.pwned=1&quot;&gt;&amp;&#39;',
    );
    expect(output.scriptHashHex).toBe('11'.repeat(32));
    expect(output).not.toBe(input);
    expect(output.chunkDetails).not.toBe(input.chunkDetails);
  });

  it.each([
    ['scriptPubKeyHex', '<svg onload=alert(1)>'],
    ['scriptHashHex', 'aa<script>'],
    ['tagHex', 'abc'],
    ['totalMs', Number.NaN],
    ['assignedIndexGroup', 1.5],
    ['isWhale', 'false'],
  ])('rejects malformed %s renderer data', (field, value) => {
    const input = validInspectorData();
    input[field] = value;
    expect(() => prepareQueryInspectorRenderDataV1(input)).toThrow();
  });

  it('rejects invalid nested timings and oversized collections', () => {
    const badTiming = validInspectorData();
    badTiming.roundTimings = [{
      phase: '<img>',
      roundIdx: 0,
      hashIdx: 0,
      realCount: 0,
      totalCount: 0,
      buildMs: 0,
      netMs: 0,
      procMs: 0,
      relocMs: 0,
    }];
    expect(() => prepareQueryInspectorRenderDataV1(badTiming)).toThrow(/phase/);

    const oversized = validInspectorData();
    oversized.candidateIndexGroups = Array.from({ length: 4_097 }, () => 0);
    expect(() => prepareQueryInspectorRenderDataV1(oversized)).toThrow(/exceeds/);
  });
});
