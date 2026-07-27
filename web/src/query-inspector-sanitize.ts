import type { QueryInspectorData, RoundTimingData } from './harmony-types.js';

const MAX_TEXT_LENGTH = 20_000;
const MAX_COLLECTION_LENGTH = 4_096;
const MAX_INDEX = 0x7fff_ffff;
const MAX_TIMING_MS = 86_400_000;

/**
 * A copy of QueryInspectorData whose string fields are safe to interpolate
 * into the inspector's fixed HTML templates. Numeric and collection fields
 * are range-checked so they cannot create scriptable attributes or unbounded
 * renderer work.
 */
export type QueryInspectorRenderDataV1 = QueryInspectorData;

export function prepareQueryInspectorRenderDataV1(
  value: unknown,
): QueryInspectorRenderDataV1 {
  const input = requireRecord(value, 'query inspector data');
  const chunkDetailsValue = optionalArray(input.chunkDetails, 'chunkDetails');
  const timingsValue = requireArray(input.roundTimings, 'roundTimings');

  return {
    address: escapeHtmlText(requireText(input.address, 'address')),
    scriptPubKeyHex: escapeHtmlText(requireHex(input.scriptPubKeyHex, 'scriptPubKeyHex')),
    scriptHashHex: escapeHtmlText(requireHex(input.scriptHashHex, 'scriptHashHex')),
    candidateIndexGroups: requireArray(
      input.candidateIndexGroups,
      'candidateIndexGroups',
    ).map((item, index) => requireInteger(
      item,
      `candidateIndexGroups[${index}]`,
      0,
      MAX_INDEX,
    )),
    assignedIndexGroup: requireInteger(
      input.assignedIndexGroup,
      'assignedIndexGroup',
      -1,
      MAX_INDEX,
    ),
    indexPlacementRound: requireInteger(
      input.indexPlacementRound,
      'indexPlacementRound',
      -1,
      MAX_INDEX,
    ),
    indexBinIndex: optionalInteger(input.indexBinIndex, 'indexBinIndex'),
    indexHashRound: optionalInteger(input.indexHashRound, 'indexHashRound'),
    indexSegment: optionalInteger(input.indexSegment, 'indexSegment'),
    indexPosition: optionalInteger(input.indexPosition, 'indexPosition'),
    indexSegmentSize: optionalInteger(input.indexSegmentSize, 'indexSegmentSize', 1),
    tagHex: input.tagHex === undefined
      ? undefined
      : escapeHtmlText(requireHex(input.tagHex, 'tagHex')),
    startChunkId: optionalInteger(input.startChunkId, 'startChunkId'),
    numChunks: optionalInteger(input.numChunks, 'numChunks'),
    isWhale: requireBoolean(input.isWhale, 'isWhale'),
    chunkDetails: chunkDetailsValue?.map((item, index) => {
      const chunk = requireRecord(item, `chunkDetails[${index}]`);
      return {
        chunkId: requireInteger(chunk.chunkId, `chunkDetails[${index}].chunkId`, 0, MAX_INDEX),
        groupId: requireInteger(chunk.groupId, `chunkDetails[${index}].groupId`, 0, MAX_INDEX),
        segment: optionalInteger(chunk.segment, `chunkDetails[${index}].segment`),
        position: optionalInteger(chunk.position, `chunkDetails[${index}].position`),
      };
    }),
    roundTimings: timingsValue.map((item, index) => sanitizeTiming(item, index)),
    totalMs: requireFiniteNumber(input.totalMs, 'totalMs', 0, MAX_TIMING_MS),
  };
}

function sanitizeTiming(value: unknown, index: number): RoundTimingData {
  const timing = requireRecord(value, `roundTimings[${index}]`);
  if (timing.phase !== 'index' && timing.phase !== 'chunk') {
    throw new Error(`roundTimings[${index}].phase must be index or chunk`);
  }
  return {
    phase: timing.phase,
    roundIdx: requireInteger(timing.roundIdx, `roundTimings[${index}].roundIdx`, 0, MAX_INDEX),
    hashIdx: requireInteger(timing.hashIdx, `roundTimings[${index}].hashIdx`, 0, MAX_INDEX),
    realCount: requireInteger(timing.realCount, `roundTimings[${index}].realCount`, 0, MAX_INDEX),
    totalCount: requireInteger(timing.totalCount, `roundTimings[${index}].totalCount`, 0, MAX_INDEX),
    buildMs: requireFiniteNumber(timing.buildMs, `roundTimings[${index}].buildMs`, 0, MAX_TIMING_MS),
    netMs: requireFiniteNumber(timing.netMs, `roundTimings[${index}].netMs`, 0, MAX_TIMING_MS),
    procMs: requireFiniteNumber(timing.procMs, `roundTimings[${index}].procMs`, 0, MAX_TIMING_MS),
    relocMs: requireFiniteNumber(timing.relocMs, `roundTimings[${index}].relocMs`, 0, MAX_TIMING_MS),
  };
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireArray(value: unknown, name: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  if (value.length > MAX_COLLECTION_LENGTH) {
    throw new Error(`${name} exceeds ${MAX_COLLECTION_LENGTH} entries`);
  }
  return value;
}

function optionalArray(value: unknown, name: string): unknown[] | undefined {
  return value === undefined ? undefined : requireArray(value, name);
}

function requireText(value: unknown, name: string): string {
  if (typeof value !== 'string') throw new Error(`${name} must be a string`);
  if (value.length > MAX_TEXT_LENGTH) throw new Error(`${name} is too long`);
  return value;
}

function requireHex(value: unknown, name: string): string {
  const text = requireText(value, name);
  if (text.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(text)) {
    throw new Error(`${name} must be even-length hexadecimal text`);
  }
  return text;
}

function requireBoolean(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${name} must be a boolean`);
  return value;
}

function optionalInteger(
  value: unknown,
  name: string,
  minimum = 0,
): number | undefined {
  return value === undefined
    ? undefined
    : requireInteger(value, name, minimum, MAX_INDEX);
}

function requireInteger(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return value as number;
}

function requireFiniteNumber(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be a finite number from ${minimum} through ${maximum}`);
  }
  return value;
}

function escapeHtmlText(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;',
  })[character] ?? character);
}
