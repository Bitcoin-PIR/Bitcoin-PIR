import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { LeakageProfile, RoundProfile } from '../leakage.js';

interface NativeCorpus {
  backend: 'dpf' | 'harmony';
  servers: Record<string, string>;
  queries: Array<{
    script_hash_hex: string;
    profile: LeakageProfile;
  }>;
}

interface ExpectedProfile {
  rounds: number;
  requestBytes: number;
  responseBytes: number;
  kindCounts: Record<string, number>;
}

const fixtures: Array<{ file: string; expected: ExpectedProfile }> = [
  {
    file: 'dpf_corpus.json',
    expected: {
      rounds: 23,
      requestBytes: 405_563,
      responseBytes: 9_570_707,
      kindCounts: {
        index: 2,
        chunk: 2,
        merkle_tree_tops: 1,
        index_merkle_siblings: 12,
        chunk_merkle_siblings: 6,
      },
    },
  },
  {
    file: 'harmony_corpus.json',
    expected: {
      rounds: 23,
      requestBytes: 2_154_526,
      responseBytes: 131_221_536,
      kindCounts: {
        info: 1,
        harmony_hint_refresh: 8,
        index: 2,
        chunk: 2,
        merkle_tree_tops: 1,
        index_merkle_siblings: 6,
        chunk_merkle_siblings: 3,
      },
    },
  },
];

function loadCorpus(file: string): NativeCorpus {
  const path = resolve(__dirname, `../../test/fixtures/${file}`);
  return JSON.parse(readFileSync(path, 'utf8')) as NativeCorpus;
}

function totals(rounds: RoundProfile[]): { requestBytes: number; responseBytes: number } {
  return rounds.reduce(
    (sum, round) => ({
      requestBytes: sum.requestBytes + round.request_bytes,
      responseBytes: sum.responseBytes + round.response_bytes,
    }),
    { requestBytes: 0, responseBytes: 0 },
  );
}

describe.each(fixtures)('$file empirical leakage corpus', ({ file, expected }) => {
  it('pins two structurally and byte-identical not-found transcripts', () => {
    const corpus = loadCorpus(file);
    expect(corpus.backend).toMatch(/^(dpf|harmony)$/);
    expect(Object.values(corpus.servers)).not.toHaveLength(0);
    expect(corpus.queries).toHaveLength(2);
    expect(corpus.queries[0].script_hash_hex).toMatch(/^[0-9a-f]{40}$/);
    expect(corpus.queries[1].script_hash_hex).toMatch(/^[0-9a-f]{40}$/);
    expect(corpus.queries[0].script_hash_hex).not.toBe(corpus.queries[1].script_hash_hex);
    expect(corpus.queries[0].profile).toEqual(corpus.queries[1].profile);
  });

  it('pins the measured round and byte inventory', () => {
    const rounds = loadCorpus(file).queries[0].profile.rounds as RoundProfile[];
    expect(rounds).toHaveLength(expected.rounds);
    expect(totals(rounds)).toEqual({
      requestBytes: expected.requestBytes,
      responseBytes: expected.responseBytes,
    });

    const kindCounts = Object.fromEntries(
      Object.keys(expected.kindCounts).map((kind) => [
        kind,
        rounds.filter((round) => round.kind === kind).length,
      ]),
    );
    expect(kindCounts).toEqual(expected.kindCounts);
  });

  it('keeps every recorded byte count and padding vector well-formed', () => {
    for (const round of loadCorpus(file).queries[0].profile.rounds as RoundProfile[]) {
      expect(round.request_bytes).toBeGreaterThan(0);
      expect(round.response_bytes).toBeGreaterThan(0);
      expect(Number.isInteger(round.server_id)).toBe(true);
      expect(round.items.every((item) => Number.isInteger(item) && item >= 0)).toBe(true);
    }
  });
});
