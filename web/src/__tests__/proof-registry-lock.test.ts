import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  PRODUCTION_ONION_DB_PROOF_V2_PINS,
  PRODUCTION_ORAM_DB_PROOF_V2_PINS,
} from '../attest-pin.js';

interface GeneratedProofLock {
  registry: { commit: string };
  bundles: Array<{ dbId: number; proofFields: Record<string, unknown> }>;
}

const lock = JSON.parse(
  readFileSync(
    new URL('../../../verification/locks/generated-proofs.json', import.meta.url),
    'utf8',
  ),
) as GeneratedProofLock;

describe('generated proof registry lock', () => {
  it('pins an immutable registry commit and exactly matches the ORAM v2 frontend pins', () => {
    expect(lock.registry.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(lock.bundles.map((bundle) => bundle.dbId)).toEqual([0, 1]);
    expect(PRODUCTION_ORAM_DB_PROOF_V2_PINS).toHaveLength(lock.bundles.length);

    for (const bundle of lock.bundles) {
      const pin = PRODUCTION_ORAM_DB_PROOF_V2_PINS.find(({ dbId }) => dbId === bundle.dbId);
      expect(pin).toBeDefined();
      for (const [field, expected] of Object.entries(bundle.proofFields)) {
        expect((pin as unknown as Record<string, unknown>)[field], `db ${bundle.dbId} ${field}`)
          .toBe(expected);
      }
    }
  });

  it('keeps the Hetzner Onion and VPSBG ORAM proof producers distinct', () => {
    expect(PRODUCTION_ONION_DB_PROOF_V2_PINS.map((pin) => pin.builderBinarySha256Hex))
      .toEqual(Array(2).fill(
        '1150d6a2d746398d9046e677e1f0d36f4c4ccb3c390265ea8cf14d7c1f23671c',
      ));
    expect(PRODUCTION_ORAM_DB_PROOF_V2_PINS.map((pin) => pin.builderBinarySha256Hex))
      .toEqual(Array(2).fill(
        'cf973a833f9b892743e451da4c2937c82865b12d8901c48ac4483b5e0696ba6f',
      ));
    expect(PRODUCTION_ONION_DB_PROOF_V2_PINS.map((pin) => pin.builderGitCommit))
      .toEqual(Array(2).fill('d49a199e290ccbb05b6481c5ba691cb516aa76bb'));
    expect(PRODUCTION_ORAM_DB_PROOF_V2_PINS.map((pin) => pin.builderGitCommit))
      .toEqual(Array(2).fill('8d9d21a6be560236cb666269cf1f93a3de53bb1f'));
  });
});
