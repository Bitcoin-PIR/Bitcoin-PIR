import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { PRODUCTION_ONION_DB_PROOF_V2_PINS } from '../attest-pin.js';

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
  it('pins an immutable registry commit and exactly matches the Onion v2 frontend pins', () => {
    expect(lock.registry.commit).toMatch(/^[0-9a-f]{40}$/);
    expect(lock.bundles.map((bundle) => bundle.dbId)).toEqual([0, 1]);
    expect(PRODUCTION_ONION_DB_PROOF_V2_PINS).toHaveLength(lock.bundles.length);

    for (const bundle of lock.bundles) {
      const pin = PRODUCTION_ONION_DB_PROOF_V2_PINS.find(({ dbId }) => dbId === bundle.dbId);
      expect(pin).toBeDefined();
      for (const [field, expected] of Object.entries(bundle.proofFields)) {
        expect((pin as unknown as Record<string, unknown>)[field], `db ${bundle.dbId} ${field}`)
          .toBe(expected);
      }
    }
  });
});
