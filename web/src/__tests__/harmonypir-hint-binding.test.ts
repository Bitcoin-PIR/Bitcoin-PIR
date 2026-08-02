import { describe, expect, it } from 'vitest';
import {
  buildCacheKey,
  resourceBindingToHarmonyHintCacheBindingV1,
} from '../harmonypir_hint_db.js';

describe('Harmony hint resource cache binding', () => {
  it('maps the generic resource variant into the exact cache PRP backend', () => {
    const cacheBinding = resourceBindingToHarmonyHintCacheBindingV1({
      providerIdHex: '11'.repeat(32),
      policyDigestHex: '22'.repeat(32),
      scopeIdHex: '33'.repeat(32),
      offerId: 21,
      datasetIdHex: '44'.repeat(32),
      variant: 1,
    });

    expect(cacheBinding).toEqual({
      providerIdHex: '11'.repeat(32),
      policyDigestHex: '22'.repeat(32),
      scopeIdHex: '33'.repeat(32),
      offerId: 21,
      datasetIdHex: '44'.repeat(32),
      prpBackend: 1,
    });
    expect(buildCacheKey(cacheBinding, 0)).toMatch(/\|0\|1$/);
  });
});
