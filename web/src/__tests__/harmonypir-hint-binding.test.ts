import { describe, expect, it } from 'vitest';
import { buildCacheKey } from '../harmonypir_hint_db.js';

describe('Harmony hint cache binding', () => {
  it('keys records by dataset root, db id, and PRP backend', () => {
    const binding = { datasetIdHex: '44'.repeat(32), prpBackend: 1 };
    expect(buildCacheKey(binding, 0)).toBe(`${'44'.repeat(32)}|0|1`);
    expect(buildCacheKey(binding, 2)).toMatch(/\|2\|1$/);
  });

  it('rejects malformed dataset roots and non-integer backends', () => {
    expect(() => buildCacheKey({ datasetIdHex: 'zz', prpBackend: 0 }, 0)).toThrow(
      'datasetIdHex',
    );
    expect(() =>
      buildCacheKey({ datasetIdHex: '44'.repeat(32), prpBackend: 1.5 }, 0),
    ).toThrow('PRP backend');
  });
});
