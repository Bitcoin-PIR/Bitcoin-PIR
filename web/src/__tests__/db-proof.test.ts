import { describe, expect, it } from 'vitest';
import { DELTA_940611_948454_DB_PROOF_PIN } from '../attest-pin.js';
import { databaseProofAnchorPoints, mempoolSpaceBlockUrl } from '../db-proof.js';

describe('database proof Bitcoin anchors', () => {
  it('returns both independently meaningful endpoints for a delta', () => {
    expect(databaseProofAnchorPoints(DELTA_940611_948454_DB_PROOF_PIN)).toEqual([
      {
        role: 'from',
        height: 940611,
        blockHashHex: DELTA_940611_948454_DB_PROOF_PIN.fromBlockHashHex,
      },
      {
        role: 'latest',
        height: 948454,
        blockHashHex: DELTA_940611_948454_DB_PROOF_PIN.blockHashHex,
      },
    ]);
  });

  it('only creates mempool.space links for canonical block hashes', () => {
    expect(mempoolSpaceBlockUrl(DELTA_940611_948454_DB_PROOF_PIN.blockHashHex)).toBe(
      `https://mempool.space/block/${DELTA_940611_948454_DB_PROOF_PIN.blockHashHex}`,
    );
    expect(mempoolSpaceBlockUrl('not-a-block-hash')).toBeUndefined();
    expect(mempoolSpaceBlockUrl('00'.repeat(32) + '" onclick="alert(1)')).toBeUndefined();
  });
});
