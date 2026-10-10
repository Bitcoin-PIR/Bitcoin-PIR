import { describe, expect, it, vi } from 'vitest';
import { requireVerifiedQueryResultsV1 } from '../strict-result-release.js';

const traced = () => ({ allIndexBins: [{ pbcGroup: 0 }] });

describe('strict PIR result release', () => {
  it('returns the exact batch only after every verdict is true', async () => {
    const batch = [traced(), traced()];
    const verify = vi.fn(async () => [true, true]);
    await expect(requireVerifiedQueryResultsV1(batch, verify, 'DPF db 0'))
      .resolves.toEqual(batch);
    expect(verify).toHaveBeenCalledWith(batch);
  });

  it.each([
    { batch: [null], reason: 'no verifiable INDEX trace' },
    { batch: [{}], reason: 'no verifiable INDEX trace' },
    { batch: [{ allIndexBins: [] }], reason: 'no verifiable INDEX trace' },
  ])('rejects missing proof material before invoking the verifier', async ({ batch, reason }) => {
    const verify = vi.fn(async () => [true]);
    await expect(requireVerifiedQueryResultsV1(batch, verify, 'Harmony db 0'))
      .rejects.toThrow(reason);
    expect(verify).not.toHaveBeenCalled();
  });

  it('accepts an opaque live handle but still requires a true verifier verdict', async () => {
    const pending = { verificationPending: true as const };
    await expect(requireVerifiedQueryResultsV1(
      [pending], async () => [true], 'Onion db 0',
    )).resolves.toEqual([pending]);
    await expect(requireVerifiedQueryResultsV1(
      [pending], async () => [false], 'Onion db 0',
    )).rejects.toThrow('verification failed');
  });

  it('rejects a false verdict and verifier length skew', async () => {
    await expect(requireVerifiedQueryResultsV1(
      [traced(), traced()], async () => [true, false], 'DPF delta db 1',
    )).rejects.toThrow('result 1');
    await expect(requireVerifiedQueryResultsV1(
      [traced(), traced()], async () => [true], 'Harmony db 0',
    )).rejects.toThrow('1 verdicts for 2 results');
  });

  it('propagates verifier errors without releasing the batch', async () => {
    await expect(requireVerifiedQueryResultsV1(
      [traced()], async () => { throw new Error('transport closed'); }, 'DPF db 0',
    )).rejects.toThrow('transport closed');
  });
});
