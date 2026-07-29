import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
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

  it('keeps production DPF and Harmony rendering after the strict release gate', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const dpf = html.slice(
      html.indexOf('async function queryUtxos()'),
      html.indexOf('async function runDpfQueryOnce()'),
    );
    const harmony = html.slice(
      html.indexOf('async function hpQueryUtxos()'),
      html.indexOf('async function runHarmonyQueryOnce()'),
    );
    expect(dpf.indexOf('requireVerifiedQueryResultsV1(')).toBeGreaterThan(0);
    expect(dpf.indexOf('renderDeltaResult(')).toBeGreaterThan(
      dpf.indexOf('requireVerifiedQueryResultsV1('),
    );
    expect(dpf.indexOf('renderResult(')).toBeGreaterThan(
      dpf.indexOf('requireVerifiedQueryResultsV1('),
    );
    expect(dpf).not.toContain('addBatchMerkleButton(');
    expect(harmony.indexOf('requireVerifiedQueryResultsV1(')).toBeGreaterThan(0);
    expect(harmony.indexOf('renderResult(')).toBeGreaterThan(
      harmony.indexOf('requireVerifiedQueryResultsV1('),
    );
    expect(harmony).not.toContain('addBatchMerkleButton(');
  });
});
