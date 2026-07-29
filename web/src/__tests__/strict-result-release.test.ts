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

  it('keeps production DPF, Harmony, and Onion rendering after the strict release gate', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const dpf = html.slice(
      html.indexOf('async function queryUtxos()'),
      html.indexOf('async function runDpfQueryOnce()'),
    );
    const harmony = html.slice(
      html.indexOf('async function hpQueryUtxos()'),
      html.indexOf('async function runHarmonyQueryOnce()'),
    );
    const onion = html.slice(
      html.indexOf('async function opQueryUtxos()'),
      html.indexOf("document.getElementById('op-queryBtn').addEventListener"),
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
    expect(onion.indexOf('requireVerifiedQueryResultsV1(')).toBeGreaterThan(0);
    expect(onion.indexOf('renderResult(')).toBeGreaterThan(
      onion.indexOf('requireVerifiedQueryResultsV1('),
    );
  });

  it('preflights the selected DPF/Harmony database before constructing the second admission leg', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const staged = html.slice(
      html.indexOf('async function prepareIndependentProductLeg'),
      html.indexOf('async function prepareCurrentIndependentProductLeg'),
    );
    const dpf = staged.slice(0, staged.indexOf("const providerIndex = role === 'hint'"));
    const harmony = staged.slice(staged.indexOf("const providerIndex = role === 'hint'"));
    expect(dpf.indexOf('await connected.prepareStrictAdmission(dbId)')).toBeGreaterThan(0);
    expect(dpf.indexOf('new ProviderAdmissionSessionV1(')).toBeGreaterThan(
      dpf.indexOf('await connected.prepareStrictAdmission(dbId)'),
    );
    expect(harmony.indexOf('await connected.prepareStrictAdmission(dbId)')).toBeGreaterThan(0);
    expect(harmony.indexOf('new ProviderAdmissionSessionV1(')).toBeGreaterThan(
      harmony.indexOf('await connected.prepareStrictAdmission(dbId)'),
    );
  });

  it('rejects Onion/ORAM database selector drift before a paid operation starts', () => {
    const html = readFileSync(new URL('../../index.html', import.meta.url), 'utf8');
    const onion = html.slice(
      html.indexOf('async function opQueryUtxos()'),
      html.indexOf("document.getElementById('op-queryBtn').addEventListener"),
    );
    const oram = html.slice(
      html.indexOf('async function oramQueryUtxos()'),
      html.indexOf('async function runOramQueryOnce()'),
    );
    expect(onion.indexOf('opClient.getDbId() !== onionAdmissionDbId')).toBeGreaterThan(0);
    expect(onion.indexOf('queryClient.queryBatch(')).toBeGreaterThan(
      onion.indexOf('opClient.getDbId() !== onionAdmissionDbId'),
    );
    expect(oram.indexOf('selectedDbId !== oramAdmissionDbId')).toBeGreaterThan(0);
    expect(oram.indexOf('queryClient.queryDelta(')).toBeGreaterThan(
      oram.indexOf('selectedDbId !== oramAdmissionDbId'),
    );
    const onionChange = html.slice(
      html.indexOf("document.getElementById('op-dbSelect').addEventListener"),
      html.indexOf('// ═══════════════════════════════════════════════════════════════\n        // HarmonyPIR'),
    );
    expect(onionChange).toContain("closeAdmissionAttempt(\n                    'onion'");
    const oramChange = html.slice(
      html.indexOf("document.getElementById('oram-dbSelect').addEventListener"),
      html.indexOf('</script>', html.indexOf("document.getElementById('oram-dbSelect')")),
    );
    expect(oramChange).toContain("closeAdmissionAttempt(\n                    'oram'");
  });
});
