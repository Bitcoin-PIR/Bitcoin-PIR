import { readFile } from 'node:fs/promises';
import { beforeAll, describe, expect, it, vi } from 'vitest';

const { requireSdkWasm } = vi.hoisted(() => ({ requireSdkWasm: vi.fn() }));
vi.mock('../sdk-bridge.js', () => ({ requireSdkWasm }));
import { verifyBuilderSnpReport, type BuilderSnpPolicy } from '../builder-snp-proof.js';
import { extractSnpMeasurement } from '../bhtm-proof.js';
import { bytesToHex } from '../hash.js';

describe('builder SNP platform selection', () => {
  let report: Uint8Array;
  let certificates: { arkPem: string; askPem: string; vcekPem: string };
  let policy: BuilderSnpPolicy;
  let oldReport: Uint8Array;
  let oldCertificates: typeof certificates;

  beforeAll(async () => {
    const sdk = await import('pir-sdk-wasm');
    const wasm = await readFile(new URL('../../../crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm', import.meta.url));
    sdk.initSync({ module: wasm });
    requireSdkWasm.mockReturnValue(sdk);
    const fixture = new URL('../../../crates/trust/attest-verify/testdata/milan/', import.meta.url);
    oldReport = new Uint8Array(await readFile(new URL('report.bin', fixture)));
    oldCertificates = {
      arkPem: await readFile(new URL('ark.pem', fixture), 'utf8'),
      askPem: await readFile(new URL('ask.pem', fixture), 'utf8'),
      vcekPem: await readFile(new URL('vcek.pem', fixture), 'utf8'),
    };
    // This runtime report fixture exercises certificate/signature/policy checks;
    // source-proof tests separately check the builder evidence REPORT_DATA binding.
    const current = JSON.parse(await readFile(new URL('./fixtures/milan-current-platform-report.json', import.meta.url), 'utf8'));
    report = new Uint8Array(Buffer.from(current.reportBase64, 'base64'));
    certificates = { arkPem: current.arkPem, askPem: current.askPem, vcekPem: current.vcekPem };
    policy = { amdProduct: 'Milan', measurementHex: current.measurementHex };
  });

  it('verifies a real Milan report through the builder path', () => {
    expect(() => verifyBuilderSnpReport(report, certificates, policy)).not.toThrow();
  });

  it('retains the Turin default and rejects a Milan chain under it', () => {
    expect(() => verifyBuilderSnpReport(report, certificates, { measurementHex: policy.measurementHex })).toThrow();
  });

  it('rejects the older signed Milan report below the current mitigation floor', () => {
    expect(() => verifyBuilderSnpReport(oldReport, oldCertificates, {
      amdProduct: 'Milan', measurementHex: bytesToHex(extractSnpMeasurement(oldReport)),
    })).toThrow('mitigation vector lacks required bits');
  });

  it('rejects a different measured image and a modified signed report', () => {
    expect(() => verifyBuilderSnpReport(report, certificates, { ...policy, measurementHex: '00'.repeat(48) })).toThrow();
    const changed = report.slice();
    changed[0x50] ^= 1;
    expect(() => verifyBuilderSnpReport(changed, certificates, policy)).toThrow();
  });

  it('rejects an unknown product in a decoded manifest', () => {
    const unknown = JSON.parse(JSON.stringify({ ...policy, amdProduct: 'unknown' })) as BuilderSnpPolicy;
    expect(() => verifyBuilderSnpReport(report, certificates, unknown)).toThrow('unsupported builder AMD product');
  });
});
