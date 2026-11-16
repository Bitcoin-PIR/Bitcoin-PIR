import {
  AMD_MILAN_ARK_FINGERPRINT,
  AMD_TURIN_ARK_FINGERPRINT,
  applySevSnpPlatformFloor,
} from './attest-pin.js';
import { hexToBytes } from './hash.js';
import { requireSdkWasm } from './sdk-bridge.js';

export interface BuilderSnpPolicy {
  measurementHex: string;
  /** Omitted by historical Turin proof manifests. */
  amdProduct?: 'Turin' | 'Milan';
}

export function verifyBuilderSnpReport(
  report: Uint8Array,
  certificates: { arkPem: string; askPem: string; vcekPem: string },
  expected: BuilderSnpPolicy,
): void {
  const product = expected.amdProduct ?? 'Turin';
  if (product !== 'Turin' && product !== 'Milan') {
    throw new Error(`unsupported builder AMD product: ${product}`);
  }
  const ark = product === 'Milan' ? AMD_MILAN_ARK_FINGERPRINT : AMD_TURIN_ARK_FINGERPRINT;
  const sdk = requireSdkWasm();
  const policy = new sdk.WasmPolicyRequirements();
  policy.setExpectedMeasurement(hexToBytes(expected.measurementHex.trim().toLowerCase().replace(/^0x/, '')));
  applySevSnpPlatformFloor(policy, ark);
  sdk.verifyRawSnpReport(
    report, certificates.arkPem, certificates.askPem, certificates.vcekPem, ark, policy,
  );
}
