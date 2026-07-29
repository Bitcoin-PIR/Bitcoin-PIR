import {
  AdmissionCredentialVaultV1,
  type AdmissionCapabilityBindingV1,
} from '../src/admission-vault.js';
import { hexToBytes } from '../src/hash.js';
import {
  initSdkWasm,
  requireSdkWasm,
  type ServicePolicyViewV1,
  type WasmAcceptedServicePolicyV1,
} from '../src/sdk-bridge.js';

const SERVICE_POLICY_RESPONSE_OPCODE = 0x0d;
const SERVICE_PROTOCOL_VERSION = 1;

export interface CdkCashuBrowserFixtureV1 {
  providerIdHex: string;
  policySigningPubkeyHex: string;
  policyBytes: number[];
  originalToken: string;
  browserToken: string;
  actualMintEndpoint: string;
  signedMintEndpoint: string;
  expectedAmount: number;
}

interface CdkCashuBrowserResultV1 {
  providerIdHex: string;
  policyDigestHex: string;
  scopeIdHex: string;
  offerId: number;
  canonicalSpend: number[];
  originalTokenRejection: string;
  capabilityCountBeforeTake: number;
  capabilityCountAfterTake: number;
  localStorage: Record<string, string>;
}

async function importRealCdkToken(
  fixture: CdkCashuBrowserFixtureV1,
): Promise<CdkCashuBrowserResultV1> {
  validateFixture(fixture);
  if (!await initSdkWasm()) throw new Error('real pir-sdk-wasm failed to initialize');
  const sdk = requireSdkWasm();
  const vault = await AdmissionCredentialVaultV1.open();
  let accepted: WasmAcceptedServicePolicyV1 | null = null;
  try {
    const channel = new sdk.WasmStandaloneOnionServiceAdmissionV1(
      0,
      new Uint8Array(32).fill(0xc7),
    );
    try {
      accepted = await vault.advancePolicyCheckpoint(
        fixture.providerIdHex,
        sdk.initialServicePolicyCheckpointV1(),
        (checkpoint) => {
          const candidate = channel.acceptPolicyResponse(
            frameSignedPolicy(Uint8Array.from(fixture.policyBytes)),
            exactHexBytes('providerIdHex', fixture.providerIdHex, 32),
            exactHexBytes('policySigningPubkeyHex', fixture.policySigningPubkeyHex, 32),
            nowUnix(),
            checkpoint,
          );
          return {
            nextCheckpoint: candidate.checkpointBytes(),
            value: candidate,
            discard: () => candidate.free(),
          };
        },
      );
      accepted.acknowledgeCheckpointPersisted();
      channel.verifyPolicySession(accepted);
    } finally {
      channel.free();
    }

    const view = accepted.offersJson() as ServicePolicyViewV1;
    const scope = view.scopes.find((candidate) => candidate.workload === 'dpf-query');
    const offer = scope?.offers.find((candidate) =>
      candidate.acquisition === 'cashu-ecash'
      && candidate.authorization === 'cashu-ecash'
      && candidate.verification === 'standard-cashu-mint-online');
    if (!scope || !offer) throw new Error('signed fixture has no standard Cashu DPF offer');
    if (view.providerIdHex !== fixture.providerIdHex
        || offer.endpoint !== fixture.signedMintEndpoint
        || offer.price.kind !== 'cashu'
        || offer.price.unit !== 'sat'
        || offer.price.amount !== String(fixture.expectedAmount)) {
      throw new Error('verified standard Cashu offer differs from the owner-only fixture');
    }

    const scopeId = exactHexBytes('scopeIdHex', scope.scopeIdHex, 32);
    let originalTokenRejection = '';
    try {
      const unexpected = accepted.importStandardCashuToken(
        scopeId,
        offer.offerId,
        fixture.originalToken,
        nowUnix(),
      );
      unexpected.fill(0);
      throw new Error('the HTTP loopback token unexpectedly matched a signed HTTPS mint identity');
    } catch (error) {
      originalTokenRejection = String((error as Error).message ?? error);
      if (!originalTokenRejection.includes('mint does not match the signed manifest')) {
        throw new Error('the original CDK token failed for an unexpected reason');
      }
    }

    const payload = accepted.importStandardCashuToken(
      scopeId,
      offer.offerId,
      fixture.browserToken,
      nowUnix(),
    );
    const binding: AdmissionCapabilityBindingV1 = {
      providerIdHex: view.providerIdHex,
      policyDigestHex: view.policyDigestHex,
      scopeIdHex: scope.scopeIdHex,
      offerId: offer.offerId,
      scheme: 'cashu-ecash',
    };
    try {
      accepted.validateAuthorizationProof(scopeId, offer.offerId, payload);
      if (containsUtf8(payload, fixture.originalToken)
          || containsUtf8(payload, fixture.browserToken)
          || containsUtf8(payload, fixture.actualMintEndpoint)
          || containsUtf8(payload, fixture.signedMintEndpoint)) {
        throw new Error('canonical provider spend retained wallet token or mint endpoint metadata');
      }
      await vault.putCapability({ ...binding, payload });
    } finally {
      payload.fill(0);
    }

    const capabilityCountBeforeTake = await vault.countCapabilities(binding);
    const capability = await vault.takeSingleUseCapability(binding, (candidate) => {
      accepted?.validateAuthorizationProof(scopeId, offer.offerId, candidate);
    });
    if (!capability) throw new Error('encrypted vault lost the imported Cashu capability');
    const canonicalSpend = Array.from(capability.payload);
    capability.payload.fill(0);
    const capabilityCountAfterTake = await vault.countCapabilities(binding);

    return {
      providerIdHex: view.providerIdHex,
      policyDigestHex: view.policyDigestHex,
      scopeIdHex: scope.scopeIdHex,
      offerId: offer.offerId,
      canonicalSpend,
      originalTokenRejection,
      capabilityCountBeforeTake,
      capabilityCountAfterTake,
      localStorage: Object.fromEntries(
        Array.from({ length: localStorage.length }, (_, index) => localStorage.key(index))
          .filter((key): key is string => key !== null)
          .map((key) => [key, localStorage.getItem(key) ?? '']),
      ),
    };
  } finally {
    accepted?.free();
    vault.close();
    fixture.policyBytes.fill(0);
    fixture.originalToken = '';
    fixture.browserToken = '';
  }
}

function validateFixture(fixture: CdkCashuBrowserFixtureV1): void {
  exactHexBytes('providerIdHex', fixture.providerIdHex, 32);
  exactHexBytes('policySigningPubkeyHex', fixture.policySigningPubkeyHex, 32);
  if (!Array.isArray(fixture.policyBytes)
      || fixture.policyBytes.length === 0
      || fixture.policyBytes.length > 128 * 1024
      || fixture.policyBytes.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    throw new Error('policyBytes must contain one bounded signed policy');
  }
  if (!/^cashuB[A-Za-z0-9_-]+={0,2}$/.test(fixture.originalToken)
      || !/^cashuB[A-Za-z0-9_-]+={0,2}$/.test(fixture.browserToken)) {
    throw new Error('CDK fixtures must be canonical cashuB token strings');
  }
  const signedLocalhost = /^https:\/\/localhost:([0-9]+)$/.exec(fixture.signedMintEndpoint);
  const signedPort = signedLocalhost ? Number(signedLocalhost[1]) : 0;
  if (!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(fixture.actualMintEndpoint)
      || (fixture.signedMintEndpoint !== 'https://cdk-loopback.invalid'
          && (!Number.isSafeInteger(signedPort) || signedPort < 1024 || signedPort > 65535))
      || !Number.isSafeInteger(fixture.expectedAmount)
      || fixture.expectedAmount <= 0) {
    throw new Error('CDK browser fixture crossed its loopback/synthetic-identity boundary');
  }
}

function frameSignedPolicy(policy: Uint8Array): Uint8Array {
  const payloadLength = 1 + 1 + 4 + policy.length;
  const frame = new Uint8Array(4 + payloadLength);
  const view = new DataView(frame.buffer);
  view.setUint32(0, payloadLength, true);
  frame[4] = SERVICE_POLICY_RESPONSE_OPCODE;
  frame[5] = SERVICE_PROTOCOL_VERSION;
  view.setUint32(6, policy.length, true);
  frame.set(policy, 10);
  return frame;
}

function exactHexBytes(field: string, value: string, length: number): Uint8Array {
  if (!new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw new Error(`${field} is not canonical lowercase ${length}-byte hex`);
  }
  const bytes = hexToBytes(value);
  if (bytes.every((byte) => byte === 0)) throw new Error(`${field} must be non-zero`);
  return bytes;
}

function containsUtf8(haystack: Uint8Array, value: string): boolean {
  const needle = new TextEncoder().encode(value);
  try {
    if (needle.length === 0 || needle.length > haystack.length) return false;
    outer: for (let start = 0; start <= haystack.length - needle.length; start += 1) {
      for (let offset = 0; offset < needle.length; offset += 1) {
        if (haystack[start + offset] !== needle[offset]) continue outer;
      }
      return true;
    }
    return false;
  } finally {
    needle.fill(0);
  }
}

function nowUnix(): bigint {
  return BigInt(Math.floor(Date.now() / 1_000));
}

const api = { importRealCdkToken };

declare global {
  interface Window {
    paymentCdkCashuTest: typeof api;
    __paymentCdkLocalStorageWrites?: Array<[string, string]>;
  }
}

window.paymentCdkCashuTest = api;
void initSdkWasm().then((ready) => {
  if (!ready) throw new Error('real pir-sdk-wasm failed to initialize');
  document.documentElement.dataset.paymentCdkCashuReady = 'true';
});
