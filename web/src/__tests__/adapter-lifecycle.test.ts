import { beforeEach, describe, expect, it, vi } from 'vitest';

const { policyFree } = vi.hoisted(() => ({ policyFree: vi.fn() }));

vi.mock('../sdk-bridge.js', () => ({
  requireSdkWasm: () => ({
    WasmPolicyRequirements: class {
      free(): void {
        policyFree();
      }
    },
  }),
}));

import { BatchPirClientAdapter } from '../dpf-adapter.js';
import { HarmonyPirClientAdapter } from '../harmonypir-adapter.js';
import type { WasmAnnounceVerification, WasmAttestVerification } from '../sdk-bridge.js';

function fakeAttestation(free: () => void): WasmAttestVerification {
  return {
    sevStatus: 'noSevHost',
    serverStaticPub: new Uint8Array(32).fill(1),
    serverStaticPubHex: '01'.repeat(32),
    binarySha256Hex: '02'.repeat(32),
    gitRev: 'test',
    launchMeasurementHex: '',
    hasVcekChain: false,
    free,
  } as unknown as WasmAttestVerification;
}

function fakeAnnouncement(free: () => void): WasmAnnounceVerification {
  return {
    serverId: 'pir1',
    operatorPubkeyHex: '03'.repeat(32),
    identityPubkeyHex: '04'.repeat(32),
    channelPub: new Uint8Array(32).fill(1),
    channelPubHex: '01'.repeat(32),
    binarySha256Hex: '02'.repeat(32),
    gitRev: 'test',
    validFrom: 0n,
    validUntil: 0n,
    issuedAt: 0n,
    chainVerified: true,
    chainError: '',
    checkPinnedOperator() {},
    checkChannelBinding() {},
    checkFreshness() {},
    free,
  } as unknown as WasmAnnounceVerification;
}

describe('adapter WASM lifecycle', () => {
  beforeEach(() => {
    policyFree.mockClear();
  });

  it('frees both DPF attestation handles when a UI callback throws', async () => {
    const free0 = vi.fn();
    const free1 = vi.fn();
    const handles = [fakeAttestation(free0), fakeAttestation(free1)];
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      onAttestation: () => {
        throw new Error('render failed');
      },
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => handles[idx]),
      upgradeToSecureChannel: vi.fn(),
    };

    await expect((adapter as any).attestAndUpgrade()).rejects.toThrow('render failed');
    expect(free0).toHaveBeenCalledOnce();
    expect(free1).toHaveBeenCalledOnce();
    expect(policyFree).toHaveBeenCalledOnce();
  });

  it('frees the first DPF attestation if logging the second attest failure throws', async () => {
    const free0 = vi.fn();
    const first = fakeAttestation(free0);
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      onLog: () => {
        throw new Error('log renderer failed');
      },
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => {
        if (idx === 0) return first;
        throw new Error('second attest failed');
      }),
    };

    await expect((adapter as any).attestAndUpgrade()).rejects.toThrow('log renderer failed');
    expect(free0).toHaveBeenCalledOnce();
    expect(policyFree).not.toHaveBeenCalled();
  });

  it('frees DPF attest and announce handles when BigInt conversion rejects config', async () => {
    const free0 = vi.fn();
    const free1 = vi.fn();
    const announceFree = vi.fn();
    const handles = [fakeAttestation(free0), fakeAttestation(free1)];
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      verifyOperatorIdentity: true,
      maxAnnounceAgeSeconds: 1.5,
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => handles[idx]),
      upgradeToSecureChannel: vi.fn(async () => {}),
      announce: vi.fn(async () => fakeAnnouncement(announceFree)),
    };

    await expect((adapter as any).attestAndUpgrade()).rejects.toThrow();
    expect(announceFree).toHaveBeenCalledOnce();
    expect(free0).toHaveBeenCalledOnce();
    expect(free1).toHaveBeenCalledOnce();
    expect(policyFree).toHaveBeenCalledOnce();
  });

  it('frees both Harmony attestation handles when a UI callback throws', async () => {
    const free0 = vi.fn();
    const free1 = vi.fn();
    const handles = [fakeAttestation(free0), fakeAttestation(free1)];
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://pir1.invalid',
      queryServerUrl: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      onAttestation: () => {
        throw new Error('render failed');
      },
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => handles[idx]),
      upgradeToSecureChannel: vi.fn(),
    };

    await expect((adapter as any).attestAndUpgrade()).rejects.toThrow('render failed');
    expect(free0).toHaveBeenCalledOnce();
    expect(free1).toHaveBeenCalledOnce();
    expect(policyFree).toHaveBeenCalledOnce();
  });

  it('fully frees a Harmony client when strict reconnect bootstrap fails', async () => {
    const disconnect = vi.fn(async () => {});
    const free = vi.fn();
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://pir1.invalid',
      queryServerUrl: 'wss://pir2.invalid',
      strictVerification: true,
    });
    (adapter as any).wasmClient = {
      isConnected: true,
      disconnect,
      connect: vi.fn(async () => {
        throw new Error('fresh transport failed');
      }),
      setRequireVerifiedDatabaseRoots: vi.fn(),
      free,
    };
    adapter.hintsLoaded = true;

    await expect(adapter.reconnectQueryServer()).rejects.toThrow('fresh transport failed');
    expect(disconnect).toHaveBeenCalledTimes(2);
    expect(free).toHaveBeenCalledOnce();
    expect(adapter.hintsLoaded).toBe(false);
    expect((adapter as any).wasmClient).toBeNull();
    expect(adapter.isQueryServerConnected()).toBe(false);
  });
});
