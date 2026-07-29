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

function fakeAnnouncement(
  free: () => void,
  checkPinnedOperator: (pin: Uint8Array) => void = () => {},
): WasmAnnounceVerification {
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
    checkPinnedOperator,
    checkChannelBinding() {},
    checkFreshness() {},
    free,
  } as unknown as WasmAnnounceVerification;
}

function fakeInstalledProof(dbId = 0): any {
  const proof = { dbId, muhashHex: 'aa'.repeat(32), bucketSuperRootHex: 'bb'.repeat(32) };
  return {
    pin: { dbId },
    proof,
    status: { state: 'verified', proof },
  };
}

describe('adapter WASM lifecycle', () => {
  beforeEach(() => {
    policyFree.mockClear();
  });

  it('scrubs DPF result data when inclusion verification returns false', async () => {
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: false,
    });
    (adapter as any).wasmClient = {
      verifyMerkleBatch: vi.fn(async () => [false]),
    };
    const result: any = {
      entries: [{ txid: new Uint8Array(32).fill(1), vout: 0, amount: 9n }],
      totalSats: 9n,
      startChunkId: 1,
      numChunks: 1,
      numRounds: 1,
      isWhale: false,
      rawChunkData: new Uint8Array([7]),
      allIndexBins: [{ pbcGroup: 0, binIndex: 0, binContent: new Uint8Array([1]) }],
    };
    await expect(adapter.verifyMerkleBatch([result])).resolves.toEqual([false]);
    expect(result).toMatchObject({ entries: [], totalSats: 0n, merkleVerified: false });
    expect(result.rawChunkData).toBeUndefined();
    expect(result.allIndexBins).toBeUndefined();
  });

  it('scrubs Harmony result data when inclusion verification returns false', async () => {
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: false,
    });
    (adapter as any).wasmClient = {
      verifyMerkleBatch: vi.fn(async () => [false]),
    };
    const result: any = {
      address: 'fixture',
      scriptHash: '11'.repeat(20),
      utxos: [{ txid: '22'.repeat(32), vout: 0, value: 9 }],
      whale: false,
      rawChunkData: new Uint8Array([7]),
      allIndexBins: [{ pbcGroup: 0, binIndex: 0, binContent: new Uint8Array([1]) }],
    };
    await expect(adapter.verifyMerkleBatch([result], undefined, 0)).resolves.toEqual([false]);
    expect(result).toMatchObject({ utxos: [], merkleVerified: false });
    expect(result.rawChunkData).toBeUndefined();
    expect(result.allIndexBins).toBeUndefined();
  });

  it('never persists a main-only Harmony hint cache over a complete entitlement', async () => {
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: true,
      prpBackend: 0,
    });
    const saveHints = vi.fn(() => new Uint8Array([1]));
    (adapter as any).wasmClient = {
      hasCompleteHints: vi.fn(() => false),
      saveHints,
    };
    (adapter as any).catalog = { databases: [] };
    (adapter as any).catalogToSdkHandle = () => ({ free: vi.fn() });
    (adapter as any).databaseProofs.set(0, {
      state: 'verified',
      proof: { bucketSuperRootHex: '51'.repeat(32) },
    });
    await adapter.saveHintsToCache({
      providerIdHex: '11'.repeat(32),
      policyDigestHex: '31'.repeat(32),
      scopeIdHex: '21'.repeat(32),
      offerId: 1,
      datasetIdHex: '51'.repeat(32),
      prpBackend: 0,
    });
    expect(saveHints).not.toHaveBeenCalled();
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

  it('passes independent DPF operator pins to their matching legs', async () => {
    const firstPin = new Uint8Array(32).fill(0x11);
    const secondPin = new Uint8Array(32).fill(0x22);
    const seen: Uint8Array[] = [];
    const handles = [fakeAttestation(vi.fn()), fakeAttestation(vi.fn())];
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      strictVerification: true,
      verifyOperatorIdentity: true,
      pinnedOperatorPubkey0: firstPin,
      pinnedOperatorPubkey1: secondPin,
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => handles[idx]),
      upgradeToSecureChannel: vi.fn(async () => {}),
      announce: vi.fn(async () => fakeAnnouncement(vi.fn(), (pin) => seen.push(pin.slice()))),
    };

    await expect((adapter as any).attestAndUpgrade()).resolves.toBeUndefined();
    expect(seen).toEqual([firstPin, secondPin]);
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

  it('passes independent Harmony hint/query operator pins to their matching legs', async () => {
    const hintPin = new Uint8Array(32).fill(0x31);
    const queryPin = new Uint8Array(32).fill(0x32);
    const seen: Uint8Array[] = [];
    const handles = [fakeAttestation(vi.fn()), fakeAttestation(vi.fn())];
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://pir1.invalid',
      queryServerUrl: 'wss://pir2.invalid',
      expectedArkFingerprint: null,
      strictVerification: true,
      verifyOperatorIdentity: true,
      pinnedHintOperatorPubkey: hintPin,
      pinnedQueryOperatorPubkey: queryPin,
    });
    (adapter as any).wasmClient = {
      attest: vi.fn(async (idx: number) => handles[idx]),
      upgradeToSecureChannel: vi.fn(async () => {}),
      announce: vi.fn(async () => fakeAnnouncement(vi.fn(), (pin) => seen.push(pin.slice()))),
    };

    await expect((adapter as any).attestAndUpgrade()).resolves.toBeUndefined();
    expect(seen).toEqual([hintPin, queryPin]);
  });

  it('preserves an admitted DPF first leg when the second transport fails', async () => {
    const disconnectServer = vi.fn(async () => {});
    const diagnosticDisconnect = vi.fn();
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
    });
    (adapter as any).strictLegReady = [true, false];
    (adapter as any).ws1 = {
      connect: vi.fn(async () => {}),
      disconnect: diagnosticDisconnect,
    };
    (adapter as any).wasmClient = {
      connectServer: vi.fn(async (idx: number) => {
        if (idx === 1) throw new Error('second transport unavailable');
      }),
      disconnectServer,
      isServerConnected: vi.fn((idx: number) => idx === 0),
    };

    await expect(adapter.connectLeg(1)).rejects.toThrow('second transport unavailable');

    expect(adapter.isLegReady(0)).toBe(true);
    expect(adapter.isLegReady(1)).toBe(false);
    expect(disconnectServer).toHaveBeenCalledOnce();
    expect(disconnectServer).toHaveBeenCalledWith(1);
    expect(diagnosticDisconnect).toHaveBeenCalledOnce();
  });

  it('recognizes two staged DPF secure legs before committing aggregate readiness', () => {
    const binary0 = '41'.repeat(32);
    const binary1 = '42'.repeat(32);
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
      verifyOperatorIdentity: true,
      expectedServer0Pin: { binarySha256Hex: binary0 },
      expectedServer1Pin: { binarySha256Hex: binary1 },
      expectedServer0Id: 'pir1',
      expectedServer1Id: 'pir2',
    });
    (adapter as any).secureChannelLegs = [true, true];
    (adapter as any).secureChannelEstablished = false;
    adapter.attestation = {
      server0: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
      server1: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
    };
    adapter.operatorIdentity = {
      server0: { state: 'verified', serverId: 'pir1', binarySha256Hex: binary0 },
      server1: { state: 'verified', serverId: 'pir2', binarySha256Hex: binary1 },
    };

    expect(() => (adapter as any).assertStrictTransportReady()).not.toThrow();
  });

  it('preserves Harmony hints and hint admission when the query leg fails', async () => {
    const disconnectProvider = vi.fn(async () => {});
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: true,
    });
    (adapter as any).strictLegReady = [true, false];
    adapter.hintsLoaded = true;
    (adapter as any).wasmClient = {
      connectProvider: vi.fn(async (idx: number) => {
        if (idx === 1) throw new Error('query transport unavailable');
      }),
      disconnectProvider,
      isProviderConnected: vi.fn((idx: number) => idx === 0),
    };

    await expect(adapter.connectLeg(1)).rejects.toThrow('query transport unavailable');

    expect(adapter.isLegReady(0)).toBe(true);
    expect(adapter.isLegReady(1)).toBe(false);
    expect(adapter.hintsLoaded).toBe(true);
    expect(disconnectProvider).toHaveBeenCalledOnce();
    expect(disconnectProvider).toHaveBeenCalledWith(1);
  });

  it('clears the DPF adapter session mirror when the final staged leg closes', async () => {
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: '',
      strictVerification: true,
    });
    (adapter as any).catalog = { databases: [{ dbId: 0 }] };
    (adapter as any).databaseProofs.set(0, { state: 'verified' });
    (adapter as any).strictLegReady = [true, false];
    (adapter as any).wasmClient = {
      disconnectServer: vi.fn(async () => {}),
      isServerConnected: vi.fn(() => false),
    };

    await adapter.disconnectLeg(0);

    expect(adapter.getCatalog()).toBeNull();
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
    expect(adapter.isLegReady(0)).toBe(false);
  });

  it('clears in-memory Harmony hints and catalog when the final role closes', async () => {
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: '',
      strictVerification: true,
    });
    (adapter as any).catalog = { databases: [{ dbId: 0 }] };
    (adapter as any).databaseProofs.set(0, { state: 'verified' });
    (adapter as any).strictLegReady = [true, false];
    adapter.hintsLoaded = true;
    (adapter as any).wasmClient = {
      disconnectProvider: vi.fn(async () => {}),
      isProviderConnected: vi.fn(() => false),
    };

    await adapter.disconnectLeg(0);

    expect(adapter.getCatalog()).toBeNull();
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
    expect(adapter.hintsLoaded).toBe(false);
    expect(adapter.isLegReady(0)).toBe(false);
  });

  it('keeps DPF queries blocked until one shared post-authorization preflight completes', async () => {
    const preflightDatabase = vi.fn(async () => {});
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
    });
    (adapter as any).pairConsistencyReady = true;
    (adapter as any).pairPreflightState = 'pending';
    (adapter as any).strictLegReady = [true, true];
    (adapter as any).secureChannelLegs = [true, true];
    (adapter as any).installedProofsByLeg = [
      [fakeInstalledProof()],
      [fakeInstalledProof()],
    ];
    (adapter as any).wasmClient = { preflightDatabase };

    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    await Promise.all([adapter.finalizeStrictPair(0), adapter.finalizeStrictPair(0)]);

    expect(preflightDatabase).toHaveBeenCalledOnce();
    await expect(adapter.queryBatch([], undefined, 1)).rejects.toThrow(
      'strict DPF admission is bound to db_id 0, not db_id 1',
    );
  });

  it('makes a failed Harmony post-authorization preflight fail closed and one-shot', async () => {
    const preflightDatabase = vi.fn(async () => {
      throw new Error('tree-top mismatch');
    });
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: true,
    });
    (adapter as any).pairConsistencyReady = true;
    (adapter as any).pairPreflightState = 'pending';
    (adapter as any).strictLegReady = [true, true];
    (adapter as any).secureChannelLegs = [true, true];
    (adapter as any).installedProofsByLeg = [
      [fakeInstalledProof()],
      [fakeInstalledProof()],
    ];
    (adapter as any).wasmClient = { preflightDatabase };

    await expect(adapter.finalizeStrictPair(0)).rejects.toThrow('tree-tops preflight failed');
    await expect(adapter.finalizeStrictPair(0)).rejects.toThrow('retry is disabled');
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
  });

  it('does not let an obsolete DPF preflight completion revive a disconnected pair', async () => {
    let releasePreflight!: () => void;
    const preflightDatabase = vi.fn(() => new Promise<void>((resolve) => {
      releasePreflight = resolve;
    }));
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
    });
    (adapter as any).pairConsistencyReady = true;
    (adapter as any).pairPreflightState = 'pending';
    (adapter as any).strictLegReady = [true, true];
    (adapter as any).secureChannelLegs = [true, true];
    (adapter as any).installedProofsByLeg = [
      [fakeInstalledProof()],
      [fakeInstalledProof()],
    ];
    (adapter as any).wasmClient = {
      preflightDatabase,
      disconnectServer: vi.fn(async () => {}),
      isServerConnected: vi.fn(() => false),
    };

    const finalization = adapter.finalizeStrictPair(0);
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(0);
    releasePreflight();

    await expect(finalization).rejects.toThrow('invalidated while in flight');
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
  });

  it('does not let an obsolete Harmony preflight completion revive a disconnected pair', async () => {
    let releasePreflight!: () => void;
    const preflightDatabase = vi.fn(() => new Promise<void>((resolve) => {
      releasePreflight = resolve;
    }));
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: true,
    });
    (adapter as any).pairConsistencyReady = true;
    (adapter as any).pairPreflightState = 'pending';
    (adapter as any).strictLegReady = [true, true];
    (adapter as any).secureChannelLegs = [true, true];
    (adapter as any).installedProofsByLeg = [
      [fakeInstalledProof()],
      [fakeInstalledProof()],
    ];
    (adapter as any).wasmClient = {
      preflightDatabase,
      disconnectProvider: vi.fn(async () => {}),
      isProviderConnected: vi.fn(() => false),
    };

    const finalization = adapter.finalizeStrictPair(0);
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(1);
    releasePreflight();

    await expect(finalization).rejects.toThrow('invalidated while in flight');
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
  });
});
