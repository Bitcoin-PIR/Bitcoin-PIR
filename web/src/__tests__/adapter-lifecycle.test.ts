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

const OPERATOR_PIN_0 = new Uint8Array(32).fill(0x41);
const OPERATOR_PIN_1 = new Uint8Array(32).fill(0x42);
const BINARY_0 = '51'.repeat(32);
const BINARY_1 = '52'.repeat(32);

function strictDpfPair(client: any): BatchPirClientAdapter {
  const adapter = new BatchPirClientAdapter({
    server0Url: 'wss://pir1.invalid',
    server1Url: 'wss://pir2.invalid',
    strictVerification: true,
    verifyOperatorIdentity: true,
    expectedServer0Pin: { binarySha256Hex: BINARY_0 },
    expectedServer1Pin: { binarySha256Hex: BINARY_1 },
    expectedServer0Id: 'pir1',
    expectedServer1Id: 'pir2',
    pinnedOperatorPubkey0: OPERATOR_PIN_0,
    pinnedOperatorPubkey1: OPERATOR_PIN_1,
  });
  const state = adapter as any;
  state.wasmClient = client;
  state.secureChannelLegs = [true, true];
  state.strictLegReady = [true, true];
  state.installedProofsByLeg = [[fakeInstalledProof()], [fakeInstalledProof()]];
  state.pairConsistencyReady = true;
  state.pairPreflightState = 'pending';
  adapter.attestation = {
    server0: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
    server1: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
  };
  adapter.operatorIdentity = {
    server0: { state: 'verified', serverId: 'pir1', binarySha256Hex: BINARY_0 },
    server1: { state: 'verified', serverId: 'pir2', binarySha256Hex: BINARY_1 },
  };
  state.legGenerations = [1, 1];
  state.legOwners = [
    {
      generation: 1,
      client,
      diagnostic: state.ws0,
      url: 'wss://pir1.invalid',
      configSignature: state.legConfigSignature(0),
    },
    {
      generation: 1,
      client,
      diagnostic: state.ws1,
      url: 'wss://pir2.invalid',
      configSignature: state.legConfigSignature(1),
    },
  ];
  return adapter;
}

function strictHarmonyPair(client: any): HarmonyPirClientAdapter {
  const adapter = new HarmonyPirClientAdapter({
    hintServerUrl: 'wss://hint.invalid',
    queryServerUrl: 'wss://query.invalid',
    strictVerification: true,
    verifyOperatorIdentity: true,
    expectedServer0Pin: { binarySha256Hex: BINARY_0 },
    expectedServer1Pin: { binarySha256Hex: BINARY_1 },
    expectedServer0Id: 'hint',
    expectedServer1Id: 'query',
    pinnedHintOperatorPubkey: OPERATOR_PIN_0,
    pinnedQueryOperatorPubkey: OPERATOR_PIN_1,
  });
  const state = adapter as any;
  state.wasmClient = client;
  state.secureChannelLegs = [true, true];
  state.strictLegReady = [true, true];
  state.installedProofsByLeg = [[fakeInstalledProof()], [fakeInstalledProof()]];
  state.pairConsistencyReady = true;
  state.pairPreflightState = 'pending';
  adapter.attestation = {
    hint: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
    query: { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
  };
  adapter.operatorIdentity = {
    hint: { state: 'verified', serverId: 'hint', binarySha256Hex: BINARY_0 },
    query: { state: 'verified', serverId: 'query', binarySha256Hex: BINARY_1 },
  };
  state.legGenerations = [1, 1];
  state.legOwners = [
    {
      generation: 1,
      client,
      url: 'wss://hint.invalid',
      configSignature: state.legConfigSignature(0),
    },
    {
      generation: 1,
      client,
      url: 'wss://query.invalid',
      configSignature: state.legConfigSignature(1),
    },
  ];
  return adapter;
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

  it('defensively retains directory-configured operator pins for both staged adapters', () => {
    const dpfPin = new Uint8Array(32).fill(0x71);
    const harmonyPin = new Uint8Array(32).fill(0x72);
    const dpf = new BatchPirClientAdapter({
      server0Url: '', server1Url: '', strictVerification: true,
    });
    const harmony = new HarmonyPirClientAdapter({
      hintServerUrl: '', queryServerUrl: '', strictVerification: true,
    });

    dpf.configureServerLeg(0, {
      url: 'wss://directory-dpf.invalid',
      pinnedOperatorPubkey: dpfPin,
    });
    harmony.configureProviderLeg(0, {
      url: 'wss://directory-hint.invalid',
      pinnedOperatorPubkey: harmonyPin,
    });
    dpfPin.fill(0xff);
    harmonyPin.fill(0xff);

    expect((dpf as any).operatorPinForLeg(0)).toEqual(new Uint8Array(32).fill(0x71));
    expect((harmony as any).operatorPinForLeg(0)).toEqual(new Uint8Array(32).fill(0x72));
  });

  it('retains manual constructor pins when only a staged endpoint is reconfigured', () => {
    const dpfPin = new Uint8Array(32).fill(0x73);
    const harmonyPin = new Uint8Array(32).fill(0x74);
    const dpfExpected = { binarySha256Hex: '73'.repeat(32) };
    const harmonyExpected = { binarySha256Hex: '74'.repeat(32) };
    const dpf = new BatchPirClientAdapter({
      server0Url: '',
      server1Url: '',
      strictVerification: true,
      expectedServer0Pin: dpfExpected,
      expectedServer0Id: 'manual-dpf',
      pinnedOperatorPubkey0: dpfPin,
    });
    const harmony = new HarmonyPirClientAdapter({
      hintServerUrl: '',
      queryServerUrl: '',
      strictVerification: true,
      expectedServer0Pin: harmonyExpected,
      expectedServer0Id: 'manual-hint',
      pinnedHintOperatorPubkey: harmonyPin,
    });

    dpf.configureServerLeg(0, { url: 'wss://manual-dpf.invalid' });
    harmony.configureProviderLeg(0, { url: 'wss://manual-hint.invalid' });
    dpfPin.fill(0xff);
    harmonyPin.fill(0xff);
    dpfExpected.binarySha256Hex = 'ff'.repeat(32);
    harmonyExpected.binarySha256Hex = 'ff'.repeat(32);

    expect((dpf as any).operatorPinForLeg(0)).toEqual(new Uint8Array(32).fill(0x73));
    expect((dpf as any).config.expectedServer0Pin.binarySha256Hex).toBe('73'.repeat(32));
    expect((dpf as any).config.expectedServer0Id).toBe('manual-dpf');
    expect((harmony as any).operatorPinForLeg(0)).toEqual(new Uint8Array(32).fill(0x74));
    expect((harmony as any).config.expectedServer0Pin.binarySha256Hex).toBe('74'.repeat(32));
    expect((harmony as any).config.expectedServer0Id).toBe('manual-hint');
  });

  it('preserves an admitted DPF first leg when the second transport fails', async () => {
    const disconnectServer = vi.fn(async () => {});
    const diagnosticDisconnect = vi.fn();
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
      pinnedOperatorPubkey0: OPERATOR_PIN_0,
      pinnedOperatorPubkey1: OPERATOR_PIN_1,
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
    expect((adapter as any).wasmClient.connectServer).toHaveBeenCalledWith(1);
  });

  it('rejects duplicate DPF operator pins before dialing the second provider', async () => {
    const duplicate = new Uint8Array(32).fill(0x61);
    const connectDiagnostic = vi.fn(async () => {});
    const connectServer = vi.fn(async () => {});
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: 'wss://pir2.invalid',
      strictVerification: true,
      pinnedOperatorPubkey0: duplicate,
      pinnedOperatorPubkey1: duplicate.slice(),
    });
    (adapter as any).strictLegReady = [true, false];
    (adapter as any).ws1 = { connect: connectDiagnostic, disconnect: vi.fn() };
    (adapter as any).wasmClient = {
      connectServer,
      isServerConnected: vi.fn((idx: number) => idx === 0),
    };

    await expect(adapter.connectLeg(1)).rejects.toThrow('distinct operator pins');
    expect(connectDiagnostic).not.toHaveBeenCalled();
    expect(connectServer).not.toHaveBeenCalled();
    expect(adapter.isLegReady(0)).toBe(true);
  });

  it('rejects duplicate Harmony operator pins before dialing the second provider', async () => {
    const duplicate = new Uint8Array(32).fill(0x62);
    const connectProvider = vi.fn(async () => {});
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: 'wss://query.invalid',
      strictVerification: true,
      pinnedHintOperatorPubkey: duplicate,
      pinnedQueryOperatorPubkey: duplicate.slice(),
    });
    (adapter as any).strictLegReady = [true, false];
    (adapter as any).wasmClient = {
      connectProvider,
      isProviderConnected: vi.fn((idx: number) => idx === 0),
    };

    await expect(adapter.connectLeg(1)).rejects.toThrow('distinct operator pins');
    expect(connectProvider).not.toHaveBeenCalled();
    expect(adapter.isLegReady(0)).toBe(true);
  });

  it('does not let a late DPF diagnostic connect revive a disconnected leg', async () => {
    let releaseDiagnostic!: () => void;
    const connectServer = vi.fn(async () => {});
    const diagnosticDisconnect = vi.fn();
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: '',
      strictVerification: true,
      pinnedOperatorPubkey0: OPERATOR_PIN_0,
    });
    (adapter as any).ws0 = {
      connect: vi.fn(() => new Promise<void>((resolve) => { releaseDiagnostic = resolve; })),
      disconnect: diagnosticDisconnect,
    };
    (adapter as any).wasmClient = {
      connectServer,
      disconnectServer: vi.fn(async () => {}),
      isServerConnected: vi.fn(() => false),
    };

    const connecting = adapter.connectLeg(0);
    await Promise.resolve();
    await adapter.disconnectLeg(0);
    releaseDiagnostic();

    await expect(connecting).rejects.toThrow('connection attempt was invalidated');
    expect(connectServer).not.toHaveBeenCalled();
    expect(diagnosticDisconnect).toHaveBeenCalledTimes(2);
    expect(adapter.isLegReady(0)).toBe(false);
    expect(adapter.getCatalog()).toBeNull();
  });

  it('frees a late DPF catalog handle and never publishes it after disconnect', async () => {
    let releaseCatalog!: (value: any) => void;
    const catalogFree = vi.fn();
    const fetchCatalogFromServer = vi.fn(() => new Promise<any>((resolve) => {
      releaseCatalog = resolve;
    }));
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://pir1.invalid',
      server1Url: '',
      strictVerification: true,
      verifyOperatorIdentity: true,
      expectedArkFingerprint: null,
      expectedServer0Pin: { binarySha256Hex: '02'.repeat(32) },
      expectedServer0Id: 'pir1',
      pinnedOperatorPubkey0: OPERATOR_PIN_0,
      databaseProofPins: [
        { dbId: 0, paramsHashHex: '01'.repeat(32) } as any,
      ],
    });
    (adapter as any).ws0 = { connect: vi.fn(async () => {}), disconnect: vi.fn() };
    (adapter as any).wasmClient = {
      connectServer: vi.fn(async () => {}),
      disconnectServer: vi.fn(async () => {}),
      isServerConnected: vi.fn(() => false),
      attest: vi.fn(async () => fakeAttestation(vi.fn())),
      upgradeServerToSecureChannel: vi.fn(async () => {}),
      announce: vi.fn(async () => fakeAnnouncement(vi.fn())),
      fetchCatalogFromServer,
    };

    const connecting = adapter.connectLeg(0);
    for (let index = 0; index < 10 && !fetchCatalogFromServer.mock.calls.length; index += 1) {
      await Promise.resolve();
    }
    expect(fetchCatalogFromServer).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(0);
    releaseCatalog({
      toJson: () => JSON.stringify({ databases: [{ db_id: 0 }] }),
      free: catalogFree,
    });

    await expect(connecting).rejects.toThrow('connection attempt was invalidated');
    expect(catalogFree).toHaveBeenCalledOnce();
    expect(adapter.getCatalog()).toBeNull();
  });

  it('does not let a late Harmony native connect revive a disconnected role', async () => {
    let releaseConnect!: () => void;
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: '',
      strictVerification: true,
      pinnedHintOperatorPubkey: OPERATOR_PIN_0,
    });
    (adapter as any).wasmClient = {
      connectProvider: vi.fn(() => new Promise<void>((resolve) => { releaseConnect = resolve; })),
      disconnectProvider: vi.fn(async () => {}),
      isProviderConnected: vi.fn(() => false),
    };

    const connecting = adapter.connectLeg(0);
    await Promise.resolve();
    await adapter.disconnectLeg(0);
    releaseConnect();

    await expect(connecting).rejects.toThrow('connection attempt was invalidated');
    expect(adapter.isLegReady(0)).toBe(false);
    expect(adapter.getCatalog()).toBeNull();
  });

  it('frees a late Harmony catalog handle and never publishes it after disconnect', async () => {
    let releaseCatalog!: (value: any) => void;
    const catalogFree = vi.fn();
    const fetchCatalogFromProvider = vi.fn(() => new Promise<any>((resolve) => {
      releaseCatalog = resolve;
    }));
    const adapter = new HarmonyPirClientAdapter({
      hintServerUrl: 'wss://hint.invalid',
      queryServerUrl: '',
      strictVerification: true,
      verifyOperatorIdentity: true,
      expectedArkFingerprint: null,
      expectedServer0Pin: { binarySha256Hex: '02'.repeat(32) },
      expectedServer0Id: 'pir1',
      pinnedHintOperatorPubkey: OPERATOR_PIN_0,
      databaseProofPins: [
        { dbId: 0, paramsHashHex: '01'.repeat(32) } as any,
      ],
    });
    (adapter as any).wasmClient = {
      connectProvider: vi.fn(async () => {}),
      disconnectProvider: vi.fn(async () => {}),
      isProviderConnected: vi.fn(() => false),
      attest: vi.fn(async () => fakeAttestation(vi.fn())),
      upgradeProviderToSecureChannel: vi.fn(async () => {}),
      announce: vi.fn(async () => fakeAnnouncement(vi.fn())),
      fetchCatalogFromProvider,
    };

    const connecting = adapter.connectLeg(0);
    for (let index = 0; index < 10 && !fetchCatalogFromProvider.mock.calls.length; index += 1) {
      await Promise.resolve();
    }
    expect(fetchCatalogFromProvider).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(0);
    releaseCatalog({
      toJson: () => JSON.stringify({ databases: [{ db_id: 0 }] }),
      free: catalogFree,
    });

    await expect(connecting).rejects.toThrow('connection attempt was invalidated');
    expect(catalogFree).toHaveBeenCalledOnce();
    expect(adapter.getCatalog()).toBeNull();
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
      pinnedOperatorPubkey0: OPERATOR_PIN_0,
      pinnedOperatorPubkey1: OPERATOR_PIN_1,
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
      pinnedHintOperatorPubkey: OPERATOR_PIN_0,
      pinnedQueryOperatorPubkey: OPERATOR_PIN_1,
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

  it('keeps DPF capability use and queries blocked until pre-authorization preflight completes', async () => {
    const preflightDatabase = vi.fn(async () => {});
    const authorizeService = vi.fn(async () => ({}));
    const adapter = strictDpfPair({ preflightDatabase, authorizeService });
    const port = adapter.serviceAdmissionPort(0, 0);

    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    expect(() => port.authorize({} as any, new Uint8Array(32), 0, new Uint8Array()))
      .toThrow('requires prepared strict admission');
    await Promise.all([
      adapter.prepareStrictAdmission(0),
      adapter.prepareStrictAdmission(0),
    ]);

    expect(preflightDatabase).toHaveBeenCalledOnce();
    await port.authorize({} as any, new Uint8Array(32), 0, new Uint8Array());
    expect(authorizeService).toHaveBeenCalledOnce();
    await expect(adapter.queryBatch([], undefined, 1)).rejects.toThrow(
      'strict DPF admission is bound to db_id 0, not db_id 1',
    );
  });

  it('rechecks distinct operator pins at the final DPF pair gate', async () => {
    const preflightDatabase = vi.fn(async () => {});
    const adapter = strictDpfPair({ preflightDatabase });
    (adapter as any).config.pinnedOperatorPubkey1 = OPERATOR_PIN_0.slice();
    (adapter as any).legOwners[1].configSignature = (adapter as any).legConfigSignature(1);

    await expect(adapter.prepareStrictAdmission(0)).rejects.toThrow('distinct operator pins');
    expect(preflightDatabase).not.toHaveBeenCalled();
  });

  it('rechecks distinct operator pins at the final Harmony pair gate', async () => {
    const preflightDatabase = vi.fn(async () => {});
    const adapter = strictHarmonyPair({ preflightDatabase });
    (adapter as any).config.pinnedQueryOperatorPubkey = OPERATOR_PIN_0.slice();
    (adapter as any).legOwners[1].configSignature = (adapter as any).legConfigSignature(1);

    await expect(adapter.prepareStrictAdmission(0)).rejects.toThrow('distinct operator pins');
    expect(preflightDatabase).not.toHaveBeenCalled();
  });

  it('allows first-leg Harmony policy display but blocks capability paths before preflight', async () => {
    const policy = { marker: 'signed-policy' } as any;
    const fetchServicePolicy = vi.fn(async () => policy);
    const requestHintPowChallenge = vi.fn(async () => ({ marker: 'challenge' }));
    const adapter = strictHarmonyPair({
      preflightDatabase: vi.fn(async () => {}),
      fetchServicePolicy,
      requestHintPowChallenge,
    });
    const port = adapter.hintServiceAdmissionPort(0);

    await expect(port.fetchPolicy(
      new Uint8Array(32),
      new Uint8Array(32),
      1n,
      new Uint8Array(),
    )).resolves.toBe(policy);
    await expect(adapter.fetchHints()).rejects.toThrow(
      'hint acquisition requires prepared strict admission',
    );
    expect(() => port.requestPowChallenge(
      policy,
      new Uint8Array(32),
      0,
      1n,
    )).toThrow('requires prepared strict admission');

    await adapter.prepareStrictAdmission(0);
    await port.requestPowChallenge(policy, new Uint8Array(32), 0, 1n);
    expect(requestHintPowChallenge).toHaveBeenCalledOnce();
    expect(fetchServicePolicy).toHaveBeenCalledWith(
      0,
      0,
      expect.any(Uint8Array),
      expect.any(Uint8Array),
      1n,
      expect.any(Uint8Array),
    );
  });

  it('makes a failed Harmony pre-authorization preflight fail closed and one-shot', async () => {
    const preflightDatabase = vi.fn(async () => {
      throw new Error('tree-top mismatch');
    });
    const adapter = strictHarmonyPair({ preflightDatabase });

    await expect(adapter.prepareStrictAdmission(0)).rejects.toThrow('tree-tops preflight failed');
    await expect(adapter.prepareStrictAdmission(0)).rejects.toThrow('retry is disabled');
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
  });

  it('does not let an obsolete DPF preflight completion revive a disconnected pair', async () => {
    let releasePreflight!: () => void;
    const preflightDatabase = vi.fn(() => new Promise<void>((resolve) => {
      releasePreflight = resolve;
    }));
    const adapter = strictDpfPair({
      preflightDatabase,
      disconnectServer: vi.fn(async () => {}),
      isServerConnected: vi.fn(() => false),
    });

    const finalization = adapter.prepareStrictAdmission(0);
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(0);
    releasePreflight();

    await expect(finalization).rejects.toThrow('invalidated');
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
  });

  it('does not let an obsolete Harmony preflight completion revive a disconnected pair', async () => {
    let releasePreflight!: () => void;
    const preflightDatabase = vi.fn(() => new Promise<void>((resolve) => {
      releasePreflight = resolve;
    }));
    const adapter = strictHarmonyPair({
      preflightDatabase,
      disconnectProvider: vi.fn(async () => {}),
      isProviderConnected: vi.fn(() => false),
    });

    const finalization = adapter.prepareStrictAdmission(0);
    expect(preflightDatabase).toHaveBeenCalledOnce();
    await adapter.disconnectLeg(1);
    releasePreflight();

    await expect(finalization).rejects.toThrow('invalidated');
    await expect(adapter.queryBatch([])).rejects.toThrow('strict verification is not ready');
    expect(adapter.getDatabaseProofStatus(0)).toBeUndefined();
  });
});
