import { describe, expect, it, vi } from 'vitest';

import type { DatabaseProofPin } from '../db-proof.js';
import type { WasmDatabaseProof } from '../sdk-bridge.js';
import {
  assertStrictDatabasePinCoverage,
  assertStrictTransportReady,
  collectStrictTransportFailures,
  verifyInstallAndPreflightDatabaseProofs,
  type StrictDatabaseProofClient,
  type StrictTransportOptions,
} from '../strict-verification.js';

const PIN: DatabaseProofPin = {
  dbId: 0,
  buildKind: 'snapshot',
  fromHeight: 100,
  height: 100,
  fromBlockHashHex: '11'.repeat(32),
  blockHashHex: '22'.repeat(32),
  muhashHex: '33'.repeat(32),
  bucketSuperRootHex: '44'.repeat(32),
  onionSuperRootHex: '55'.repeat(32),
  paramsHashHex: '66'.repeat(32),
  networkMagicHex: 'f9beb4d9',
  builderBinarySha256Hex: '77'.repeat(32),
  builderGitCommit: 'deadbeef',
};

type TrackedProof = WasmDatabaseProof & { freeMock: ReturnType<typeof vi.fn> };

function proofHandle(pin: DatabaseProofPin, overrides: Partial<WasmDatabaseProof> = {}): TrackedProof {
  const freeMock = vi.fn();
  return {
    dbId: pin.dbId,
    buildKind: pin.buildKind,
    fromHeight: pin.fromHeight,
    fromBlockHashHex: pin.fromBlockHashHex,
    height: pin.height,
    blockHashHex: pin.blockHashHex,
    muhashHex: pin.muhashHex,
    bucketSuperRootHex: pin.bucketSuperRootHex,
    onionSuperRootHex: pin.onionSuperRootHex,
    paramsHashHex: pin.paramsHashHex,
    networkMagicHex: pin.networkMagicHex,
    builderBinarySha256Hex: pin.builderBinarySha256Hex,
    builderGitCommit: pin.builderGitCommit,
    onionEntrySize: pin.onionEntrySize ?? 3_328,
    toJson: () => ({}),
    free: freeMock,
    freeMock,
    ...overrides,
  };
}

describe('strict database proof flow', () => {
  it('requires an exact one-to-one pin set for the authenticated catalog', () => {
    const pin1 = { ...PIN, dbId: 1 };
    expect(() => assertStrictDatabasePinCoverage([0, 1], [PIN, pin1])).not.toThrow();
    expect(() => assertStrictDatabasePinCoverage([0, 1], [PIN]))
      .toThrow('missing pins for db 1');
    expect(() => assertStrictDatabasePinCoverage([0], [PIN, pin1]))
      .toThrow('pins for unknown db 1');
    expect(() => assertStrictDatabasePinCoverage([0, 0], [PIN]))
      .toThrow('duplicate db ids: 0');
    expect(() => assertStrictDatabasePinCoverage([0], [PIN, { ...PIN }]))
      .toThrow('pins contain duplicate db ids: 0');
  });

  it('transfers each exact handle, installs all roots before preflight, and never frees success', async () => {
    const pin1 = { ...PIN, dbId: 1, blockHashHex: '88'.repeat(32) };
    const handle0 = proofHandle(PIN);
    const handle1 = proofHandle(pin1);
    const handles = new Map([
      [0, handle0],
      [1, handle1],
    ]);
    const installed: WasmDatabaseProof[] = [];
    const order: string[] = [];
    const statuses: string[] = [];
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async (dbId) => {
        order.push(`verify:${dbId}`);
        return handles.get(dbId)!;
      }),
      installVerifiedDatabaseProof: vi.fn((handle) => {
        order.push(`install:${handle.dbId}`);
        installed.push(handle);
      }),
      preflightDatabase: vi.fn(async (dbId) => {
        order.push(`preflight:${dbId}`);
      }),
    };

    const result = await verifyInstallAndPreflightDatabaseProofs({
      client,
      pins: [PIN, pin1],
      onStatus: (dbId, status) => {
        order.push(`status:${dbId}:${status.state}`);
        statuses.push(status.state);
      },
    });

    expect(installed[0]).toBe(handle0);
    expect(installed[1]).toBe(handle1);
    expect(handle0.freeMock).not.toHaveBeenCalled();
    expect(handle1.freeMock).not.toHaveBeenCalled();
    expect(statuses).toEqual(['verified', 'verified']);
    expect(result.map((status) => status.dbId)).toEqual([0, 1]);
    expect(order).toEqual([
      'verify:0',
      'install:0',
      'verify:1',
      'install:1',
      'preflight:0',
      'status:0:verified',
      'preflight:1',
      'status:1:verified',
    ]);
    expect(client.verifyDatabaseProof).toHaveBeenNthCalledWith(
      1,
      PIN.dbId,
      PIN.paramsHashHex,
      PIN.builderBinarySha256Hex,
      PIN.builderGitCommit,
    );
  });

  it('rejects an empty strict pin set', async () => {
    const client = {
      verifyDatabaseProof: vi.fn(),
      installVerifiedDatabaseProof: vi.fn(),
      preflightDatabase: vi.fn(),
    } as unknown as StrictDatabaseProofClient;

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [] }),
    ).rejects.toThrow('requires at least one pinned database proof');
    expect(client.verifyDatabaseProof).not.toHaveBeenCalled();
  });

  it('frees an unconsumed handle and reports a full-field pin mismatch', async () => {
    const handle = proofHandle(PIN, { muhashHex: 'aa'.repeat(32) });
    const install = vi.fn();
    const preflight = vi.fn();
    const onStatus = vi.fn();
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => handle),
      installVerifiedDatabaseProof: install,
      preflightDatabase: preflight,
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN], onStatus }),
    ).rejects.toThrow(/pin mismatch.*muhashHex/i);

    expect(handle.freeMock).toHaveBeenCalledOnce();
    expect(install).not.toHaveBeenCalled();
    expect(preflight).not.toHaveBeenCalled();
    expect(onStatus).toHaveBeenCalledWith(
      0,
      expect.objectContaining({ state: 'unverified', mismatches: [expect.stringContaining('muhashHex')] }),
    );
  });

  it.each([
    ['dbId', 9],
    ['buildKind', 'delta'],
    ['fromHeight', 99],
    ['height', 101],
    ['fromBlockHashHex', 'aa'.repeat(32)],
    ['blockHashHex', 'aa'.repeat(32)],
    ['muhashHex', 'aa'.repeat(32)],
    ['bucketSuperRootHex', 'aa'.repeat(32)],
    ['onionSuperRootHex', 'aa'.repeat(32)],
    ['paramsHashHex', 'aa'.repeat(32)],
    ['networkMagicHex', '0b110907'],
    ['builderBinarySha256Hex', 'aa'.repeat(32)],
    ['builderGitCommit', 'badc0de'],
  ] as const)('rejects a mismatch in production-pin field %s', async (field, value) => {
    const handle = proofHandle(PIN, { [field]: value });
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => handle),
      installVerifiedDatabaseProof: vi.fn(),
      preflightDatabase: vi.fn(),
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN] }),
    ).rejects.toThrow(new RegExp(field));
    expect(handle.freeMock).toHaveBeenCalledOnce();
    expect(client.installVerifiedDatabaseProof).not.toHaveBeenCalled();
  });

  it('frees the handle if reading the WASM proof summary throws', async () => {
    const handle = proofHandle(PIN);
    Object.defineProperty(handle, 'muhashHex', {
      get: () => { throw new Error('destroyed proof getter'); },
    });
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => handle),
      installVerifiedDatabaseProof: vi.fn(),
      preflightDatabase: vi.fn(),
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN] }),
    ).rejects.toThrow('destroyed proof getter');
    expect(handle.freeMock).toHaveBeenCalledOnce();
  });

  it('reports and throws a Rust/WASM proof verification failure', async () => {
    const onStatus = vi.fn();
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => {
        throw new Error('bad builder signature');
      }),
      installVerifiedDatabaseProof: vi.fn(),
      preflightDatabase: vi.fn(),
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN], onStatus }),
    ).rejects.toThrow('bad builder signature');
    expect(onStatus).toHaveBeenCalledWith(
      0,
      expect.objectContaining({ state: 'unverified', error: 'bad builder signature' }),
    );
    expect(client.installVerifiedDatabaseProof).not.toHaveBeenCalled();
  });

  it('reports install failure and treats the handed-off handle as consumed', async () => {
    const handle = proofHandle(PIN);
    const onStatus = vi.fn();
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => handle),
      installVerifiedDatabaseProof: vi.fn(() => {
        throw new Error('native root rejected');
      }),
      preflightDatabase: vi.fn(),
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN], onStatus }),
    ).rejects.toThrow('native root rejected');
    expect(handle.freeMock).not.toHaveBeenCalled();
    expect(onStatus).toHaveBeenCalledWith(
      0,
      expect.objectContaining({ state: 'unverified', error: 'install failed: native root rejected' }),
    );
    expect(client.preflightDatabase).not.toHaveBeenCalled();
  });

  it('reports and throws a tree-tops preflight failure after installation', async () => {
    const handle = proofHandle(PIN);
    const onStatus = vi.fn();
    const client: StrictDatabaseProofClient = {
      verifyDatabaseProof: vi.fn(async () => handle),
      installVerifiedDatabaseProof: vi.fn(),
      preflightDatabase: vi.fn(async () => {
        throw new Error('bucket super-root mismatch');
      }),
    };

    await expect(
      verifyInstallAndPreflightDatabaseProofs({ client, pins: [PIN], onStatus }),
    ).rejects.toThrow('bucket super-root mismatch');
    expect(client.installVerifiedDatabaseProof).toHaveBeenCalledWith(handle);
    expect(handle.freeMock).not.toHaveBeenCalled();
    expect(onStatus).toHaveBeenCalledWith(
      0,
      expect.objectContaining({
        state: 'unverified',
        error: 'preflight failed: bucket super-root mismatch',
      }),
    );
  });
});

const STRICT_TRANSPORT_OK: StrictTransportOptions = {
  secureChannelEstablished: true,
  attestations: [
    { state: 'verified', sevStatus: 'noSevHost', pinStatus: 'match' },
    { state: 'verified-vcek', sevStatus: 'reportDataMatch', pinStatus: 'match' },
  ],
  expectedPins: [
    { binarySha256Hex: '11'.repeat(32) },
    { measurementHex: '22'.repeat(48), binarySha256Hex: '33'.repeat(32) },
  ],
  expectedServerIds: ['pir1', 'pir2'],
  requireOperatorIdentity: true,
  operatorIdentities: [
    { state: 'verified', serverId: 'pir1', binarySha256Hex: '11'.repeat(32) },
    { state: 'verified', serverId: 'pir2', binarySha256Hex: '33'.repeat(32) },
  ],
};

describe('strict transport gate', () => {
  it('accepts a binary-pinned Hetzner no-SEV server plus VCEK-verified VPSBG SEV-SNP', () => {
    expect(collectStrictTransportFailures(STRICT_TRANSPORT_OK)).toEqual([]);
    expect(() => assertStrictTransportReady(STRICT_TRANSPORT_OK)).not.toThrow();
  });

  it.each([
    [
      'missing secure channel',
      { ...STRICT_TRANSPORT_OK, secureChannelEstablished: false },
      'secure-channel upgrade did not complete',
    ],
    [
      'pin mismatch',
      {
        ...STRICT_TRANSPORT_OK,
        attestations: [
          { state: 'mismatch', sevStatus: 'noSevHost', pinStatus: 'binary-mismatch' },
          STRICT_TRANSPORT_OK.attestations[1],
        ],
      },
      'server 0: attestation pin status is binary-mismatch, expected match',
    ],
    [
      'measurement without VCEK validation',
      {
        ...STRICT_TRANSPORT_OK,
        attestations: [
          STRICT_TRANSPORT_OK.attestations[0],
          { state: 'verified', sevStatus: 'reportDataMatch', pinStatus: 'match' },
        ],
      },
      'server 1: a measurement pin requires verified-vcek attestation',
    ],
    [
      'no-SEV host without binary pin',
      {
        ...STRICT_TRANSPORT_OK,
        expectedPins: [{}, STRICT_TRANSPORT_OK.expectedPins[1]],
      },
      'server 0: no attestation pin is configured',
    ],
    [
      'operator identity failure',
      {
        ...STRICT_TRANSPORT_OK,
        operatorIdentities: [{ state: 'unverified' }, { state: 'verified' }],
      },
      'server 0: operator identity is unverified, expected verified',
    ],
  ])('rejects %s', (_name, options, expectedFailure) => {
    const failures = collectStrictTransportFailures(options as StrictTransportOptions);
    expect(failures).toContain(expectedFailure);
    expect(() => assertStrictTransportReady(options as StrictTransportOptions)).toThrow(
      expectedFailure,
    );
  });

  it('requires both configured pins and both verified operator identities', () => {
    const failures = collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      expectedPins: [undefined, STRICT_TRANSPORT_OK.expectedPins[1]],
      operatorIdentities: undefined,
    });

    expect(failures).toContain('server 0: no attestation pin is configured');
    expect(failures).toContain('server 0: operator identity is missing, expected verified');
    expect(failures).toContain('server 1: operator identity is missing, expected verified');
  });

  it('rejects two verified endpoints that both identify as pir2', () => {
    const failures = collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      operatorIdentities: [
        { state: 'verified', serverId: 'pir2', binarySha256Hex: '11'.repeat(32) },
        { state: 'verified', serverId: 'pir2', binarySha256Hex: '33'.repeat(32) },
      ],
    });

    expect(failures).toContain('server 0: operator server id is pir2, expected pir1');
    expect(() => assertStrictTransportReady({
      ...STRICT_TRANSPORT_OK,
      operatorIdentities: [
        { state: 'verified', serverId: 'pir2', binarySha256Hex: '11'.repeat(32) },
        { state: 'verified', serverId: 'pir2', binarySha256Hex: '33'.repeat(32) },
      ],
    })).toThrow('server 0: operator server id is pir2, expected pir1');
  });

  it('requires a verified operator identity for no-SEV even when the flag is false', () => {
    const failures = collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      requireOperatorIdentity: false,
      operatorIdentities: [
        { state: 'not-checked' },
        { state: 'not-checked' },
      ],
    });

    expect(failures).toContain(
      'server 0: operator identity is not-checked, expected verified',
    );
    expect(failures).not.toContain(
      'server 1: operator identity is not-checked, expected verified',
    );
  });

  it('binds a no-SEV operator manifest binary to the production binary pin', () => {
    const failures = collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      operatorIdentities: [
        { state: 'verified', serverId: 'pir1', binarySha256Hex: 'ff'.repeat(32) },
        STRICT_TRANSPORT_OK.operatorIdentities![1],
      ],
    });

    expect(failures).toContain(
      'server 0: operator binary sha256 does not match the configured binary pin',
    );
  });

  it('requires two distinct configured endpoint identities', () => {
    expect(collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      expectedServerIds: ['pir2', 'pir2'],
    })).toContain('expected server ids must be distinct, both endpoints are configured as pir2');

    expect(collectStrictTransportFailures({
      ...STRICT_TRANSPORT_OK,
      expectedServerIds: [undefined, 'pir2'],
    })).toContain('server 0: no expected server id is configured');
  });
});
