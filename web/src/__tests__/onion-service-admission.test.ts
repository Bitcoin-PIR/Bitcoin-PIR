import { describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  instances: [] as Array<{
    dbId: number;
    exporter: Uint8Array;
    free: ReturnType<typeof vi.fn>;
    verifyPolicySession: ReturnType<typeof vi.fn>;
  }>,
}));

vi.mock('../sdk-bridge.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../sdk-bridge.js')>();
  class StandaloneAdmission {
    readonly dbId: number;
    readonly exporter: Uint8Array;
    readonly free = vi.fn();
    readonly verifyPolicySession = vi.fn();

    constructor(dbId: number, exporter: Uint8Array) {
      this.dbId = dbId;
      this.exporter = exporter.slice();
      mocked.instances.push(this);
    }

    policyRequest() { return new Uint8Array([1, 0, 0, 0, 0x0d]); }
    acceptPolicyResponse() { return { accepted: true }; }
    authorizationRequest() { return new Uint8Array([1, 0, 0, 0, 0x0e]); }
    acceptAuthorizationResponse() { return { granted: true }; }
    powChallengeRequest() { return new Uint8Array([1, 0, 0, 0, 0x0f]); }
    acceptPowChallengeResponse() { return { challenge: true }; }
  }
  return {
    ...actual,
    requireSdkWasm: () => ({
      WasmStandaloneOnionServiceAdmissionV1: StandaloneAdmission,
    }),
  };
});

import { OnionPirWebClient } from '../onionpir_client.js';

function readyClient(sendRaw: ReturnType<typeof vi.fn>) {
  const client = new OnionPirWebClient({
    serverUrl: 'wss://provider.invalid',
    strictVerification: true,
  });
  const internal = client as any;
  internal.ws = { isOpen: () => true, sendRaw };
  internal.strictReady = true;
  internal.secureChannelEstablished = true;
  internal.secureChannel = {
    serviceAuthorizationExporterV1: () => new Uint8Array(32).fill(7),
  };
  internal.databaseProofStatuses.set(3, { state: 'verified', dbId: 3 });
  return client;
}

describe('standalone OnionPIR service admission port', () => {
  it('uses the current verified socket/exporter and releases one-shot WASM state', async () => {
    mocked.instances.length = 0;
    const response = new Uint8Array([1, 0, 0, 0, 0x8d]);
    const sendRaw = vi.fn().mockResolvedValue(response);
    const client = readyClient(sendRaw);

    const accepted = await client.serviceAdmissionPort(3).fetchPolicy(
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      1_700_000_000n,
      new Uint8Array(),
    );

    expect(accepted).toEqual({ accepted: true });
    expect(sendRaw).toHaveBeenCalledOnce();
    expect([...sendRaw.mock.calls[0][0]]).toEqual([1, 0, 0, 0, 0x0d]);
    expect(mocked.instances).toHaveLength(1);
    expect(mocked.instances[0].dbId).toBe(3);
    expect(mocked.instances[0].exporter).toEqual(new Uint8Array(32).fill(7));
    expect(mocked.instances[0].free).toHaveBeenCalledOnce();
  });

  it('fails before network I/O when strict database verification is absent', async () => {
    const sendRaw = vi.fn();
    const client = readyClient(sendRaw);
    (client as any).databaseProofStatuses.clear();

    await expect(client.serviceAdmissionPort(3).authorize(
      {} as any,
      new Uint8Array(32),
      1,
      new Uint8Array(),
    )).rejects.toThrow('verified database proof');
    expect(sendRaw).not.toHaveBeenCalled();
  });

  it('checks the current standalone exporter before capability retirement', () => {
    mocked.instances.length = 0;
    const client = readyClient(vi.fn());
    const policy = { accepted: true } as any;

    client.serviceAdmissionPort(3).assertSessionBinding(policy);

    expect(mocked.instances).toHaveLength(1);
    expect(mocked.instances[0].verifyPolicySession).toHaveBeenCalledWith(policy);
    expect(mocked.instances[0].free).toHaveBeenCalledOnce();
  });

  it('never retries an authorization whose send outcome is unknown', async () => {
    mocked.instances.length = 0;
    const sendRaw = vi.fn().mockRejectedValue(new Error('connection lost after send'));
    const client = readyClient(sendRaw);

    await expect(client.serviceAdmissionPort(3).authorize(
      {} as any,
      new Uint8Array(32).fill(4),
      9,
      new Uint8Array([5]),
    )).rejects.toThrow('connection lost after send');
    expect(sendRaw).toHaveBeenCalledOnce();
    expect(mocked.instances).toHaveLength(1);
    expect(mocked.instances[0].free).toHaveBeenCalledOnce();
  });
});
