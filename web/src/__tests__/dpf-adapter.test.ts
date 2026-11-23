import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BatchPirClientAdapter } from '../dpf-adapter.js';

const mocks = vi.hoisted(() => ({
  wasmConstructor: vi.fn(),
  verifyDatabaseProofs: vi.fn(),
}));

vi.mock('../sdk-bridge.js', () => ({
  initSdkWasm: vi.fn(async () => true),
  isSdkWasmReady: vi.fn(() => true),
  requireSdkWasm: () => ({ WasmDpfClient: mocks.wasmConstructor }),
}));

vi.mock('../verification.js', () => ({
  arkFingerprint: vi.fn(),
  attestPair: vi.fn(),
  gateOperatorIdentity: vi.fn(),
  verifyDatabaseProofs: mocks.verifyDatabaseProofs,
}));

function fakeClient() {
  return {
    isConnected: true,
    connect: vi.fn(async () => {}),
    connectIroh: vi.fn(async () => {}),
    disconnect: vi.fn(async () => {}),
    free: vi.fn(),
    onStateChange: vi.fn(),
    fetchCatalog: vi.fn(async () => ({
      toJson: () => ({ databases: [] }),
      free: vi.fn(),
    })),
  };
}

let client: ReturnType<typeof fakeClient>;

beforeEach(() => {
  vi.clearAllMocks();
  client = fakeClient();
  mocks.wasmConstructor.mockImplementation(() => client);
  mocks.verifyDatabaseProofs.mockResolvedValue(undefined);
});

describe('BatchPirClientAdapter transport selection', () => {
  it('keeps URL WebSocket connect as the default', async () => {
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://server0.example',
      server1Url: 'wss://server1.example',
      useSecureChannel: false,
    });
    await adapter.connect();

    expect(mocks.wasmConstructor).toHaveBeenCalledWith(
      'wss://server0.example',
      'wss://server1.example',
    );
    expect(client.connect).toHaveBeenCalledOnce();
    expect(client.connectIroh).not.toHaveBeenCalled();
  });

  it('passes manual tickets in server order without calling URL connect', async () => {
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://unused0.example',
      server1Url: 'wss://unused1.example',
      irohTickets: ['ticket-zero', 'ticket-one'],
      useSecureChannel: false,
    });
    await adapter.connect();

    expect(mocks.wasmConstructor).toHaveBeenCalledWith('iroh:server0', 'iroh:server1');
    expect(client.connectIroh).toHaveBeenCalledWith('ticket-zero', 'ticket-one');
    expect(client.connect).not.toHaveBeenCalled();
    expect(mocks.verifyDatabaseProofs).toHaveBeenCalledOnce();
  });

  it('uses the existing teardown when Iroh connect fails', async () => {
    client.connectIroh.mockRejectedValueOnce(new Error('relay unavailable'));
    const adapter = new BatchPirClientAdapter({
      server0Url: 'wss://unused0.example',
      server1Url: 'wss://unused1.example',
      irohTickets: ['ticket-zero', 'ticket-one'],
      useSecureChannel: false,
    });

    await expect(adapter.connect()).rejects.toThrow('relay unavailable');
    expect(client.disconnect).toHaveBeenCalledOnce();
    expect(client.free).toHaveBeenCalledOnce();
  });
});
