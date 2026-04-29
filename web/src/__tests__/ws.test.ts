import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ManagedWebSocket } from '../ws.js';

// ─── Mock WebSocket ──────────────────────────────────────────────────────────

class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: MockWebSocket[] = [];

  binaryType = '';
  readyState = MockWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onerror: ((e: any) => void) | null = null;
  onmessage: ((e: { data: ArrayBuffer }) => void) | null = null;
  onclose: (() => void) | null = null;

  sent: Uint8Array[] = [];

  constructor(_url: string) {
    MockWebSocket.instances.push(this);
    // Auto-open after microtask
    queueMicrotask(() => this.onopen?.());
  }

  send(data: Uint8Array) {
    this.sent.push(new Uint8Array(data));
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.();
  }

  /** Simulate receiving a message from the server */
  receiveMessage(data: Uint8Array) {
    // `Uint8Array.buffer` is typed `ArrayBuffer | SharedArrayBuffer` in
    // newer DOM types, but `.slice()` over a fresh `Uint8Array` constructed
    // from `new Uint8Array([...])` always backs onto a plain `ArrayBuffer`.
    // Narrow with a cast — the runtime invariant is preserved by the
    // construction sites of the test fixtures (`new Uint8Array([…])` and
    // `new Uint8Array(N)`).
    const buffer = data.buffer.slice(
      data.byteOffset,
      data.byteOffset + data.byteLength,
    ) as ArrayBuffer;
    this.onmessage?.({ data: buffer });
  }

  /** Simulate receiving a pong response */
  receivePong() {
    // Pong: [len=1 LE][variant=0x00]
    this.receiveMessage(new Uint8Array([1, 0, 0, 0, 0x00]));
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  vi.stubGlobal('WebSocket', MockWebSocket);
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

// ─── Tests ───────────────────────────────────────────────────────────────────

describe('ManagedWebSocket', () => {
  it('connects successfully', async () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    await ws.connect();
    expect(ws.isOpen()).toBe(true);
    ws.disconnect();
  });

  it('sends and receives in FIFO order', async () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    await ws.connect();
    const mock = MockWebSocket.instances[0];

    // Send two requests
    const p1 = ws.sendRaw(new Uint8Array([1]));
    const p2 = ws.sendRaw(new Uint8Array([2]));

    // Reply to first, then second
    const resp1 = new Uint8Array([5, 0, 0, 0, 0x01, 0xAA]);
    const resp2 = new Uint8Array([5, 0, 0, 0, 0x01, 0xBB]);
    mock.receiveMessage(resp1);
    mock.receiveMessage(resp2);

    expect(await p1).toEqual(resp1);
    expect(await p2).toEqual(resp2);

    ws.disconnect();
  });

  it('filters pong responses', async () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    await ws.connect();
    const mock = MockWebSocket.instances[0];

    const p1 = ws.sendRaw(new Uint8Array([1]));

    // Send pong (should be filtered)
    mock.receivePong();

    // Send real response (should resolve p1)
    const realResp = new Uint8Array([5, 0, 0, 0, 0x01, 0xFF]);
    mock.receiveMessage(realResp);

    expect(await p1).toEqual(realResp);
    ws.disconnect();
  });

  it('times out after configured duration', async () => {
    const ws = new ManagedWebSocket({
      url: 'ws://test',
      requestTimeoutMs: 1000,
    });
    await ws.connect();

    const p = ws.sendRaw(new Uint8Array([1]));

    // Advance past timeout
    vi.advanceTimersByTime(1001);

    await expect(p).rejects.toThrow('timed out');
    ws.disconnect();
  });

  it('sends heartbeat pings at configured interval', async () => {
    const ws = new ManagedWebSocket({
      url: 'ws://test',
      heartbeatIntervalMs: 5000,
    });
    await ws.connect();
    const mock = MockWebSocket.instances[0];

    expect(mock.sent.length).toBe(0);

    vi.advanceTimersByTime(5000);
    expect(mock.sent.length).toBe(1);
    // Verify it's a ping: [1,0,0,0, 0x00]
    expect(mock.sent[0]).toEqual(new Uint8Array([1, 0, 0, 0, 0x00]));

    vi.advanceTimersByTime(5000);
    expect(mock.sent.length).toBe(2);

    ws.disconnect();
  });

  it('rejects pending on disconnect', async () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    await ws.connect();

    const p = ws.sendRaw(new Uint8Array([1]));
    ws.disconnect();

    await expect(p).rejects.toThrow('Disconnected');
  });

  it('throws when sending on closed socket', async () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    await ws.connect();
    ws.disconnect();

    expect(() => ws.sendRaw(new Uint8Array([1]))).toThrow('Not connected');
  });

  it('calls onClose callback', async () => {
    const onClose = vi.fn();
    const ws = new ManagedWebSocket({ url: 'ws://test', onClose });
    await ws.connect();
    const mock = MockWebSocket.instances[0];

    mock.close(); // simulate server-initiated close

    expect(onClose).toHaveBeenCalledOnce();
  });

  it('isOpen returns false before connect', () => {
    const ws = new ManagedWebSocket({ url: 'ws://test' });
    expect(ws.isOpen()).toBe(false);
  });
});
