/**
 * Shared WebSocket management for all PIR backends.
 *
 * Provides a managed WebSocket with:
 * - FIFO request/response queue
 * - Pong response filtering (prevents pongs from stealing query callbacks)
 * - Periodic heartbeat pings (30s default)
 * - Request timeout (120s default)
 * - Connection state tracking
 */

export interface ManagedWsConfig {
  url: string;
  label?: string;
  onLog?: (msg: string, level: 'info' | 'success' | 'error') => void;
  onClose?: () => void;
  heartbeatIntervalMs?: number;
  requestTimeoutMs?: number;
}

type PendingCallback = {
  resolve: (data: Uint8Array) => void;
  reject: (err: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
};

/** Standard ping message: [4B len=1 LE][1B variant=0x00] */
const PING_MSG = new Uint8Array([1, 0, 0, 0, 0x00]);

export class ManagedWebSocket {
  private ws: WebSocket | null = null;
  private pending: PendingCallback[] = [];
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private config: Required<Pick<ManagedWsConfig, 'url'>> & ManagedWsConfig;

  private get heartbeatMs() { return this.config.heartbeatIntervalMs ?? 30_000; }
  private get timeoutMs() { return this.config.requestTimeoutMs ?? 120_000; }

  constructor(config: ManagedWsConfig) {
    this.config = config;
  }

  private log(msg: string, level: 'info' | 'success' | 'error' = 'info') {
    this.config.onLog?.(msg, level);
  }

  /** Connect and resolve when the WebSocket is open. */
  connect(): Promise<void> {
    const label = this.config.label ?? this.config.url;
    this.log(`Connecting to ${label}`);

    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(this.config.url);
      ws.binaryType = 'arraybuffer';

      ws.onopen = () => {
        this.ws = ws;
        this.pending = [];
        this.startHeartbeat();
        resolve();
      };

      ws.onerror = () => {
        reject(new Error(`Failed to connect to ${label}`));
      };

      ws.onmessage = (event) => {
        const data = new Uint8Array(event.data as ArrayBuffer);

        // Filter pong responses: [4B len LE][1B variant]
        // Pong: len=1, variant=0x00
        if (data.length >= 5) {
          const len = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
          if (len === 1 && data[4] === 0x00) {
            return; // Silently discard pong
          }
        }

        const cb = this.pending.shift();
        if (cb) {
          clearTimeout(cb.timeout);
          cb.resolve(data);
        }
      };

      ws.onclose = () => {
        this.ws = null;
        this.stopHeartbeat();
        this.config.onClose?.();
      };
    });
  }

  /** Send raw bytes and wait for the next response (FIFO). */
  sendRaw(msg: Uint8Array): Promise<Uint8Array> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Not connected (${this.config.label ?? this.config.url})`);
    }

    return new Promise<Uint8Array>((resolve, reject) => {
      const timeout = setTimeout(() => {
        const idx = this.pending.findIndex(p => p.resolve === resolve);
        if (idx !== -1) this.pending.splice(idx, 1);
        reject(new Error(`Request timed out (${this.config.label ?? this.config.url})`));
      }, this.timeoutMs);

      this.pending.push({ resolve, reject, timeout });
      this.ws!.send(msg);
    });
  }

  /** Check if the WebSocket is open. */
  isOpen(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  /** Gracefully close the connection. */
  disconnect(): void {
    this.stopHeartbeat();
    // Reject all pending
    for (const cb of this.pending) {
      clearTimeout(cb.timeout);
      cb.reject(new Error('Disconnected'));
    }
    this.pending = [];
    this.ws?.close();
    this.ws = null;
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(PING_MSG);
      }
    }, this.heartbeatMs);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}
