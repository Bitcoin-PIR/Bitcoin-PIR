/**
 * WebSocket client for Bitcoin PIR system
 * 
 * Handles communication with PIR servers via WebSocket protocol
 */

import { encodeRequest, decodeResponse, Request, Response } from './sbp.js';
import { createDpf } from './dpf.js';
import {
  CUCKOO_NUM_BUCKETS,
  CHUNKS_NUM_ENTRIES,
  TXID_MAPPING_NUM_BUCKETS,
} from './constants.js';

// Re-export Request and Response types
export type { Request, Response } from './sbp.js';

/**
 * PIR client configuration
 */
export interface PirClientConfig {
  server1Url: string;
  server2Url: string;
}

/**
 * PIR WebSocket client
 */
export class PirClient {
  private ws1: WebSocket | null = null;
  private ws2: WebSocket | null = null;
  private config: PirClientConfig;
  private dpf = createDpf();
  private pendingRequests: Map<number, (response: Response) => void> =
    new Map();
  private requestCounter = 0;

  constructor(config: PirClientConfig) {
    this.config = config;
  }

  /**
   * Connect to both servers
   */
  async connect(): Promise<void> {
    console.log(`[DEBUG] Main connect(): Starting parallel connection to both servers`);
    try {
      await Promise.all([
        this.connectToServer(1),
        this.connectToServer(2),
      ]);
      console.log(`[DEBUG] Main connect(): Both connections completed successfully`);
    } catch (error) {
      console.log(`[DEBUG] Main connect(): Connection failed with error:`, error);
      throw error;
    }
  }

  /**
   * Connect to a specific server
   */
  private async connectToServer(serverNum: 1 | 2): Promise<void> {
    const url = serverNum === 1 ? this.config.server1Url : this.config.server2Url;
    console.log(`[DEBUG] [SERVER ${serverNum}] Step 1: Starting connection to ${url}`);
    console.log(`[DEBUG] [SERVER ${serverNum}] Timestamp: ${new Date().toISOString()}`);
    console.log(`[DEBUG] [SERVER ${serverNum}] Browser WebSocket support: ${typeof WebSocket !== 'undefined'}`);
    
    try {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      console.log(`[DEBUG] [SERVER ${serverNum}] Step 2: WebSocket object created successfully`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket readyState: ${ws.readyState} (${['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'][ws.readyState]})`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket URL: ${ws.url}`);
      console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket protocol: ${ws.protocol || 'none'}`);

      return new Promise((resolve, reject) => {
        console.log(`[DEBUG] [SERVER ${serverNum}] Step 3: Creating event handlers`);
        
        ws.onopen = () => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step 5: onopen event fired! Connection successful!`);
          console.log(`[DEBUG] [SERVER ${serverNum}] WebSocket readyState: ${ws.readyState}`);
          if (serverNum === 1) {
            this.ws1 = ws;
          } else {
            this.ws2 = ws;
          }
          console.log(`[DEBUG] [SERVER ${serverNum}] Step 6: Resolving connection promise`);
          resolve();
        };

        ws.onerror = (event: Event) => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step ERROR: onerror fired! Connection failed.`);
          const errorEvent = event as ErrorEvent;
          console.error(`[DEBUG] [SERVER ${serverNum}] Error details:`, {
            type: event.type,
            url: url,
            readyState: ws.readyState,
            readyStateText: ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'][ws.readyState],
            message: errorEvent?.message || 'No message',
            error: errorEvent?.error || 'Unknown error',
            timestamp: new Date().toISOString(),
          });
          console.error(`[DEBUG] [SERVER ${serverNum}] Full error object:`, event);
          reject(new Error(`Failed to connect to server ${serverNum}: ${errorEvent?.message || 'Unknown error'}`));
        };

        ws.onclose = (event: CloseEvent) => {
          console.log(`[DEBUG] [SERVER ${serverNum}] Step CLOSE: onclose fired (connection closed)`);
          console.log(`[DEBUG] [SERVER ${serverNum}] Close code: ${event.code}, reason: ${event.reason || 'none'}, wasClean: ${event.wasClean}`);
          if (serverNum === 1) {
            this.ws1 = null;
          } else {
            this.ws2 = null;
          }
        };

        console.log(`[DEBUG] [SERVER ${serverNum}] Step 4: Event handlers registered, waiting for connection...`);
      });
    } catch (error) {
      console.log(`[DEBUG] [SERVER ${serverNum}] CRITICAL ERROR during WebSocket creation:`, error);
      throw error;
    }
  }

  /**
   * Disconnect from servers
   */
  disconnect(): void {
    this.ws1?.close();
    this.ws2?.close();
    this.ws1 = null;
    this.ws2 = null;
  }

  /**
   * Check if connected to both servers
   */
  isConnected(): boolean {
    return (
      this.ws1 !== null &&
      this.ws2 !== null &&
      this.ws1.readyState === WebSocket.OPEN &&
      this.ws2.readyState === WebSocket.OPEN
    );
  }

  /**
   * Send a request to a specific server
   */
  private async sendRequest(
    serverNum: 1 | 2,
    request: Request,
  ): Promise<Response> {
    const ws = serverNum === 1 ? this.ws1 : this.ws2;

    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Not connected to server ${serverNum}`);
    }

    const requestId = this.requestCounter++;
    const encoded = encodeRequest(request);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error(`Request to server ${serverNum} timed out`));
      }, 30000); // 30 second timeout

      this.pendingRequests.set(requestId, (response: Response) => {
        clearTimeout(timeout);
        resolve(response);
      });

      ws.onmessage = (event) => {
        try {
          const response = decodeResponse(new Uint8Array(event.data));
          const callback = this.pendingRequests.get(requestId);
          if (callback) {
            this.pendingRequests.delete(requestId);
            callback(response);
          }
        } catch (error) {
          console.error('Failed to decode response:', error);
          reject(error);
        }
      };

      ws.send(encoded);
    });
  }

  /**
   * Send ping to both servers
   */
  async ping(): Promise<{ pong1: Response; pong2: Response }> {
    const request: Request = { Ping: {} };
    const [pong1, pong2] = await Promise.all([
      this.sendRequest(1, request),
      this.sendRequest(2, request),
    ]);
    return { pong1, pong2 };
  }

  /**
   * List databases on a server
   */
  async listDatabases(serverNum: 1 | 2): Promise<Response> {
    const request: Request = { ListDatabases: {} };
    return await this.sendRequest(serverNum, request);
  }

  /**
   * Get database info
   */
  async getDatabaseInfo(
    serverNum: 1 | 2,
    databaseId: string,
  ): Promise<Response> {
    const request: Request = { GetDatabaseInfo: { database_id: databaseId } };
    return await this.sendRequest(serverNum, request);
  }

  /**
   * Query a database on both servers
   */
  async queryDatabase(
    databaseId: string,
    index1: number,
    index2: number,
    n: number = 24,
  ): Promise<{ response1: Response; response2: Response }> {
    // Generate DPF keys for both indices (async)
    const keys1 = await this.dpf.genKeys(index1, n);
    const keys2 = await this.dpf.genKeys(index2, n);

    const request: Request = {
      QueryDatabase: {
        database_id: databaseId,
        dpf_key1: keys1.key1,
        dpf_key2: keys1.key2,
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request),
      this.sendRequest(2, request),
    ]);

    return { response1, response2 };
  }

  /**
   * Query a single-location database on both servers
   */
  async queryDatabaseSingle(
    databaseId: string,
    index: number,
    n: number = 24,
  ): Promise<{ response1: Response; response2: Response }> {
    // Generate DPF key for the index (async)
    const key = await this.dpf.genSingleKey(index, n);

    const request: Request = {
      QueryDatabaseSingle: {
        database_id: databaseId,
        dpf_key: key,
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request),
      this.sendRequest(2, request),
    ]);

    return { response1, response2 };
  }

  /**
   * Query the cuckoo database for a script hash
   * Uses proper cuckoo hash functions to compute locations
   */
  async queryCuckooIndex(
    scriptHash: Uint8Array,
    numBuckets: number = CUCKOO_NUM_BUCKETS,
  ): Promise<{ response1: Response; response2: Response; loc1: number; loc2: number }> {
    // Import the cuckoo hash functions
    const { cuckooHash1, cuckooHash2 } = await import('./hash.js');
    
    // Compute cuckoo locations
    const loc1 = cuckooHash1(scriptHash, numBuckets);
    const loc2 = cuckooHash2(scriptHash, numBuckets);
    
    // Compute n (domain size) from numBuckets
    const n = Math.ceil(Math.log2(numBuckets));
    
    // Generate DPF keys for both locations (async)
    const keys1 = await this.dpf.genKeys(loc1, n);
    const keys2 = await this.dpf.genKeys(loc2, n);

    // Create request for both locations
    const request1: Request = {
      QueryDatabase: {
        database_id: 'utxo_cuckoo_index',
        dpf_key1: keys1.key1,
        dpf_key2: keys2.key1,  // Server 1 gets key1 for both locations
      },
    };
    
    const request2: Request = {
      QueryDatabase: {
        database_id: 'utxo_cuckoo_index',
        dpf_key1: keys1.key2,  // Server 2 gets key2 for both locations
        dpf_key2: keys2.key2,
      },
    };

    // Send to both servers
    const [response1, response2] = await Promise.all([
      this.sendRequest(1, request1),
      this.sendRequest(2, request2),
    ]);

    return { response1, response2, loc1, loc2 };
  }

  /**
   * XOR two buffers
   */
  private xorBuffers(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(Math.max(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = (a[i] || 0) ^ (b[i] || 0);
    }
    return result;
  }
}

/**
 * Create a PIR client with default configuration
 */
export function createPirClient(
  server1Url: string = 'ws://localhost:8091',
  server2Url: string = 'ws://localhost:8092',
): PirClient {
  return new PirClient({ server1Url, server2Url });
}