/**
 * HarmonyPIR Worker Pool
 *
 * Manages a pool of Web Workers, each owning a subset of HarmonyBucket
 * instances. Provides async methods for batch build_request/process_response
 * that distribute work across workers and collect results.
 */

export interface BuildItem {
  bucketId: number;
  binIndex?: number;  // undefined = dummy
}

export interface ProcessItem {
  bucketId: number;
  response: Uint8Array;
}

export class HarmonyWorkerPool {
  private workers: Worker[] = [];
  private numWorkers: number;
  private pendingRequests = new Map<number, (data: any) => void>();
  private requestId = 0;
  private readyCounts = 0;

  constructor(numWorkers?: number) {
    this.numWorkers = numWorkers ?? Math.min(navigator.hardwareConcurrency || 4, 4);
  }

  /** Get which worker owns a given bucketId. */
  private ownerOf(bucketId: number): number {
    return bucketId % this.numWorkers;
  }

  /** Initialize workers: load WASM in each. Returns when all are ready. */
  async init(wasmJsUrl: string, wasmBinaryUrl: string): Promise<void> {
    // Create a blob URL for the worker script.
    // We use inline worker code that imports the actual worker module.
    // But since our worker is a standalone TS file compiled by Vite,
    // we need to create workers from a URL.
    //
    // For Vite: use `new Worker(new URL(...), { type: 'module' })` pattern.
    // For compatibility: use inline blob worker that loads the compiled JS.

    const workerCode = await this.fetchWorkerCode();
    const blob = new Blob([workerCode], { type: 'application/javascript' });
    const workerUrl = URL.createObjectURL(blob);

    const readyPromises: Promise<void>[] = [];

    for (let i = 0; i < this.numWorkers; i++) {
      const worker = new Worker(workerUrl);
      this.workers.push(worker);

      worker.onmessage = (ev) => this.handleMessage(i, ev.data);
      worker.onerror = (ev) => console.error(`Worker ${i} error:`, ev);

      readyPromises.push(new Promise<void>((resolve, reject) => {
        const handler = (ev: MessageEvent) => {
          if (ev.data.type === 'ready') {
            worker.removeEventListener('message', handler);
            resolve();
          } else if (ev.data.type === 'error') {
            worker.removeEventListener('message', handler);
            reject(new Error(ev.data.error));
          }
        };
        worker.addEventListener('message', handler);
      }));

      worker.postMessage({ type: 'init', wasmJsUrl, wasmBinaryUrl });
    }

    await Promise.all(readyPromises);
    URL.revokeObjectURL(workerUrl);
  }

  /** Create a bucket on the appropriate worker. */
  async createBucket(
    bucketId: number, n: number, w: number, t: number,
    prpKey: Uint8Array, backend: number,
  ): Promise<void> {
    const workerId = this.ownerOf(bucketId);
    return new Promise((resolve, reject) => {
      const handler = (ev: MessageEvent) => {
        if (ev.data.type === 'bucketCreated' && ev.data.bucketId === bucketId) {
          this.workers[workerId].removeEventListener('message', handler);
          resolve();
        } else if (ev.data.type === 'error') {
          this.workers[workerId].removeEventListener('message', handler);
          reject(new Error(ev.data.error));
        }
      };
      this.workers[workerId].addEventListener('message', handler);
      this.workers[workerId].postMessage({
        type: 'createBucket', bucketId, n, w, t, prpKey, backend,
      });
    });
  }

  /** Load hints for a bucket on its owning worker. */
  loadHints(bucketId: number, hints: Uint8Array): void {
    const workerId = this.ownerOf(bucketId);
    // Transfer the hints buffer to avoid copy.
    const copy = new Uint8Array(hints);
    this.workers[workerId].postMessage(
      { type: 'loadHints', bucketId, hints: copy },
      [copy.buffer],
    );
  }

  /**
   * Build requests for a batch of buckets in parallel across workers.
   * Returns a map of bucketId → request bytes.
   */
  async buildBatchRequests(items: BuildItem[]): Promise<Map<number, Uint8Array>> {
    // Group items by owning worker.
    const byWorker = new Map<number, BuildItem[]>();
    for (const item of items) {
      const w = this.ownerOf(item.bucketId);
      if (!byWorker.has(w)) byWorker.set(w, []);
      byWorker.get(w)!.push(item);
    }

    // Send to each worker in parallel, collect results.
    const allResults = new Map<number, Uint8Array>();
    const promises: Promise<void>[] = [];

    for (const [workerId, workerItems] of byWorker) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, (data) => {
          for (const r of data.results) {
            allResults.set(r.bucketId, r.bytes);
          }
          resolve();
        });
      }));

      this.workers[workerId].postMessage({
        type: 'buildBatch',
        requestId: reqId,
        items: workerItems,
      });
    }

    await Promise.all(promises);
    return allResults;
  }

  /**
   * Process responses for a batch of buckets in parallel across workers.
   * Returns a map of bucketId → answer bytes.
   */
  async processBatchResponses(items: ProcessItem[]): Promise<Map<number, Uint8Array>> {
    // Group by owning worker.
    const byWorker = new Map<number, ProcessItem[]>();
    for (const item of items) {
      const w = this.ownerOf(item.bucketId);
      if (!byWorker.has(w)) byWorker.set(w, []);
      byWorker.get(w)!.push(item);
    }

    const allResults = new Map<number, Uint8Array>();
    const promises: Promise<void>[] = [];

    for (const [workerId, workerItems] of byWorker) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, (data) => {
          for (const r of data.results) {
            allResults.set(r.bucketId, r.answer);
          }
          resolve();
        });
      }));

      // Transfer response buffers to worker.
      const transferables = workerItems
        .map(item => item.response.buffer)
        .filter((buf, i, arr) => arr.indexOf(buf) === i); // dedupe

      this.workers[workerId].postMessage(
        { type: 'processBatch', requestId: reqId, items: workerItems },
        transferables,
      );
    }

    await Promise.all(promises);
    return allResults;
  }

  /** Terminate all workers. */
  terminate(): void {
    for (const w of this.workers) {
      w.terminate();
    }
    this.workers = [];
    this.pendingRequests.clear();
  }

  get size(): number {
    return this.numWorkers;
  }

  // ─── Internal ──────────────────────────────────────────────────────────────

  private handleMessage(workerId: number, data: any): void {
    if (data.type === 'buildBatchResult' || data.type === 'processBatchResult') {
      const cb = this.pendingRequests.get(data.requestId);
      if (cb) {
        this.pendingRequests.delete(data.requestId);
        cb(data);
      }
    }
  }

  /** Fetch and return the compiled worker JS code. */
  private async fetchWorkerCode(): Promise<string> {
    // The worker TS is compiled alongside the main bundle by Vite.
    // We fetch the compiled JS from the same origin.
    // Try the Vite dev path first, then the production path.
    const paths = [
      '/src/harmonypir_worker.ts',   // Vite dev (serves TS directly)
      '/harmonypir_worker.js',       // Production build
    ];

    for (const path of paths) {
      try {
        const resp = await fetch(path);
        if (resp.ok) {
          return await resp.text();
        }
      } catch { /* try next */ }
    }

    throw new Error('Could not load harmonypir_worker code');
  }
}
