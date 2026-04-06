/**
 * HarmonyPIR Worker Pool
 *
 * Manages a pool of Web Workers, each owning a subset of HarmonyGroup
 * instances. Provides async methods for batch build_request/process_response
 * that distribute work across workers and collect results.
 */

export interface BuildItem {
  groupId: number;
  binIndex?: number;  // undefined = dummy
}

export interface BuildResult {
  bytes: Uint8Array;
  segment?: number;   // PRP segment (undefined for dummies)
  position?: number;  // Position within segment (undefined for dummies)
}

export interface ProcessItem {
  groupId: number;
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

  /** Get which worker owns a given groupId. */
  private ownerOf(groupId: number): number {
    return groupId % this.numWorkers;
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

    const workerCode = this.getWorkerCode();
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

  /** Create a group on the appropriate worker. */
  async createGroup(
    groupId: number, n: number, w: number, t: number,
    prpKey: Uint8Array, backend: number,
  ): Promise<void> {
    const workerId = this.ownerOf(groupId);
    return new Promise((resolve, reject) => {
      const handler = (ev: MessageEvent) => {
        if (ev.data.type === 'groupCreated' && ev.data.groupId === groupId) {
          this.workers[workerId].removeEventListener('message', handler);
          resolve();
        } else if (ev.data.type === 'error') {
          this.workers[workerId].removeEventListener('message', handler);
          reject(new Error(ev.data.error));
        }
      };
      this.workers[workerId].addEventListener('message', handler);
      this.workers[workerId].postMessage({
        type: 'createGroup', groupId, n, w, t, prpKey, backend,
      });
    });
  }

  /** Load hints for a group on its owning worker. */
  loadHints(groupId: number, hints: Uint8Array): void {
    const workerId = this.ownerOf(groupId);
    // Transfer the hints buffer to avoid copy.
    const copy = new Uint8Array(hints);
    this.workers[workerId].postMessage(
      { type: 'loadHints', groupId, hints: copy },
      [copy.buffer],
    );
  }

  /**
   * Build requests for a batch of groups in parallel across workers.
   * Returns a map of groupId -> request bytes.
   */
  async buildBatchRequests(items: BuildItem[]): Promise<Map<number, BuildResult>> {
    // Group items by owning worker.
    const byWorker = new Map<number, BuildItem[]>();
    for (const item of items) {
      const w = this.ownerOf(item.groupId);
      if (!byWorker.has(w)) byWorker.set(w, []);
      byWorker.get(w)!.push(item);
    }

    // Send to each worker in parallel, collect results.
    const allResults = new Map<number, BuildResult>();
    const promises: Promise<void>[] = [];

    for (const [workerId, workerItems] of byWorker) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, (data) => {
          for (const r of data.results) {
            allResults.set(r.groupId, {
              bytes: r.bytes,
              segment: r.segment,
              position: r.position,
            });
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
   * Process responses for a batch of groups in parallel across workers.
   * Returns a map of groupId -> answer bytes.
   */
  async processBatchResponses(items: ProcessItem[]): Promise<Map<number, Uint8Array>> {
    // Group by owning worker.
    const byWorker = new Map<number, ProcessItem[]>();
    for (const item of items) {
      const w = this.ownerOf(item.groupId);
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
            allResults.set(r.groupId, r.answer);
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

  /**
   * Complete deferred relocation for groups that had process_response_xor_only called.
   * Must be called before the next query on these groups.
   */
  async finishRelocation(groupIds: number[]): Promise<void> {
    // Group by owning worker.
    const byWorker = new Map<number, number[]>();
    for (const id of groupIds) {
      const w = this.ownerOf(id);
      if (!byWorker.has(w)) byWorker.set(w, []);
      byWorker.get(w)!.push(id);
    }

    const promises: Promise<void>[] = [];
    for (const [workerId, ids] of byWorker) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, () => resolve());
      }));
      this.workers[workerId].postMessage({
        type: 'finishRelocation',
        requestId: reqId,
        groupIds: ids,
      });
    }
    await Promise.all(promises);
  }

  /**
   * Serialize all group state from all workers.
   * Returns a map of groupId -> serialized bytes.
   */
  async serializeAll(): Promise<Map<number, Uint8Array>> {
    const allResults = new Map<number, Uint8Array>();
    const promises: Promise<void>[] = [];

    for (let i = 0; i < this.numWorkers; i++) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, (data) => {
          for (const r of data.results) {
            allResults.set(r.groupId, r.data);
          }
          resolve();
        });
      }));
      this.workers[i].postMessage({ type: 'serializeAll', requestId: reqId });
    }

    await Promise.all(promises);
    return allResults;
  }

  /**
   * Deserialize group state into workers from a map of groupId -> serialized bytes.
   */
  async deserializeAll(groups: Map<number, Uint8Array>, prpKey: Uint8Array): Promise<void> {
    const promises: Promise<void>[] = [];
    for (const [groupId, data] of groups) {
      const workerId = this.ownerOf(groupId);
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve, reject) => {
        this.pendingRequests.set(reqId, (resp) => {
          if (resp.error) reject(new Error(resp.error));
          else resolve();
        });
      }));
      // Copy data for transfer.
      const copy = new Uint8Array(data);
      const keyCopy = new Uint8Array(prpKey);
      this.workers[workerId].postMessage(
        { type: 'deserializeGroup', requestId: reqId, groupId, data: copy, prpKey: keyCopy },
        [copy.buffer],
      );
    }
    await Promise.all(promises);
  }

  /**
   * Get the minimum queries_remaining across all groups in all workers.
   */
  async getMinQueriesRemaining(): Promise<number> {
    let globalMin = Infinity;
    const promises: Promise<void>[] = [];

    for (let i = 0; i < this.numWorkers; i++) {
      const reqId = this.requestId++;
      promises.push(new Promise<void>((resolve) => {
        this.pendingRequests.set(reqId, (data) => {
          if (data.minRemaining < globalMin) globalMin = data.minRemaining;
          resolve();
        });
      }));
      this.workers[i].postMessage({ type: 'queryRemaining', requestId: reqId });
    }

    await Promise.all(promises);
    return globalMin === Infinity ? 0 : globalMin;
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
    if (data.type === 'buildBatchResult' || data.type === 'processBatchResult'
        || data.type === 'relocationDone' || data.type === 'serializeResult'
        || data.type === 'groupDeserialized' || data.type === 'queryRemainingResult') {
      const cb = this.pendingRequests.get(data.requestId);
      if (cb) {
        this.pendingRequests.delete(data.requestId);
        cb(data);
      }
    }
  }

  /** Return the worker JS code as an inline string. */
  private getWorkerCode(): string {
    // Inlined JS (no TypeScript) to avoid fetch/compile issues.
    // This must stay in sync with harmonypir_worker.ts.
    return `
'use strict';
const groups = new Map();
let wasm = null;

self.onmessage = async (ev) => {
  const msg = ev.data;
  switch (msg.type) {
    case 'init': {
      try {
        const resp = await fetch(msg.wasmJsUrl);
        if (!resp.ok) throw new Error('Fetch failed: ' + resp.status);
        let jsText = await resp.text();
        if (jsText.startsWith('let wasm_bindgen')) {
          jsText = 'var wasm_bindgen' + jsText.slice('let wasm_bindgen'.length);
        }
        (0, eval)(jsText);
        const wb = self.wasm_bindgen;
        if (!wb) throw new Error('wasm_bindgen not defined after eval');
        await wb(msg.wasmBinaryUrl);
        wasm = wb;
        self.postMessage({ type: 'ready' });
      } catch (e) {
        self.postMessage({ type: 'error', error: e.message });
      }
      break;
    }
    case 'createGroup': {
      if (!wasm) { self.postMessage({ type: 'error', error: 'WASM not loaded' }); return; }
      try {
        const group = wasm.HarmonyBucket.new_with_backend(
          msg.n, msg.w, msg.t, msg.prpKey, msg.groupId, msg.backend
        );
        groups.set(msg.groupId, group);
        self.postMessage({ type: 'groupCreated', groupId: msg.groupId });
      } catch (e) {
        self.postMessage({ type: 'error', error: 'createGroup(' + msg.groupId + '): ' + e.message });
      }
      break;
    }
    case 'loadHints': {
      const group = groups.get(msg.groupId);
      if (!group) { self.postMessage({ type: 'error', error: 'group ' + msg.groupId + ' not found' }); return; }
      try {
        group.load_hints(msg.hints);
        self.postMessage({ type: 'hintsLoaded', groupId: msg.groupId });
      } catch (e) {
        self.postMessage({ type: 'error', error: 'loadHints(' + msg.groupId + '): ' + e.message });
      }
      break;
    }
    case 'buildBatch': {
      const results = [];
      const transferables = [];
      for (const item of msg.items) {
        const group = groups.get(item.groupId);
        if (!group) continue;
        let bytes, segment, position;
        if (item.binIndex !== undefined) {
          const req = group.build_request(item.binIndex);
          bytes = new Uint8Array(req.request);
          segment = req.segment;
          position = req.position;
          req.free();
        } else {
          bytes = new Uint8Array(group.build_synthetic_dummy());
        }
        results.push({ groupId: item.groupId, bytes, segment, position });
        transferables.push(bytes.buffer);
      }
      self.postMessage({ type: 'buildBatchResult', requestId: msg.requestId, results }, transferables);
      break;
    }
    case 'processBatch': {
      const results = [];
      const transferables = [];
      for (const item of msg.items) {
        const group = groups.get(item.groupId);
        if (!group) continue;
        const answer = group.process_response_xor_only(item.response);
        results.push({ groupId: item.groupId, answer });
        transferables.push(answer.buffer);
      }
      self.postMessage({ type: 'processBatchResult', requestId: msg.requestId, results }, transferables);
      break;
    }
    case 'finishRelocation': {
      for (const groupId of msg.groupIds) {
        const group = groups.get(groupId);
        if (group) group.finish_relocation();
      }
      self.postMessage({ type: 'relocationDone', requestId: msg.requestId });
      break;
    }
    case 'serializeAll': {
      const results = [];
      const transferables = [];
      for (const [groupId, group] of groups) {
        const data = new Uint8Array(group.serialize());
        results.push({ groupId, data });
        transferables.push(data.buffer);
      }
      self.postMessage({ type: 'serializeResult', requestId: msg.requestId, results }, transferables);
      break;
    }
    case 'deserializeGroup': {
      try {
        const group = wasm.HarmonyBucket.deserialize(msg.data, msg.prpKey, msg.groupId);
        groups.set(msg.groupId, group);
        self.postMessage({ type: 'groupDeserialized', requestId: msg.requestId, groupId: msg.groupId });
      } catch (e) {
        self.postMessage({ type: 'groupDeserialized', requestId: msg.requestId, error: e.message });
      }
      break;
    }
    case 'queryRemaining': {
      let minRemaining = Infinity;
      for (const [, group] of groups) {
        const r = group.queries_remaining();
        if (r < minRemaining) minRemaining = r;
      }
      self.postMessage({ type: 'queryRemainingResult', requestId: msg.requestId, minRemaining });
      break;
    }
  }
};
`;
  }
}
