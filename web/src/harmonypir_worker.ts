/**
 * HarmonyPIR Web Worker
 *
 * Each worker loads its own WASM instance and owns a subset of
 * HarmonyBucket instances. Handles build_request, build_synthetic_dummy,
 * process_response, and hint loading — keeping the tight state coupling
 * (build_request ↔ process_response) within a single thread.
 */

// Minimal WASM interface — matches harmonypir_wasm no-modules output.
interface HarmonyBucketWasm {
  load_hints(hintsData: Uint8Array): void;
  build_request(q: number): { request: Uint8Array; segment: number; position: number; query_index: number; free(): void };
  build_synthetic_dummy(): Uint8Array;
  process_response(response: Uint8Array): Uint8Array;
  queries_remaining(): number;
  free(): void;
}

interface WasmBindgen {
  HarmonyBucket: {
    new_with_backend(n: number, w: number, t: number, prpKey: Uint8Array, bucketId: number, backend: number): HarmonyBucketWasm;
  };
  (wasmUrl: string): Promise<void>;
}

// ─── Worker state ────────────────────────────────────────────────────────────

const buckets = new Map<number, HarmonyBucketWasm>();
let wasm: WasmBindgen | null = null;

// ─── Message types ───────────────────────────────────────────────────────────

interface InitMsg {
  type: 'init';
  wasmJsUrl: string;
  wasmBinaryUrl: string;
}

interface CreateBucketMsg {
  type: 'createBucket';
  bucketId: number;
  n: number;
  w: number;
  t: number;
  prpKey: Uint8Array;
  backend: number;
}

interface LoadHintsMsg {
  type: 'loadHints';
  bucketId: number;
  hints: Uint8Array;
}

interface BuildBatchMsg {
  type: 'buildBatch';
  requestId: number;
  items: Array<{
    bucketId: number;
    binIndex?: number;  // undefined = dummy
  }>;
}

interface ProcessBatchMsg {
  type: 'processBatch';
  requestId: number;
  items: Array<{
    bucketId: number;
    response: Uint8Array;
  }>;
}

type WorkerMessage = InitMsg | CreateBucketMsg | LoadHintsMsg | BuildBatchMsg | ProcessBatchMsg;

// ─── Message handler ─────────────────────────────────────────────────────────

self.onmessage = async (ev: MessageEvent<WorkerMessage>) => {
  const msg = ev.data;

  switch (msg.type) {
    case 'init': {
      try {
        // Load WASM JS via fetch + eval (same approach as main thread).
        const resp = await fetch(msg.wasmJsUrl);
        if (!resp.ok) throw new Error(`Fetch failed: ${resp.status}`);
        let jsText = await resp.text();
        // Patch `let wasm_bindgen` → `var wasm_bindgen` so it's accessible globally.
        if (jsText.startsWith('let wasm_bindgen')) {
          jsText = 'var wasm_bindgen' + jsText.slice('let wasm_bindgen'.length);
        }
        // eval in worker scope — `var` creates a global in the worker.
        (0, eval)(jsText);
        const wb = (self as any).wasm_bindgen as WasmBindgen;
        if (!wb) throw new Error('wasm_bindgen not defined after eval');
        await wb(msg.wasmBinaryUrl);
        wasm = wb;
        (self as any).postMessage({ type: 'ready' });
      } catch (e: any) {
        (self as any).postMessage({ type: 'error', error: e.message });
      }
      break;
    }

    case 'createBucket': {
      if (!wasm) { (self as any).postMessage({ type: 'error', error: 'WASM not loaded' }); return; }
      try {
        const bucket = wasm.HarmonyBucket.new_with_backend(
          msg.n, msg.w, msg.t, msg.prpKey, msg.bucketId, msg.backend,
        );
        buckets.set(msg.bucketId, bucket);
        (self as any).postMessage({ type: 'bucketCreated', bucketId: msg.bucketId });
      } catch (e: any) {
        (self as any).postMessage({ type: 'error', error: `createBucket(${msg.bucketId}): ${e.message}` });
      }
      break;
    }

    case 'loadHints': {
      const bucket = buckets.get(msg.bucketId);
      if (!bucket) { (self as any).postMessage({ type: 'error', error: `bucket ${msg.bucketId} not found` }); return; }
      try {
        bucket.load_hints(msg.hints);
        (self as any).postMessage({ type: 'hintsLoaded', bucketId: msg.bucketId });
      } catch (e: any) {
        (self as any).postMessage({ type: 'error', error: `loadHints(${msg.bucketId}): ${e.message}` });
      }
      break;
    }

    case 'buildBatch': {
      const results: Array<{ bucketId: number; bytes: Uint8Array }> = [];
      const transferables: ArrayBuffer[] = [];

      for (const item of msg.items) {
        const bucket = buckets.get(item.bucketId);
        if (!bucket) continue;

        let bytes: Uint8Array;
        if (item.binIndex !== undefined) {
          // Real query.
          const req = bucket.build_request(item.binIndex);
          bytes = new Uint8Array(req.request);
          req.free();
        } else {
          // Dummy.
          bytes = new Uint8Array(bucket.build_synthetic_dummy());
        }
        results.push({ bucketId: item.bucketId, bytes });
        transferables.push(bytes.buffer as ArrayBuffer);
      }

      (self as any).postMessage(
        { type: 'buildBatchResult', requestId: msg.requestId, results },
        transferables,
      );
      break;
    }

    case 'processBatch': {
      const results: Array<{ bucketId: number; answer: Uint8Array }> = [];
      const transferables: ArrayBuffer[] = [];

      for (const item of msg.items) {
        const bucket = buckets.get(item.bucketId);
        if (!bucket) continue;

        const answer = bucket.process_response(item.response);
        results.push({ bucketId: item.bucketId, answer });
        transferables.push(answer.buffer as ArrayBuffer);
      }

      (self as any).postMessage(
        { type: 'processBatchResult', requestId: msg.requestId, results },
        transferables,
      );
      break;
    }
  }
};
