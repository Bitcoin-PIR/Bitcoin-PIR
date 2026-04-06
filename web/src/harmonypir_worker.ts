/**
 * HarmonyPIR Web Worker
 *
 * Each worker loads its own WASM instance and owns a subset of
 * HarmonyGroup instances. Handles build_request, build_synthetic_dummy,
 * process_response, and hint loading — keeping the tight state coupling
 * (build_request <-> process_response) within a single thread.
 */

// Minimal WASM interface — matches harmonypir_wasm no-modules output.
interface HarmonyGroupWasm {
  load_hints(hintsData: Uint8Array): void;
  build_request(q: number): { request: Uint8Array; segment: number; position: number; query_index: number; free(): void };
  build_synthetic_dummy(): Uint8Array;
  process_response(response: Uint8Array): Uint8Array;
  queries_remaining(): number;
  free(): void;
}

interface WasmBindgen {
  HarmonyGroup: {  // Note: pre-built WASM may still export HarmonyBucket
    new_with_backend(n: number, w: number, t: number, prpKey: Uint8Array, groupId: number, backend: number): HarmonyGroupWasm;
  };
  (wasmUrl: string): Promise<void>;
}

// ─── Worker state ────────────────────────────────────────────────────────────

const groups = new Map<number, HarmonyGroupWasm>();
let wasm: WasmBindgen | null = null;

// ─── Message types ───────────────────────────────────────────────────────────

interface InitMsg {
  type: 'init';
  wasmJsUrl: string;
  wasmBinaryUrl: string;
}

interface CreateGroupMsg {
  type: 'createGroup';
  groupId: number;
  n: number;
  w: number;
  t: number;
  prpKey: Uint8Array;
  backend: number;
}

interface LoadHintsMsg {
  type: 'loadHints';
  groupId: number;
  hints: Uint8Array;
}

interface BuildBatchMsg {
  type: 'buildBatch';
  requestId: number;
  items: Array<{
    groupId: number;
    binIndex?: number;  // undefined = dummy
  }>;
}

interface ProcessBatchMsg {
  type: 'processBatch';
  requestId: number;
  items: Array<{
    groupId: number;
    response: Uint8Array;
  }>;
}

type WorkerMessage = InitMsg | CreateGroupMsg | LoadHintsMsg | BuildBatchMsg | ProcessBatchMsg;

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

    case 'createGroup': {
      if (!wasm) { (self as any).postMessage({ type: 'error', error: 'WASM not loaded' }); return; }
      try {
        const group = wasm.HarmonyBucket.new_with_backend(
          msg.n, msg.w, msg.t, msg.prpKey, msg.groupId, msg.backend,
        );
        groups.set(msg.groupId, group);
        (self as any).postMessage({ type: 'groupCreated', groupId: msg.groupId });
      } catch (e: any) {
        (self as any).postMessage({ type: 'error', error: `createGroup(${msg.groupId}): ${e.message}` });
      }
      break;
    }

    case 'loadHints': {
      const group = groups.get(msg.groupId);
      if (!group) { (self as any).postMessage({ type: 'error', error: `group ${msg.groupId} not found` }); return; }
      try {
        group.load_hints(msg.hints);
        (self as any).postMessage({ type: 'hintsLoaded', groupId: msg.groupId });
      } catch (e: any) {
        (self as any).postMessage({ type: 'error', error: `loadHints(${msg.groupId}): ${e.message}` });
      }
      break;
    }

    case 'buildBatch': {
      const results: Array<{ groupId: number; bytes: Uint8Array }> = [];
      const transferables: ArrayBuffer[] = [];

      for (const item of msg.items) {
        const group = groups.get(item.groupId);
        if (!group) continue;

        let bytes: Uint8Array;
        if (item.binIndex !== undefined) {
          // Real query.
          const req = group.build_request(item.binIndex);
          bytes = new Uint8Array(req.request);
          req.free();
        } else {
          // Dummy.
          bytes = new Uint8Array(group.build_synthetic_dummy());
        }
        results.push({ groupId: item.groupId, bytes });
        transferables.push(bytes.buffer as ArrayBuffer);
      }

      (self as any).postMessage(
        { type: 'buildBatchResult', requestId: msg.requestId, results },
        transferables,
      );
      break;
    }

    case 'processBatch': {
      const results: Array<{ groupId: number; answer: Uint8Array }> = [];
      const transferables: ArrayBuffer[] = [];

      for (const item of msg.items) {
        const group = groups.get(item.groupId);
        if (!group) continue;

        const answer = group.process_response(item.response);
        results.push({ groupId: item.groupId, answer });
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
