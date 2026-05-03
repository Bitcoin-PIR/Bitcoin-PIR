use wasm_bindgen::prelude::*;

use crate::bitstring::BitstringGen;
use crate::cache::{CounterCache, PartitionCache};
use crate::fastprp::FastPrp;

// ── Binary serialization helpers ───────────────────────────────────
//
// Format:
//   [8] stride u64_le
//   [4] num_depths u32_le
//   [8] n u64_le
//   For each stride-cache depth:
//     [4] count u32_le
//     [count*4] entries u32_le[]
//   [4] num_pcache_depths u32_le
//   For each pcache depth:
//     [4] count u32_le
//     [count*12] entries (u64_le, u32_le)[]

fn serialize_caches(cc: &CounterCache, pc: &PartitionCache) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header
    buf.extend_from_slice(&cc.stride.to_le_bytes());
    buf.extend_from_slice(&cc.num_depths.to_le_bytes());
    buf.extend_from_slice(&cc.n.to_le_bytes());

    // Stride cache
    let raw = cc.raw_cache();
    for depth_entries in raw {
        buf.extend_from_slice(&(depth_entries.len() as u32).to_le_bytes());
        for &val in depth_entries {
            buf.extend_from_slice(&val.to_le_bytes());
        }
    }

    // Partition cache
    let depths = pc.raw_depths();
    buf.extend_from_slice(&(depths.len() as u32).to_le_bytes());
    for depth_entries in depths {
        buf.extend_from_slice(&(depth_entries.len() as u32).to_le_bytes());
        for &(pos, cum) in depth_entries {
            buf.extend_from_slice(&pos.to_le_bytes());
            buf.extend_from_slice(&cum.to_le_bytes());
        }
    }

    buf
}

fn deserialize_caches(data: &[u8]) -> Result<(CounterCache, PartitionCache), String> {
    let mut off = 0usize;

    macro_rules! read_u32 {
        () => {{
            if off + 4 > data.len() { return Err("truncated".into()); }
            let v = u32::from_le_bytes(data[off..off+4].try_into().unwrap());
            off += 4;
            v
        }};
    }
    macro_rules! read_u64 {
        () => {{
            if off + 8 > data.len() { return Err("truncated".into()); }
            let v = u64::from_le_bytes(data[off..off+8].try_into().unwrap());
            off += 8;
            v
        }};
    }

    let stride = read_u64!();
    let num_depths = read_u32!();
    let n = read_u64!();

    // Stride cache
    let mut cache_data = Vec::with_capacity(num_depths as usize);
    for _ in 0..num_depths {
        let count = read_u32!() as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(read_u32!());
        }
        cache_data.push(entries);
    }
    let cc = CounterCache::from_raw(stride, num_depths, n, cache_data);

    // Partition cache
    let num_pc_depths = read_u32!() as usize;
    let mut pc_depths = Vec::with_capacity(num_pc_depths);
    for _ in 0..num_pc_depths {
        let count = read_u32!() as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let pos = read_u64!();
            let cum = read_u32!();
            entries.push((pos, cum));
        }
        pc_depths.push(entries);
    }
    let pc = PartitionCache::from_raw(pc_depths);

    Ok((cc, pc))
}

// ── WASM wrapper ───────────────────────────────────────────────────

#[wasm_bindgen]
pub struct WasmFastPrp {
    inner: FastPrp,
    key: [u8; 16],
    n: u64,
}

#[wasm_bindgen]
impl WasmFastPrp {
    /// Build from scratch — constructs both caches from key.
    #[wasm_bindgen(constructor)]
    pub fn new(key: &[u8], n: f64) -> Result<WasmFastPrp, JsError> {
        let key: [u8; 16] = key.try_into().map_err(|_| JsError::new("key must be 16 bytes"))?;
        let n = n as u64;
        let inner = FastPrp::new(&key, n);
        Ok(WasmFastPrp { inner, key, n })
    }

    /// Build with a custom cache stride.
    #[wasm_bindgen(js_name = "withStride")]
    pub fn with_stride(key: &[u8], n: f64, stride: f64) -> Result<WasmFastPrp, JsError> {
        let key: [u8; 16] = key.try_into().map_err(|_| JsError::new("key must be 16 bytes"))?;
        let n = n as u64;
        let inner = FastPrp::with_stride(&key, n, stride as u64);
        Ok(WasmFastPrp { inner, key, n })
    }

    /// Load from pre-serialized cache bytes + key.
    /// The partition cache is rebuilt from key (deterministic).
    #[wasm_bindgen(js_name = "fromCacheBytes")]
    pub fn from_cache_bytes(key: &[u8], n: f64, cache_bytes: &[u8]) -> Result<WasmFastPrp, JsError> {
        let key: [u8; 16] = key.try_into().map_err(|_| JsError::new("key must be 16 bytes"))?;
        let n = n as u64;
        let (cc, pc) = deserialize_caches(cache_bytes).map_err(|e| JsError::new(&e))?;
        let inner = FastPrp::from_parts(&key, n, cc, pc);
        Ok(WasmFastPrp { inner, key, n })
    }

    /// Halve the stride cache once (incremental caching §5.3).
    pub fn refine(&mut self) {
        let gen = BitstringGen::new(&self.key, self.n);
        // Access cache mutably through a rebuild.
        let cc = self.inner.counter_cache();
        let mut new_cc = CounterCache::from_raw(
            cc.stride, cc.num_depths, cc.n, cc.raw_cache().clone(),
        );
        new_cc.refine(&gen);
        let pc = PartitionCache::from_raw(self.inner.partition_cache().raw_depths().clone());
        self.inner = FastPrp::from_parts(&self.key, self.n, new_cc, pc);
    }

    /// Refine until stride ≤ target. Returns number of steps.
    #[wasm_bindgen(js_name = "refineTo")]
    pub fn refine_to(&mut self, target_stride: f64) -> u32 {
        let gen = BitstringGen::new(&self.key, self.n);
        let cc = self.inner.counter_cache();
        let mut new_cc = CounterCache::from_raw(
            cc.stride, cc.num_depths, cc.n, cc.raw_cache().clone(),
        );
        let steps = new_cc.refine_to(&gen, target_stride as u64);
        let pc = PartitionCache::from_raw(self.inner.partition_cache().raw_depths().clone());
        self.inner = FastPrp::from_parts(&self.key, self.n, new_cc, pc);
        steps
    }

    /// Forward PRP: permute(x) → y.
    pub fn permute(&self, x: f64) -> f64 {
        self.inner.permute(x as u64) as f64
    }

    /// Inverse PRP: unpermute(y) → x.
    pub fn unpermute(&self, y: f64) -> f64 {
        self.inner.unpermute(y as u64) as f64
    }

    /// Permute 4 inputs at once. Returns Float64Array(4).
    pub fn permute4(&self, x0: f64, x1: f64, x2: f64, x3: f64) -> js_sys::Float64Array {
        let results = self.inner.permute_4([x0 as u64, x1 as u64, x2 as u64, x3 as u64]);
        let arr = js_sys::Float64Array::new_with_length(4);
        arr.set_index(0, results[0] as f64);
        arr.set_index(1, results[1] as f64);
        arr.set_index(2, results[2] as f64);
        arr.set_index(3, results[3] as f64);
        arr
    }

    /// Batch permute the entire domain. Returns Float64Array(N).
    #[wasm_bindgen(js_name = "batchPermute")]
    pub fn batch_permute(&self) -> js_sys::Float64Array {
        let table = self.inner.batch_permute();
        let arr = js_sys::Float64Array::new_with_length(table.len() as u32);
        for (i, &v) in table.iter().enumerate() {
            arr.set_index(i as u32, v as f64);
        }
        arr
    }

    /// Export both caches as a binary blob for server→client transfer.
    #[wasm_bindgen(js_name = "exportCacheBytes")]
    pub fn export_cache_bytes(&self) -> Vec<u8> {
        serialize_caches(self.inner.counter_cache(), self.inner.partition_cache())
    }

    /// Domain size N.
    #[wasm_bindgen(getter, js_name = "domainSize")]
    pub fn domain_size(&self) -> f64 {
        self.inner.domain_size() as f64
    }

    /// Current cache stride.
    #[wasm_bindgen(getter, js_name = "cacheStride")]
    pub fn cache_stride(&self) -> f64 {
        self.inner.cache_stride() as f64
    }

    /// Cache memory in bytes.
    #[wasm_bindgen(getter, js_name = "cacheSizeBytes")]
    pub fn cache_size_bytes(&self) -> f64 {
        self.inner.cache_size_bytes() as f64
    }
}
