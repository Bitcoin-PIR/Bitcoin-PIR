const { WasmFastPrp } = require('../pkg/fastprp.js');

const key = new Uint8Array([
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
]);

function bench(label, fn, iters) {
  // warmup
  for (let i = 0; i < Math.min(100, iters); i++) fn(i);
  const t0 = performance.now();
  for (let i = 0; i < iters; i++) fn(i);
  const ms = performance.now() - t0;
  const us = (ms * 1000) / iters;
  console.log(`  ${label}: ${us.toFixed(1)} us/op  (${iters} ops in ${ms.toFixed(0)} ms)`);
  return us;
}

console.log("=== WASM FastPRP Benchmark ===\n");

for (const logN of [14, 20, 23]) {
  const n = 1 << logN;
  console.log(`N = 2^${logN} = ${n}`);

  const t0 = performance.now();
  const prp = new WasmFastPrp(key, n);
  const initMs = performance.now() - t0;
  console.log(`  init: ${initMs.toFixed(0)} ms, stride=${prp.cacheStride}, cache=${(prp.cacheSizeBytes/1024).toFixed(0)} KB`);

  const numOps = logN >= 23 ? 2000 : 5000;

  bench("permute", (i) => prp.permute(i % n), numOps);
  bench("unpermute", (i) => prp.unpermute(i % n), numOps);
  bench("permute4", (i) => {
    const b = (i * 4) % n;
    prp.permute4(b, (b+1)%n, (b+2)%n, (b+3)%n);
  }, numOps / 4);

  if (logN <= 14) {
    bench("batchPermute", () => prp.batchPermute(), 20);
  }

  // Test refine speed
  if (logN >= 20) {
    const coarse = WasmFastPrp.withStride(key, n, prp.cacheStride * 8);
    const t1 = performance.now();
    coarse.refineTo(prp.cacheStride);
    const refineMs = performance.now() - t1;
    console.log(`  refine (3 steps): ${refineMs.toFixed(0)} ms`);
    coarse.free();
  }

  prp.free();
  console.log();
}

// Cache export/import benchmark
console.log("Cache serialization (N=2^20):");
{
  const prp = new WasmFastPrp(key, 1 << 20);
  const t0 = performance.now();
  const bytes = prp.exportCacheBytes();
  console.log(`  export: ${(performance.now() - t0).toFixed(1)} ms, ${(bytes.length/1024).toFixed(0)} KB`);
  const t1 = performance.now();
  const prp2 = WasmFastPrp.fromCacheBytes(key, 1 << 20, bytes);
  console.log(`  import: ${(performance.now() - t1).toFixed(1)} ms`);
  prp.free();
  prp2.free();
}
