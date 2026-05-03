const { WasmFastPrp } = require('../pkg/fastprp.js');

const key = new Uint8Array([
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
]);

let passed = 0;
let failed = 0;

function assert(cond, msg) {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failed++;
  } else {
    passed++;
  }
}

function assertEq(a, b, msg) {
  assert(a === b, `${msg}: expected ${b}, got ${a}`);
}

// ── Test 1: Basic permute / unpermute roundtrip ──
console.log("Test 1: permute/unpermute roundtrip (N=1024)");
{
  const prp = new WasmFastPrp(key, 1024);
  for (let x = 0; x < 1024; x++) {
    const y = prp.permute(x);
    const xBack = prp.unpermute(y);
    assert(y >= 0 && y < 1024, `permute(${x})=${y} out of range`);
    assertEq(xBack, x, `roundtrip x=${x}`);
  }
  prp.free();
}

// ── Test 2: Verify it's a permutation ──
console.log("Test 2: verify permutation (N=1024)");
{
  const prp = new WasmFastPrp(key, 1024);
  const seen = new Set();
  for (let x = 0; x < 1024; x++) {
    seen.add(prp.permute(x));
  }
  assertEq(seen.size, 1024, "should produce 1024 unique outputs");
  prp.free();
}

// ── Test 3: permute4 matches individual calls ──
console.log("Test 3: permute4 consistency (N=2048)");
{
  const prp = new WasmFastPrp(key, 2048);
  for (let base = 0; base < 2048; base += 4) {
    const results = prp.permute4(base, base+1, base+2, base+3);
    for (let i = 0; i < 4; i++) {
      assertEq(results[i], prp.permute(base + i), `permute4[${base+i}]`);
    }
  }
  prp.free();
}

// ── Test 4: batchPermute matches individual ──
console.log("Test 4: batchPermute consistency (N=256)");
{
  const prp = new WasmFastPrp(key, 256);
  const table = prp.batchPermute();
  assertEq(table.length, 256, "table length");
  for (let x = 0; x < 256; x++) {
    assertEq(table[x], prp.permute(x), `batch[${x}]`);
  }
  prp.free();
}

// ── Test 5: Export/import cache roundtrip ──
console.log("Test 5: cache export/import roundtrip (N=512)");
{
  const prp1 = new WasmFastPrp(key, 512);
  const bytes = prp1.exportCacheBytes();
  assert(bytes.length > 0, "exported bytes should be non-empty");

  const prp2 = WasmFastPrp.fromCacheBytes(key, 512, bytes);
  for (let x = 0; x < 512; x++) {
    assertEq(prp2.permute(x), prp1.permute(x), `imported permute(${x})`);
    assertEq(prp2.unpermute(prp1.permute(x)), x, `imported roundtrip(${x})`);
  }
  prp1.free();
  prp2.free();
}

// ── Test 6: Coarse cache + refine ──
console.log("Test 6: coarse cache + refine (N=1024)");
{
  // Build with coarse stride
  const coarse = WasmFastPrp.withStride(key, 1024, 256);
  const coarseBytes = coarse.exportCacheBytes();
  const coarseStride = coarse.cacheStride;
  coarse.free();

  // Load and refine
  const prp = WasmFastPrp.fromCacheBytes(key, 1024, coarseBytes);
  assert(prp.cacheStride >= coarseStride / 2 || prp.cacheStride === coarseStride,
    `initial stride=${prp.cacheStride}`);

  const steps = prp.refineTo(32);
  assert(steps > 0, `should refine at least once, got ${steps} steps`);
  assert(prp.cacheStride <= 32, `stride should be ≤32, got ${prp.cacheStride}`);

  // Verify correctness after refinement
  const direct = new WasmFastPrp(key, 1024);
  for (let x = 0; x < 1024; x++) {
    assertEq(prp.permute(x), direct.permute(x), `refined permute(${x})`);
  }
  prp.free();
  direct.free();
}

// ── Test 7: Getters ──
console.log("Test 7: getters");
{
  const prp = new WasmFastPrp(key, 10000);
  assertEq(prp.domainSize, 10000, "domainSize");
  assert(prp.cacheStride > 0, "cacheStride > 0");
  assert(prp.cacheSizeBytes > 0, "cacheSizeBytes > 0");
  prp.free();
}

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
