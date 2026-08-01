import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  inspectDynamicElfV1,
  validatePublisherNetnsFailedUnitV1,
  validatePublisherNodeElfClosureBytesV1,
} from "./payment-v1-publisher-netns-schema.mjs";

const unitName = "bitcoinpir-payment-v1-publisher-netns.service";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function dynamicElfFixture({ interpreter = null, needed = [], soname = null } = {}) {
  const bytes = Buffer.alloc(4096);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(3, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(interpreter === null ? 2 : 3, 56);
  const base = 0x400000n;
  const dynamicOffset = 512;
  const stringTableOffset = 1024;
  const strings = ["", ...needed, ...(soname === null ? [] : [soname])];
  const stringOffsets = new Map();
  let stringCursor = 0;
  for (const value of strings) {
    if (!stringOffsets.has(value)) stringOffsets.set(value, stringCursor);
    bytes.write(`${value}\0`, stringTableOffset + stringCursor, "ascii");
    stringCursor += Buffer.byteLength(value, "ascii") + 1;
  }
  const dynamicEntries = [
    ...needed.map((name) => [1n, BigInt(stringOffsets.get(name))]),
    [5n, base + BigInt(stringTableOffset)],
    [10n, BigInt(stringCursor)],
    ...(soname === null ? [] : [[14n, BigInt(stringOffsets.get(soname))]]),
    [0n, 0n],
  ];
  for (const [index, [tag, value]] of dynamicEntries.entries()) {
    bytes.writeBigInt64LE(tag, dynamicOffset + index * 16);
    bytes.writeBigUInt64LE(value, dynamicOffset + index * 16 + 8);
  }
  const writeProgramHeader = (index, type, fileOffset, fileSize) => {
    const offset = 64 + index * 56;
    bytes.writeUInt32LE(type, offset);
    bytes.writeUInt32LE(type === 1 ? 5 : 4, offset + 4);
    bytes.writeBigUInt64LE(BigInt(fileOffset), offset + 8);
    bytes.writeBigUInt64LE(base + BigInt(fileOffset), offset + 16);
    bytes.writeBigUInt64LE(base + BigInt(fileOffset), offset + 24);
    bytes.writeBigUInt64LE(BigInt(fileSize), offset + 32);
    bytes.writeBigUInt64LE(BigInt(fileSize), offset + 40);
    bytes.writeBigUInt64LE(type === 1 ? 4096n : 8n, offset + 48);
  };
  writeProgramHeader(0, 1, 0, bytes.length);
  writeProgramHeader(1, 2, dynamicOffset, dynamicEntries.length * 16);
  if (interpreter !== null) {
    const interpreterOffset = 384;
    bytes.write(`${interpreter}\0`, interpreterOffset, "ascii");
    writeProgramHeader(
      2,
      3,
      interpreterOffset,
      Buffer.byteLength(interpreter, "ascii") + 1,
    );
  }
  return bytes;
}

function failedUnit(overrides = {}) {
  return {
    active_enter_timestamp_monotonic: "0",
    active_state: "failed",
    exec_main_code: "2",
    exec_main_status: "15",
    inactive_enter_timestamp_monotonic: "200",
    invocation_id: "a".repeat(32),
    load_state: "loaded",
    main_pid: "0",
    name: unitName,
    need_daemon_reload: "no",
    result: "timeout",
    state_change_timestamp_monotonic: "200",
    sub_state: "failed",
    ...overrides,
  };
}

test("failed-unit schema accepts strict pre-READY and post-READY terminal timelines", () => {
  assert.equal(validatePublisherNetnsFailedUnitV1(failedUnit()), true);
  assert.equal(validatePublisherNetnsFailedUnitV1(failedUnit({
    active_enter_timestamp_monotonic: "100",
    exec_main_code: "1",
    exec_main_status: "42",
    result: "exit-code",
  })), true);
});

test("failed-unit schema rejects ambiguous or non-terminal timestamp relations", () => {
  for (const overrides of [
    { inactive_enter_timestamp_monotonic: "0", state_change_timestamp_monotonic: "0" },
    { inactive_enter_timestamp_monotonic: "201" },
    { active_enter_timestamp_monotonic: "200" },
    { active_enter_timestamp_monotonic: "201" },
  ]) {
    assert.throws(
      () => validatePublisherNetnsFailedUnitV1(failedUnit(overrides)),
      /not one terminal failed\/failed systemd invocation/u,
    );
  }
});

test("Node closure accepts libc's reviewed PT_INTERP but not a second-stage loader", () => {
  const ptInterp = "/lib64/ld-linux-x86-64.so.2";
  const loaderPath = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
  const libcPath = "/usr/lib/x86_64-linux-gnu/libc.so.6";
  const loaderBytes = dynamicElfFixture({ soname: "ld-linux-x86-64.so.2" });
  const libcBytes = dynamicElfFixture({
    interpreter: ptInterp,
    needed: ["ld-linux-x86-64.so.2"],
    soname: "libc.so.6",
  });
  const nodeBytes = dynamicElfFixture({
    interpreter: ptInterp,
    needed: ["ld-linux-x86-64.so.2", "libc.so.6"],
  });
  const closure = {
    objects: [
      {
        needed: [],
        pin: { path: loaderPath, sha256: sha256(loaderBytes) },
        soname: "ld-linux-x86-64.so.2",
      },
      {
        needed: ["ld-linux-x86-64.so.2"],
        pin: { path: libcPath, sha256: sha256(libcBytes) },
        soname: "libc.so.6",
      },
    ],
    node_needed: ["ld-linux-x86-64.so.2", "libc.so.6"],
    pt_interp: ptInterp,
  };
  const objectBytes = new Map([
    [loaderPath, loaderBytes],
    [libcPath, libcBytes],
  ]);
  assert.deepEqual(
    validatePublisherNodeElfClosureBytesV1({ closure, nodeBytes, objectBytes })
      .objects.map((object) => object.pt_interp),
    [null, ptInterp],
  );

  const nestedLoaderBytes = dynamicElfFixture({
    interpreter: ptInterp,
    soname: "ld-linux-x86-64.so.2",
  });
  const nestedLoaderClosure = structuredClone(closure);
  nestedLoaderClosure.objects[0].pin.sha256 = sha256(nestedLoaderBytes);
  assert.throws(
    () => validatePublisherNodeElfClosureBytesV1({
      closure: nestedLoaderClosure,
      nodeBytes,
      objectBytes: new Map([
        [loaderPath, nestedLoaderBytes],
        [libcPath, libcBytes],
      ]),
    }),
    /ELF metadata differs from its approved closure/u,
  );

  const dependentLoaderBytes = dynamicElfFixture({
    needed: ["libc.so.6"],
    soname: "ld-linux-x86-64.so.2",
  });
  const dependentLoaderClosure = structuredClone(closure);
  dependentLoaderClosure.objects[0].needed = ["libc.so.6"];
  dependentLoaderClosure.objects[0].pin.sha256 = sha256(dependentLoaderBytes);
  assert.throws(
    () => validatePublisherNodeElfClosureBytesV1({
      closure: dependentLoaderClosure,
      nodeBytes,
      objectBytes: new Map([
        [loaderPath, dependentLoaderBytes],
        [libcPath, libcBytes],
      ]),
    }),
    /ELF metadata differs from its approved closure/u,
  );

  const foreignInterpreterBytes = dynamicElfFixture({
    interpreter: "/lib64/unreviewed-loader.so.2",
    needed: ["ld-linux-x86-64.so.2"],
    soname: "libc.so.6",
  });
  const foreignInterpreterClosure = structuredClone(closure);
  foreignInterpreterClosure.objects[1].pin.sha256 = sha256(foreignInterpreterBytes);
  assert.throws(
    () => validatePublisherNodeElfClosureBytesV1({
      closure: foreignInterpreterClosure,
      nodeBytes,
      objectBytes: new Map([
        [loaderPath, loaderBytes],
        [libcPath, foreignInterpreterBytes],
      ]),
    }),
    /ELF metadata differs from its approved closure/u,
  );
});

test("dynamic ELF names reject high-bit bytes before ASCII decoding", () => {
  const highBitNeeded = dynamicElfFixture({ needed: ["libc.so.6"] });
  highBitNeeded[1025] |= 0x80;
  assert.throws(
    () => inspectDynamicElfV1(highBitNeeded),
    /DT_NEEDED\[0\] is not strict ASCII/u,
  );

  const highBitInterpreter = dynamicElfFixture({
    interpreter: "/lib64/ld-linux-x86-64.so.2",
  });
  highBitInterpreter[384] |= 0x80;
  assert.throws(
    () => inspectDynamicElfV1(highBitInterpreter),
    /PT_INTERP is not one bounded strict-ASCII/u,
  );
});
