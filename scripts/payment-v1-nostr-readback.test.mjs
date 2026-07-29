#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  eventProjection,
  eventSetDigest,
  readRelay,
} from "./payment-v1-nostr-readback.mjs";

const requireFromWeb = createRequire(new URL("../web/package.json", import.meta.url));
const { WebSocketServer } = requireFromWeb("ws");

const SCRIPT = new URL("./payment-v1-nostr-readback.mjs", import.meta.url);
const SCRIPT_PATH = fileURLToPath(SCRIPT);
const VALID_RELAYS = ["wss://a.example", "wss://b.example:8443/v1"];
const EXPECTED_SET_DIGEST = "0".repeat(64);

function run(artifact, relays = VALID_RELAYS, centralizedSingleRelay = false) {
  return spawnSync(
    process.execPath,
    [
      SCRIPT_PATH,
      "--artifact",
      artifact,
      ...relays.flatMap((relay) => ["--relay", relay]),
      ...(centralizedSingleRelay ? ["--centralized-single-relay"] : []),
      "--expected-set-digest-hex",
      EXPECTED_SET_DIGEST,
    ],
    { encoding: "utf8", timeout: 5_000 },
  );
}

test("single relay requires explicit centralized mode and never downgrades strict mode", () => {
  const directory = privateTempdir();
  try {
    const artifact = join(directory, "artifact.json");
    writeFileSync(artifact, "{}", { mode: 0o600 });

    const strictOne = run(artifact, ["wss://central.example"]);
    assert.equal(strictOne.status, 2);
    assert.match(strictOne.stderr, /strict-relay-count-out-of-range/);

    const centralizedOne = run(artifact, ["wss://central.example"], true);
    assert.equal(centralizedOne.status, 2);
    assert.match(centralizedOne.stderr, /invalid-artifact-shape/);
    assert.doesNotMatch(
      centralizedOne.stderr,
      /centralized-single-relay-requires-exactly-one-relay/,
    );

    const centralizedTwo = run(artifact, VALID_RELAYS, true);
    assert.equal(centralizedTwo.status, 2);
    assert.match(
      centralizedTwo.stderr,
      /centralized-single-relay-requires-exactly-one-relay/,
    );

    const strictZero = run(artifact, []);
    assert.equal(strictZero.status, 2);
    assert.match(strictZero.stderr, /strict-relay-count-out-of-range/);

    const strictNine = run(
      artifact,
      Array.from({ length: 9 }, (_, index) => `wss://relay-${index}.example`),
    );
    assert.equal(strictNine.status, 2);
    assert.match(strictNine.stderr, /strict-relay-count-out-of-range/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function privateTempdir() {
  const directory = mkdtempSync(join(tmpdir(), "bpir-nostr-readback-test-"));
  chmodSync(directory, 0o700);
  return directory;
}

function makeEvent(content = "", marker = "3") {
  const pubkey = "2".repeat(64);
  const createdAt = 1;
  const kind = 30_078;
  const tags = [];
  const id = createHash("sha256")
    .update(JSON.stringify([0, pubkey, createdAt, kind, tags, content]))
    .digest("hex");
  return {
    content,
    created_at: createdAt,
    id,
    kind,
    pubkey,
    sig: marker.repeat(128),
    tags,
  };
}

function expectedEvents(...events) {
  return new Map(events.map((event) => [event.id, eventProjection(event)]));
}

async function withWebSocketServer(onConnection, exercise) {
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await once(server, "listening");
  server.on("connection", onConnection);
  const { port } = server.address();
  try {
    await exercise(`ws://127.0.0.1:${port}`);
  } finally {
    for (const client of server.clients) client.terminate();
    await new Promise((resolve) => server.close(resolve));
  }
}

test("raw relay aliases fail before URL normalization", () => {
  const directory = privateTempdir();
  try {
    const artifact = join(directory, "artifact.json");
    writeFileSync(artifact, "{}", { mode: 0o600 });
    const invalid = [
      "ws://a.example",
      "wss://A.example",
      "wss://a.example:443",
      "wss://a.example:08443/v1",
      "wss://127.0.0.1",
      "wss://[::1]",
      "wss://internal",
      "wss://a.example.",
      "wss://a.example/",
      "wss://a.example//query",
      "wss://a.example/v1//query",
      "wss://a.example/v1/../query",
      "wss://a.example/v1%2fquery",
      "wss://a.example/v1?x=1",
      "wss://a.example/v1#x",
      "wss://user@a.example/v1",
      "wss://a.example\\v1",
      " wss://a.example/v1",
      "wss://bücher.example/v1",
      `wss://a.example/${"x".repeat(512)}`,
    ];
    for (const relay of invalid) {
      const result = run(artifact, [relay, VALID_RELAYS[1]]);
      assert.equal(result.status, 2, relay);
      assert.match(result.stderr, /relay-must-be-canonical-public-wss/, relay);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("canonical relay forms advance to artifact validation without network I/O", () => {
  const directory = privateTempdir();
  try {
    const artifact = join(directory, "artifact.json");
    writeFileSync(artifact, "{}", { mode: 0o600 });
    const result = run(artifact);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /invalid-artifact-shape/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("readback requires the publisher event-set digest before dialing", () => {
  const directory = privateTempdir();
  try {
    const artifact = join(directory, "artifact.json");
    const event = makeEvent("digest-bound");
    writeFileSync(artifact, JSON.stringify(["EVENT", event]), { mode: 0o600 });
    const result = run(artifact);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /event-set-digest-mismatch/);
    assert.notEqual(eventSetDigest(expectedEvents(event)), EXPECTED_SET_DIGEST);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("event-set digest fixture matches the Rust publisher", () => {
  const firstId = "01".repeat(32);
  const secondId = "03".repeat(32);
  const expected = new Map([
    [secondId, JSON.stringify([secondId, "", 0, 0, [], "", "04".repeat(64)])],
    [firstId, JSON.stringify([firstId, "", 0, 0, [], "", "02".repeat(64)])],
  ]);
  assert.equal(
    eventSetDigest(expected),
    "56ae675b14cb305c03b5d6d9a6f9475702fc263629e9f33a4ac93d4c8399dd6c",
  );
});

test("artifact reader rejects symlink directory device and oversized file", () => {
  const directory = privateTempdir();
  try {
    const regular = join(directory, "regular.json");
    const link = join(directory, "link.json");
    const nested = join(directory, "nested");
    const oversized = join(directory, "oversized.json");
    writeFileSync(regular, "{}", { mode: 0o600 });
    symlinkSync(regular, link);
    mkdirSync(nested, { mode: 0o700 });
    writeFileSync(oversized, Buffer.alloc(5 * 1024 * 1024 + 1), { mode: 0o600 });

    for (const path of [link, nested, oversized]) {
      const result = run(path);
      assert.equal(result.status, 2, path);
      assert.match(
        result.stderr,
        /artifact-(not-regular-file|size-or-platform-boundary)/,
        path,
      );
    }
    if (process.platform !== "win32") {
      const device = run("/dev/zero");
      assert.equal(device.status, 2);
      assert.match(device.stderr, /artifact-not-regular-file/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("artifact reader enforces one cumulative five MiB budget", () => {
  const directory = privateTempdir();
  try {
    const first = join(directory, "first.json");
    const second = join(directory, "second.json");
    const content = "x".repeat(2_700_000);
    writeFileSync(first, JSON.stringify(["EVENT", makeEvent(content, "3")]), {
      mode: 0o600,
    });
    writeFileSync(second, JSON.stringify(["EVENT", makeEvent(content, "4")]), {
      mode: 0o600,
    });
    const result = spawnSync(
      process.execPath,
      [
        SCRIPT_PATH,
        "--artifact",
        first,
        "--artifact",
        second,
        ...VALID_RELAYS.flatMap((relay) => ["--relay", relay]),
        "--expected-set-digest-hex",
        EXPECTED_SET_DIGEST,
      ],
      { encoding: "utf8", timeout: 5_000 },
    );
    assert.equal(result.status, 2);
    assert.match(result.stderr, /artifact-size-or-platform-boundary/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("artifact reader rejects a FIFO without blocking", { skip: process.platform === "win32" }, () => {
  const directory = privateTempdir();
  try {
    const fifo = join(directory, "artifact.fifo");
    const created = spawnSync("mkfifo", [fifo], { encoding: "utf8", timeout: 2_000 });
    assert.equal(created.status, 0, created.stderr);
    const result = run(fifo);
    assert.notEqual(result.status, null, "reader timed out on FIFO");
    assert.equal(result.status, 2);
    assert.match(result.stderr, /artifact-not-regular-file/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("relay session accepts every exact event once followed by EOSE", async () => {
  const event = makeEvent("exact-readback");
  const expected = expectedEvents(event);
  await withWebSocketServer(
    (socket) => {
      socket.once("message", (request) => {
        const subscription = JSON.parse(request.toString("utf8"))[1];
        socket.send(JSON.stringify(["EVENT", subscription, event]));
        socket.send(JSON.stringify(["EOSE", subscription]));
      });
    },
    async (url) => readRelay(url, expected, 1_000),
  );
});

test("relay session rejects duplicate event and premature EOSE", async () => {
  const event = makeEvent("duplicate");
  const expected = expectedEvents(event);
  await withWebSocketServer(
    (socket) => {
      socket.once("message", (request) => {
        const subscription = JSON.parse(request.toString("utf8"))[1];
        socket.send(JSON.stringify(["EVENT", subscription, event]));
        socket.send(JSON.stringify(["EVENT", subscription, event]));
      });
    },
    async (url) => assert.rejects(readRelay(url, expected, 1_000), /duplicate-event/),
  );
  await withWebSocketServer(
    (socket) => {
      socket.once("message", (request) => {
        const subscription = JSON.parse(request.toString("utf8"))[1];
        socket.send(JSON.stringify(["EOSE", subscription]));
      });
    },
    async (url) => assert.rejects(readRelay(url, expected, 1_000), /missing-event/),
  );
});

test("relay session rejects control frames oversized payload and total timeout", async () => {
  const event = makeEvent("bounded");
  const expected = expectedEvents(event);
  await withWebSocketServer(
    (socket) => socket.once("message", () => socket.ping("unexpected")),
    async (url) => assert.rejects(readRelay(url, expected, 1_000), /control-frame/),
  );
  await withWebSocketServer(
    (socket) =>
      socket.once("message", () => socket.send("x".repeat(512 * 1024 + 1))),
    async (url) => assert.rejects(readRelay(url, expected, 1_000), /transport-failed/),
  );
  await withWebSocketServer(
    (socket) => socket.once("message", () => {}),
    async (url) => assert.rejects(readRelay(url, expected, 50), /timeout/),
  );
});
