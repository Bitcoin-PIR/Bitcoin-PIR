#!/usr/bin/env node

// Staging-only NIP-01 readback for frozen, already Rust-verified directory
// artifacts. This script never reads a signing key and has no publish path.

import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// Resolve the repository's lockfile-pinned WebSocket implementation from the
// Web package. Its `maxPayload` limit rejects an untrusted relay frame before
// JavaScript allocates an arbitrarily large reply string.
const requireFromWeb = createRequire(new URL("../web/package.json", import.meta.url));
const { WebSocket } = requireFromWeb("ws");

const MAX_ARTIFACT_BYTES = 5 * 1024 * 1024;
const MAX_EVENTS = 64;
const MAX_REPLY_MESSAGE_BYTES = 512 * 1024;
// A relay EVENT adds the subscription ID and array punctuation around each
// frozen artifact message. Keep that bounded overhead without rejecting an
// otherwise valid near-limit artifact set.
const MAX_REPLY_BYTES = MAX_ARTIFACT_BYTES + MAX_EVENTS * 256;
const DEFAULT_TIMEOUT_MS = 30_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 120_000;
const EVENT_KEYS = ["content", "created_at", "id", "kind", "pubkey", "sig", "tags"];

function usage() {
  return `Usage:
  node scripts/payment-v1-nostr-readback.mjs \\
    --artifact directory-checkpoints.json \\
    --relay wss://relay-one.example \\
    --relay wss://relay-two.example:8443 \\
    --expected-set-digest-hex LOWERCASE_SHA256_FROM_PUBLISH \\
    [--timeout-ms 30000]

  # Explicit centralized/degraded mode accepts exactly one relay:
  node scripts/payment-v1-nostr-readback.mjs \\
    --artifact directory-checkpoints.json \\
    --relay wss://relay-one.example \\
    --centralized-single-relay \\
    --expected-set-digest-hex LOWERCASE_SHA256_FROM_PUBLISH

Reads one canonical EVENT artifact or one exact 16-checkpoint array per
--artifact, requests those public event IDs with standard NIP-01 REQ filters,
and requires each relay to return every exact frozen event once before EOSE.
The artifacts must first pass bpir-admin directory-artifact publish validation.`;
}

function parseArgs(argv) {
  const result = {
    artifacts: [],
    relays: [],
    expectedSetDigest: undefined,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    centralizedSingleRelay: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === "--help" || option === "-h") {
      console.log(usage());
      process.exit(0);
    }
    if (option === "--centralized-single-relay") {
      if (result.centralizedSingleRelay) {
        throw new Error("duplicate-centralized-single-relay-option");
      }
      result.centralizedSingleRelay = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error("missing-option-value");
    }
    index += 1;
    if (option === "--artifact") {
      result.artifacts.push(value);
    } else if (option === "--relay") {
      result.relays.push(value);
    } else if (option === "--timeout-ms") {
      if (!/^[1-9][0-9]*$/.test(value)) {
        throw new Error("invalid-timeout");
      }
      result.timeoutMs = Number(value);
    } else if (option === "--expected-set-digest-hex") {
      result.expectedSetDigest = value;
    } else {
      throw new Error("unknown-option");
    }
  }
  if (result.artifacts.length === 0) {
    throw new Error("missing-artifact");
  }
  if (result.centralizedSingleRelay) {
    if (result.relays.length !== 1) {
      throw new Error("centralized-single-relay-requires-exactly-one-relay");
    }
  } else if (result.relays.length < 2 || result.relays.length > 8) {
    throw new Error("strict-relay-count-out-of-range");
  }
  if (result.timeoutMs < MIN_TIMEOUT_MS || result.timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error("timeout-out-of-range");
  }
  if (!isLowerHex(result.expectedSetDigest, 32)) {
    throw new Error("missing-or-invalid-expected-set-digest");
  }
  const hosts = new Set();
  const urls = new Set();
  const targets = [];
  for (const relay of result.relays) {
    const target = parseCanonicalPublicWssOrigin(relay);
    if (urls.has(target.url) || hosts.has(target.host)) {
      throw new Error("relay-hostnames-must-be-distinct");
    }
    urls.add(target.url);
    hosts.add(target.host);
    targets.push(target);
  }
  result.relays = targets;
  return result;
}

function parseCanonicalPublicWssOrigin(endpoint) {
  if (
    typeof endpoint !== "string" ||
    endpoint.length > 512 ||
    !endpoint.startsWith("wss://") ||
    /[^\x00-\x7f]/.test(endpoint) ||
    /[\x00-\x20\x7f]/.test(endpoint)
  ) {
    throw new Error("relay-must-be-canonical-public-wss");
  }
  const rest = endpoint.slice("wss://".length);
  if (
    rest.length === 0 ||
    rest.endsWith("/") ||
    /[@\\?#]/.test(rest)
  ) {
    throw new Error("relay-must-be-canonical-public-wss");
  }
  const authority = rest;
  if (
    authority.length === 0 ||
    authority.startsWith("[") ||
    (authority.match(/:/g) ?? []).length > 1
  ) {
    throw new Error("relay-must-be-canonical-public-wss");
  }
  const colon = authority.lastIndexOf(":");
  const host = colon === -1 ? authority : authority.slice(0, colon);
  const port = colon === -1 ? undefined : authority.slice(colon + 1);
  const labels = host.split(".");
  if (
    host.length === 0 ||
    host.length > 253 ||
    !host.includes(".") ||
    host.startsWith(".") ||
    host.endsWith(".") ||
    /^[0-9a-fA-FxX.]+$/.test(host) ||
    labels.some(
      (label) =>
        label.length === 0 ||
        label.length > 63 ||
        label.startsWith("-") ||
        label.endsWith("-") ||
        !/^[a-z0-9-]+$/.test(label),
    )
  ) {
    throw new Error("relay-must-be-canonical-public-wss");
  }
  if (port !== undefined) {
    const parsed = Number(port);
    if (
      !/^[0-9]+$/.test(port) ||
      !Number.isSafeInteger(parsed) ||
      parsed <= 0 ||
      parsed > 65_535 ||
      parsed === 443 ||
      String(parsed) !== port
    ) {
      throw new Error("relay-must-be-canonical-public-wss");
    }
  }
  return { url: endpoint, host };
}

function isLowerHex(value, bytes) {
  return (
    typeof value === "string" &&
    value.length === bytes * 2 &&
    /^[0-9a-f]+$/.test(value)
  );
}

function eventProjection(event) {
  if (event === null || typeof event !== "object" || Array.isArray(event)) {
    throw new Error("invalid-event-object");
  }
  const keys = Object.keys(event).sort();
  if (JSON.stringify(keys) !== JSON.stringify(EVENT_KEYS)) {
    throw new Error("invalid-event-fields");
  }
  if (
    !isLowerHex(event.id, 32) ||
    !isLowerHex(event.pubkey, 32) ||
    !isLowerHex(event.sig, 64) ||
    !Number.isSafeInteger(event.created_at) ||
    event.created_at <= 0 ||
    event.kind !== 30_078 ||
    !Array.isArray(event.tags) ||
    event.tags.some(
      (tag) =>
        !Array.isArray(tag) ||
        tag.length === 0 ||
        tag.some((value) => typeof value !== "string"),
    ) ||
    typeof event.content !== "string"
  ) {
    throw new Error("invalid-event-value");
  }
  const canonicalIdPreimage = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  const computedId = createHash("sha256").update(canonicalIdPreimage).digest("hex");
  if (computedId !== event.id) {
    throw new Error("invalid-event-id");
  }
  return JSON.stringify([
    event.id,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
    event.sig,
  ]);
}

function eventSetDigest(expected) {
  const identities = Array.from(expected.entries())
    .map(([id, projection]) => {
      const fields = JSON.parse(projection);
      return { id, signature: fields[6] };
    })
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  const count = Buffer.alloc(4);
  count.writeUInt32LE(identities.length);
  const hasher = createHash("sha256");
  hasher.update("bitcoinpir-directory-event-set-v1\0", "utf8");
  hasher.update(count);
  for (const identity of identities) {
    hasher.update(Buffer.from(identity.id, "hex"));
    hasher.update(Buffer.from(identity.signature, "hex"));
  }
  return hasher.digest("hex");
}

function readRegularFileBounded(path, remainingBytes) {
  let before;
  try {
    before = lstatSync(path, { bigint: true });
  } catch {
    throw new Error("artifact-stat-failed");
  }
  if (!before.isFile()) {
    throw new Error("artifact-not-regular-file");
  }
  if (
    before.size <= 0n ||
    before.size > BigInt(remainingBytes) ||
    typeof constants.O_NOFOLLOW !== "number" ||
    typeof constants.O_NONBLOCK !== "number"
  ) {
    throw new Error("artifact-size-or-platform-boundary");
  }

  let descriptor;
  try {
    descriptor = openSync(
      path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
  } catch {
    throw new Error("artifact-open-failed");
  }
  try {
    const opened = fstatSync(descriptor, { bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.mtimeNs !== before.mtimeNs ||
      opened.ctimeNs !== before.ctimeNs ||
      opened.size <= 0n ||
      opened.size > BigInt(remainingBytes)
    ) {
      throw new Error("artifact-file-changed");
    }
    const expectedLength = Number(opened.size);
    const buffer = Buffer.alloc(expectedLength + 1);
    let total = 0;
    try {
      while (total < buffer.length) {
        const count = readSync(
          descriptor,
          buffer,
          total,
          buffer.length - total,
          total,
        );
        if (count === 0) break;
        total += count;
      }
    } catch {
      throw new Error("artifact-read-failed");
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (
      total !== expectedLength ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeNs !== opened.mtimeNs ||
      after.ctimeNs !== opened.ctimeNs
    ) {
      buffer.fill(0);
      throw new Error("artifact-file-changed");
    }
    return buffer.subarray(0, total);
  } finally {
    closeSync(descriptor);
  }
}

function loadExpectedEvents(paths) {
  const expected = new Map();
  let totalArtifactBytes = 0;
  for (const path of paths) {
    const bytes = readRegularFileBounded(
      path,
      MAX_ARTIFACT_BYTES - totalArtifactBytes,
    );
    totalArtifactBytes += bytes.length;
    let artifact;
    try {
      artifact = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      bytes.fill(0);
      throw new Error("invalid-artifact-json");
    }
    bytes.fill(0);
    let messages;
    if (Array.isArray(artifact) && artifact.length === 2 && artifact[0] === "EVENT") {
      messages = [artifact];
    } else if (
      Array.isArray(artifact) &&
      artifact.length === 16 &&
      artifact.every(
        (message) => Array.isArray(message) && message.length === 2 && message[0] === "EVENT",
      )
    ) {
      messages = artifact;
    } else {
      throw new Error("invalid-artifact-shape");
    }
    for (const message of messages) {
      const event = message[1];
      const projection = eventProjection(event);
      if (expected.has(event.id)) {
        throw new Error("duplicate-event-id");
      }
      expected.set(event.id, projection);
      if (expected.size > MAX_EVENTS) {
        throw new Error("too-many-events");
      }
    }
  }
  return expected;
}

function readRelay(relay, expected, timeoutMs) {
  return new Promise((resolve, reject) => {
    const subscriptionId = `bpir-smoke-${randomBytes(8).toString("hex")}`;
    const seen = new Set();
    let totalReplyBytes = 0;
    let replyMessages = 0;
    let finished = false;
    const socket = new WebSocket(relay, {
      followRedirects: false,
      handshakeTimeout: timeoutMs,
      maxPayload: MAX_REPLY_MESSAGE_BYTES,
      perMessageDeflate: false,
    });
    const timer = setTimeout(() => finishError("timeout"), timeoutMs);

    function closeSocket() {
      if (socket.readyState !== WebSocket.CLOSED) {
        try {
          socket.terminate();
        } catch {
          // No later handler may send once `finished` is set.
        }
      }
    }

    function finishError(code) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      closeSocket();
      reject(new Error(code));
    }

    function finishOk() {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        socket.send(JSON.stringify(["CLOSE", subscriptionId]));
        socket.close(1000, "readback-complete");
        const forceClose = setTimeout(() => {
          if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
        }, 1_000);
        forceClose.unref();
        socket.once("close", () => clearTimeout(forceClose));
      } catch {
        // All required events and EOSE were already received; abort locally.
        closeSocket();
      }
      resolve();
    }

    socket.on("open", () => {
      if (finished) {
        closeSocket();
        return;
      }
      socket.send(
        JSON.stringify(["REQ", subscriptionId, { ids: Array.from(expected.keys()) }]),
      );
    });
    socket.on("message", (data, isBinary) => {
      if (finished) return;
      if (isBinary) {
        finishError("non-text-reply");
        return;
      }
      const reply = typeof data === "string" ? data : data.toString("utf8");
      const size = Buffer.byteLength(reply, "utf8");
      totalReplyBytes += size;
      replyMessages += 1;
      if (
        size > MAX_REPLY_MESSAGE_BYTES ||
        totalReplyBytes > MAX_REPLY_BYTES ||
        replyMessages > expected.size + 1
      ) {
        finishError("reply-bound-exceeded");
        return;
      }
      let response;
      try {
        response = JSON.parse(reply);
      } catch {
        finishError("invalid-json");
        return;
      }
      if (
        Array.isArray(response) &&
        response.length === 3 &&
        response[0] === "EVENT" &&
        response[1] === subscriptionId
      ) {
        const event = response[2];
        let projection;
        try {
          projection = eventProjection(event);
        } catch {
          finishError("invalid-event");
          return;
        }
        const expectedProjection = expected.get(event.id);
        if (expectedProjection === undefined) {
          finishError("unexpected-event");
        } else if (seen.has(event.id)) {
          finishError("duplicate-event");
        } else if (projection !== expectedProjection) {
          finishError("event-mismatch");
        } else {
          seen.add(event.id);
        }
        return;
      }
      if (
        Array.isArray(response) &&
        response.length === 2 &&
        response[0] === "EOSE" &&
        response[1] === subscriptionId
      ) {
        if (seen.size !== expected.size) {
          finishError("missing-event");
        } else {
          finishOk();
        }
        return;
      }
      finishError("unexpected-reply");
    });
    socket.on("error", () => finishError("transport-failed"));
    socket.on("ping", () => finishError("control-frame"));
    socket.on("pong", () => finishError("control-frame"));
    socket.on("close", () => {
      if (!finished) finishError("closed-before-eose");
    });
  });
}

async function main() {
  let args;
  let expected;
  try {
    args = parseArgs(process.argv.slice(2));
    expected = loadExpectedEvents(args.artifacts);
    if (eventSetDigest(expected) !== args.expectedSetDigest) {
      throw new Error("event-set-digest-mismatch");
    }
  } catch (error) {
    console.error(`nostr-readback: ${error.message}`);
    console.error(usage());
    process.exitCode = 2;
    return;
  }

  let failures = 0;
  const directoryMode = args.centralizedSingleRelay
    ? "centralized-single-relay"
    : "strict-multi-relay";
  const assurance = args.centralizedSingleRelay
    ? "centralized-degraded-no-relay-cross-check"
    : "multi-origin-split-view-capable";
  for (const relay of args.relays) {
    try {
      await readRelay(relay.url, expected, args.timeoutMs);
      console.log(
        `relay_host=${relay.host} event_count=${expected.size} event_set_digest_hex=${args.expectedSetDigest} directory_mode=${directoryMode} assurance=${assurance} result=ok`,
      );
    } catch (error) {
      failures += 1;
      console.error(
        `relay_host=${relay.host} event_count=${expected.size} event_set_digest_hex=${args.expectedSetDigest} directory_mode=${directoryMode} assurance=${assurance} result=${error.message}`,
      );
    }
  }
  if (failures !== 0) {
    process.exitCode = 1;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}

export { eventProjection, eventSetDigest, readRelay };
