#!/usr/bin/env node

// Operator readback of the Nostr service directory (docs/DIRECTORY_PROTOCOL.md).
// Reads the full 16-shard catalog from each relay as the browser does, verifies
// it with the browser's WASM verifier and prints what a client would see; with
// --artifact, also checks that every relay serves each event of the given
// `bpir-admin directory-artifact` outputs. Loads no key and publishes nothing.
// Needs the WASM package:
//   wasm-pack build crates/sdk/wasm --target web --out-dir pkg

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

const USAGE = `Usage:
  node scripts/directory-readback.mjs \\
    --directory-pubkey-hex HEX \\
    --relay wss://relay-one.example [--relay wss://relay-two.example ...] \\
    [--centralized-single-relay] [--artifact FILE ...] [--timeout-ms 10000]

Strict mode (the default) takes two to eight distinct relays and compares
their views; --centralized-single-relay takes exactly one. Exit status 1 when
a relay, shard or artifact event is missing or rejected.`;

function readCatalog(url, requests, timeoutMs) {
  return new Promise((resolve, reject) => {
    const subscriptions = requests.map((request) => JSON.parse(request)[1]);
    const open = new Set(subscriptions);
    const events = [];
    const socket = new WebSocket(url);
    const finish = (error) => {
      clearTimeout(timer);
      socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
      try {
        if (!error) for (const id of subscriptions) socket.send(JSON.stringify(["CLOSE", id]));
        socket.close();
      } catch {
        // The connection is gone either way.
      }
      if (error) reject(new Error(error));
      else resolve(events);
    };
    const timer = setTimeout(() => finish("no EOSE on every shard in time"), timeoutMs);
    socket.onopen = () => requests.forEach((request) => socket.send(request));
    socket.onmessage = ({ data }) => {
      let message;
      try {
        message = JSON.parse(data);
      } catch {
        return finish("malformed JSON");
      }
      const [type, id] = Array.isArray(message) ? message : [];
      if (type === "EVENT" && open.has(id)) events.push(data);
      else if (type === "EOSE" && open.delete(id)) {
        if (open.size === 0) finish(null);
      } else if (type === "CLOSED") finish(`subscription closed: ${message[2] ?? ""}`);
      else if (type === "EVENT" || type === "EOSE") finish(`unexpected ${type}`);
    };
    socket.onerror = () => finish("WebSocket error");
    socket.onclose = () => finish("closed before EOSE");
  });
}

/** Event ids of one artifact: an `["EVENT", event]` message or an array of them. */
function artifactEventIds(path) {
  const artifact = JSON.parse(readFileSync(path, "utf8"));
  const messages = artifact[0] === "EVENT" ? [artifact] : artifact;
  return messages.map((message) => {
    if (message[0] !== "EVENT" || typeof message[1]?.id !== "string") {
      throw new Error(`${path} is not an EVENT message or an array of them`);
    }
    return message[1].id;
  });
}

async function main() {
  let args;
  try {
    ({ values: args } = parseArgs({
      options: {
        "directory-pubkey-hex": { type: "string" },
        relay: { type: "string", multiple: true, default: [] },
        "centralized-single-relay": { type: "boolean", default: false },
        artifact: { type: "string", multiple: true, default: [] },
        "timeout-ms": { type: "string", default: "10000" },
        help: { type: "boolean", short: "h", default: false },
      },
    }));
  } catch (error) {
    console.error(`directory-readback: ${error.message}\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  const key = args["directory-pubkey-hex"] ?? "";
  const relays = args.relay;
  const centralized = args["centralized-single-relay"];
  const timeoutMs = Number(args["timeout-ms"]);
  const relaysOk = centralized
    ? relays.length === 1
    : relays.length >= 2 && relays.length <= 8 && new Set(relays).size === relays.length;
  if (!/^[0-9a-f]{64}$/.test(key) || !relaysOk || !(timeoutMs > 0)) {
    console.error(USAGE);
    return 2;
  }
  const artifactIds = args.artifact.flatMap(artifactEventIds);

  const pkg = new URL("../crates/sdk/wasm/pkg/", import.meta.url);
  const sdk = await import(new URL("pir_sdk_wasm.js", pkg).href);
  sdk.initSync({ module: readFileSync(new URL("pir_sdk_wasm_bg.wasm", pkg)) });
  const keyBytes = Uint8Array.from(Buffer.from(key, "hex"));
  const requests = sdk.directoryCatalogRequestsV1(keyBytes);

  let failures = 0;
  const views = [];
  const viewRelays = [];
  for (const [index, read] of (await Promise.allSettled(
    relays.map((url) => readCatalog(url, requests, timeoutMs)),
  )).entries()) {
    if (read.status === "rejected") {
      failures += 1;
      console.log(`relay=${relays[index]} result=failed reason=${JSON.stringify(read.reason.message)}`);
      continue;
    }
    views.push(read.value);
    viewRelays.push(relays[index]);
    const served = new Set(read.value.map((message) => JSON.parse(message)[2]?.id));
    const missing = artifactIds.filter((id) => !served.has(id));
    failures += missing.length;
    console.log(
      `relay=${relays[index]} result=complete events=${read.value.length}`
        + (artifactIds.length ? ` artifact_events=${artifactIds.length} missing=${missing.length}` : ""),
    );
    for (const id of missing) console.log(`relay=${relays[index]} missing_event_id=${id}`);
  }

  const catalog = JSON.parse(sdk.verifyDirectoryCatalogV1(
    JSON.stringify(views),
    undefined,
    keyBytes,
    BigInt(Math.floor(Date.now() / 1000)),
  ));
  const degraded = centralized || catalog.shards.length < 16
    || catalog.shards.some((shard) => shard.views < 2);
  console.log(
    `catalog mode=${centralized ? "centralized-single-relay" : "strict-multi-relay"} degraded=${degraded}`
      + ` shards=${catalog.shards.length}/16 valid_until=${catalog.validUntil}`,
  );
  for (const shard of catalog.shards) {
    console.log(`shard=${shard.shard} epoch=${shard.epoch} views=${shard.views} event_id=${shard.eventId}`);
  }
  for (const entry of catalog.entries) {
    const hints = entry.hints;
    console.log(
      `provider=${entry.providerId} server_id=${entry.serverId} sequence=${entry.directorySequence}`
        + ` role=${hints[0]?.role ?? "-"} attestation=${hints[0]?.attestation ?? "-"}`
        + ` backends=${hints.map((hint) => `${hint.backend}:${hint.access}`).join(",") || "-"}`
        + ` health=${entry.health} endpoints=${entry.endpoints.join(",")}`
        + ` valid_until=${entry.validUntil} event_id=${entry.eventId}`,
    );
  }
  for (const rejection of catalog.rejected) {
    failures += 1;
    const relay = rejection.relay === null ? "-" : viewRelays[rejection.relay];
    console.log(
      `rejected relay=${relay} shard=${rejection.shard ?? "-"} reason=${JSON.stringify(rejection.reason)}`,
    );
  }
  return failures === 0 ? 0 : 1;
}

process.exitCode = await main();
