import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  parsePublisherPrivateWebSocketResponse,
} from "./payment-v1-publisher-private-health-probe.mjs";

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const KEY = "MDEyMzQ1Njc4OWFiY2RlZg==";
const ACCEPT = createHash("sha1").update(`${KEY}${WS_GUID}`, "ascii").digest("base64");

function response(extraHeaders = [], suffix = "") {
  return Buffer.from([
    "HTTP/1.1 101 Switching Protocols",
    "Connection: keep-alive, Upgrade",
    "Upgrade: websocket",
    `Sec-WebSocket-Accept: ${ACCEPT}`,
    ...extraHeaders,
    "",
    suffix,
  ].join("\r\n"), "latin1");
}
test("private publisher response parser accepts only the complete RFC 6455 upgrade", () => {
  assert.equal(parsePublisherPrivateWebSocketResponse(response(), KEY), true);
  assert.equal(
    parsePublisherPrivateWebSocketResponse(Buffer.from("HTTP/1.1 101 Switching", "ascii"), KEY),
    null,
  );
});

for (const [label, bytes, expected] of [
  [
    "bare LF",
    response(["Connection-Guard: accepted\n"]),
    /bare carriage return or line feed/u,
  ],
  [
    "bare CR",
    response(["Connection-Guard: accepted\r"]),
    /bare carriage return or line feed/u,
  ],
  [
    "unrequested subprotocol",
    response(["Sec-WebSocket-Protocol: nostr"]),
    /unrequested protocol or extension/u,
  ],
  [
    "unrequested extension",
    response(["Sec-WebSocket-Extensions: permessage-deflate"]),
    /unrequested protocol or extension/u,
  ],
  [
    "bytes after headers",
    response([], "unexpected"),
    /unexpected bytes after its headers/u,
  ],
]) {
  test(`private publisher response parser rejects ${label}`, () => {
    assert.throws(
      () => parsePublisherPrivateWebSocketResponse(bytes, KEY),
      expected,
    );
  });
}
