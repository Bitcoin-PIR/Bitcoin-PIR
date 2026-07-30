import assert from "node:assert/strict";
import { once } from "node:events";
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import test from "node:test";

import {
  CADDY_ADMIN_UDS_TEST_ONLY_IO as realFs,
} from "./payment-v1-caddy-admin-uds-transaction.mjs";

function withTemporaryDirectory(fn) {
  const directory = mkdtempSync(join(tmpdir(), "bpir-caddy-admin-uds-"));
  chmodSync(directory, 0o700);
  try {
    return fn(directory);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
}

function contentPin(snapshot, path) {
  return {
    gid: snapshot.gid,
    mode: snapshot.mode,
    path,
    sha256: snapshot.sha256,
    size: snapshot.size,
    uid: snapshot.uid,
  };
}

test("real filesystem exclusive publication exposes one final single-link inode", () => {
  withTemporaryDirectory((directory) => {
    const pendingPath = join(directory, ".receipt.pending");
    const finalPath = join(directory, "receipt.json");
    writeFileSync(pendingPath, "receipt\n", { mode: 0o600 });

    const published = realFs.publishPreparedExclusive({ path: finalPath, pendingPath });
    assert.equal(published.snapshot.nlink, 1);
    assert.equal(existsSync(pendingPath), false);
    assert.equal(readFileSync(finalPath, "utf8"), "receipt\n");
    assert.equal(Number(lstatSync(finalPath).nlink), 1);

    const secondPending = join(directory, ".second.pending");
    writeFileSync(secondPending, "other\n", { mode: 0o600 });
    assert.throws(
      () => realFs.publishPreparedExclusive({ path: finalPath, pendingPath: secondPending }),
      (error) => error?.code === "EEXIST" && error.pending_path === secondPending,
    );
    assert.equal(readFileSync(finalPath, "utf8"), "receipt\n");
    assert.equal(readFileSync(secondPending, "utf8"), "other\n");
  });
});

test("real filesystem reads and publication reject hard-linked inputs", () => {
  withTemporaryDirectory((directory) => {
    const pendingPath = join(directory, ".receipt.pending");
    const aliasPath = join(directory, ".receipt.alias");
    const finalPath = join(directory, "receipt.json");
    writeFileSync(pendingPath, "receipt\n", { mode: 0o600 });
    linkSync(pendingPath, aliasPath);
    assert.throws(
      () => realFs.readRegular(pendingPath),
      /single-link regular file/u,
    );
    assert.throws(
      () => realFs.publishPreparedExclusive({ path: finalPath, pendingPath }),
      /single-link regular file/u,
    );
    assert.equal(existsSync(finalPath), false);
  });
});

test("real filesystem replacement atomically installs the descriptor-verified candidate", () => {
  withTemporaryDirectory((directory) => {
    const targetPath = join(directory, "Caddyfile");
    const preparedPath = join(directory, ".Caddyfile.candidate");
    writeFileSync(targetPath, "old\n", { mode: 0o644 });
    writeFileSync(preparedPath, "candidate\n", { mode: 0o644 });
    chmodSync(targetPath, 0o644);
    chmodSync(preparedPath, 0o644);
    const current = realFs.readRegular(targetPath);
    const prepared = realFs.readRegular(preparedPath);

    const installed = realFs.replacePrepared({
      expectedCurrent: current.snapshot,
      pin: contentPin(prepared.snapshot, targetPath),
      preparedPath,
      targetPath,
    });
    assert.equal(installed.bytes.toString("utf8"), "candidate\n");
    assert.equal(installed.snapshot.nlink, 1);
    assert.equal(existsSync(preparedPath), false);
    assert.equal(readFileSync(targetPath, "utf8"), "candidate\n");
  });
});

test("Linux executes the exact descriptor whose full snapshot was approved", {
  skip: process.platform !== "linux",
}, () => {
  withTemporaryDirectory((directory) => {
    const executablePath = join(directory, "probe.sh");
    writeFileSync(executablePath, "#!/bin/sh\nprintf 'descriptor-ok\\n'\n", { mode: 0o755 });
    chmodSync(executablePath, 0o755);
    const pin = realFs.readRegular(executablePath).snapshot;
    const result = realFs.runPinnedBinary(pin, []);
    assert.equal(result.status, 0);
    assert.equal(result.stderr.length, 0);
    assert.equal(result.stdout.toString("utf8"), "descriptor-ok\n");
  });
});

test("bounded HTTP probe rejects a partial response instead of hanging", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "Content-Length": "32" });
    response.write("partial");
    response.socket.destroy();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address !== null && typeof address === "object");
  try {
    await assert.rejects(
      realFs.boundedHttpRequest({
        hostname: "127.0.0.1",
        method: "GET",
        path: "/",
        port: address.port,
        protocol: "http:",
      }),
      /aborted|closed|socket hang up|ECONNRESET/u,
    );
  } finally {
    server.close();
    await once(server, "close");
  }
});
