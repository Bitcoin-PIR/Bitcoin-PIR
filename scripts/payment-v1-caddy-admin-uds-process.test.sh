#!/bin/sh

set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH='' cd -- "$script_directory/.." && pwd -P)
fixture="$script_directory/fixtures/payment-v1-caddy-admin-uds-process.Caddyfile"
probe="$script_directory/payment-v1-caddy-admin-uds-probe.mjs"
gate="$script_directory/payment-v1-caddy-admin-uds-gate.mjs"
import_fixture="$script_directory/fixtures/payment-v1-caddy-admin-uds-import-main.Caddyfile"
import_override="$script_directory/fixtures/payment-v1-caddy-admin-uds-import-override.Caddyfile"
caddy_image="caddy@sha256:844f60b64e4724a5aa8245e019dace0d3f199f7433ce6c57676cb30a920dbad9"
node_image="node@sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e"
suffix="$$"
container="bpir-caddy-admin-uds-$suffix"
volume="bpir-caddy-admin-uds-$suffix"
socket="/run/bitcoinpir-caddy-admin/admin.sock"
log_sentinel="bitcoinpir-caddy-admin-uds-do-not-log-$suffix"

cleanup() {
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm --force "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

test -f "$fixture"
test -f "$probe"
test -f "$gate"
test -f "$import_fixture"
test -f "$import_override"
test -d "$repository/.git" || test -f "$repository/.git"
gate_sha=$(node -e 'const { createHash } = require("node:crypto"); const { readFileSync } = require("node:fs"); process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"));' "$gate")
case "$gate_sha" in
  *[!0-9a-f]*|"")
    echo "caddy-admin-uds-process=FAIL: invalid gate SHA-256" >&2
    exit 1
    ;;
esac
if test "${#gate_sha}" -ne 64; then
  echo "caddy-admin-uds-process=FAIL: invalid gate SHA-256 length" >&2
  exit 1
fi

if BPIR_ADMIN_GATE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
  node "$probe" <"$gate" >/dev/null 2>&1; then
  echo "caddy-admin-uds-process=FAIL: probe accepted a wrong gate digest" >&2
  exit 1
fi
if BPIR_ADMIN_GATE_SHA256="$gate_sha" node "$probe" </dev/null >/dev/null 2>&1; then
  echo "caddy-admin-uds-process=FAIL: probe accepted empty gate stdin" >&2
  exit 1
fi
if dd if="$gate" bs=1 count=64 2>/dev/null \
  | BPIR_ADMIN_GATE_SHA256="$gate_sha" node "$probe" >/dev/null 2>&1; then
  echo "caddy-admin-uds-process=FAIL: probe accepted truncated gate stdin" >&2
  exit 1
fi

BPIR_IMPORT_FIXTURE="$import_fixture" BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
  node --input-type=module -e '
    import { readFileSync } from "node:fs";
    import { pathToFileURL } from "node:url";
    const { buildHardenedCaddyfile } = await import(pathToFileURL(process.env.BPIR_GATE));
    try {
      buildHardenedCaddyfile(readFileSync(process.env.BPIR_IMPORT_FIXTURE), "replace-explicit-tcp-admin");
      throw new Error("gate accepted a Caddyfile import override");
    } catch (error) {
      if (!/must not contain import directives/u.test(error.message)) throw error;
    }
  '

# shellcheck disable=SC2016 # JavaScript template literals are intentionally single-quoted.
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --volume "$import_fixture:/etc/caddy/Caddyfile:ro" \
  --volume "$import_override:/etc/caddy/payment-v1-caddy-admin-uds-import-override.Caddyfile:ro" \
  --entrypoint /usr/bin/caddy \
  "$caddy_image" \
  adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
  | node -e 'const chunks=[]; process.stdin.on("data", chunk => chunks.push(chunk)); process.stdin.on("end", () => { const adapted=JSON.parse(Buffer.concat(chunks)); if (adapted?.admin?.listen !== "127.0.0.1:2019") throw new Error(`real Caddy import did not override admin as expected: ${adapted?.admin?.listen}`); });'

# Keep the policy lexer pinned to the real Caddy v2.11.4 tokenization table.
# Every non-canonical Unicode whitespace recognized by Go must be rejected by
# the gate, while the pinned binary must demonstrate that it would otherwise
# dispatch the hidden second admin directive. Quoted directive names are also
# real Caddy tokens and receive the same fail-closed treatment.
# shellcheck disable=SC2016 # JavaScript template literals are intentionally single-quoted.
BPIR_CADDY_IMAGE="$caddy_image" BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
  node --input-type=module -e '
    import { spawnSync } from "node:child_process";
    import { pathToFileURL } from "node:url";
    const { buildHardenedCaddyfile } = await import(pathToFileURL(process.env.BPIR_GATE));
    const dockerArgv = [
      "run", "--rm", "-i", "--network", "none", "--read-only",
      "--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
      "--security-opt", "no-new-privileges", "--entrypoint", "/usr/bin/caddy",
      process.env.BPIR_CADDY_IMAGE, "adapt", "--config", "-", "--adapter", "caddyfile",
    ];
    const cases = [
      0x000b, 0x000c, 0x0085, 0x00a0, 0x1680,
      0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
      0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f,
      0x3000,
    ].map((codePoint) => ({
      expected: /non-canonical Caddy whitespace/u,
      label: `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`,
      token: `admin${String.fromCodePoint(codePoint)}127.0.0.1:2020`,
    }));
    cases.push(
      { expected: /quoted admin directives/u, label: "double-quoted-admin", token: "\"admin\" 127.0.0.1:2020" },
      { expected: /quoted admin directives/u, label: "backtick-admin", token: `${String.fromCodePoint(96)}admin${String.fromCodePoint(96)} 127.0.0.1:2020` },
    );
    for (const current of cases) {
      const preimage = Buffer.from(`{\n\tadmin 127.0.0.1:2019\n\t${current.token}\n}\n`, "utf8");
      let rejected = false;
      try {
        buildHardenedCaddyfile(preimage, "replace-explicit-tcp-admin");
      } catch (error) {
        if (!current.expected.test(error.message)) throw error;
        rejected = true;
      }
      if (!rejected) throw new Error(`gate accepted hidden second admin: ${current.label}`);
      const real = spawnSync("docker", dockerArgv, {
        encoding: "utf8",
        input: preimage,
        maxBuffer: 2 * 1024 * 1024,
        timeout: 30_000,
      });
      if (real.status !== 0) {
        throw new Error(`pinned Caddy did not parse ${current.label}: ${real.stderr.trim()}`);
      }
      const adapted = JSON.parse(real.stdout);
      if (adapted?.admin?.listen !== "127.0.0.1:2020") {
        throw new Error(`pinned Caddy did not dispatch hidden second admin ${current.label}`);
      }
    }
  '

# Canonicalize the exact v2.11.4 adapter output now, then require the live UDS
# readback from the same candidate to reproduce its digest and byte length.
# shellcheck disable=SC2016 # JavaScript template literals are intentionally single-quoted.
expected_adapted_tuple=$(
  docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges \
    --volume "$fixture:/etc/caddy/Caddyfile:ro" \
    --entrypoint /usr/bin/caddy \
    "$caddy_image" \
    adapt --config /etc/caddy/Caddyfile --adapter caddyfile \
    | BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
      node --input-type=module -e '
        import { pathToFileURL } from "node:url";
        const chunks = [];
        for await (const chunk of process.stdin) chunks.push(chunk);
        const { canonicalizeAdaptedCaddyJson, sha256 } =
          await import(pathToFileURL(process.env.BPIR_GATE));
        const canonical = canonicalizeAdaptedCaddyJson(Buffer.concat(chunks), "real Caddy adapted JSON");
        process.stdout.write(`${sha256(canonical)}:${canonical.length}`);
      '
)
test -n "$expected_adapted_tuple"

docker volume create "$volume" >/dev/null
test "$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$node_image" node --version)" = "v22.22.2"
docker run --detach \
  --name "$container" \
  --network none \
  --read-only \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --tmpfs /config:rw,nosuid,nodev,noexec,mode=0700 \
  --tmpfs /data:rw,nosuid,nodev,noexec,mode=0700 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,mode=0700 \
  --volume "$volume:/run/bitcoinpir-caddy-admin" \
  --volume "$fixture:/etc/caddy/Caddyfile:ro" \
  --env "BPIR_LOG_SECRET_SENTINEL=$log_sentinel" \
  --entrypoint /bin/sh \
  "$caddy_image" \
  -ec 'test "$(caddy version | awk "{print \$1}")" = v2.11.4; chmod 0700 /run/bitcoinpir-caddy-admin; umask 0077; unset CADDY_ADMIN; exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile' \
  >/dev/null

attempt=0
while ! docker exec "$container" test -S "$socket" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if test "$attempt" -ge 100; then
    docker logs "$container" >&2
    echo "caddy-admin-uds-process=FAIL: admin socket did not appear" >&2
    exit 1
  fi
  sleep 0.1
done

test "$(docker exec "$container" stat -c '%u:%g:%a:%F' /run/bitcoinpir-caddy-admin)" = "0:0:700:directory"
test "$(docker exec "$container" stat -c '%u:%g:%a:%F' "$socket")" = "0:0:200:socket"
test "$(docker exec "$container" awk '/^Uid:/ {print $2 ":" $3 ":" $4 ":" $5}' /proc/1/status)" = "0:0:0:0"
test "$(docker exec "$container" awk '/^Gid:/ {print $2 ":" $3 ":" $4 ":" $5}' /proc/1/status)" = "0:0:0:0"
test "$(docker exec "$container" sh -c 'tr "\000" " " </proc/1/cmdline')" = "caddy run --config /etc/caddy/Caddyfile --adapter caddyfile "
test "$(docker exec "$container" sh -c 'tr "\000" "\n" </proc/1/environ | grep -c "^CADDY_ADMIN=" || true')" = "0"
if docker logs "$container" 2>&1 | grep -F -e BPIR_LOG_SECRET_SENTINEL -e "$log_sentinel" >/dev/null; then
  echo "caddy-admin-uds-process=FAIL: service environment leaked to logs" >&2
  exit 1
fi
test "$(docker exec "$container" sh -c 'awk '\''$2 ~ /:07E3$/ && $4 == "0A" {count++} END {print count+0}'\'' /proc/net/tcp /proc/net/tcp6')" = "0"
test "$(docker exec "$container" curl --fail --silent --show-error --max-time 3 http://127.0.0.1:18080/)" = "bitcoinpir-caddy-admin-uds-ok"
# shellcheck disable=SC2016 # JavaScript template literals are intentionally single-quoted.
docker exec "$container" curl --fail --silent --show-error --max-time 3 \
    --unix-socket "$socket" http://localhost/config/ \
  | BPIR_EXPECTED_ADAPTED_TUPLE="$expected_adapted_tuple" \
    BPIR_GATE="$script_directory/payment-v1-caddy-admin-uds-gate.mjs" \
    node --input-type=module -e '
      import { pathToFileURL } from "node:url";
      const chunks = [];
      for await (const chunk of process.stdin) chunks.push(chunk);
      const { canonicalizeAdaptedCaddyJson, sha256 } =
        await import(pathToFileURL(process.env.BPIR_GATE));
      const canonical = canonicalizeAdaptedCaddyJson(Buffer.concat(chunks), "live Caddy admin readback");
      const observed = `${sha256(canonical)}:${canonical.length}`;
      if (observed !== process.env.BPIR_EXPECTED_ADAPTED_TUPLE) {
        throw new Error("live Caddy admin readback drifted from the exact candidate adapter output");
      }
    '

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --cap-add SETGID \
  --cap-add SETPCAP \
  --cap-add SETUID \
  --security-opt no-new-privileges \
  --volume "$volume:/run/bitcoinpir-caddy-admin" \
  --volume "$repository:/work:ro" \
  --workdir /work \
  "$node_image" \
  node /work/scripts/payment-v1-caddy-admin-uds-real-adapter.test.mjs

docker exec "$container" chmod 0755 /run/bitcoinpir-caddy-admin
docker exec "$container" chmod 0666 "$socket"
docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --cap-add SETGID \
  --cap-add SETPCAP \
  --cap-add SETUID \
  --security-opt no-new-privileges \
  --volume "$volume:/run/bitcoinpir-caddy-admin" \
  --volume "$repository:/work:ro" \
  --workdir /work \
  --env BPIR_REAL_ADAPTER_MODE=permission-drift \
  "$node_image" \
  node /work/scripts/payment-v1-caddy-admin-uds-real-adapter.test.mjs
docker exec "$container" chmod 0700 /run/bitcoinpir-caddy-admin
docker exec "$container" chmod 0200 "$socket"

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "$volume:/run/bitcoinpir-caddy-admin" \
  --volume "$probe:/probe.mjs:ro" \
  --volume "$gate:/gate.mjs:ro" \
  --env "BPIR_ADMIN_GATE_SHA256=$gate_sha" \
  --env BPIR_EXPECT_ADMIN_PROBE=root-readback \
  --env BPIR_ADMIN_PROBE_LABEL=root \
  --entrypoint /bin/sh \
  "$node_image" \
  -ec 'exec node /probe.mjs < /gate.mjs'

for identity in \
  cloudflared:52901 \
  directory:52903 \
  issuer:52904 \
  pir:52902 \
  provider:52905 \
  source-fair:52906
do
  name=${identity%:*}
  uid=${identity#*:}
  docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user "$uid:$uid" \
    --volume "$volume:/run/bitcoinpir-caddy-admin" \
    --volume "$probe:/probe.mjs:ro" \
    --volume "$gate:/gate.mjs:ro" \
    --env "BPIR_ADMIN_GATE_SHA256=$gate_sha" \
    --env BPIR_EXPECT_ADMIN_PROBE=EACCES \
    --env "BPIR_ADMIN_PROBE_LABEL=$name" \
    --entrypoint /bin/sh \
    "$node_image" \
    -ec 'exec node /probe.mjs < /gate.mjs'
done

if docker exec "$container" curl --fail --silent --max-time 1 http://127.0.0.1:2019/config/ >/dev/null 2>&1; then
  echo "caddy-admin-uds-process=FAIL: IPv4 TCP admin remained reachable" >&2
  exit 1
fi
if docker exec "$container" curl --fail --silent --max-time 1 'http://[::1]:2019/config/' >/dev/null 2>&1; then
  echo "caddy-admin-uds-process=FAIL: IPv6 TCP admin remained reachable" >&2
  exit 1
fi

main_pid_before=$(docker inspect --format '{{.State.Pid}}' "$container")
docker exec "$container" caddy reload \
  --config /etc/caddy/Caddyfile \
  --adapter caddyfile \
  --address unix//run/bitcoinpir-caddy-admin/admin.sock
main_pid_after=$(docker inspect --format '{{.State.Pid}}' "$container")
test "$main_pid_after" = "$main_pid_before"
test "$(docker exec "$container" stat -c '%u:%g:%a:%F' "$socket")" = "0:0:200:socket"
test "$(docker exec "$container" sh -c 'awk '\''$2 ~ /:07E3$/ && $4 == "0A" {count++} END {print count+0}'\'' /proc/net/tcp /proc/net/tcp6')" = "0"

docker run --rm \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "$volume:/run/bitcoinpir-caddy-admin" \
  --volume "$probe:/probe.mjs:ro" \
  --volume "$gate:/gate.mjs:ro" \
  --env "BPIR_ADMIN_GATE_SHA256=$gate_sha" \
  --env BPIR_EXPECT_ADMIN_PROBE=root-readback \
  --env BPIR_ADMIN_PROBE_LABEL=root-after-reload \
  --entrypoint /bin/sh \
  "$node_image" \
  -ec 'exec node /probe.mjs < /gate.mjs'

if docker logs "$container" 2>&1 | grep -F -e BPIR_LOG_SECRET_SENTINEL -e "$log_sentinel" >/dev/null; then
  echo "caddy-admin-uds-process=FAIL: reload leaked service environment to logs" >&2
  exit 1
fi

echo "caddy-admin-uds-process=PASS caddy=v2.11.4 node=v22.22.2 root=readback adapted-canonical=exact nonroot=EACCES tcp2019=absent reload=uds environ-log=absent import-override=proven-and-rejected unicode-and-quoted-admin=proven-and-rejected"
