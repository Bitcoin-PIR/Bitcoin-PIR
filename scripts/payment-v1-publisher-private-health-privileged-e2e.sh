#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != Linux || "$(id -u)" != 0 ]]; then
  echo "publisher private-health e2e requires disposable Linux with euid 0" >&2
  exit 2
fi
if [[ "${BPIR_PUBLISHER_PRIVATE_HEALTH_TEST:-}" != "I_UNDERSTAND_DISPOSABLE_HOST" ]]; then
  echo "set BPIR_PUBLISHER_PRIVATE_HEALTH_TEST=I_UNDERSTAND_DISPOSABLE_HOST" >&2
  exit 2
fi
if [[ ! -f /.dockerenv && "${BPIR_PUBLISHER_NETNS_DISPOSABLE_VM:-}" != "yes" ]]; then
  echo "refusing a non-container host without BPIR_PUBLISHER_NETNS_DISPOSABLE_VM=yes" >&2
  exit 2
fi

for command in cc ip ldd openssl readlink sha256sum stat update-ca-certificates; do
  if ! command -v "$command" >/dev/null; then
    echo "missing required private-health test command: $command" >&2
    exit 2
  fi
done
if [[ ! -x /usr/bin/node ]]; then
  echo "missing exact /usr/bin/node private-health runtime" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
caddy="${BPIR_CADDY_BIN:-/usr/local/bin/caddy}"
if [[ ! -x "$caddy" ]]; then
  echo "missing executable Caddy test binary: $caddy" >&2
  exit 2
fi
if [[ "$("$caddy" version | awk '{print $1}')" != v2.11.4 ]]; then
  echo "publisher private-health e2e requires Caddy v2.11.4" >&2
  exit 2
fi

readonly namespace=bpir-directory-publisher
readonly host_interface=bpirpubhealthh
readonly client_interface=bpirpubhealthc
readonly publisher_host=publisher.payment-v1.test
readonly launcher_manifest=/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256
readonly executor=/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs
readonly integrated_gate=/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs
readonly publisher_gate=/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs
readonly schema_validator=/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs
readonly health_probe=/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs
readonly node_loader_closure=/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256
readonly managed_template="$repo_root/deploy/payment-v1/edge/integrated-existing-bhtm-caddy.managed.Caddyfile.in"
readonly test_ca=/usr/local/share/ca-certificates/bitcoinpir-publisher-health-e2e.crt

test_root="$(mktemp -d /tmp/bitcoinpir-publisher-private-health.XXXXXX)"
caddy_pid=""
backend_pid=""
ca_store_changed=0
namespace_created=0
host_interface_created=0
namespace_identity=""
host_interface_ifindex=""
host_interface_mac=""
launcher=""
created_files=()
created_directories=()
declare -A created_file_identities=()
declare -A created_directory_identities=()

reserve_output_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    echo "publisher private-health e2e refuses existing output: $path" >&2
    exit 1
  fi
  created_files+=("$path")
}

record_created_file() {
  local path="$1"
  local identity
  identity="$(stat -Lc '%d:%i' -- "$path")"
  created_file_identities["$path"]="$identity"
}

ensure_test_directory() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    if [[ ! -d "$path" || -L "$path" ]]; then
      echo "publisher private-health e2e refuses non-directory parent: $path" >&2
      exit 1
    fi
    return
  fi
  mkdir --mode=0755 -- "$path"
  created_directories+=("$path")
  created_directory_identities["$path"]="$(stat -Lc '%d:%i' -- "$path")"
}

cleanup() {
  local cleanup_status=$?
  local cleanup_failed=0
  local expected_identity path pid
  trap - EXIT
  set +e
  pid="$caddy_pid"
  caddy_pid=""
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  pid="$backend_pid"
  backend_pid=""
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  if [[ "$namespace_created" -eq 1 &&
        ( -e "/run/netns/$namespace" || -L "/run/netns/$namespace" ) ]]; then
    if [[ ! -L "/run/netns/$namespace" && -n "$namespace_identity" &&
          "$(stat -Lc '%d:%i' -- "/run/netns/$namespace" 2>/dev/null || true)" == "$namespace_identity" ]]; then
      ip netns delete "$namespace" >/dev/null 2>&1 || cleanup_failed=1
    else
      echo "publisher private-health e2e preserves drifted publisher namespace" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$namespace_created" -eq 1 &&
        ( -e "/run/netns/$namespace" || -L "/run/netns/$namespace" ) ]]; then
    cleanup_failed=1
  fi
  if [[ "$host_interface_created" -eq 1 &&
        ( -e "/sys/class/net/$host_interface" || -L "/sys/class/net/$host_interface" ) ]]; then
    if [[ -n "$host_interface_ifindex" && -n "$host_interface_mac" &&
          "$(cat "/sys/class/net/$host_interface/ifindex" 2>/dev/null || true)" == "$host_interface_ifindex" &&
          "$(cat "/sys/class/net/$host_interface/address" 2>/dev/null || true)" == "$host_interface_mac" ]]; then
      ip link delete "$host_interface" >/dev/null 2>&1 || cleanup_failed=1
    else
      echo "publisher private-health e2e preserves drifted publisher host interface" >&2
      cleanup_failed=1
    fi
  fi
  if [[ "$host_interface_created" -eq 1 &&
        ( -e "/sys/class/net/$host_interface" || -L "/sys/class/net/$host_interface" ) ]]; then
    cleanup_failed=1
  fi
  for ((index = ${#created_files[@]} - 1; index >= 0; index--)); do
    path="${created_files[index]}"
    expected_identity="${created_file_identities[$path]:-}"
    if [[ -n "$expected_identity" && -e "$path" && ! -L "$path" &&
          "$(stat -Lc '%d:%i' -- "$path" 2>/dev/null || true)" == "$expected_identity" ]]; then
      rm -f -- "$path" || cleanup_failed=1
    elif [[ -e "$path" || -L "$path" ]]; then
      echo "publisher private-health e2e preserves drifted/unconfirmed output: $path" >&2
      cleanup_failed=1
    fi
  done
  if [[ "$ca_store_changed" -eq 1 ]]; then
    update-ca-certificates --fresh >/dev/null 2>&1 || cleanup_failed=1
  fi
  for ((index = ${#created_directories[@]} - 1; index >= 0; index--)); do
    path="${created_directories[index]}"
    expected_identity="${created_directory_identities[$path]:-}"
    if [[ -n "$expected_identity" && -d "$path" && ! -L "$path" &&
          "$(stat -Lc '%d:%i' -- "$path" 2>/dev/null || true)" == "$expected_identity" ]]; then
      rmdir -- "$path" >/dev/null 2>&1 || cleanup_failed=1
    elif [[ -e "$path" || -L "$path" ]]; then
      echo "publisher private-health e2e preserves drifted test directory: $path" >&2
      cleanup_failed=1
    fi
  done
  rm -rf -- "$test_root" || cleanup_failed=1
  if [[ "$cleanup_failed" -eq 1 && "$cleanup_status" -eq 0 ]]; then
    cleanup_status=1
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT

if ! netns_listing="$(ip netns list)"; then
  echo "publisher private-health e2e cannot enumerate network namespaces" >&2
  exit 1
fi
if awk '{print $1}' <<<"$netns_listing" | grep -Fx "$namespace" >/dev/null 2>&1 ||
   [[ -e "/sys/class/net/$host_interface" || -L "/sys/class/net/$host_interface" ]]; then
  echo "publisher private-health e2e refuses an existing production-named netns or veth" >&2
  exit 1
fi

cc -std=c11 -O2 -static -Wall -Wextra -Werror \
  "$repo_root/scripts/payment-v1-publisher-netns-launcher.c" \
  -o "$test_root/payment-v1-publisher-netns-launcher"
launcher_sha256="$(sha256sum "$test_root/payment-v1-publisher-netns-launcher" | awk '{print $1}')"
launcher="/opt/bitcoinpir/publisher-netns-launcher/$launcher_sha256/payment-v1-publisher-netns-launcher"
for path in \
  "$test_ca" \
  "$integrated_gate" \
  "$health_probe" \
  "$executor" \
  "$publisher_gate" \
  "$schema_validator" \
  "$node_loader_closure" \
  "$launcher_manifest" \
  "$launcher"; do
  reserve_output_path "$path"
done

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 \
  -subj /CN=BitcoinPIR-Publisher-Health-E2E-CA \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -addext subjectKeyIdentifier=hash \
  -keyout "$test_root/ca.key" -out "$test_root/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=$publisher_host" \
  -keyout "$test_root/server.key" -out "$test_root/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -sha256 \
  -in "$test_root/server.csr" -CA "$test_root/ca.crt" -CAkey "$test_root/ca.key" \
  -CAcreateserial -out "$test_root/server.crt" \
  -extfile <(printf '%s\n' \
    "subjectAltName=DNS:$publisher_host" \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth") >/dev/null 2>&1
ca_store_changed=1
install -o root -g root -m 0644 "$test_root/ca.crt" "$test_ca"
record_created_file "$test_ca"
update-ca-certificates >/dev/null
leaf_sha256="$(openssl x509 -in "$test_root/server.crt" -outform DER | sha256sum | awk '{print $1}')"

ip netns add "$namespace"
namespace_created=1
namespace_identity="$(stat -Lc '%d:%i' -- "/run/netns/$namespace")"
ip link add "$host_interface" type veth peer name "$client_interface"
host_interface_created=1
host_interface_ifindex="$(cat "/sys/class/net/$host_interface/ifindex")"
host_interface_mac="$(cat "/sys/class/net/$host_interface/address")"
ip link set "$client_interface" netns "$namespace"
ip address add 10.203.0.1/30 dev "$host_interface"
ip link set "$host_interface" up
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip address add 10.203.0.2/30 dev "$client_interface"
ip netns exec "$namespace" ip link set "$client_interface" up

/usr/bin/node - "$test_root/backend.sock" "$test_root/backend.ready" <<'NODE' &
const { createHash } = require("node:crypto");
const { chmodSync, writeFileSync } = require("node:fs");
const net = require("node:net");

const [socketPath, readyPath] = process.argv.slice(2);
const magic = Buffer.from("\r\n\r\n\0\r\nQUIT\n", "latin1");
const server = net.createServer((socket) => {
  let bytes = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.length < 16) return;
    if (!bytes.subarray(0, 12).equals(magic) || bytes[12] !== 0x21) {
      socket.destroy(new Error("missing PROXY protocol v2 header"));
      return;
    }
    const proxyLength = bytes.readUInt16BE(14);
    const httpOffset = 16 + proxyLength;
    const headerEnd = bytes.indexOf("\r\n\r\n", httpOffset);
    if (headerEnd < 0) return;
    const request = bytes.subarray(httpOffset, headerEnd).toString("latin1");
    const key = request.match(/^Sec-WebSocket-Key: ([A-Za-z0-9+/]{22}==)$/imu)?.[1];
    if (!request.startsWith("GET / HTTP/1.1\r\n") || key === undefined) {
      socket.destroy(new Error("malformed proxied WebSocket request"));
      return;
    }
    const accept = createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`, "ascii")
      .digest("base64");
    socket.end([
      "HTTP/1.1 101 Switching Protocols",
      "Connection: Upgrade",
      "Upgrade: websocket",
      `Sec-WebSocket-Accept: ${accept}`,
      "",
      "",
    ].join("\r\n"));
  });
});
server.listen(socketPath, () => {
  chmodSync(socketPath, 0o666);
  writeFileSync(readyPath, "ready\n", { mode: 0o600 });
});
NODE
backend_pid="$!"

for _ in $(seq 1 100); do
  [[ -f "$test_root/backend.ready" ]] && break
  if ! kill -0 "$backend_pid" 2>/dev/null; then
    wait "$backend_pid" || true
    backend_pid=""
    exit 1
  fi
  sleep 0.05
done
test -f "$test_root/backend.ready"

/usr/bin/node "$repo_root/scripts/payment-v1-deployment-template-gate.mjs" >/dev/null
/usr/bin/node - \
  "$managed_template" "$test_root/Caddyfile" "$publisher_host" \
  "$test_root/server.crt" "$test_root/server.key" "$test_root/backend.sock" <<'NODE'
const { readFileSync, writeFileSync } = require("node:fs");

const [templatePath, outputPath, publisherHost, certificatePath, keyPath, backendPath] =
  process.argv.slice(2);
const lines = readFileSync(templatePath, "utf8").split("\n");
const start = lines.indexOf("@DIRECTORY_PUBLISHER_HTTPS_HOST@ {");
if (start < 0 || lines.indexOf("@DIRECTORY_PUBLISHER_HTTPS_HOST@ {", start + 1) >= 0) {
  throw new Error("managed Caddy template does not contain one publisher block");
}
let depth = 0;
let end = -1;
for (let index = start; index < lines.length; index += 1) {
  depth += (lines[index].match(/\{/g) ?? []).length;
  depth -= (lines[index].match(/\}/g) ?? []).length;
  if (depth === 0) {
    end = index;
    break;
  }
  if (depth < 0) throw new Error("managed publisher block has unbalanced braces");
}
if (end <= start || depth !== 0) throw new Error("managed publisher block is truncated");
let block = `${lines.slice(start, end + 1).join("\n")}\n`;
function replaceExact(needle, replacement, count = 1) {
  const observed = block.split(needle).length - 1;
  if (observed !== count) {
    throw new Error(`managed publisher block expected ${count} occurrence(s) of ${needle}`);
  }
  block = block.replaceAll(needle, replacement);
}
replaceExact("@DIRECTORY_PUBLISHER_HTTPS_HOST@", publisherHost, 3);
replaceExact("@DIRECTORY_PUBLISHER_PRIVATE_BIND@", "10.203.0.1");
replaceExact("@DIRECTORY_PUBLISHER_CLIENT_IP@", "10.203.0.2");
replaceExact(
  "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.crt",
  certificatePath,
);
replaceExact(
  "/etc/bitcoinpir/payment-v1/edge/directory-publisher-server.key",
  keyPath,
);
replaceExact(
  "unix//run/bitcoinpir-source-fair-edge/directory-publisher.sock",
  `unix/${backendPath}`,
);
if (/@[A-Z][A-Z0-9_]+@/u.test(block)) {
  throw new Error("managed publisher block retains an unresolved placeholder");
}
writeFileSync(outputPath, [
  "{",
  "\tadmin off",
  "\tauto_https off",
  "\tpersist_config off",
  "}",
  "",
  block,
].join("\n"), { encoding: "utf8", mode: 0o600 });
NODE

"$caddy" validate --config "$test_root/Caddyfile" --adapter caddyfile >/dev/null
"$caddy" run --config "$test_root/Caddyfile" --adapter caddyfile \
  >"$test_root/caddy.out" 2>"$test_root/caddy.err" &
caddy_pid="$!"

caddy_ready=no
for _ in $(seq 1 100); do
  if /usr/bin/node -e '
    const net = require("node:net");
    const socket = net.connect({host:"10.203.0.1",port:443});
    socket.setTimeout(100);
    socket.once("connect",()=>{socket.destroy();process.exit(0)});
    socket.once("error",()=>process.exit(1));
    socket.once("timeout",()=>process.exit(1));
  ' >/dev/null 2>&1; then caddy_ready=yes; break; fi
  if ! kill -0 "$caddy_pid" 2>/dev/null; then
    cat "$test_root/caddy.err" >&2
    wait "$caddy_pid" || true
    caddy_pid=""
    exit 1
  fi
  sleep 0.05
done
if [[ "$caddy_ready" != yes ]]; then
  cat "$test_root/caddy.err" >&2
  echo "private publisher Caddy listener did not become reachable" >&2
  exit 1
fi

# An otherwise-valid request from the host namespace must miss the exact-source
# matcher. This proves that a host-side health check cannot accidentally certify
# the private publisher lane.
/usr/bin/node --use-openssl-ca - "$publisher_host" <<'NODE'
const tls = require("node:tls");
const { randomBytes } = require("node:crypto");
const host = process.argv[2];
const key = randomBytes(16).toString("base64");
const socket = tls.connect({host:"10.203.0.1",port:443,servername:host,rejectUnauthorized:true});
let response = Buffer.alloc(0);
function fail(message) {
  process.stderr.write(`host-negative publisher probe: ${message}\n`);
  socket.destroy();
  process.exit(1);
}
const timeout = setTimeout(() => fail("timed out"), 3000);
socket.once("secureConnect", () => socket.write([
  "GET / HTTP/1.1", `Host: ${host}`, "Connection: Upgrade", "Upgrade: websocket",
  "Sec-WebSocket-Version: 13", `Sec-WebSocket-Key: ${key}`, "", "",
].join("\r\n")));
socket.on("data", (chunk) => {
  response = Buffer.concat([response, chunk]);
  if (!response.includes("\r\n\r\n")) return;
  clearTimeout(timeout);
  socket.destroy();
  if (!response.toString("latin1").startsWith("HTTP/1.1 404 ")) {
    fail(`unexpected status: ${response.subarray(0, response.indexOf("\r\n")).toString("latin1")}`);
  }
});
socket.once("error", (error) => fail(error.message));
NODE

for path in \
  /etc/bitcoinpir \
  /etc/bitcoinpir/payment-v1 \
  /etc/bitcoinpir/payment-v1/publisher-netns \
  /usr/local/libexec \
  /usr/local/libexec/bitcoinpir; do
  ensure_test_directory "$path"
done
install -o root -g root -m 0555 \
  "$repo_root/scripts/payment-v1-integrated-caddy-overlay-gate.mjs" "$integrated_gate"
record_created_file "$integrated_gate"
install -o root -g root -m 0555 \
  "$repo_root/scripts/payment-v1-publisher-private-health-probe.mjs" "$health_probe"
record_created_file "$health_probe"
for path in "$executor" "$publisher_gate" "$schema_validator"; do
  printf '%s\n' 'export const sealedFixture = true;' >"$path"
  chmod 0555 "$path"
  record_created_file "$path"
done

for path in \
  /opt/bitcoinpir \
  /opt/bitcoinpir/publisher-netns-launcher \
  "$(dirname "$launcher")"; do
  ensure_test_directory "$path"
done
install -o root -g root -m 0555 "$test_root/payment-v1-publisher-netns-launcher" "$launcher"
record_created_file "$launcher"

loader="$(readlink -f /lib64/ld-linux-x86-64.so.2)"
[[ "$loader" == /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ]]
closure_paths="$(
  ldd /usr/bin/node | awk '/=> \// { print $3 } /^\// { print $1 }' |
    while IFS= read -r path; do readlink -f "$path"; done |
    grep -Fxv "$loader" | sort -u
)"
[[ -n "$closure_paths" ]]
{
  sha256sum "$loader"
  while IFS= read -r path; do
    [[ "$path" == /usr/lib/x86_64-linux-gnu/* && \
       "${path#/usr/lib/x86_64-linux-gnu/}" != */* ]]
    sha256sum "$path"
  done <<<"$closure_paths"
} >"$node_loader_closure"
chmod 0444 "$node_loader_closure"
record_created_file "$node_loader_closure"
[[ ! -e /etc/ld.so.preload ]]
{
  sha256sum /usr/bin/node
  sha256sum "$integrated_gate"
  sha256sum "$executor"
  sha256sum "$publisher_gate"
  sha256sum "$schema_validator"
  sha256sum "$health_probe"
  sha256sum "$node_loader_closure"
} >"$launcher_manifest"
chmod 0444 "$launcher_manifest"
record_created_file "$launcher_manifest"
launcher_manifest_sha256="$(sha256sum "$launcher_manifest" | awk '{print $1}')"

namespace_device="$(stat -Lc %d "/run/netns/$namespace")"
namespace_inode="$(stat -Lc %i "/run/netns/$namespace")"
check_base64="$(/usr/bin/node - "$publisher_host" "$leaf_sha256" <<'NODE'
const [host, leaf] = process.argv.slice(2);
const check = {
  connect_ip: "10.203.0.1",
  expected_body_sha256: null,
  expected_status: 101,
  host,
  kind: "websocket-upgrade",
  lane: "directory-publisher",
  leaf_certificate_sha256: leaf,
  max_response_bytes: 16384,
  network_namespace: "bpir-directory-publisher",
  path: "/",
  timeout_ms: 3000,
};
process.stdout.write(Buffer.from(`${JSON.stringify(check)}\n`, "utf8").toString("base64"));
NODE
)"

# Match the production transaction adapter: the parent descriptor-opens the
# launcher, installs it as child fd 3, and executes only /proc/self/fd/3.
result="$(/usr/bin/node - \
  "$launcher" "$launcher_sha256" "$launcher_manifest_sha256" \
  "$namespace_device" "$namespace_inode" "$check_base64" <<'NODE'
const { constants, closeSync, fstatSync, openSync } = require("node:fs");
const { spawnSync } = require("node:child_process");

const [launcherPath, launcherSha256, manifestSha256, namespaceDevice,
  namespaceInode, checkBase64] = process.argv.slice(2);
const fd = openSync(
  launcherPath,
  constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC,
);
try {
  const before = fstatSync(fd, { bigint: true });
  const child = spawnSync("/proc/self/fd/3", [
    "--approved-launcher-sha256", launcherSha256,
    "--approved-manifest-sha256", manifestSha256,
    "--", "publisher-private-health-probe",
    "--namespace-device", namespaceDevice,
    "--namespace-inode", namespaceInode,
    "--check-base64", checkBase64,
  ], {
    encoding: null,
    env: { LANG: "C", LC_ALL: "C", PATH: "/usr/sbin:/usr/bin:/sbin:/bin" },
    killSignal: "SIGKILL",
    maxBuffer: 512 * 1024,
    shell: false,
    stdio: ["ignore", "pipe", "pipe", fd],
    timeout: 13_000,
  });
  const after = fstatSync(fd, { bigint: true });
  for (const key of ["dev", "ino", "ctimeNs", "mtimeNs", "size"]) {
    if (after[key] !== before[key]) throw new Error(`launcher descriptor drifted at ${key}`);
  }
  if (child.error !== undefined || child.status !== 0 || child.signal !== null) {
    process.stderr.write(child.stderr ?? Buffer.alloc(0));
    throw child.error ?? new Error(`fd3 launcher exited ${child.status} signal ${child.signal}`);
  }
  process.stdout.write(child.stdout);
} finally {
  closeSync(fd);
}
NODE
)"
/usr/bin/node -e '
  const value = JSON.parse(process.argv[1]);
  if (value.success !== true || value.status !== 101 || value.body_sha256 !== null ||
      !/^[0-9a-f]{64}$/.test(value.leaf_certificate_sha256)) process.exit(1);
' "$result"

# The externally receipt-bound namespace identity is mandatory; a host or stale
# namespace receipt must fail before the sealed JavaScript probe executes.
if "$launcher" \
    --approved-launcher-sha256 "$launcher_sha256" \
    --approved-manifest-sha256 "$launcher_manifest_sha256" -- \
    publisher-private-health-probe \
    --namespace-device "$namespace_device" \
    --namespace-inode "$((namespace_inode + 1))" \
    --check-base64 "$check_base64" \
    >"$test_root/stale.out" 2>"$test_root/stale.err"; then
  echo "launcher accepted a stale publisher namespace identity" >&2
  exit 1
fi
grep -F "publisher namespace descriptor differs from the approved receipt" \
  "$test_root/stale.err" >/dev/null

echo "payment-v1 publisher private-health privileged e2e: ok"
