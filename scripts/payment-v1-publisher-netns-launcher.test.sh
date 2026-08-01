#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(id -u)" != "0" || \
      "${BPIR_DISPOSABLE_TEST_CONTAINER:-}" != "1" ]]; then
  echo "publisher-netns-launcher test must run as root in the disposable Linux test container" >&2
  exit 77
fi

repository="${1:?repository root required}"
launcher_source="${repository}/scripts/payment-v1-publisher-netns-launcher.c"
launcher_staging="/tmp/payment-v1-publisher-netns-launcher"
manifest="/etc/bitcoinpir/payment-v1/publisher-netns/launcher-inputs.sha256"
executor="/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-ceremony.mjs"
integrated_gate="/usr/local/libexec/bitcoinpir/payment-v1-integrated-caddy-overlay-gate.mjs"
publisher_gate="/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-gate.mjs"
schema_validator="/usr/local/libexec/bitcoinpir/payment-v1-publisher-netns-schema.mjs"
health_probe="/usr/local/libexec/bitcoinpir/payment-v1-publisher-private-health-probe.mjs"
node_loader_closure="/etc/bitcoinpir/payment-v1/publisher-netns/node-loader-closure.sha256"

cc -std=c11 -O2 -static -DBPIR_PUBLISHER_LAUNCHER_TEST_HOOKS \
  -Wall -Wextra -Werror "${launcher_source}" \
  -o "${launcher_staging}"
if ldd "${launcher_staging}" 2>&1 | grep -Ev 'not a dynamic executable|statically linked' >/dev/null; then
  echo "publisher launcher unexpectedly has a dynamic-loader dependency" >&2
  exit 1
fi
node --input-type=module --eval '
  import { readFileSync } from "node:fs";
  import { inspectStaticElfV1 } from "./scripts/payment-v1-publisher-netns-schema.mjs";
  const evidence = inspectStaticElfV1(readFileSync(process.argv[1]));
  if (evidence.pt_dynamic || evidence.pt_interp || evidence.sha256.length !== 64) process.exit(1);
' "${launcher_staging}"
launcher_sha256="$(sha256sum "${launcher_staging}" | cut -d' ' -f1)"
launcher="/opt/bitcoinpir/publisher-netns-launcher/${launcher_sha256}/payment-v1-publisher-netns-launcher"
install -d -m 0755 "$(dirname "${launcher}")"
install -m 0555 "${launcher_staging}" "${launcher}"
install -d -m 0755 /etc/bitcoinpir/payment-v1/publisher-netns /usr/local/libexec/bitcoinpir
if [[ ! -x /usr/bin/node ]]; then
  install -m 0755 /usr/local/bin/node /usr/bin/node
fi
printf '%s\n' 'export const integrated = "integrated";' >"${integrated_gate}"
printf '%s\n' 'export const publisher = "publisher";' >"${publisher_gate}"
printf '%s\n' 'export const schema = "schema-v2";' >"${schema_validator}"
printf '%s\n' 'export const privateHealthProbe = "sealed";' >"${health_probe}"
# shellcheck disable=SC2016 # JavaScript template literal must remain shell-literal.
printf '%s\n' \
  'import { integrated } from "./payment-v1-integrated-caddy-overlay-gate.mjs";' \
  'import { publisher } from "./payment-v1-publisher-netns-gate.mjs";' \
  'import { schema } from "./payment-v1-publisher-netns-schema.mjs";' \
  'import { existsSync } from "node:fs";' \
  'if (integrated !== "integrated" || publisher !== "publisher" || schema !== "schema-v2") throw new Error("gate drift");' \
  'if (process.execPath !== "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" || process.argv0 !== "/usr/bin/node" || process.argv[0] !== "/usr/bin/node") throw new Error("descriptor loader identity drift");' \
  'for (const flag of ["--no-expose-wasm", "--jitless", "--use-openssl-ca"]) if (!process.execArgv.includes(flag)) throw new Error(`missing closed Node flag ${flag}`);' \
  'if (typeof WebAssembly !== "undefined") throw new Error("WebAssembly remained exposed");' \
  'if (existsSync("/proc/self/fd/57")) throw new Error("unreviewed inherited fd");' \
  'process.stdout.write(`launcher-ok:${process.argv.slice(2).join(":")}\n`);' \
  >"${executor}"
chmod 0555 "${integrated_gate}" "${publisher_gate}" "${schema_validator}" \
  "${health_probe}" "${executor}"

write_loader_closure() {
  local loader
  loader="$(readlink -f /lib64/ld-linux-x86-64.so.2)"
  [[ "${loader}" == /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ]]
  local closure_paths
  closure_paths="$(
    ldd /usr/bin/node | awk '/=> \// { print $3 } /^\// { print $1 }' |
      while IFS= read -r path; do readlink -f "${path}"; done |
      grep -Fxv "${loader}" | sort -u
  )"
  [[ -n "${closure_paths}" ]]
  {
    sha256sum "${loader}"
    while IFS= read -r path; do
      [[ "${path}" == /usr/lib/x86_64-linux-gnu/* && "${path#/usr/lib/x86_64-linux-gnu/}" != */* ]]
      sha256sum "${path}"
    done <<<"${closure_paths}"
  } >"${node_loader_closure}"
  chmod 0444 "${node_loader_closure}"
}

write_loader_closure

write_manifest() {
  {
    sha256sum /usr/bin/node
    sha256sum "${integrated_gate}"
    sha256sum "${executor}"
    sha256sum "${publisher_gate}"
    sha256sum "${schema_validator}"
    sha256sum "${health_probe}"
    sha256sum "${node_loader_closure}"
  } >"${manifest}"
  chmod 0444 "${manifest}"
}

write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"
output="$({ "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
  --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan --fixture ok; \
  } 57>/tmp/unreviewed-inherited-fd)"
[[ "${output}" == "launcher-ok:validate-plan:--fixture:ok" ]]

printf '%s\n' '# test must be rejected before the explicit loader executes' \
  >/etc/ld.so.preload
if "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-global-preload.out 2>/tmp/launcher-global-preload.err; then
  echo "global loader preload file was accepted" >&2
  exit 1
fi
rm -f /etc/ld.so.preload
grep -F "global dynamic-loader preload file must not exist" \
  /tmp/launcher-global-preload.err >/dev/null

pause_directory="$(mktemp -d /tmp/payment-v1-launcher-pause.XXXXXX)"
BPIR_LAUNCHER_TEST_PAUSE_DIRECTORY="${pause_directory}" \
  "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
  --approved-manifest-sha256 "${manifest_sha256}" -- descriptor-race \
  > /tmp/launcher-race.out 2>/tmp/launcher-race.err &
race_pid="$!"
for _ in $(seq 1 500); do
  [[ -e "${pause_directory}/ready" ]] && break
  kill -0 "${race_pid}" 2>/dev/null || { wait "${race_pid}"; exit 1; }
  sleep 0.01
done
[[ -e "${pause_directory}/ready" ]]
printf '%s\n' \
  'import { writeFileSync } from "node:fs";' \
  'writeFileSync("/tmp/atomic-entrypoint-replacement-executed", "bad\n");' \
  > /tmp/replacement-executor.mjs
printf '%s\n' \
  'import { writeFileSync } from "node:fs";' \
  'writeFileSync("/tmp/atomic-import-replacement-executed", "bad\n");' \
  'export const integrated = "bad";' \
  > /tmp/replacement-integrated.mjs
chmod 0555 /tmp/replacement-executor.mjs /tmp/replacement-integrated.mjs
mv -f /tmp/replacement-executor.mjs "${executor}"
mv -f /tmp/replacement-integrated.mjs "${integrated_gate}"
touch "${pause_directory}/continue"
wait "${race_pid}"
grep -Fx "launcher-ok:descriptor-race" /tmp/launcher-race.out >/dev/null
[[ ! -e /tmp/atomic-entrypoint-replacement-executed ]]
[[ ! -e /tmp/atomic-import-replacement-executed ]]
rm -rf -- "${pause_directory}"

printf '%s\n' 'export const integrated = "integrated";' >"${integrated_gate}"
# shellcheck disable=SC2016 # JavaScript template literal must remain shell-literal.
printf '%s\n' \
  'import { integrated } from "./payment-v1-integrated-caddy-overlay-gate.mjs";' \
  'import { publisher } from "./payment-v1-publisher-netns-gate.mjs";' \
  'import { schema } from "./payment-v1-publisher-netns-schema.mjs";' \
  'import { existsSync } from "node:fs";' \
  'if (integrated !== "integrated" || publisher !== "publisher" || schema !== "schema-v2") throw new Error("gate drift");' \
  'if (process.execPath !== "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" || process.argv0 !== "/usr/bin/node" || process.argv[0] !== "/usr/bin/node") throw new Error("descriptor loader identity drift");' \
  'for (const flag of ["--no-expose-wasm", "--jitless", "--use-openssl-ca"]) if (!process.execArgv.includes(flag)) throw new Error(`missing closed Node flag ${flag}`);' \
  'if (typeof WebAssembly !== "undefined") throw new Error("WebAssembly remained exposed");' \
  'if (existsSync("/proc/self/fd/57")) throw new Error("unreviewed inherited fd");' \
  'process.stdout.write(`launcher-ok:${process.argv.slice(2).join(":")}\n`);' \
  >"${executor}"
chmod 0555 "${integrated_gate}" "${executor}"
write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"

printf '%s\n' \
  'import { writeFileSync } from "node:fs";' \
  'writeFileSync("/tmp/unreviewed-import-executed", "bad\n");' \
  'export const integrated = "tampered";' \
  >"${integrated_gate}"
chmod 0555 "${integrated_gate}"
if "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-tamper.out 2>/tmp/launcher-tamper.err; then
  echo "tampered imported module was accepted" >&2
  exit 1
fi
[[ ! -e /tmp/unreviewed-import-executed ]]
grep -F "pinned input SHA-256 differs" /tmp/launcher-tamper.err >/dev/null

printf '%s\n' 'export const integrated = "integrated";' >"${integrated_gate}"
chmod 0555 "${integrated_gate}"
write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"

cp "${node_loader_closure}" /tmp/node-loader-closure.valid
chmod 0644 "${node_loader_closure}"
first_digest_nibble="$(head -n 1 /tmp/node-loader-closure.valid | cut -c1)"
replacement_digest_nibble=0
[[ "${first_digest_nibble}" == 0 ]] && replacement_digest_nibble=1
sed "1s/^./${replacement_digest_nibble}/" /tmp/node-loader-closure.valid \
  >"${node_loader_closure}"
if cmp -s /tmp/node-loader-closure.valid "${node_loader_closure}"; then
  echo "loader closure tamper fixture did not change the object digest" >&2
  exit 1
fi
chmod 0444 "${node_loader_closure}"
write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"
if "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-closure.out 2>/tmp/launcher-closure.err; then
  echo "tampered loader closure object digest was accepted" >&2
  exit 1
fi
grep -F "Node loader object SHA-256 differs" /tmp/launcher-closure.err >/dev/null
install -m 0444 /tmp/node-loader-closure.valid "${node_loader_closure}"
write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"

printf '%s\n' \
  'import { writeFileSync } from "node:fs";' \
  'writeFileSync("/tmp/node-options-import-executed", "bad\n");' \
  > /tmp/unreviewed-node-option.mjs
if NODE_OPTIONS='--import=/tmp/unreviewed-node-option.mjs' \
    "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-env.out 2>/tmp/launcher-env.err; then
  echo "malicious NODE_OPTIONS was accepted" >&2
  exit 1
fi
[[ ! -e /tmp/node-options-import-executed ]]
grep -F "Node environment is forbidden" /tmp/launcher-env.err >/dev/null

wrong_manifest_sha256="$(printf 'wrong-manifest\n' | sha256sum | cut -d' ' -f1)"
if "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${wrong_manifest_sha256}" -- validate-plan \
    >/tmp/launcher-manifest.out 2>/tmp/launcher-manifest.err; then
  echo "unapproved launcher manifest was accepted" >&2
  exit 1
fi
grep -F "externally approved digest" /tmp/launcher-manifest.err >/dev/null

wrong_launcher_sha256="$(printf 'wrong-launcher\n' | sha256sum | cut -d' ' -f1)"
if "${launcher}" --approved-launcher-sha256 "${wrong_launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-self.out 2>/tmp/launcher-self.err; then
  echo "unapproved publisher launcher was accepted" >&2
  exit 1
fi
grep -F "launcher executable SHA-256 differs" /tmp/launcher-self.err >/dev/null

printf '%s\n' \
  '#include <fcntl.h>' \
  '#include <unistd.h>' \
  '__attribute__((constructor)) static void injected(void) {' \
  '  int fd = open("/tmp/launcher-loader-executed", O_WRONLY | O_CREAT, 0600);' \
  '  if (fd >= 0) close(fd);' \
  '}' \
  >/tmp/unreviewed-launcher-preload.c
cc -shared -fPIC /tmp/unreviewed-launcher-preload.c -o /tmp/unreviewed-launcher-preload.so
if LD_PRELOAD=/tmp/unreviewed-launcher-preload.so \
    "${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
    --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan \
    >/tmp/launcher-loader.out 2>/tmp/launcher-loader.err; then
  echo "malicious launcher LD_PRELOAD environment was accepted" >&2
  exit 1
fi
[[ ! -e /tmp/launcher-loader-executed ]]
grep -F "dynamic-loader or Node environment is forbidden" \
  /tmp/launcher-loader.err >/dev/null

echo "publisher-netns-launcher-tests: ok"
