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

cc -std=c11 -O2 -static -Wall -Wextra -Werror "${launcher_source}" \
  -o "${launcher_staging}"
if ldd "${launcher_staging}" 2>&1 | grep -Ev 'not a dynamic executable|statically linked' >/dev/null; then
  echo "publisher launcher unexpectedly has a dynamic-loader dependency" >&2
  exit 1
fi
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
printf '%s\n' \
  'import { integrated } from "./payment-v1-integrated-caddy-overlay-gate.mjs";' \
  'import { publisher } from "./payment-v1-publisher-netns-gate.mjs";' \
  'if (integrated !== "integrated" || publisher !== "publisher") throw new Error("gate drift");' \
  'process.stdout.write(`launcher-ok:${process.argv.slice(2).join(":")}\n`);' \
  >"${executor}"
chmod 0555 "${integrated_gate}" "${publisher_gate}" "${executor}"

write_manifest() {
  {
    sha256sum /usr/bin/node
    sha256sum "${integrated_gate}"
    sha256sum "${executor}"
    sha256sum "${publisher_gate}"
  } >"${manifest}"
  chmod 0444 "${manifest}"
}

write_manifest
manifest_sha256="$(sha256sum "${manifest}" | cut -d' ' -f1)"
output="$("${launcher}" --approved-launcher-sha256 "${launcher_sha256}" \
  --approved-manifest-sha256 "${manifest_sha256}" -- validate-plan --fixture ok)"
[[ "${output}" == "launcher-ok:validate-plan:--fixture:ok" ]]

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
