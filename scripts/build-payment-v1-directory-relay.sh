#!/usr/bin/env bash

set -euo pipefail

readonly build_image='docker.io/library/rust@sha256:4ec71e955e6c08aeb238885083222ddff79d82eb87654a96c76e38e94da1a53b'
readonly rust_toolchain='1.94.1-x86_64-unknown-linux-gnu'
readonly unprivileged_uid='65532'
readonly unprivileged_gid='65532'
readonly script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

usage() {
  cat <<'EOF'
Usage: scripts/build-payment-v1-directory-relay.sh \
  --repository ABSOLUTE_GIT_ROOT --source-commit FULL_40_HEX --output ABSENT_ABSOLUTE_DIRECTORY

Creates owner-only, non-production build evidence for the BitcoinPIR directory
relay. It archives exactly SOURCE_COMMIT, then performs two independent clean
Linux/amd64 builds in a registry-digest-pinned Rust container with networking
disabled. It does not read a relay selection, config, publisher key, remote
host, wallet, or deployment credential. Its output remains owned by the
invoking EUID and is preparation evidence, not a root-owned installation or a
security boundary against that EUID or root after PASS.

The pinned image must already exist locally. Pulling or approving that image is
a separate supply-chain action; this script uses docker run --pull=never.
EOF
}

repository=''
source_commit=''
output=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository) repository="${2:-}"; shift 2 ;;
    --source-commit) source_commit="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ -z "$repository" || -z "$source_commit" || -z "$output" ]]; then
  usage >&2
  exit 2
fi
if [[ ! "$repository" = /* || ! "$output" = /* || ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo 'directory-relay-build: paths must be absolute and source commit must be full lowercase 40-hex' >&2
  exit 1
fi

reject_docker_mount_path() {
  local candidate="$1"
  local label="$2"
  if [[ "$candidate" =~ [[:cntrl:],] ]]; then
    echo "directory-relay-build: $label contains a Docker --mount delimiter or control byte" >&2
    exit 1
  fi
}

repository="$(cd "$repository" && pwd -P)"
output_parent="$(cd "$(dirname "$output")" && pwd -P)"
output="$output_parent/$(basename "$output")"
reject_docker_mount_path "$repository" 'repository path'
reject_docker_mount_path "$output_parent" 'output parent path'
reject_docker_mount_path "$output" 'output path'
if [[ -e "$output" || -L "$output" ]]; then
  echo "directory-relay-build: output already exists: $output" >&2
  exit 1
fi
if [[ ! -d "$repository/.git" || -L "$repository/.git" || \
      ! -d "$repository/.git/objects" || -L "$repository/.git/objects" ]]; then
  echo 'directory-relay-build: repository must expose its canonical .git object database directory' >&2
  exit 1
fi

readonly host_uid="$(id -u)"
readonly host_gid="$(id -g)"
if [[ "$host_uid" == '0' || "$host_gid" == '0' ]]; then
  echo 'directory-relay-build: writable bind mounts require a non-root host UID/GID' >&2
  exit 1
fi

docker_path="$(command -v docker || true)"
if [[ -z "$docker_path" ]]; then
  echo 'directory-relay-build: docker is unavailable' >&2
  exit 1
fi
host_timeout_path="$(command -v timeout || true)"
if [[ -z "$host_timeout_path" || ! "$host_timeout_path" = /* ]]; then
  echo 'directory-relay-build: an absolute host timeout executable is required' >&2
  exit 1
fi
rename_helper_source="$script_root/scripts/payment-v1-renameat2-noreplace.rs"
if [[ ! -f "$rename_helper_source" || -L "$rename_helper_source" ]]; then
  echo 'directory-relay-build: the reviewed renameat2 helper source is unavailable' >&2
  exit 1
fi
reject_docker_mount_path "$rename_helper_source" 'renameat2 helper source path'
if ! "$host_timeout_path" --signal=KILL 30s \
  "$docker_path" image inspect "$build_image" >/dev/null 2>&1; then
  echo 'directory-relay-build: pinned build image is not present locally' >&2
  exit 1
fi

umask 077
staging="$(mktemp -d "$output_parent/.directory-relay-build.XXXXXX")"
publisher_helper_directory=''
output_parent_initial_snapshot="$(node \
  "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  snapshot-directory-chain \
  --directory "$output_parent")"
cleanup() {
  if [[ -n "${publisher_helper_directory:-}" && -d "$publisher_helper_directory" ]]; then
    rm -rf -- "$publisher_helper_directory"
  fi
  if [[ -n "${staging:-}" && -d "$staging" ]]; then
    rm -rf -- "$staging"
  fi
}
trap cleanup EXIT

# SOURCE_COMMIT and the git_source array expand inside the container shell.
# shellcheck disable=SC2016
"$host_timeout_path" --signal=KILL 330s "$docker_path" run \
  --rm \
  --pull=never \
  --platform linux/amd64 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 3221225472 \
  --memory-swap 3221225472 \
  --pids-limit 128 \
  --cpus 2 \
  --ulimit nofile=1024:1024 \
  --ulimit core=0:0 \
  --user "$host_uid:$host_gid" \
  --tmpfs "/work:rw,exec,nosuid,nodev,size=2g,uid=$host_uid,gid=$host_gid,mode=0700" \
  --mount "type=bind,src=$repository,dst=/repository,readonly" \
  --mount "type=bind,src=$staging,dst=/output" \
  --env "SOURCE_COMMIT=$source_commit" \
  --env GIT_ATTR_NOSYSTEM=1 \
  --env GIT_CONFIG_GLOBAL=/dev/null \
  --env GIT_CONFIG_NOSYSTEM=1 \
  --env GIT_DEFAULT_HASH=sha1 \
  --env GIT_NO_REPLACE_OBJECTS=1 \
  --env XDG_CONFIG_HOME=/nonexistent \
  "$build_image" \
  /usr/bin/timeout --signal=KILL 300s /bin/bash -ceu '
    set -o pipefail
    if [[ ! -d /repository/.git/objects || -L /repository/.git/objects ]]; then
      echo "directory-relay-build: noncanonical Git object-store directory is forbidden" >&2
      exit 1
    fi
    if /usr/bin/find /repository/.git/objects -type l -print -quit | /usr/bin/grep -q .; then
      echo "directory-relay-build: symlinked Git object-store input is forbidden" >&2
      exit 1
    fi
    for alternate in \
      /repository/.git/objects/info/alternates \
      /repository/.git/objects/info/http-alternates; do
      if [[ -s "$alternate" ]]; then
        echo "directory-relay-build: alternate Git object stores are forbidden" >&2
        exit 1
      fi
    done
    /usr/bin/git init --bare --quiet /work/source.git
    /bin/cp -a /repository/.git/objects/. /work/source.git/objects/
    /bin/rm -rf /work/source.git/objects/info
    /bin/mkdir -m 0700 /work/source.git/objects/info
    git_source=(
      /usr/bin/git
      --no-replace-objects
      -c core.attributesFile=/dev/null
      --git-dir=/work/source.git
    )
    resolved="$("${git_source[@]}" rev-parse --verify "$SOURCE_COMMIT^{commit}")"
    if [[ "$resolved" != "$SOURCE_COMMIT" ]]; then
      echo "directory-relay-build: exact source commit is unavailable" >&2
      exit 1
    fi
    "${git_source[@]}" archive \
      --format=tar \
      --prefix="BitcoinPIR-$SOURCE_COMMIT/" \
      --output=/output/source.tar \
      "$SOURCE_COMMIT"
    "${git_source[@]}" show "$SOURCE_COMMIT:Cargo.lock" > /output/Cargo.lock
    /usr/bin/git --version > /output/git-version.txt
    /usr/bin/tar --version | /usr/bin/sed -n "1p" > /output/tar-version.txt
  '

build_once() {
  local build_number="$1"
  local result_directory="$staging/result-$build_number"
  mkdir -m 0700 "$result_directory"
  "$host_timeout_path" --signal=KILL 1830s "$docker_path" run \
    --rm \
    --pull=never \
    --platform linux/amd64 \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 6442450944 \
    --memory-swap 6442450944 \
    --pids-limit 512 \
    --cpus 2 \
    --ulimit nofile=4096:4096 \
    --ulimit core=0:0 \
    --user "$host_uid:$host_gid" \
    --tmpfs "/work:rw,exec,nosuid,nodev,size=4g,uid=$host_uid,gid=$host_gid,mode=0700" \
    --mount "type=bind,src=$staging/source.tar,dst=/input/source.tar,readonly" \
    --mount "type=bind,src=$result_directory,dst=/output" \
    --env CARGO_INCREMENTAL=0 \
    --env SOURCE_DATE_EPOCH=0 \
    --env "RUSTUP_TOOLCHAIN=$rust_toolchain" \
    --env CARGO_TARGET_DIR=/work/target \
    --env "RUSTFLAGS=-C debuginfo=0 -C strip=symbols --remap-path-prefix=/work/source/BitcoinPIR-$source_commit=/workspace" \
    "$build_image" \
    /usr/bin/timeout --signal=KILL 1800s /bin/bash -ceu '
      mkdir -p /work/source /work/target
      /usr/bin/tar -xf /input/source.tar -C /work/source
      cd "/work/source/BitcoinPIR-'"$source_commit"'"
      cargo build --release --locked --offline -p bitcoinpir-directory-relay --bin bitcoinpir-directory-relay
      /usr/bin/install -m 0555 /work/target/release/bitcoinpir-directory-relay /output/bitcoinpir-directory-relay
    '
  cp "$result_directory/bitcoinpir-directory-relay" \
    "$staging/bitcoinpir-directory-relay.build-$build_number"
  chmod 0555 "$staging/bitcoinpir-directory-relay.build-$build_number"
  rm -rf -- "$result_directory"
}

build_once 1
build_once 2
if ! cmp -s \
  "$staging/bitcoinpir-directory-relay.build-1" \
  "$staging/bitcoinpir-directory-relay.build-2"; then
  echo 'directory-relay-build: two clean builds are not byte-identical' >&2
  exit 1
fi
cp "$staging/bitcoinpir-directory-relay.build-1" "$staging/bitcoinpir-directory-relay"
chmod 0555 "$staging/bitcoinpir-directory-relay"

"$host_timeout_path" --signal=KILL 30s "$docker_path" run \
  --rm \
  --pull=never \
  --platform linux/amd64 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 268435456 \
  --memory-swap 268435456 \
  --pids-limit 64 \
  --cpus 1 \
  --ulimit nofile=256:256 \
  --ulimit core=0:0 \
  --user "$unprivileged_uid:$unprivileged_gid" \
  --tmpfs "/work:rw,exec,nosuid,nodev,size=64m,uid=$unprivileged_uid,gid=$unprivileged_gid,mode=0700" \
  --mount "type=bind,src=$staging/bitcoinpir-directory-relay,dst=/proof/bitcoinpir-directory-relay,readonly" \
  "$build_image" \
  /usr/bin/timeout --signal=KILL 15s \
  /proof/bitcoinpir-directory-relay --version >"$staging/binary-version.txt"

node "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  create-manifest \
  --repository "$repository" \
  --artifacts "$staging" \
  --source-commit "$source_commit" \
  --docker "$docker_path" \
  --output "$staging/build-manifest.json"

chmod 0444 "$staging/source.tar" "$staging/Cargo.lock" \
  "$staging/binary-version.txt" "$staging/git-version.txt" \
  "$staging/tar-version.txt" "$staging/build-manifest.json"

# Compile the reviewed publisher before the final artifact seal. The compiled
# helper is not part of the artifact set and performs only the final Linux/amd64
# renameat2(RENAME_NOREPLACE); no compiler or shell runs between the final seal
# and that syscall wrapper.
publisher_helper_directory="$(mktemp -d "$output_parent/.directory-relay-publisher.XXXXXX")"
reject_docker_mount_path "$publisher_helper_directory" 'publisher helper directory path'
"$host_timeout_path" --signal=KILL 60s "$docker_path" run \
  --rm \
  --pull=never \
  --platform linux/amd64 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 67108864 \
  --memory-swap 67108864 \
  --pids-limit 16 \
  --cpus 1 \
  --ulimit nofile=64:64 \
  --ulimit core=0:0 \
  --user "$host_uid:$host_gid" \
  --tmpfs "/work:rw,exec,nosuid,nodev,size=64m,uid=$host_uid,gid=$host_gid,mode=0700" \
  --mount "type=bind,src=$rename_helper_source,dst=/input/payment-v1-renameat2-noreplace.rs,readonly" \
  --mount "type=bind,src=$publisher_helper_directory,dst=/output" \
  "$build_image" \
  /usr/bin/timeout --signal=KILL 45s /bin/bash -ceu '
    cd /work
    /usr/local/cargo/bin/rustc \
      --edition=2024 \
      --check-cfg "cfg(payment_v1_test_force_enosys)" \
      -C debuginfo=0 \
      -C opt-level=2 \
      -C strip=symbols \
      -D warnings \
      /input/payment-v1-renameat2-noreplace.rs \
      -o /output/payment-v1-renameat2-noreplace
  '
publisher_helper="$publisher_helper_directory/payment-v1-renameat2-noreplace"
chmod 0555 "$publisher_helper"
reject_docker_mount_path "$publisher_helper" 'compiled publisher helper path'
node -e '
  const stat = require("node:fs").lstatSync(process.argv[1], { bigint: true });
  const euid = BigInt(process.geteuid());
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n ||
      stat.uid !== euid || (stat.mode & 0o7777n) !== 0o555n) process.exit(1);
' "$publisher_helper"

staging_name="$(basename "$staging")"
output_name="$(basename "$output")"
# The template literal is evaluated by Node, not the host shell.
# shellcheck disable=SC2016
readonly staging_identity="$(node -e '
  const stat = require("node:fs").lstatSync(process.argv[1], { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) process.exit(1);
  process.stdout.write(`${stat.dev}:${stat.ino}`);
' "$staging")"

# Verify stable output-parent identities across the long builds. Temporary
# verifier siblings legitimately change the parent's timestamps, so a fresh
# precise fingerprint is taken only after helper compilation. Then perform the
# complete closed-world artifact seal and immediately invoke the precompiled
# no-clobber publisher. ENOSYS, EEXIST and every other refusal fail closed.
node "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  verify-directory-chain-identity \
  --directory "$output_parent" \
  --snapshot "$output_parent_initial_snapshot" >/dev/null
output_parent_publication_snapshot="$(node \
  "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  snapshot-directory-chain \
  --directory "$output_parent")"
node "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  verify-directory-chain \
  --directory "$output_parent" \
  --snapshot "$output_parent_publication_snapshot" >/dev/null
artifact_publication_seal="$(node \
  "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  fast-seal-build \
  --artifacts "$staging" \
  --source-commit "$source_commit")"
"$host_timeout_path" --signal=KILL 30s "$docker_path" run \
  --rm \
  --pull=never \
  --platform linux/amd64 \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 67108864 \
  --memory-swap 67108864 \
  --pids-limit 16 \
  --cpus 1 \
  --ulimit nofile=64:64 \
  --ulimit core=0:0 \
  --user "$host_uid:$host_gid" \
  --tmpfs "/work:rw,exec,nosuid,nodev,size=64m,uid=$host_uid,gid=$host_gid,mode=0700" \
  --mount "type=bind,src=$publisher_helper,dst=/publisher/payment-v1-renameat2-noreplace,readonly" \
  --mount "type=bind,src=$output_parent,dst=/publish" \
  "$build_image" \
  /usr/bin/timeout --signal=KILL 15s \
  /publisher/payment-v1-renameat2-noreplace \
  "/publish/$staging_name" "/publish/$output_name"
output_identity=''
if [[ ! -e "$staging" && -d "$output" && ! -L "$output" ]]; then
  # The template literal is evaluated by Node, not the host shell.
  # shellcheck disable=SC2016
  output_identity="$(node -e '
    const stat = require("node:fs").lstatSync(process.argv[1], { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) process.exit(1);
    process.stdout.write(`${stat.dev}:${stat.ino}`);
  ' "$output")"
fi
if [[ -e "$staging" || ! -d "$output" || -L "$output" || \
      "$output_identity" != "$staging_identity" ]]; then
  echo 'directory-relay-build: atomic no-clobber output publication failed closed' >&2
  exit 1
fi
published_artifact_seal="$(node \
  "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  fast-seal-build \
  --artifacts "$output" \
  --source-commit "$source_commit")"
if [[ "$published_artifact_seal" != "$artifact_publication_seal" ]]; then
  echo 'directory-relay-build: published artifact bytes or precise fingerprints changed' >&2
  exit 1
fi

# Publication is preparation-only, but PASS is withheld until the published
# path itself completes the full canonical-source, two-rebuild and version
# verification. A final fast seal closes the post-verification window.
node "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  verify-build \
  --repository "$repository" \
  --artifacts "$output" \
  --source-commit "$source_commit" \
  --docker "$docker_path" >/dev/null
post_verification_artifact_seal="$(node \
  "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  fast-seal-build \
  --artifacts "$output" \
  --source-commit "$source_commit")"
if [[ "$post_verification_artifact_seal" != "$artifact_publication_seal" ]]; then
  echo 'directory-relay-build: published artifact changed during full verification' >&2
  exit 1
fi
node "$script_root/scripts/payment-v1-directory-relay-artifact-gate.mjs" \
  verify-directory-chain-identity \
  --directory "$output_parent" \
  --snapshot "$output_parent_publication_snapshot" >/dev/null
staging=''
echo "directory-relay-build: PASS output=$output"
