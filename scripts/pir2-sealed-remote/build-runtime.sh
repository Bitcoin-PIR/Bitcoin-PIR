#!/usr/bin/env bash
# Runs on the VPSBG stock rootfs as pir: clone the reviewed commit from the uploaded
# bundle and build the pir2 runtime (docs/runbooks/uki-build.md section 1).
set -euo pipefail
: "${SHA:?release commit}"; : "${D:?build dir}"
[ "$(id -un)" = pir ] || { echo "run as pir" >&2; exit 1; }
export PATH=/home/pir/.cargo/bin:$PATH
cd "$D"
[ -d source/.git ] || git clone -q "$D/source.bundle" source
git -C source checkout -q --detach "$SHA"
[ "$(git -C source rev-parse HEAD)" = "$SHA" ] || { echo "HEAD mismatch" >&2; exit 1; }
[ -z "$(git -C source status --porcelain)" ] || { echo "source tree not clean" >&2; exit 1; }
echo "source_commit=$SHA"
cd source
cargo --version; rustc --version
cargo build --locked --release -p runtime --features cuckoo-oram --bin unified_server 2>&1 | tail -2
strip --strip-debug target/release/unified_server
sha256sum target/release/unified_server | tee "$D/unified_server.sha256"
echo "PASS runtime_build"
