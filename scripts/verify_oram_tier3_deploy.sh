#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for the ORAM-enabled Tier 3 UKI built from BitcoinPIR
# commit 3cd52355. Run after uploading the UKI in the VPSBG measured-boot
# portal and waiting for cloudflared to reconnect.

SERVER=${SERVER:-wss://weikeng2.bitcoinpir.org}
EXPECT_MEASUREMENT=${EXPECT_MEASUREMENT:-9b92966e641f948ea855e205c8a8a258f15ea0c5135fe444362333ac0299bf8e2ebead5868bacbd4041abace0eb3b9b5}
EXPECT_BINARY=${EXPECT_BINARY:-3660318aed600b583d503d27f5d166420222fb228a6bd5befc3e15410d25b291}
EXPECT_ARK_FINGERPRINT=${EXPECT_ARK_FINGERPRINT:-1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a}
ORAM_SMOKE_HASH=${ORAM_SMOKE_HASH:-4242424242424242424242424242424242424242}
ORAM_PADDED_SLOTS=${ORAM_PADDED_SLOTS:-25}

if [ -n "${BPIR_ADMIN:-}" ]; then
    ADMIN_CMD=("$BPIR_ADMIN")
elif [ -x ./target/release/bpir-admin ]; then
    ADMIN_CMD=(./target/release/bpir-admin)
elif [ -x ./target/debug/bpir-admin ]; then
    ADMIN_CMD=(./target/debug/bpir-admin)
else
    ADMIN_CMD=(cargo run --locked -p bpir-admin --)
fi

echo "server:              $SERVER"
echo "expected measurement: $EXPECT_MEASUREMENT"
echo "expected binary:     $EXPECT_BINARY"
echo "expected ARK fp:     $EXPECT_ARK_FINGERPRINT"
echo

"${ADMIN_CMD[@]}" attest "$SERVER" \
    --expect-measurement "$EXPECT_MEASUREMENT" \
    --expect-binary "$EXPECT_BINARY"
echo
"${ADMIN_CMD[@]}" channel-test "$SERVER" --expect-ark-fingerprint "$EXPECT_ARK_FINGERPRINT"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 0 --padded-slots "$ORAM_PADDED_SLOTS" "$ORAM_SMOKE_HASH"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 1 --padded-slots "$ORAM_PADDED_SLOTS" "$ORAM_SMOKE_HASH"
