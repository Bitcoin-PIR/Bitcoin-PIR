#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for the ORAM-enabled Tier 3 UKI built from BitcoinPIR
# commit d126f36a. Run after uploading the UKI in the VPSBG measured-boot
# portal and waiting for cloudflared to reconnect.

SERVER=${SERVER:-wss://weikeng2.bitcoinpir.org}
EXPECT_MEASUREMENT=${EXPECT_MEASUREMENT:-db1a0a4c43e07c212590f705679b8d5d8b6335a6dd755550b65558a675226f1f2207524ef83213bb7fd1e69b472953f2}
EXPECT_BINARY=${EXPECT_BINARY:-4cf7d467032d7c7c48147495a0307771fd196dac403a7feb62d6f4f7502045b4}
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
    --expect-binary "$EXPECT_BINARY" \
    --expect-ark-fingerprint "$EXPECT_ARK_FINGERPRINT"
echo
"${ADMIN_CMD[@]}" channel-test "$SERVER" --expect-ark-fingerprint "$EXPECT_ARK_FINGERPRINT"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 0 --padded-slots "$ORAM_PADDED_SLOTS" "$ORAM_SMOKE_HASH"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 1 --padded-slots "$ORAM_PADDED_SLOTS" "$ORAM_SMOKE_HASH"
