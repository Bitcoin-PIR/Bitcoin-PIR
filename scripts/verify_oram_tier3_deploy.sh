#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for the ORAM-enabled Tier 3 UKI. Run after uploading the
# candidate UKI in the VPSBG measured-boot portal and waiting for cloudflared
# to reconnect. EXPECT_MEASUREMENT and EXPECT_BINARY intentionally have no
# defaults so a stale repository pin cannot silently bless a new deployment.

SERVER=${SERVER:-wss://weikeng2.bitcoinpir.org}
: "${EXPECT_MEASUREMENT:?set EXPECT_MEASUREMENT to the reviewed live Tier 3 launch measurement}"
: "${EXPECT_BINARY:?set EXPECT_BINARY to the reviewed unified_server SHA-256}"
# The Direct ORAM host is an AMD Milan (web/src/attest-pin.ts AMD_MILAN_ARK_FINGERPRINT_HEX).
EXPECT_ARK_FINGERPRINT=${EXPECT_ARK_FINGERPRINT:-69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd}
ORAM_SMOKE_HASH=${ORAM_SMOKE_HASH:-4242424242424242424242424242424242424242}
ORAM_PADDED_SLOTS=${ORAM_PADDED_SLOTS:-25}

if [ -n "${BPIR_ADMIN:-}" ]; then
    ADMIN_CMD=("$BPIR_ADMIN")
else
    # Build from the checked-out source by default. Reusing an arbitrary cached
    # target/debug binary can silently run verification logic older than this
    # deployment script. Operators may opt into a reviewed binary via BPIR_ADMIN.
    ADMIN_CMD=(cargo run --locked -q -p bpir-admin --)
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
    --server "$SERVER" --db-id 0 --padded-slots "$ORAM_PADDED_SLOTS" \
    "$ORAM_SMOKE_HASH"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 1 --padded-slots "$ORAM_PADDED_SLOTS" \
    "$ORAM_SMOKE_HASH"
