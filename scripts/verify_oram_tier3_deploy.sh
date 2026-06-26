#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for the ORAM-enabled Tier 3 UKI built from BitcoinPIR
# commit 668dd36b. Run after uploading the UKI in the VPSBG measured-boot
# portal and waiting for cloudflared to reconnect.

SERVER=${SERVER:-wss://weikeng2.bitcoinpir.org}
EXPECT_MEASUREMENT=${EXPECT_MEASUREMENT:-1e6256d9c01562b04470081d260d878436340fc406bf7d5567e5824c9b94ffcfd2c95dbd2648e7030f75023223912746}
EXPECT_BINARY=${EXPECT_BINARY:-457590cf4e17221c709be806a40d7d68a7f0978e365789cbe37f4a4d1e9aaaf1}
EXPECT_ARK_FINGERPRINT=${EXPECT_ARK_FINGERPRINT:-1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a}

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
