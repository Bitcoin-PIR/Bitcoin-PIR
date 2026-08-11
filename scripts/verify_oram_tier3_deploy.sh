#!/usr/bin/env bash
set -euo pipefail

# Post-deploy smoke for the ORAM-enabled Tier 3 UKI. Run after uploading the
# candidate UKI in the VPSBG measured-boot portal and waiting for cloudflared
# to reconnect. EXPECT_MEASUREMENT and EXPECT_BINARY intentionally have no
# defaults so a stale repository pin cannot silently bless a new deployment.

SERVER=${SERVER:-wss://weikeng2.bitcoinpir.org}
: "${EXPECT_MEASUREMENT:?set EXPECT_MEASUREMENT to the reviewed live Tier 3 launch measurement}"
: "${EXPECT_BINARY:?set EXPECT_BINARY to the reviewed unified_server SHA-256}"
EXPECT_ARK_FINGERPRINT=${EXPECT_ARK_FINGERPRINT:-1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a}
ORAM_SMOKE_HASH=${ORAM_SMOKE_HASH:-4242424242424242424242424242424242424242}
ORAM_PADDED_SLOTS=${ORAM_PADDED_SLOTS:-25}
SERVICE_PROVIDER_ID=${SERVICE_PROVIDER_ID:-85bfdd55b1408402bcad886568b732818a32472747226aa009839d45e0b96cac}
SERVICE_POLICY_SIGNING_KEY=${SERVICE_POLICY_SIGNING_KEY:-73c5889ee3bb11b79a7628bad1aa24be927f6e047abadd6dd6ce38e45bb0cfd5}
DB0_MANIFEST_ROOT=${DB0_MANIFEST_ROOT:-91421138ba94e44665bef2617af296b1c1847dea13c4df29b565012d1e0b74a6}
DB1_MANIFEST_ROOT=${DB1_MANIFEST_ROOT:-047a5b6713bf0df29d9de308fb47ff757243e365a9818cf746f399bea457d00c}
DB0_PROOF_PARAMS=${DB0_PROOF_PARAMS:-a600f33fa0e644aab533a050eabf9c03882aa00f1b293ddf9d7f4bf7c8142563}
DB1_PROOF_PARAMS=${DB1_PROOF_PARAMS:-fe6f516696bafaa2226cc1bdc7888c7c69dd263a84817dd0f18cf8027123c45d}
PROOF_BUILDER_BINARY=${PROOF_BUILDER_BINARY:-cf973a833f9b892743e451da4c2937c82865b12d8901c48ac4483b5e0696ba6f}
PROOF_BUILDER_GIT_COMMIT=${PROOF_BUILDER_GIT_COMMIT:-8d9d21a6be560236cb666269cf1f93a3de53bb1f}

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
    --service-free-pow \
    --service-provider-id-hex "$SERVICE_PROVIDER_ID" \
    --service-policy-signing-key-hex "$SERVICE_POLICY_SIGNING_KEY" \
    --service-manifest-root-hex "$DB0_MANIFEST_ROOT" \
    --service-proof-params-hash-hex "$DB0_PROOF_PARAMS" \
    --service-builder-binary-sha256-hex "$PROOF_BUILDER_BINARY" \
    --service-builder-git-commit "$PROOF_BUILDER_GIT_COMMIT" \
    "$ORAM_SMOKE_HASH"
echo
cargo run --locked -p pir-sdk-client --example oram_local_smoke -- \
    --server "$SERVER" --db-id 1 --padded-slots "$ORAM_PADDED_SLOTS" \
    --service-free-pow \
    --service-provider-id-hex "$SERVICE_PROVIDER_ID" \
    --service-policy-signing-key-hex "$SERVICE_POLICY_SIGNING_KEY" \
    --service-manifest-root-hex "$DB1_MANIFEST_ROOT" \
    --service-proof-params-hash-hex "$DB1_PROOF_PARAMS" \
    --service-builder-binary-sha256-hex "$PROOF_BUILDER_BINARY" \
    --service-builder-git-commit "$PROOF_BUILDER_GIT_COMMIT" \
    "$ORAM_SMOKE_HASH"
