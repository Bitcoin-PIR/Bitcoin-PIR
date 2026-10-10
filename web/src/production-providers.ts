/**
 * Production providers the page connects to: pir1 (Hetzner — DPF server0 /
 * Harmony hint / OnionPIR), the pir2 slot (since 2026-10-02 a MacBook without
 * a TEE — DPF server1 / Harmony query) and the Direct ORAM TEE host (VPSBG,
 * AMD Milan SEV-SNP, ORAM only). The page checks each provider against these
 * pins and shows the result; a provider that requires credits
 * (docs/CREDITS.md) is paid per metered frame from the wallet.
 *
 * Server binary/SEV and database proof pins live in `attest-pin.ts` and are
 * re-exported here only by reference; the two per-provider operator
 * identity keys below are the same values the retired
 * `functional-beta-trusted-bootstrap.json` pinned.
 */

import {
    AMD_MILAN_ARK_FINGERPRINT,
    PIR1_PIN,
    PIR2_MACBOOK_PIN,
    PIR2_TIER3_PIN,
    type ServerAttestPin,
} from './attest-pin.js';
import { hexToBytes } from './hash.js';
import type { OramBatchPlannerConfig } from './oram-adapter.js';

export interface ProductionProviderPin {
    /** Canonical WebSocket endpoint of the provider. */
    endpoint: string;
    /** Binary/SEV pin from `attest-pin.ts`. */
    serverPin: ServerAttestPin;
    /** Raw 32-byte operator identity key for REQ_ANNOUNCE checks. */
    operatorPubkey: Uint8Array;
    /** AMD ARK fingerprint for SEV hosts; `null` for no-SEV hosts. */
    expectedArkFingerprint: Uint8Array | null;
}

/** pir1 (Hetzner): DPF server0, HarmonyPIR hint, OnionPIR. No SEV. */
export const PIR1_PROVIDER: ProductionProviderPin = {
    endpoint: 'wss://weikeng1.bitcoinpir.org',
    serverPin: PIR1_PIN,
    operatorPubkey: hexToBytes(
        'd506c8630f13f31f0648228857c268d17996d600ed7169e091c88aadb5ecb2d4',
    ),
    expectedArkFingerprint: null,
};

/**
 * pir2 slot (MacBook, no TEE, since 2026-10-02): DPF server1, HarmonyPIR query.
 * Same operator key as the retired VPSBG pir2, new server identity.
 */
export const PIR2_PROVIDER: ProductionProviderPin = {
    endpoint: 'wss://bitcoin-pir-weikeng-laptop.chenweikeng.com',
    serverPin: PIR2_MACBOOK_PIN,
    operatorPubkey: hexToBytes(
        '30e02d80704f77099ae342a428ab22e1176baf61b4a0593b1783289e5cb5b63c',
    ),
    expectedArkFingerprint: null,
};

/**
 * Direct ORAM provider: the VPSBG TEE host weikeng2 (server 26939, AMD Milan,
 * Direct ORAM only). Same operator key as the pir2 slot; its own server
 * identity. Set back to `null` to pause Direct ORAM.
 */
export const ORAM_PROVIDER: ProductionProviderPin | null = {
    endpoint: 'wss://weikeng2.bitcoinpir.org',
    serverPin: PIR2_TIER3_PIN,
    operatorPubkey: hexToBytes(
        '30e02d80704f77099ae342a428ab22e1176baf61b4a0593b1783289e5cb5b63c',
    ),
    expectedArkFingerprint: AMD_MILAN_ARK_FINGERPRINT,
};

/** Shown wherever Direct ORAM would otherwise connect. */
export const ORAM_PAUSED_MESSAGE =
    'Direct ORAM is paused: it needs an attested TEE host, and none is serving it right now.';

/**
 * Direct ORAM request shape used in production. Every lookup is one
 * fixed-budget request with the same padded slot count, so the server sees
 * the same access pattern whatever the batch holds. SDK consumers pass this
 * as `OramPirClientConfig.batchPlanner` rather than choosing their own.
 */
export const PRODUCTION_ORAM_BATCH_PLANNER: Readonly<OramBatchPlannerConfig> = Object.freeze({
    accessBudget: 75,
    indexReadsPerScriptHash: 2,
    expectedChunkReadsPerScriptHash: 1,
    paddedSlotCount: 25,
    maxScriptHashesPerRequest: 25,
});
