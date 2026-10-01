/**
 * Production provider pins for the free/open query path.
 *
 * The node set is fixed: pir1 (Hetzner — DPF server0 / Harmony hint /
 * OnionPIR) and the pir2 slot (since 2026-10-02 a MacBook without a TEE —
 * DPF server1 / Harmony query; the VPSBG SEV host that also ran Direct ORAM
 * was retired, so Direct ORAM is paused). The page connects to the pinned
 * providers, runs the strict
 * attestation + database-proof preflight, and queries directly; a provider
 * that requires credits (docs/CREDITS.md) is paid per metered frame from the
 * wallet. There is no bootstrap JSON, no directory, no signed policy, and no
 * capability acquisition.
 *
 * Server binary/SEV and database proof pins live in `attest-pin.ts` and are
 * re-exported here only by reference; the two per-provider operator
 * identity keys below are the same values the retired
 * `functional-beta-trusted-bootstrap.json` pinned.
 */

import {
    PIR1_PIN,
    PIR2_MACBOOK_PIN,
    type ServerAttestPin,
} from './attest-pin.js';
import { hexToBytes } from './hash.js';
import type { OramBatchPlannerConfig } from './oram-adapter.js';

export interface ProductionProviderPin {
    /** Canonical WebSocket endpoint of the provider. */
    endpoint: string;
    /** Server id expected in the REQ_ANNOUNCE identity bundle. */
    stableServerId: string;
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
    stableServerId: 'pir1-payment-beta',
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
    stableServerId: 'pir2-macbook-v1',
    serverPin: PIR2_MACBOOK_PIN,
    operatorPubkey: hexToBytes(
        '30e02d80704f77099ae342a428ab22e1176baf61b4a0593b1783289e5cb5b63c',
    ),
    expectedArkFingerprint: null,
};

/**
 * Direct ORAM provider. `null` while paused: Direct ORAM needs a TEE, and no
 * TEE host serves it since the VPSBG pir2 was retired on 2026-10-02.
 */
export const ORAM_PROVIDER: ProductionProviderPin | null = null;

/** Shown wherever Direct ORAM would otherwise connect. */
export const ORAM_PAUSED_MESSAGE =
    'Direct ORAM is paused: it needs a TEE host, and none serves it since pir2 was retired on 2026-10-02.';

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
