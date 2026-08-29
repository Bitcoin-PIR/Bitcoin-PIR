/**
 * Production provider pins for the free/open query path.
 *
 * The node set is fixed: pir1 (Hetzner — DPF server0 / Harmony hint /
 * OnionPIR) and pir2 (VPSBG AMD SEV — DPF server1 / Harmony query /
 * Direct ORAM). Free queries are open: the page connects to the pinned
 * providers, runs the strict attestation + database-proof preflight, and
 * queries directly. There is no bootstrap JSON, no directory, no signed
 * policy, and no capability acquisition.
 *
 * Server binary/SEV and database proof pins live in `attest-pin.ts` and are
 * re-exported here only by reference; the two per-provider operator
 * identity keys below are the same values the retired
 * `functional-beta-trusted-bootstrap.json` pinned.
 */

import {
    AMD_TURIN_ARK_FINGERPRINT,
    PIR1_PIN,
    PIR2_TIER3_PIN,
    type ServerAttestPin,
} from './attest-pin.js';
import { hexToBytes } from './hash.js';

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

/** pir2 (VPSBG AMD SEV Tier 3): DPF server1, HarmonyPIR query, Direct ORAM. */
export const PIR2_PROVIDER: ProductionProviderPin = {
    endpoint: 'wss://weikeng2.bitcoinpir.org',
    stableServerId: 'pir2-vpsbg-dpf-v1',
    serverPin: PIR2_TIER3_PIN,
    operatorPubkey: hexToBytes(
        '30e02d80704f77099ae342a428ab22e1176baf61b4a0593b1783289e5cb5b63c',
    ),
    expectedArkFingerprint: AMD_TURIN_ARK_FINGERPRINT,
};
