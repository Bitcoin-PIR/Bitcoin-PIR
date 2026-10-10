/**
 * The checks the browser clients run on a connection: server attestation,
 * operator identity, and database proofs. Each check reports its outcome
 * and never refuses the connection; the caller decides what to show.
 */

import {
  applySevSnpPlatformFloor,
  getAmdTurinArkFingerprint,
  pinAcceptsBinary,
  type ServerAttestPin,
} from './attest-pin.js';
import {
  databaseProofUnavailable,
  verifiedDatabaseProofFromWasm,
  verifyDatabaseProofAgainstPin,
  type DatabaseProofPin,
  type DatabaseProofStatus,
  type VerifiedDatabaseProof,
} from './db-proof.js';
import {
  requireSdkWasm,
  type WasmAnnounceVerification,
  type WasmAttestVerification,
  type WasmDatabaseProof,
} from './sdk-bridge.js';

/**
 * One server's attestation.
 *
 * `state`:
 *   - `'unattested'`: not attested (yet).
 *   - `'plaintext'`: the server has no channel key.
 *   - `'verified'`: the SEV-SNP report binds the channel key (or the host has
 *     no SEV-SNP), the VCEK chain was not checked, and any build pin matched.
 *   - `'verified-vcek'`: as `'verified'`, plus the AMD VCEK chain and the guest
 *     policy verified against the pinned ARK.
 *   - `'mismatch'`: the binding, the VCEK chain or a build pin failed;
 *     `vcekChainError` / `pinError` say which.
 */
export interface ServerAttestation {
  state: 'unattested' | 'verified' | 'verified-vcek' | 'plaintext' | 'mismatch';
  sevStatus?: string;
  serverStaticPubHex?: string;
  binarySha256Hex?: string;
  gitRev?: string;
  launchMeasurementHex?: string;
  manifestRootsHex?: string[];
  vcekChain?: 'pass' | 'fail' | 'skipped';
  vcekChainError?: string;
  pinStatus?: 'no-pin' | 'match' | 'measurement-mismatch' | 'binary-mismatch';
  pinError?: string;
}

/**
 * One server's operator-signed identity (REQ_ANNOUNCE). `'verified'` means the
 * bundle is signed by the pinned operator key, valid now, and bound to the
 * attested channel key. `'unconfigured'`: the server has no identity.
 */
export interface OperatorIdentity {
  state: 'not-checked' | 'unconfigured' | 'verified' | 'unverified' | 'error';
  serverId?: string;
  operatorPubkeyHex?: string;
  identityPubkeyHex?: string;
  gitRev?: string;
  binarySha256Hex?: string;
  validUntil?: number;
  error?: string;
}

function errorMessage(error: unknown): string {
  return (error as Error)?.message ?? String(error);
}

function short(hex: string): string {
  return `${hex.slice(0, 16)}…`;
}

/** Summarise one attestation: the REPORT_DATA binding, the VCEK chain and
 * guest policy when `arkFingerprint` is given, and `pin` when one is set. */
export function summariseAttestation(
  att: WasmAttestVerification | null,
  pin: ServerAttestPin | undefined,
  arkFingerprint: Uint8Array | null,
): ServerAttestation {
  if (!att) return { state: 'mismatch' };
  const matched = att.sevStatus === 'reportDataMatch';
  const bound = matched || att.sevStatus === 'noSevHost';
  const result: ServerAttestation = {
    state: att.serverStaticPub.every((b) => b === 0) ? 'plaintext' : bound ? 'verified' : 'mismatch',
    sevStatus: att.sevStatus,
    serverStaticPubHex: att.serverStaticPubHex,
    binarySha256Hex: att.binarySha256Hex,
    gitRev: att.gitRev,
    launchMeasurementHex: att.launchMeasurementHex,
    manifestRootsHex: att.manifestRootsHex,
  };

  if (result.state === 'verified' && matched) {
    if (!att.hasVcekChain || !arkFingerprint) {
      result.vcekChain = 'skipped';
    } else {
      const policy = new (requireSdkWasm().WasmPolicyRequirements)();
      try {
        applySevSnpPlatformFloor(policy, arkFingerprint);
        att.verifyFull(arkFingerprint, policy);
        result.state = 'verified-vcek';
        result.vcekChain = 'pass';
      } catch (error) {
        result.state = 'mismatch';
        result.vcekChain = 'fail';
        result.vcekChainError = errorMessage(error);
      } finally {
        policy.free();
      }
    }
  }

  if (!pin) {
    result.pinStatus = 'no-pin';
  } else if (result.state === 'verified' || result.state === 'verified-vcek') {
    const failure = pinFailure(pin, att);
    if (failure) {
      result.state = 'mismatch';
      result.pinStatus = failure.status;
      result.pinError = failure.message;
    } else {
      result.pinStatus = 'match';
    }
  }
  return result;
}

function pinFailure(
  pin: ServerAttestPin,
  att: WasmAttestVerification,
): { status: 'measurement-mismatch' | 'binary-mismatch'; message: string } | null {
  if (pin.measurementHex) {
    if (!att.launchMeasurementHex) {
      return { status: 'measurement-mismatch', message: `MEASUREMENT pin ${short(pin.measurementHex)} but the report has no MEASUREMENT` };
    }
    if (pin.measurementHex.toLowerCase() !== att.launchMeasurementHex.toLowerCase()) {
      return { status: 'measurement-mismatch', message: `MEASUREMENT ${short(att.launchMeasurementHex)} does not match the pin ${short(pin.measurementHex)}` };
    }
  }
  if (pin.binarySha256Hex) {
    if (!att.binarySha256Hex) {
      return { status: 'binary-mismatch', message: `binary pin ${short(pin.binarySha256Hex)} but the report has no binary hash` };
    }
    if (!pinAcceptsBinary(pin, att.binarySha256Hex)) {
      return { status: 'binary-mismatch', message: `binary ${short(att.binarySha256Hex)} does not match the pin ${short(pin.binarySha256Hex)}` };
    }
  }
  return null;
}

/** Classify a fetched announce bundle against `pinnedOperatorPubkey` and the
 * attested channel key. Never throws. */
export function gateOperatorIdentity(
  v: WasmAnnounceVerification,
  pinnedOperatorPubkey: Uint8Array,
  expectedChannelPub: Uint8Array,
  nowUnixSeconds: bigint,
  maxAgeSeconds: bigint = 0n,
): OperatorIdentity {
  try {
    v.checkPinnedOperator(pinnedOperatorPubkey, nowUnixSeconds);
    v.checkChannelBinding(expectedChannelPub);
    v.checkFreshness(nowUnixSeconds, maxAgeSeconds);
    return {
      state: 'verified',
      serverId: v.serverId,
      operatorPubkeyHex: v.operatorPubkeyHex,
      identityPubkeyHex: v.identityPubkeyHex,
      binarySha256Hex: v.binarySha256Hex,
      gitRev: v.gitRev,
      validUntil: Number(v.validUntil),
    };
  } catch (error) {
    return {
      state: 'unverified',
      serverId: v.serverId,
      operatorPubkeyHex: v.operatorPubkeyHex,
      binarySha256Hex: v.binarySha256Hex,
      error: errorMessage(error),
    };
  }
}

/** Fetch one server's announce bundle and check it. Never throws. */
export async function checkOperatorIdentity(
  announce: () => Promise<WasmAnnounceVerification>,
  att: WasmAttestVerification | null,
  pin: Uint8Array,
  maxAgeSeconds = 0,
): Promise<OperatorIdentity> {
  if (!att) return { state: 'error', error: 'no attestation to bind the channel key to' };
  let v: WasmAnnounceVerification;
  try {
    v = await announce();
  } catch (error) {
    const message = errorMessage(error);
    return /not configured/i.test(message) ? { state: 'unconfigured' } : { state: 'error', error: message };
  }
  try {
    const now = BigInt(Math.floor(Date.now() / 1000));
    return gateOperatorIdentity(v, pin, att.serverStaticPub, now, BigInt(maxAgeSeconds));
  } finally {
    v.free();
  }
}

/** The ARK fingerprint for the VCEK chain check: `configured`, or the Turin ARK
 * when `undefined`; `null` skips the check. */
export function arkFingerprint(configured: Uint8Array | null | undefined): Uint8Array | null {
  if (configured !== undefined) return configured;
  try {
    return getAmdTurinArkFingerprint();
  } catch {
    return null;
  }
}

/** The WASM client methods a two-server client needs for `attestPair`. */
export interface AttestingPairClient {
  attest(serverIndex: number): Promise<WasmAttestVerification>;
  upgradeToSecureChannel(pub0: Uint8Array, pub1: Uint8Array): Promise<void>;
  announce(serverIndex: number): Promise<WasmAnnounceVerification>;
}

export interface PairChecks {
  attestation: [ServerAttestation, ServerAttestation];
  operatorIdentity: [OperatorIdentity, OperatorIdentity];
  secureChannel: boolean;
}

/** Attest both servers, upgrade to the encrypted channel when both present a
 * channel key, and check each server's operator identity when its operator
 * key is given. Outcomes are reported in the result. */
export async function attestPair(
  client: AttestingPairClient,
  options: {
    pins: [ServerAttestPin | undefined, ServerAttestPin | undefined];
    operatorPins: [Uint8Array | undefined, Uint8Array | undefined];
    arkFingerprint: Uint8Array | null;
    maxAnnounceAgeSeconds?: number;
    log: (msg: string, level: 'info' | 'success' | 'error') => void;
  },
): Promise<PairChecks> {
  const attest = async (idx: 0 | 1): Promise<WasmAttestVerification | null> => {
    try {
      return await client.attest(idx);
    } catch (error) {
      options.log(`attest(server${idx}) failed: ${errorMessage(error)}`, 'error');
      return null;
    }
  };
  // Sequential: both calls borrow the same native client.
  const atts = [await attest(0), await attest(1)] as const;
  try {
    const checks: PairChecks = {
      attestation: [
        summariseAttestation(atts[0], options.pins[0], options.arkFingerprint),
        summariseAttestation(atts[1], options.pins[1], options.arkFingerprint),
      ],
      operatorIdentity: [{ state: 'not-checked' }, { state: 'not-checked' }],
      secureChannel: false,
    };

    const hasKey = (att: WasmAttestVerification | null) => !!att && att.serverStaticPub.some((b) => b !== 0);
    if (atts[0] && atts[1] && hasKey(atts[0]) && hasKey(atts[1])) {
      try {
        await client.upgradeToSecureChannel(atts[0].serverStaticPub, atts[1].serverStaticPub);
        checks.secureChannel = true;
        options.log('Upgraded to the encrypted channel', 'success');
      } catch (error) {
        options.log(`upgradeToSecureChannel failed: ${errorMessage(error)}`, 'error');
      }
    } else {
      options.log('Channel left in cleartext: a server has no channel key', 'info');
    }

    for (const idx of [0, 1] as const) {
      const pin = options.operatorPins[idx];
      if (!pin) continue;
      checks.operatorIdentity[idx] = await checkOperatorIdentity(
        () => client.announce(idx),
        atts[idx],
        pin,
        options.maxAnnounceAgeSeconds ?? 0,
      );
    }
    return checks;
  } finally {
    atts[0]?.free();
    atts[1]?.free();
  }
}

/** The WASM client methods database-proof verification needs. */
export interface DatabaseProofClient {
  verifyDatabaseProof(
    dbId: number,
    expectedParamsHashHex?: string | null,
    allowedBuilderBinarySha256Hex?: string | null,
    allowedBuilderGitCommit?: string | null,
  ): Promise<WasmDatabaseProof>;
  /** Consumes `proof`, even when it throws. */
  installVerifiedDatabaseProof(proof: WasmDatabaseProof): void;
  /** Checks the server's Merkle tree-tops against the installed root. */
  preflightDatabase?(dbId: number): Promise<void>;
}

/** Verify each pinned database proof. A proof that matches its pin becomes the
 * database's trusted root, and the server's tree-tops are checked against it.
 * Every outcome goes to `onStatus`; this never throws. */
export async function verifyDatabaseProofs(
  client: DatabaseProofClient,
  pins: readonly DatabaseProofPin[],
  onStatus: (dbId: number, status: DatabaseProofStatus) => void,
): Promise<void> {
  for (const pin of pins) onStatus(pin.dbId, await verifyDatabaseProof(client, pin));
}

async function verifyDatabaseProof(
  client: DatabaseProofClient,
  pin: DatabaseProofPin,
): Promise<DatabaseProofStatus> {
  let handle: WasmDatabaseProof | null;
  try {
    handle = await client.verifyDatabaseProof(
      pin.dbId,
      pin.paramsHashHex,
      pin.builderBinarySha256Hex,
      pin.builderGitCommit,
    );
  } catch (error) {
    return databaseProofUnavailable(pin, error);
  }
  let proof: VerifiedDatabaseProof | undefined;
  try {
    proof = verifiedDatabaseProofFromWasm(handle);
    const status = verifyDatabaseProofAgainstPin(proof, pin);
    if (status.state !== 'verified') return status;
    const installed = handle;
    handle = null;
    client.installVerifiedDatabaseProof(installed);
    await client.preflightDatabase?.(pin.dbId);
    return status;
  } catch (error) {
    return { state: 'unverified', dbId: pin.dbId, pin, proof, error: errorMessage(error) };
  } finally {
    handle?.free();
  }
}
