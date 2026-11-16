import { readFile } from 'node:fs/promises';
import { beforeAll, describe, expect, it, vi } from 'vitest';

const { requireSdkWasm } = vi.hoisted(() => ({
  requireSdkWasm: vi.fn(),
}));

vi.mock('../sdk-bridge.js', () => ({ requireSdkWasm }));
import { PRODUCTION_ORAM_DB_PROOF_V2_PINS } from '../attest-pin.js';
import { HISTORICAL_ORAM_DELTA_PIN } from './fixtures/oram-delta-pin.js';
import type { VerifiedDatabaseProof } from '../db-proof.js';
import { bytesToHex, sha256 } from '../hash.js';
import {
  attestedRootBindsManifest,
  DB1_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
  oramOnlyManifestRootHex,
  oramSourceProofManifestPathForDbId,
  paramsHashV2ForAttestedBuildEvidence,
  parseAttestedBuildEvidence,
  parseDirectOramManifestBinding,
  reportDataForBuildEvidence,
  verifyOramSourceProof,
  type OramSourceLiveRuntime,
  type OramSourceProofManifest,
} from '../oram-source-proof.js';

const publicRoot = new URL('../../public/', import.meta.url);
const SERVER_MANIFEST_ROOT =
  '2e4c7ac695ad026b7a9bf32cc1ee7dbff863d57763b72f328cfc0f975f3d6d37';
const DB1_SERVER_MANIFEST_ROOT =
  '047a5b6713bf0df29d9de308fb47ff757243e365a9818cf746f399bea457d00c';
const DB0_PIN = PRODUCTION_ORAM_DB_PROOF_V2_PINS.find((pin) => pin.dbId === 0)!;
const DB1_PIN = HISTORICAL_ORAM_DELTA_PIN;
const LIVE_DB0_PROOF: VerifiedDatabaseProof = {
  ...DB0_PIN,
  manifestRootHex: SERVER_MANIFEST_ROOT,
};
const LIVE_DB1_PROOF: VerifiedDatabaseProof = {
  ...DB1_PIN,
  manifestRootHex: DB1_SERVER_MANIFEST_ROOT,
};
const LIVE_DB0_RUNTIME: OramSourceLiveRuntime = {
  state: 'verified-vcek',
  sevStatus: 'reportDataMatch',
  vcekChain: 'pass',
  pinStatus: 'match',
  manifestRootHex: SERVER_MANIFEST_ROOT,
};
const LIVE_DB1_RUNTIME: OramSourceLiveRuntime = {
  ...LIVE_DB0_RUNTIME,
  manifestRootHex: DB1_SERVER_MANIFEST_ROOT,
};

async function publicArtifactLoader(path: string): Promise<Uint8Array> {
  const clean = path.startsWith('/') ? path.slice(1) : path;
  return new Uint8Array(await readFile(new URL(clean, publicRoot)));
}

async function readCurrentManifest(
  manifestPath = DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
): Promise<OramSourceProofManifest> {
  return JSON.parse(
    new TextDecoder().decode(
      await publicArtifactLoader(manifestPath),
    ),
  ) as OramSourceProofManifest;
}

async function readBase64Fixture(name: string): Promise<Uint8Array> {
  const encoded = await readFile(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
  return new Uint8Array(Buffer.from(encoded.trim(), 'base64'));
}

describe('ORAM-only manifest root', () => {
  it('matches pir_core::attest::oram_only_manifest_root', () => {
    // Same fixed vector as the Rust test in crates/protocol/core/src/attest.rs.
    expect(oramOnlyManifestRootHex('11'.repeat(32))).toBe(
      'a0df7f2f77a5fe1ec7e5769b02d69774d6c56088b24df0911417262fa2ce29ab',
    );
  });

  it('binds a manifest through the root itself or its ORAM-only form only', () => {
    const root = '22'.repeat(32);
    expect(attestedRootBindsManifest(root, root)).toBe(true);
    expect(attestedRootBindsManifest(oramOnlyManifestRootHex(root).toUpperCase(), root)).toBe(true);
    expect(attestedRootBindsManifest(oramOnlyManifestRootHex('33'.repeat(32)), root)).toBe(false);
    expect(attestedRootBindsManifest('0'.repeat(64), root)).toBe(false);
    expect(attestedRootBindsManifest('', '')).toBe(false);
  });
});

describe('ORAM source input binding', () => {
  beforeAll(async () => {
    const sdk = await import('pir-sdk-wasm');
    const wasm = await readFile(
      new URL('../../../crates/sdk/wasm/pkg/pir_sdk_wasm_bg.wasm', import.meta.url),
    );
    sdk.initSync({ module: wasm });
    requireSdkWasm.mockReturnValue(sdk);
  });

  it.each([
    {
      dbId: 0,
      manifestPath: DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
      pin: DB0_PIN,
      liveProof: LIVE_DB0_PROOF,
      liveRuntime: LIVE_DB0_RUNTIME,
      buildKind: 'snapshot',
      fromHeight: 0,
      directInputs: {
        index_sha256: '8c8aedd1e4f8948b9024bc5a979b39d92795e28b0c7dfb33642668d7bb9401d2',
        index_records: '54772028',
        chunk_sha256: '9c88ed8da75bc9a43f3f3659263fc7995b6f2d27c1d8533c33721887d6af111d',
        chunk_records: '82390629',
        index_seed: '8030603977422561841',
      },
    },
    {
      dbId: 1,
      manifestPath: DB1_ORAM_SOURCE_PROOF_MANIFEST_PATH,
      pin: DB1_PIN,
      liveProof: LIVE_DB1_PROOF,
      liveRuntime: LIVE_DB1_RUNTIME,
      buildKind: 'delta',
      fromHeight: 940611,
      directInputs: {
        index_sha256: 'e06fc3dedf30096124888acef3024f21a9c049d59fd8c7d518aaf8a58ac6aa16',
        index_records: '5034692',
        chunk_sha256: '536acb605396056118c7c0836988f369c5abbfc3f7e90732ad93e819d5188e0a',
        chunk_records: '8505771',
        index_seed: '8030603977422561841',
      },
    },
  ])('verifies the published BuildEvidence V2 against live db$dbId and measured runtime', async ({
    dbId,
    manifestPath,
    pin,
    liveProof,
    liveRuntime,
    buildKind,
    fromHeight,
    directInputs,
  }) => {
    expect(oramSourceProofManifestPathForDbId(dbId)).toBe(manifestPath);
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: pin,
      liveDatabaseProof: liveProof,
      liveRuntime,
    });

    expect(status.state).toBe('verified');
    expect(status.mismatches).toEqual([]);
    expect(status.verified?.buildEvidence.version).toBe(2);
    expect(status.verified?.buildEvidence.evidenceMode).toBe('full-build');
    expect(status.verified?.buildEvidence.buildKind).toBe(buildKind);
    expect(status.verified?.buildEvidence.fromAnchor.height).toBe(fromHeight);
    expect(status.verified?.buildEvidence.anchor.height).toBe(pin.height);
    expect(status.verified?.buildEvidence.builderGitCommit).toBe(
      pin.builderGitCommit,
    );
    expect(status.verified?.directInputs).toMatchObject(directInputs);
  });

  it('maps only published ORAM source-proof database IDs', async () => {
    expect(DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH).toBe('/proofs/oram-source/current.json');
    expect(DB1_ORAM_SOURCE_PROOF_MANIFEST_PATH).toBe('/proofs/oram-source/current-db1.json');
    expect(() => oramSourceProofManifestPathForDbId(2)).toThrow(
      'unsupported ORAM source-proof db_id 2',
    );
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: { ...DB1_PIN, dbId: 2 },
      liveDatabaseProof: { ...LIVE_DB1_PROOF, dbId: 2 },
      liveRuntime: LIVE_DB1_RUNTIME,
    });
    expect(status.state).toBe('unverified');
    expect(status.error).toContain('unsupported ORAM source-proof db_id 2');
  });

  it('rejects the published db0 source bundle when the selected live database is db1', async () => {
    const status = await verifyOramSourceProof({
      manifestPath: DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH,
      artifactLoader: publicArtifactLoader,
      expectedDbPin: DB1_PIN,
      liveDatabaseProof: LIVE_DB1_PROOF,
      liveRuntime: LIVE_DB1_RUNTIME,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('attested DB pin'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('live ORAM DB proof'))).toBe(true);
  });

  it.each([
    ['builder commit', { builderGitCommit: '0'.repeat(40) }],
    ['builder binary', { builderBinarySha256Hex: '0'.repeat(64) }],
  ])('rejects a wrong production %s pin', async (_name, mutation) => {
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: { ...DB0_PIN, ...mutation },
      liveDatabaseProof: LIVE_DB0_PROOF,
      liveRuntime: LIVE_DB0_RUNTIME,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('attested DB pin'))).toBe(true);
  });

  it('rejects a substituted Direct ORAM input hash even when current.json is changed with it', async () => {
    const manifest = await readCurrentManifest();
    const ref = manifest.attestedBuilder.artifacts.serverDbManifest;
    const original = new TextDecoder().decode(await publicArtifactLoader(ref.path));
    const substituted = new TextEncoder().encode(
      original.replace(
        '8c8aedd1e4f8948b9024bc5a979b39d92795e28b0c7dfb33642668d7bb9401d2',
        '1'.repeat(64),
      ),
    );
    ref.sha256 = bytesToHex(sha256(substituted));
    ref.size = substituted.length;
    const outer = new TextEncoder().encode(JSON.stringify(manifest));

    const status = await verifyOramSourceProof({
      artifactLoader: async (path) => {
        if (path === DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH) return outer;
        if (path === ref.path) return substituted;
        return publicArtifactLoader(path);
      },
      expectedDbPin: DB0_PIN,
      liveDatabaseProof: LIVE_DB0_PROOF,
      liveRuntime: LIVE_DB0_RUNTIME,
    });

    expect(status.state).toBe('unverified');
    expect(
      status.mismatches.some((m) => m.includes('attested server DB manifest bytes sha256')),
    ).toBe(true);
  });

  it('rejects changed SNP REPORT_DATA', async () => {
    const manifest = await readCurrentManifest();
    const ref = manifest.attestedBuilder.artifacts.sevSnpReport;
    const report = (await publicArtifactLoader(ref.path)).slice();
    report[80] ^= 1;
    ref.sha256 = bytesToHex(sha256(report));
    const outer = new TextEncoder().encode(JSON.stringify(manifest));

    const status = await verifyOramSourceProof({
      artifactLoader: async (path) => {
        if (path === DEFAULT_ORAM_SOURCE_PROOF_MANIFEST_PATH) return outer;
        if (path === ref.path) return report;
        return publicArtifactLoader(path);
      },
      expectedDbPin: DB0_PIN,
      liveDatabaseProof: LIVE_DB0_PROOF,
      liveRuntime: LIVE_DB0_RUNTIME,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('BuildEvidence-derived REPORT_DATA'))).toBe(true);
  });

  it('rejects a live DB proof or runtime bound to another manifest root', async () => {
    const wrongRoot = '0'.repeat(64);
    const dbStatus = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: DB0_PIN,
      liveDatabaseProof: { ...LIVE_DB0_PROOF, manifestRootHex: wrongRoot },
      liveRuntime: LIVE_DB0_RUNTIME,
    });
    expect(dbStatus.state).toBe('unverified');
    expect(dbStatus.mismatches.some((m) => m.includes('live ORAM DB proof: manifestRootHex'))).toBe(true);

    const runtimeStatus = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: DB0_PIN,
      liveDatabaseProof: LIVE_DB0_PROOF,
      liveRuntime: { ...LIVE_DB0_RUNTIME, manifestRootHex: wrongRoot },
    });
    expect(runtimeStatus.state).toBe('unverified');
    expect(runtimeStatus.mismatches.some((m) => m.includes('live runtime manifest root'))).toBe(true);
  });

  it('requires the live AMD-verified, production-pinned runtime context', async () => {
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
      expectedDbPin: DB0_PIN,
      liveDatabaseProof: LIVE_DB0_PROOF,
      liveRuntime: { ...LIVE_DB0_RUNTIME, state: 'verified', pinStatus: 'no-pin' },
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches.some((m) => m.includes('attestation state'))).toBe(true);
    expect(status.mismatches.some((m) => m.includes('production pin'))).toBe(true);
  });

  it('requires all three live trust inputs', async () => {
    const status = await verifyOramSourceProof({
      artifactLoader: publicArtifactLoader,
    });

    expect(status.state).toBe('unverified');
    expect(status.mismatches).toContain(
      'expectedDbPin is required before an ORAM source proof can be trusted',
    );
    expect(status.mismatches).toContain(
      'liveDatabaseProof is required before an ORAM source proof can be trusted',
    );
    expect(status.mismatches).toContain(
      'liveRuntime is required before an ORAM source proof can be trusted',
    );
  });

  it('recomputes the production V2 REPORT_DATA and typed build params', async () => {
    const manifest = await readCurrentManifest();
    const evidence = await publicArtifactLoader(
      manifest.attestedBuilder.artifacts.buildEvidence.path,
    );
    const report = await publicArtifactLoader(
      manifest.attestedBuilder.artifacts.sevSnpReport.path,
    );
    const parsed = parseAttestedBuildEvidence(evidence);

    expect(parsed.version).toBe(2);
    expect(parsed.snapshotBytesDecimal).toBe('9314184426');
    expect(parsed.anchor.height).toBe(976083);
    expect(parsed.serverDbManifestSha256Hex).toBe(SERVER_MANIFEST_ROOT);
    expect(paramsHashV2ForAttestedBuildEvidence(parsed)).toBe(parsed.paramsHashHex);
    expect(bytesToHex(reportDataForBuildEvidence(evidence))).toBe(
      bytesToHex(report.slice(80, 144)),
    );
    expect(() => parseAttestedBuildEvidence(evidence.slice(0, -1))).toThrow('truncated');
    expect(() => parseAttestedBuildEvidence(Uint8Array.from([...evidence, 0]))).toThrow(
      'trailing bytes',
    );
  });

  it('matches the Rust V2 reattestation parser golden while rejecting it for production', async () => {
    const evidence = await readBase64Fixture('build-evidence-v2-reattest.base64');
    const reportData = await readBase64Fixture(
      'build-evidence-v2-reattest.report-data.base64',
    );
    const parsed = parseAttestedBuildEvidence(evidence);

    expect(bytesToHex(sha256(evidence))).toBe(
      'e9795887805769525d484824d85d8b3fcda008340c1b2332de7b46a59f055517',
    );
    expect(parsed.version).toBe(2);
    expect(parsed.evidenceMode).toBe('reattest-existing');
    expect(paramsHashV2ForAttestedBuildEvidence(parsed)).toBe(parsed.paramsHashHex);
    expect(reportDataForBuildEvidence(evidence)).toEqual(reportData);
  });

  it('parses the narrow direct_oram table without rounding its u64 seed', () => {
    const valid = `
[direct_oram]
version = 1
index_sha256 = "${'1'.repeat(64)}"
index_bytes = 25
index_records = 1
chunk_sha256 = "${'2'.repeat(64)}"
chunk_bytes = 40
chunk_records = 1
index_slots_per_bin = 4
index_hash_fns = 2
index_load_factor_ppb = 950000000
index_seed = 9223372036854775807
`;

    expect(parseDirectOramManifestBinding(valid).index_seed).toBe('9223372036854775807');
    expect(() => parseDirectOramManifestBinding(`${valid}\n${valid}`)).toThrow(
      'duplicate [direct_oram] section',
    );
    expect(() => parseDirectOramManifestBinding(`${valid}extra = 1\n`)).toThrow(
      'unknown [direct_oram] key extra',
    );
    expect(() =>
      parseDirectOramManifestBinding(valid.replace('index_bytes = 25', 'index_bytes = 26')),
    ).toThrow('INDEX bytes/records mismatch');
    expect(() =>
      parseDirectOramManifestBinding(
        valid.replace('index_seed = 9223372036854775807', 'index_seed = 18446744073709551615'),
      ),
    ).toThrow('exceeds its integer range');
  });
});
