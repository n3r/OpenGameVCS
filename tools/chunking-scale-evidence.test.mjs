import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, posix, win32 } from 'node:path';
import test from 'node:test';

import { canonicalDigest, canonicalJson } from '../foundation/benchmark-fault-harness/src/index.mjs';
import { createChunker } from '../core/chunking-manifest/js/src/index.mjs';
import {
  buildChunkingScaleEvidenceBundle,
  buildRetainedChunkingScalePublication,
  writeChunkingScaleEvidenceBundle,
  writeRetainedChunkingScalePublication,
} from './chunking-scale-evidence-bundle.mjs';
import { compareVerifiedChunkingScaleEvidence } from './chunking-scale-evidence-comparator.mjs';
import {
  SCALE_BOUNDS,
  SCALE_LOGICAL_BYTES,
  SCALE_ROOT,
  SCALE_SOURCE,
  implementationAuthority,
  isScaleEvidencePathWithinRoot,
  loadScaleReport,
  parseScaleReportText,
  scaleEvidenceSourceInventory,
  scalePublicationDirectorySyncOpenFlag,
  sha256Bytes,
} from './chunking-scale-evidence-common.mjs';
import {
  inspectVerifiedChunkingScaleEvidence,
  verifyChunkingScaleEvidenceBundle,
  verifyRetainedChunkingScalePublication,
} from './verify-chunking-scale-evidence-bundle.mjs';

const SOURCE_REVISION = '1'.repeat(40);
const PUBLISHER_ENVIRONMENT = Object.freeze({ os: 'linux', architecture: 'x64', nodeVersion: 'v24.9.0' });

function scaleReport(implementation, mutate = (value) => value) {
  const authority = implementationAuthority(implementation);
  const wallTimeMilliseconds = 1_000;
  const value = {
    schemaVersion: 'ogvcs.chunking-manifest/scale-report/v1',
    implementation,
    profile: 'chunking.opengamevcs/gear-fastcdc-1m@1',
    sourceRevision: SOURCE_REVISION,
    exactScaleExecuted: true,
    runtime: {
      os: 'linux',
      architecture: 'x64',
      version: implementation === 'javascript' ? 'v24.9.0' : '1.82.0',
    },
    source: SCALE_SOURCE,
    result: {
      class: 'cdc-1m',
      logicalBytes: String(SCALE_LOGICAL_BYTES),
      chunkCount: 102_400,
      totalChunkBytes: String(SCALE_LOGICAL_BYTES),
      minimumChunkBytes: 524_288,
      maximumChunkBytes: 2_097_152,
      wholeFileSha256: '2'.repeat(64),
      manifestObjectId: `ogvcs:v1:content-manifest:sha256:${'3'.repeat(64)}`,
      manifestSha256: '4'.repeat(64),
      manifestBytes: 8_388_608,
      boundaryTranscriptSha256: '5'.repeat(64),
    },
    resources: {
      wallTimeMilliseconds,
      cpuMicroseconds: 800_000,
      cpuSource: authority.cpuSource,
      diskReadBytes: 0,
      diskWriteBytes: 1_048_576,
      ioSource: 'linux:/proc/self/io:read_bytes+write_bytes',
      processWriteBytes: 16_777_216,
      processWriteSource: 'linux:/proc/self/io:wchar',
      measurementScope: 'source-pattern-generation-through-scratch-cleanup-before-report-publication',
      throughputBytesPerSecond: Math.floor(SCALE_LOGICAL_BYTES * 1000 / wallTimeMilliseconds),
      peakRssBytes: 134_217_728,
      maxRssSource: authority.maxRssSource,
      patternBufferBytes: SCALE_SOURCE.patternBytes,
      scalarWorkingMemoryBytes: 4_259_840,
      ledgerRecords: 102_400,
      ledgerPeakMemoryBytes: 1_048_576,
      ledgerPeakScratchBytes: 8_388_608,
      ledgerSpilled: true,
      scratchArtifactsAfter: 0,
    },
    bounds: SCALE_BOUNDS,
    overallStatus: 'passed',
  };
  return mutate(structuredClone(value));
}

function reportRecord(implementation, mutate) {
  return parseScaleReportText(`${JSON.stringify(scaleReport(implementation, mutate), null, 2)}\n`, implementation);
}

async function buildFixture(implementation, record, publisherEnvironment = PUBLISHER_ENVIRONMENT) {
  return buildChunkingScaleEvidenceBundle({
    implementation,
    reportRecord: record,
    publisherEnvironmentForTest: publisherEnvironment,
  });
}

async function rebindProjection(directory, mutate) {
  const projectionPath = join(directory, 'projection.json');
  const projection = JSON.parse(await readFile(projectionPath));
  mutate(projection);
  const projectionBytes = Buffer.from(`${canonicalJson(projection)}\n`);
  await writeFile(projectionPath, projectionBytes);
  const manifestPath = join(directory, 'manifest.json');
  const manifest = JSON.parse(await readFile(manifestPath));
  const record = manifest.artifacts.find(({ path }) => path === 'projection.json');
  record.bytes = projectionBytes.byteLength;
  record.sha256 = sha256Bytes(projectionBytes);
  manifest.bundleDigest = canonicalDigest(manifest.artifacts, 'ogvcs.chunking-manifest/exact-scale-publication/v1');
  await writeFile(manifestPath, `${canonicalJson(manifest)}\n`);
}

test('exact report parser is bounded and rejects every protected projection mutation', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-scale-report-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, 'javascript.json');
  const baseline = reportRecord('javascript');
  await writeFile(path, baseline.text, { flag: 'wx' });
  const loaded = await loadScaleReport(path, 'javascript');
  assert.equal(loaded.reportSha256, baseline.reportSha256);
  const mutations = [
    (row) => { row.extra = true; },
    (row) => { row.exactScaleExecuted = false; },
    (row) => { row.sourceRevision = '2'.repeat(39); },
    (row) => { row.runtime.architecture = 'ppc64'; },
    (row) => { row.source.patternSha256 = '0'.repeat(64); },
    (row) => { row.result.totalChunkBytes = '1'; },
    (row) => { row.result.manifestSha256 = 'f'.repeat(63); },
    (row) => { row.result.manifestSha256 = '3'.repeat(64); },
    (row) => { row.resources.cpuMicroseconds = SCALE_BOUNDS.cpuTimeMicrosecondsMaximum + 1; },
    (row) => { row.resources.cpuSource = 'caller-claimed'; },
    (row) => { row.resources.diskReadBytes = -1; },
    (row) => { row.resources.processWriteBytes = SCALE_BOUNDS.processWriteBytesMaximum + 1; },
    (row) => { row.resources.processWriteSource = 'linux:/proc/self/io:cancelled_write_bytes'; },
    (row) => { row.resources.ioSource = 'caller-claimed'; },
    (row) => { row.resources.peakRssBytes = SCALE_BOUNDS.peakRssBytesMaximum + 1; },
    (row) => { row.resources.scratchArtifactsAfter = 1; },
    (row) => { row.resources.throughputBytesPerSecond += 1; },
    (row) => { row.bounds.temporaryWholeFileAllowed = true; },
    (row) => { row.bounds.manifestBytesMaximum -= 1; },
  ];
  for (const mutate of mutations) {
    assert.throws(() => reportRecord('javascript', (row) => { mutate(row); return row; }), /chunking exact-scale evidence failure/);
  }
  assert.throws(() => parseScaleReportText(baseline.text.trim(), 'javascript'), /terminal-LF/);
  assert.throws(() => parseScaleReportText(`${baseline.text}\n`, 'javascript'), /terminal-LF/);
  assert.throws(() => parseScaleReportText(`${JSON.stringify(baseline.report)}\n`, 'javascript'), /normalized JSON/);
  assert.throws(
    () => parseScaleReportText(baseline.text.replace('  "implementation": "javascript",', '  "implementation": "rust",\n  "implementation": "javascript",'), 'javascript'),
    /normalized JSON/,
  );
  assert.throws(() => parseScaleReportText(`${' '.repeat(65_536)}\n`, 'javascript'), /bounded/);
  assert.throws(() => { baseline.report.result.chunkCount += 1; }, TypeError);
});

test('the runner manifest sink produces distinct typed ObjectID and raw digest known answers', async () => {
  const source = Buffer.from('4f70656e47616d655643530a', 'hex');
  const streamed = [];
  const chunker = createChunker({
    declaredLength: source.byteLength,
    manifestSink(bytes) { streamed.push(Buffer.from(bytes)); },
    retainEntries: false,
  });
  chunker.update(source);
  const result = await chunker.finish();
  const manifestBytes = Buffer.concat(streamed);
  const rawManifestSha256 = createHash('sha256').update(manifestBytes).digest('hex');
  assert.equal(manifestBytes.toString('hex'), 'a7000101020280100c11a2000101582036fcc2e9442be1071c275604af6e41bd93875c743dc2fdaa6037662df74c589412a300746368756e6b696e672e6f70656e67616d65766373016f676561722d666173746364632d316d02011381a200a4000101010201035820944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5010c');
  assert.equal(result.manifest.objectId, 'ogvcs:v1:content-manifest:sha256:e8f5b807d1bbe151218d49786347b0811276b841cb1bf2b98d34843f8f12170f');
  assert.equal(rawManifestSha256, 'a7ca3520438a39dbd693501d67da6e709a9f1b808f4f51cc3b88bf91a949308a');
  assert.notEqual(result.manifest.objectId.slice(-64), rawManifestSha256);
});

test('current-source inventory covers the runner and transitive JS/Rust implementation closure', async () => {
  const inventory = await scaleEvidenceSourceInventory();
  const paths = inventory.map(({ path }) => path);
  assert.deepEqual(paths, [...paths].sort());
  assert.equal(new Set(paths).size, paths.length);
  for (const path of [
    'package-lock.json',
    'core/chunking-manifest/js/package.json',
    'core/chunking-manifest/js/src/gear.mjs',
    'core/chunking-manifest/rust/Cargo.toml',
    'core/chunking-manifest/rust/Cargo.lock',
    'core/chunking-manifest/rust/src/lib.rs',
    'core/object-model/js/src/index.js',
    'core/object-model/rust/Cargo.toml',
    'core/object-model/rust/Cargo.lock',
    'core/object-model/rust/src/lib.rs',
    'core/paths-filesystem/js/src/index.mjs',
    'foundation/benchmark-fault-harness/src/canonical.mjs',
  ]) assert.ok(paths.includes(path), path);
  assert.ok(inventory.every(({ bytes, sha256 }) => bytes > 1 && /^[0-9a-f]{64}$/u.test(sha256)));
});

test('source-root containment is exact across POSIX, drive-letter, and UNC paths', () => {
  assert.equal(isScaleEvidencePathWithinRoot('/srv/repo', '/srv/repo/tools/report.mjs', posix), true);
  assert.equal(isScaleEvidencePathWithinRoot('/srv/repo', '/srv/repository/report.mjs', posix), false);
  assert.equal(isScaleEvidencePathWithinRoot('/srv/repo', '/srv/repo', posix), false);
  assert.equal(isScaleEvidencePathWithinRoot('D:\\a\\repo', 'D:\\a\\repo\\tools\\report.mjs', win32), true);
  assert.equal(isScaleEvidencePathWithinRoot('D:\\a\\repo', 'D:\\a\\repository\\report.mjs', win32), false);
  assert.equal(isScaleEvidencePathWithinRoot('D:\\a\\repo', 'E:\\a\\repo\\report.mjs', win32), false);
  assert.equal(isScaleEvidencePathWithinRoot('\\\\host\\share\\repo', '\\\\host\\share\\repo\\tools\\report.mjs', win32), true);
  assert.equal(isScaleEvidencePathWithinRoot('\\\\host\\share\\repo', '\\\\host\\share\\other\\report.mjs', win32), false);
});

test('directory durability requests write authority only on Windows', () => {
  assert.equal(scalePublicationDirectorySyncOpenFlag('win32'), 'r+');
  for (const platform of ['aix', 'darwin', 'freebsd', 'linux', 'openbsd', 'sunos']) {
    assert.equal(scalePublicationDirectorySyncOpenFlag(platform), 'r', platform);
  }
});

test('tiny projections publish as two content-addressed bundles and compare only through verified brands', { timeout: 120_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-chunking-scale-bundles-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const javascriptRecord = reportRecord('javascript');
  const rustRecord = reportRecord('rust');
  const priorRevision = process.env.OGVCS_SOURCE_REVISION;
  const priorReport = process.env.OGVCS_SCALE_REPORT_PATH;
  const priorCargo = process.env.CARGO;
  process.env.OGVCS_SOURCE_REVISION = 'invalid-test-sentinel';
  process.env.OGVCS_SCALE_REPORT_PATH = join(directory, 'runner-must-not-write');
  process.env.CARGO = join(directory, 'cargo-must-not-run');
  let javascript;
  let rust;
  try {
    javascript = await buildFixture('javascript', javascriptRecord);
    rust = await buildFixture('rust', rustRecord);
  } finally {
    if (priorRevision === undefined) delete process.env.OGVCS_SOURCE_REVISION; else process.env.OGVCS_SOURCE_REVISION = priorRevision;
    if (priorReport === undefined) delete process.env.OGVCS_SCALE_REPORT_PATH; else process.env.OGVCS_SCALE_REPORT_PATH = priorReport;
    if (priorCargo === undefined) delete process.env.CARGO; else process.env.CARGO = priorCargo;
  }
  await assert.rejects(readFile(join(directory, 'runner-must-not-write')), { code: 'ENOENT' });
  await assert.rejects(readFile(join(directory, 'cargo-must-not-run')), { code: 'ENOENT' });
  const javascriptDirectory = join(directory, 'javascript-bundle');
  const rustDirectory = join(directory, 'rust-bundle');
  await writeChunkingScaleEvidenceBundle(javascriptDirectory, javascript);
  await writeChunkingScaleEvidenceBundle(rustDirectory, rust);
  await assert.rejects(writeChunkingScaleEvidenceBundle(javascriptDirectory, javascript));

  const javascriptHandle = await verifyChunkingScaleEvidenceBundle(javascriptDirectory, 'javascript');
  const rustHandle = await verifyChunkingScaleEvidenceBundle(rustDirectory, 'rust');
  assert.equal(inspectVerifiedChunkingScaleEvidence(javascriptHandle).reportSha256, javascriptRecord.reportSha256);
  assert.equal(inspectVerifiedChunkingScaleEvidence(rustHandle).reportSha256, rustRecord.reportSha256);
  assert.equal(inspectVerifiedChunkingScaleEvidence(javascriptHandle).sourceRevisionBinding, 'workflow-supplied-not-git-bound');
  const javascriptPublication = buildRetainedChunkingScalePublication(javascript);
  const rustPublication = buildRetainedChunkingScalePublication(rust);
  const javascriptPublicationPath = join(directory, 'javascript-publication.json');
  const rustPublicationPath = join(directory, 'rust-publication.json');
  await writeRetainedChunkingScalePublication(javascriptPublicationPath, javascriptPublication);
  await writeRetainedChunkingScalePublication(rustPublicationPath, rustPublication);
  const retainedJavascriptHandle = await verifyRetainedChunkingScalePublication(javascriptPublicationPath, 'javascript');
  const retainedRustHandle = await verifyRetainedChunkingScalePublication(rustPublicationPath, 'rust');
  assert.equal(inspectVerifiedChunkingScaleEvidence(retainedJavascriptHandle).bundleDigest, inspectVerifiedChunkingScaleEvidence(javascriptHandle).bundleDigest);
  assert.equal(inspectVerifiedChunkingScaleEvidence(retainedRustHandle).publicationSha256, rustPublication.publicationSha256);
  const comparison = compareVerifiedChunkingScaleEvidence(javascriptHandle, rustHandle);
  assert.equal(comparison.matched, true);
  assert.equal(comparison.inputs.javascript.bundleDigest, inspectVerifiedChunkingScaleEvidence(javascriptHandle).bundleDigest);
  assert.throws(() => compareVerifiedChunkingScaleEvidence(rustHandle, javascriptHandle), /substituted/);
  assert.throws(() => compareVerifiedChunkingScaleEvidence(Object.freeze({}), rustHandle), /handle is invalid/);

  const tamperedPublicationPath = join(directory, 'tampered-publication.json');
  const tamperedPublication = structuredClone(javascriptPublication);
  tamperedPublication.artifacts[1].sha256 = '0'.repeat(64);
  await writeFile(tamperedPublicationPath, `${canonicalJson(tamperedPublication)}\n`);
  await assert.rejects(verifyRetainedChunkingScalePublication(tamperedPublicationPath, 'javascript'), /does not reproduce/);

  const javascriptValidationPath = join(directory, 'javascript-validation.json');
  const verifier = spawnSync(process.execPath, [
    'tools/verify-chunking-scale-evidence-bundle.mjs',
    '--implementation', 'javascript', '--bundle', javascriptDirectory, '--output', javascriptValidationPath,
  ], { cwd: SCALE_ROOT, encoding: 'utf8' });
  assert.equal(verifier.status, 0, verifier.stderr);
  assert.equal(JSON.parse(verifier.stdout).verified, true);
  assert.equal(JSON.parse(await readFile(javascriptValidationPath, 'utf8')).reportSha256, javascriptRecord.reportSha256);
  const duplicateVerifier = spawnSync(process.execPath, [
    'tools/verify-chunking-scale-evidence-bundle.mjs',
    '--implementation', 'javascript', '--bundle', javascriptDirectory, '--output', javascriptValidationPath,
  ], { cwd: SCALE_ROOT, encoding: 'utf8' });
  assert.notEqual(duplicateVerifier.status, 0);

  const comparisonPath = join(directory, 'comparison.json');
  const comparator = spawnSync(process.execPath, [
    'tools/compare-chunking-scale.mjs',
    '--javascript-bundle', javascriptDirectory, '--rust-bundle', rustDirectory, '--output', comparisonPath,
  ], { cwd: SCALE_ROOT, encoding: 'utf8' });
  assert.equal(comparator.status, 0, comparator.stderr);
  assert.equal(JSON.parse(comparator.stdout).verified, true);
  assert.equal(JSON.parse(await readFile(comparisonPath, 'utf8')).matched, true);
  const duplicateComparator = spawnSync(process.execPath, [
    'tools/compare-chunking-scale.mjs',
    '--javascript-bundle', javascriptDirectory, '--rust-bundle', rustDirectory, '--output', comparisonPath,
  ], { cwd: SCALE_ROOT, encoding: 'utf8' });
  assert.notEqual(duplicateComparator.status, 0);

  const mismatches = [
    { label: 'source-revision', pattern: /source revisions differ/, mutate(row) { row.sourceRevision = '2'.repeat(40); } },
    { label: 'architecture', pattern: /runtime architectures differ/, mutate(row) { row.runtime.architecture = 'arm64'; } },
    { label: 'result', pattern: /implementation results differ/, mutate(row) { row.result.wholeFileSha256 = '6'.repeat(64); } },
  ];
  for (const mismatch of mismatches) {
    const record = reportRecord('rust', (row) => { mismatch.mutate(row); return row; });
    const environment = { ...PUBLISHER_ENVIRONMENT, architecture: record.report.runtime.architecture };
    const built = await buildFixture('rust', record, environment);
    const path = join(directory, `rust-${mismatch.label}-bundle`);
    await writeChunkingScaleEvidenceBundle(path, built);
    const handle = await verifyChunkingScaleEvidenceBundle(path, 'rust');
    assert.throws(() => compareVerifiedChunkingScaleEvidence(javascriptHandle, handle), mismatch.pattern);
  }

  const forgedDirectory = join(directory, 'content-bound-product-forgery');
  const forged = await buildFixture('javascript', javascriptRecord);
  await writeChunkingScaleEvidenceBundle(forgedDirectory, forged);
  await rebindProjection(forgedDirectory, (projection) => { projection.reportSha256 = '0'.repeat(64); });
  await assert.rejects(verifyChunkingScaleEvidenceBundle(forgedDirectory, 'javascript'), /projection does not reproduce/);

  const revisionBindingDirectory = join(directory, 'source-revision-binding-forgery');
  const revisionBinding = await buildFixture('javascript', javascriptRecord);
  await writeChunkingScaleEvidenceBundle(revisionBindingDirectory, revisionBinding);
  const bindingManifestPath = join(revisionBindingDirectory, 'manifest.json');
  const bindingManifest = JSON.parse(await readFile(bindingManifestPath));
  bindingManifest.sourceRevisionBinding = 'git-bound';
  await writeFile(bindingManifestPath, `${canonicalJson(bindingManifest)}\n`);
  await assert.rejects(verifyChunkingScaleEvidenceBundle(revisionBindingDirectory, 'javascript'), /manifest authority is invalid/);

  const tamperedDirectory = join(directory, 'artifact-tamper');
  const tampered = await buildFixture('javascript', javascriptRecord);
  await writeChunkingScaleEvidenceBundle(tamperedDirectory, tampered);
  const reportPath = join(tamperedDirectory, 'report.json');
  const reportBytes = await readFile(reportPath);
  reportBytes[0] ^= 1;
  await writeFile(reportPath, reportBytes);
  await assert.rejects(verifyChunkingScaleEvidenceBundle(tamperedDirectory, 'javascript'), /content digest mismatch/);
});

test('evidence publisher and verifiers contain no executable scale-runner edge', async () => {
  const paths = [
    'tools/chunking-scale-evidence-bundle.mjs',
    'tools/verify-chunking-scale-evidence-bundle.mjs',
    'tools/chunking-scale-evidence-comparator.mjs',
    'tools/compare-chunking-scale.mjs',
  ];
  for (const path of paths) {
    const source = await readFile(join(SCALE_ROOT, path), 'utf8');
    assert.doesNotMatch(source, /core\/chunking-manifest\/js\/scripts\/run-scale\.mjs|--example\s+run_scale|cargo\s+run/u, path);
  }
});
