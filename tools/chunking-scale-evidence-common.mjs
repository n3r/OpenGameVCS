import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, readFile, readdir, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalDigest,
  canonicalJson,
  deepFreeze,
} from '../foundation/benchmark-fault-harness/src/index.mjs';

export const SCALE_REPORT_BYTES_MAXIMUM = 64 * 1024;
export const SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM = 256 * 1024;
export const SCALE_RETAINED_PUBLICATION_BYTES_MAXIMUM = 1024 * 1024;
export const SCALE_LOGICAL_BYTES = 100 * 1024 * 1024 * 1024;
export const SCALE_PROFILE = 'chunking.opengamevcs/gear-fastcdc-1m@1';
export const SCALE_BENCHMARK_PROFILE = 'chunking-exact-scale-release';
export const SCALE_BENCHMARK_TASK = 'chunking-exact-scale-verify';
export const SCALE_CORPUS = 'chunking-exact-scale';
export const SCALE_THRESHOLD = 'chunking-exact-scale-release-v1';
export const SCALE_REPORT_SCHEMA_VERSION = 'ogvcs.chunking-manifest/scale-report/v1';
export const SCALE_EVIDENCE_SCHEMA_VERSION = 'ogvcs.chunking-manifest/exact-scale-evidence/v1';
export const SCALE_RETAINED_PUBLICATION_SCHEMA_VERSION = 'ogvcs.chunking-manifest/exact-scale-retained-publication/v1';
export const SCALE_COMPARISON_SCHEMA_VERSION = 'ogvcs.chunking-manifest/scale-comparison/v2';
export const SCALE_UNIQUE_BYTES_BASIS = 'conservative-no-reuse-claim-all-logical';
export const SCALE_SOURCE_REVISION_BINDING = 'workflow-supplied-not-git-bound';
export const SCALE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const SCALE_AUTHORITY_ROOT = join(SCALE_ROOT, 'spec/chunking-scale-evidence/v1');

export const SCALE_EVIDENCE_SOURCE_PATHS = Object.freeze([
  '.github/workflows/chunking-manifest-scale.yml',
  'core/chunking-manifest/js/scripts/run-scale.mjs',
  'core/chunking-manifest/rust/examples/run_scale.rs',
  'spec/benchmark-fault/v1/manifest.json',
  'spec/chunking-manifest/v1/manifest.json',
  'spec/chunking-scale-evidence/v1/manifest.json',
  'spec/chunking-scale-evidence/v1/source/generate.mjs',
  'spec/chunking-scale-evidence/v1/source/model.mjs',
  'spec/chunking-scale-evidence/v1/validate-spec.mjs',
  'tools/chunking-scale-evidence-common.mjs',
  'tools/chunking-scale-evidence-bundle.mjs',
  'tools/chunking-scale-evidence-comparator.mjs',
  'tools/chunking-scale-bounded-proof.mjs',
  'tools/chunking-scale-dispatch-guard.mjs',
  'tools/verify-chunking-scale-evidence-bundle.mjs',
  'tools/compare-chunking-scale.mjs',
  'package.json',
  'package-lock.json',
  'core/chunking-manifest/js/package.json',
  'core/chunking-manifest/rust/Cargo.toml',
  'core/chunking-manifest/rust/Cargo.lock',
  'core/object-model/js/package.json',
  'core/object-model/rust/Cargo.toml',
  'core/object-model/rust/Cargo.lock',
  'core/object-model/rust/build.rs',
  'core/paths-filesystem/js/package.json',
  'foundation/benchmark-fault-harness/package.json',
  'spec/path-filesystem/v1/manifest.json',
  'spec/path-filesystem/v1/data/CaseFolding-16.0.0.txt',
]);

export const SCALE_EVIDENCE_SOURCE_TREES = Object.freeze([
  'core/chunking-manifest/js/src',
  'core/chunking-manifest/rust/src',
  'core/object-model/js/registries',
  'core/object-model/js/src',
  'core/object-model/js/unicode',
  'core/object-model/rust/registries',
  'core/object-model/rust/src',
  'core/object-model/rust/unicode',
  'core/paths-filesystem/js/src',
  'foundation/benchmark-fault-harness/src',
]);

export const SCALE_SOURCE = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/scale-source-repeated-lcg-v1',
  logicalBytes: String(SCALE_LOGICAL_BYTES),
  patternBytes: 8_388_608,
  repetitions: 12_800,
  patternSha256: 'b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4',
  seed: 1_330_075_203,
  multiplier: 1_664_525,
  increment: 1_013_904_223,
  outputByte: 'state-bits-31-through-24-after-step',
});

export const SCALE_BOUNDS = Object.freeze({
  wallTimeMillisecondsMaximum: 18_000_000,
  cpuTimeMicrosecondsMaximum: 36_000_000_000,
  processWriteBytesMaximum: 536_870_912,
  peakRssBytesMaximum: 536_870_912,
  ledgerMemoryBytesMaximum: 1_048_576,
  ledgerScratchBytesMaximum: 67_108_864,
  manifestBytesMaximum: 67_110_912,
  temporaryWholeFileAllowed: false,
});

const SHA256 = /^[0-9a-f]{64}$/u;
const SOURCE_REVISION = /^[0-9a-f]{40}$/u;
const MANIFEST_OBJECT_ID = /^ogvcs:v1:content-manifest:sha256:[0-9a-f]{64}$/u;
const IMPLEMENTATIONS = Object.freeze({
  javascript: Object.freeze({
    benchmarkId: 'ogvcs.chunking-manifest/javascript-exact-scale@1',
    cpuSource: 'node:process.cpuUsage:user+system-microseconds',
    maxRssSource: 'node:process.resourceUsage().maxRSS-kib',
    runtimeVersion: /^v24\.[0-9]+\.[0-9]+$/u,
  }),
  rust: Object.freeze({
    benchmarkId: 'ogvcs.chunking-manifest/rust-exact-scale@1',
    cpuSource: 'linux:/proc/self/schedstat:runtime-nanoseconds',
    maxRssSource: 'linux:/proc/self/status:VmHWM-kib',
    runtimeVersion: /^1\.82\.0$/u,
  }),
});
const IO_SOURCE = 'linux:/proc/self/io:read_bytes+write_bytes';
const PROCESS_WRITE_SOURCE = 'linux:/proc/self/io:wchar';
const RESOURCE_SCOPE = 'source-pattern-generation-through-scratch-cleanup-before-report-publication';

function fail(message) {
  throw new Error(`chunking exact-scale evidence failure: ${message}`);
}

export function exactKeys(value, expected, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalJson(actual) !== canonicalJson(wanted)) fail(`${label} has an unexpected shape`);
}

function exactObject(value, expected, label) {
  exactKeys(value, Object.keys(expected), label);
  if (canonicalJson(value) !== canonicalJson(expected)) fail(`${label} is not the exact declared value`);
}

function integer(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be an integer in [${minimum}, ${maximum}]`);
  }
}

function matching(value, expression, label) {
  if (typeof value !== 'string' || !expression.test(value)) fail(`${label} is invalid`);
}

function validateRuntime(runtime, implementation) {
  exactKeys(runtime, ['architecture', 'os', 'version'], `${implementation}.runtime`);
  if (runtime.os !== 'linux') fail(`${implementation}.runtime.os must be linux`);
  if (!['x64', 'arm64'].includes(runtime.architecture)) fail(`${implementation}.runtime.architecture is unsupported`);
  matching(runtime.version, IMPLEMENTATIONS[implementation].runtimeVersion, `${implementation}.runtime.version`);
}

function validateResult(result, implementation) {
  exactKeys(result, [
    'boundaryTranscriptSha256', 'chunkCount', 'class', 'logicalBytes', 'manifestBytes',
    'manifestObjectId', 'manifestSha256', 'maximumChunkBytes', 'minimumChunkBytes',
    'totalChunkBytes', 'wholeFileSha256',
  ], `${implementation}.result`);
  if (result.class !== 'cdc-1m') fail(`${implementation}.result.class is invalid`);
  if (result.logicalBytes !== SCALE_SOURCE.logicalBytes || result.totalChunkBytes !== SCALE_SOURCE.logicalBytes) {
    fail(`${implementation}.result does not account for exactly 100 GiB`);
  }
  integer(result.chunkCount, `${implementation}.result.chunkCount`, { minimum: 1, maximum: 1_048_576 });
  integer(result.minimumChunkBytes, `${implementation}.result.minimumChunkBytes`, { minimum: 1, maximum: 2_097_152 });
  integer(result.maximumChunkBytes, `${implementation}.result.maximumChunkBytes`, {
    minimum: result.minimumChunkBytes,
    maximum: 2_097_152,
  });
  if (SCALE_LOGICAL_BYTES < result.chunkCount * result.minimumChunkBytes
      || SCALE_LOGICAL_BYTES > result.chunkCount * result.maximumChunkBytes) {
    fail(`${implementation}.result chunk extrema cannot account for exactly 100 GiB`);
  }
  integer(result.manifestBytes, `${implementation}.result.manifestBytes`, {
    minimum: 1,
    maximum: SCALE_BOUNDS.manifestBytesMaximum,
  });
  matching(result.wholeFileSha256, SHA256, `${implementation}.result.wholeFileSha256`);
  matching(result.manifestObjectId, MANIFEST_OBJECT_ID, `${implementation}.result.manifestObjectId`);
  matching(result.manifestSha256, SHA256, `${implementation}.result.manifestSha256`);
  matching(result.boundaryTranscriptSha256, SHA256, `${implementation}.result.boundaryTranscriptSha256`);
  if (result.manifestObjectId.slice(-64) === result.manifestSha256) {
    fail(`${implementation}.result typed manifest ObjectID must differ from the raw manifest digest`);
  }
}

function validateResources(resources, result, implementation) {
  exactKeys(resources, [
    'cpuMicroseconds', 'cpuSource', 'diskReadBytes', 'diskWriteBytes', 'ioSource',
    'ledgerPeakMemoryBytes', 'ledgerPeakScratchBytes', 'ledgerRecords', 'ledgerSpilled',
    'maxRssSource', 'measurementScope', 'patternBufferBytes', 'peakRssBytes',
    'processWriteBytes', 'processWriteSource',
    'scalarWorkingMemoryBytes', 'scratchArtifactsAfter', 'throughputBytesPerSecond',
    'wallTimeMilliseconds',
  ], `${implementation}.resources`);
  integer(resources.wallTimeMilliseconds, `${implementation}.resources.wallTimeMilliseconds`, { minimum: 1, maximum: SCALE_BOUNDS.wallTimeMillisecondsMaximum });
  integer(resources.cpuMicroseconds, `${implementation}.resources.cpuMicroseconds`, { minimum: 1, maximum: SCALE_BOUNDS.cpuTimeMicrosecondsMaximum });
  if (resources.cpuSource !== IMPLEMENTATIONS[implementation].cpuSource) fail(`${implementation}.resources.cpuSource is invalid`);
  if (resources.ioSource !== IO_SOURCE) fail(`${implementation}.resources.ioSource is invalid`);
  if (resources.processWriteSource !== PROCESS_WRITE_SOURCE) fail(`${implementation}.resources.processWriteSource is invalid`);
  if (resources.measurementScope !== RESOURCE_SCOPE) fail(`${implementation}.resources.measurementScope is invalid`);
  integer(resources.diskReadBytes, `${implementation}.resources.diskReadBytes`);
  integer(resources.diskWriteBytes, `${implementation}.resources.diskWriteBytes`);
  integer(resources.processWriteBytes, `${implementation}.resources.processWriteBytes`, { maximum: SCALE_BOUNDS.processWriteBytesMaximum });
  integer(resources.throughputBytesPerSecond, `${implementation}.resources.throughputBytesPerSecond`, { minimum: 1 });
  const expectedThroughput = Math.floor(SCALE_LOGICAL_BYTES * 1000 / resources.wallTimeMilliseconds);
  if (resources.throughputBytesPerSecond !== expectedThroughput) fail(`${implementation}.resources.throughputBytesPerSecond does not reproduce`);
  integer(resources.peakRssBytes, `${implementation}.resources.peakRssBytes`, { minimum: 1, maximum: SCALE_BOUNDS.peakRssBytesMaximum });
  integer(resources.patternBufferBytes, `${implementation}.resources.patternBufferBytes`, { minimum: SCALE_SOURCE.patternBytes, maximum: SCALE_SOURCE.patternBytes });
  integer(resources.scalarWorkingMemoryBytes, `${implementation}.resources.scalarWorkingMemoryBytes`, { minimum: 4_259_840, maximum: 4_259_840 });
  integer(resources.ledgerRecords, `${implementation}.resources.ledgerRecords`, { minimum: result.chunkCount, maximum: result.chunkCount });
  integer(resources.ledgerPeakMemoryBytes, `${implementation}.resources.ledgerPeakMemoryBytes`, { minimum: 1, maximum: SCALE_BOUNDS.ledgerMemoryBytesMaximum });
  integer(resources.ledgerPeakScratchBytes, `${implementation}.resources.ledgerPeakScratchBytes`, { minimum: 1, maximum: SCALE_BOUNDS.ledgerScratchBytesMaximum });
  integer(resources.scratchArtifactsAfter, `${implementation}.resources.scratchArtifactsAfter`, { minimum: 0, maximum: 0 });
  if (resources.ledgerSpilled !== true) fail(`${implementation}.resources.ledgerSpilled must be true`);
  if (resources.maxRssSource !== IMPLEMENTATIONS[implementation].maxRssSource) fail(`${implementation}.resources.maxRssSource is invalid`);
}

export function validateScaleReport(report, expectedImplementation) {
  if (!Object.hasOwn(IMPLEMENTATIONS, expectedImplementation)) fail('implementation must be javascript or rust');
  exactKeys(report, ['bounds', 'exactScaleExecuted', 'implementation', 'overallStatus', 'profile', 'resources', 'result', 'runtime', 'schemaVersion', 'source', 'sourceRevision'], expectedImplementation);
  if (report.schemaVersion !== SCALE_REPORT_SCHEMA_VERSION) fail(`${expectedImplementation}.schemaVersion is invalid`);
  if (report.implementation !== expectedImplementation) fail(`${expectedImplementation}.implementation is invalid`);
  if (report.profile !== SCALE_PROFILE) fail(`${expectedImplementation}.profile is invalid`);
  matching(report.sourceRevision, SOURCE_REVISION, `${expectedImplementation}.sourceRevision`);
  if (report.exactScaleExecuted !== true) fail(`${expectedImplementation}.exactScaleExecuted must be true`);
  if (report.overallStatus !== 'passed') fail(`${expectedImplementation}.overallStatus must be passed`);
  validateRuntime(report.runtime, expectedImplementation);
  exactObject(report.source, SCALE_SOURCE, `${expectedImplementation}.source`);
  validateResult(report.result, expectedImplementation);
  validateResources(report.resources, report.result, expectedImplementation);
  exactObject(report.bounds, SCALE_BOUNDS, `${expectedImplementation}.bounds`);
  return report;
}

export function parseScaleReportText(text, expectedImplementation) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') < 2
      || Buffer.byteLength(text, 'utf8') > SCALE_REPORT_BYTES_MAXIMUM
      || !text.endsWith('\n') || text.endsWith('\n\n') || text.includes('\r') || text.includes('\0')
      || /[^\u0009\u000a\u0020-\u007e]/u.test(text)) {
    fail(`${expectedImplementation} report is not bounded terminal-LF ASCII JSON`);
  }
  let report;
  try { report = JSON.parse(text); } catch { fail(`${expectedImplementation} report is not JSON`); }
  if (`${JSON.stringify(report, null, 2)}\n` !== text) fail(`${expectedImplementation} report is not exact normalized JSON`);
  validateScaleReport(report, expectedImplementation);
  return Object.freeze({ bytes: Buffer.from(text, 'utf8'), report: deepFreeze(report), reportSha256: sha256Bytes(text), text });
}

function sameFile(left, right) {
  return left.size === right.size && left.mtimeMs === right.mtimeMs
    && (left.ino === 0 || right.ino === 0 || left.ino === right.ino);
}

export async function loadBoundedRegular(path, maximum, label) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || before.size < 2 || before.size > maximum) fail(`${label} must be one bounded regular file`);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (bytes.byteLength !== before.size || !sameFile(before, after)) fail(`${label} changed while read`);
    return Object.freeze({ bytes, stat: before });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('chunking exact-scale evidence failure:')) throw error;
    fail(`${label} cannot be opened safely`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function loadScaleReport(path, expectedImplementation) {
  const { bytes } = await loadBoundedRegular(path, SCALE_REPORT_BYTES_MAXIMUM, `${expectedImplementation} report`);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(`${expectedImplementation} report is not UTF-8`); }
  return parseScaleReportText(text, expectedImplementation);
}

async function loadCanonical(path, maximum, label) {
  const { bytes } = await loadBoundedRegular(path, maximum, label);
  let value;
  try { value = JSON.parse(bytes); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail(`${label} is not canonical terminal-LF JSON`);
  return Object.freeze({ bytes, value: deepFreeze(value) });
}

export async function loadScaleEvidenceAuthority() {
  const manifestRecord = await loadCanonical(join(SCALE_AUTHORITY_ROOT, 'manifest.json'), SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM, 'exact-scale contract manifest');
  const manifest = manifestRecord.value;
  exactKeys(manifest, ['artifactSetSha256', 'artifacts', 'authoritySetSha256', 'contractVersion', 'counts', 'generatedBy', 'owner', 'predecessorPins', 'schemaVersion'], 'exact-scale contract manifest');
  if (manifest.schemaVersion !== 'ogvcs.chunking-manifest/exact-scale-contract-manifest/v1'
      || manifest.contractVersion !== '0.1.0-rc.1' || manifest.owner !== 'ogvcs-007') fail('exact-scale contract manifest header differs');
  const expectedPaths = ['registries/exact-scale-authority.json', 'schemas/retained-publication.schema.json', 'schemas/scale-report.schema.json', 'thresholds/chunking-exact-scale-release-v1.json'];
  if (!Array.isArray(manifest.artifacts) || canonicalJson(manifest.artifacts.map(({ path }) => path)) !== canonicalJson(expectedPaths)
      || manifest.artifactSetSha256 !== canonicalDigest(manifest.artifacts, 'ogvcs.chunking-manifest/exact-scale-artifact-set/v1')) fail('exact-scale artifact inventory differs');
  const loaded = new Map();
  for (const record of manifest.artifacts) {
    const artifact = await loadCanonical(join(SCALE_AUTHORITY_ROOT, record.path), SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM, `exact-scale artifact ${record.path}`);
    if (artifact.bytes.byteLength !== record.bytes || sha256Bytes(artifact.bytes) !== record.sha256) fail(`exact-scale artifact ${record.path} has a content digest mismatch`);
    loaded.set(record.path, artifact.value);
  }
  const authority = loaded.get('registries/exact-scale-authority.json');
  const threshold = loaded.get('thresholds/chunking-exact-scale-release-v1.json');
  if (authority?.owner !== 'ogvcs-007' || authority?.corpus?.id !== SCALE_CORPUS || authority?.task?.id !== SCALE_BENCHMARK_TASK
      || authority?.profile?.id !== SCALE_BENCHMARK_PROFILE
      || authority.profile.sourceRevisionBinding !== SCALE_SOURCE_REVISION_BINDING
      || canonicalJson(authority.corpus.source) !== canonicalJson(SCALE_SOURCE)
      || canonicalJson(threshold?.entries?.map(({ id }) => id)) !== canonicalJson([
        'exact-scale-executed', 'exact-logical-bytes', 'wall-time-bound', 'cpu-time-bound', 'process-write-bound', 'peak-rss-bound',
        'ledger-memory-bound', 'ledger-scratch-bound', 'manifest-byte-bound', 'scratch-cleaned', 'no-whole-file-temporary',
      ])) fail('exact-scale authority fields differ');
  if (manifest.authoritySetSha256 !== canonicalDigest({ authority, threshold }, 'ogvcs.chunking-manifest/exact-scale-authority-set/v1')) fail('exact-scale authority set differs');
  for (const name of ['benchmark', 'chunking']) {
    const pin = manifest.predecessorPins[name];
    const bytes = await readFile(join(SCALE_ROOT, pin.manifestPath));
    if (sha256Bytes(bytes) !== pin.manifestSha256) fail(`${name} predecessor pin differs`);
  }
  return deepFreeze({
    manifest,
    manifestSha256: sha256Bytes(manifestRecord.bytes),
    authority,
    threshold,
    retainedPublicationSchema: loaded.get('schemas/retained-publication.schema.json'),
    reportSchema: loaded.get('schemas/scale-report.schema.json'),
  });
}

function thresholdActual(report, metric) {
  const values = {
    exactScaleExecuted: report.exactScaleExecuted,
    logicalBytes: report.result.logicalBytes,
    wallTimeMilliseconds: report.resources.wallTimeMilliseconds,
    cpuMicroseconds: report.resources.cpuMicroseconds,
    processWriteBytes: report.resources.processWriteBytes,
    peakRssBytes: report.resources.peakRssBytes,
    ledgerPeakMemoryBytes: report.resources.ledgerPeakMemoryBytes,
    ledgerPeakScratchBytes: report.resources.ledgerPeakScratchBytes,
    manifestBytes: report.result.manifestBytes,
    scratchArtifactsAfter: report.resources.scratchArtifactsAfter,
    temporaryWholeFileAllowed: report.bounds.temporaryWholeFileAllowed,
  };
  if (!Object.hasOwn(values, metric)) fail(`threshold metric ${metric} is unsupported`);
  return values[metric];
}

export function evaluateScaleThresholds(threshold, report) {
  const evaluations = threshold.entries.map((entry) => {
    const actual = thresholdActual(report, entry.metric);
    const passed = entry.operator === 'equal' ? actual === entry.value
      : entry.operator === 'maximum' && typeof actual === 'number' && typeof entry.value === 'number' && actual <= entry.value;
    if (!passed) fail(`threshold ${entry.id} failed`);
    return Object.freeze({ id: entry.id, requirementId: entry.requirementId, metric: entry.metric, operator: entry.operator, expected: entry.value, actual, status: 'passed' });
  });
  return Object.freeze(evaluations);
}

export function captureScalePublisherEnvironment(report, supplied) {
  const value = supplied ?? { os: process.platform, architecture: process.arch, nodeVersion: process.version };
  exactKeys(value, ['architecture', 'nodeVersion', 'os'], 'publisher environment');
  if (!['darwin', 'linux', 'win32'].includes(value.os)
      || !['arm64', 'x64'].includes(value.architecture)
      || !/^v24\.[0-9]+\.[0-9]+$/u.test(value.nodeVersion)) fail('publisher environment is unsupported');
  return deepFreeze(structuredClone(value));
}

export function exactScaleProjection({ authority, implementation, publisherEnvironment, reportRecord, evidenceSourceSetSha256 }) {
  const report = reportRecord.report;
  if (report.implementation !== implementation) fail('report implementation differs');
  const thresholdEvaluations = evaluateScaleThresholds(authority.threshold, report);
  const body = {
    schemaVersion: SCALE_EVIDENCE_SCHEMA_VERSION,
    implementation,
    sourceRevision: report.sourceRevision,
    sourceRevisionBinding: SCALE_SOURCE_REVISION_BINDING,
    profile: SCALE_PROFILE,
    exactScaleExecuted: true,
    uniqueBytesBasis: SCALE_UNIQUE_BYTES_BASIS,
    authority: {
      contractManifestSha256: authority.manifestSha256,
      authoritySetSha256: authority.manifest.authoritySetSha256,
      benchmarkManifestSha256: authority.manifest.predecessorPins.benchmark.manifestSha256,
      chunkingManifestSha256: authority.manifest.predecessorPins.chunking.manifestSha256,
      evidenceSourceSetSha256,
      thresholdId: authority.threshold.id,
      thresholdSha256: canonicalDigest(authority.threshold, 'ogvcs.chunking-manifest/exact-scale-thresholds/v1'),
    },
    publisherEnvironment,
    reportSha256: reportRecord.reportSha256,
    thresholdEvaluations,
    overallStatus: 'passed',
  };
  return deepFreeze({ ...body, projectionSha256: canonicalDigest(body, 'ogvcs.chunking-manifest/exact-scale-projection/v1') });
}

export function implementationAuthority(implementation) {
  if (!Object.hasOwn(IMPLEMENTATIONS, implementation)) fail('implementation must be javascript or rust');
  return IMPLEMENTATIONS[implementation];
}

export function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function scalePublicationDirectorySyncOpenFlag(platform = process.platform) {
  // libuv opens Windows directories with FILE_FLAG_BACKUP_SEMANTICS. Its
  // read-only flag supplies only FILE_GENERIC_READ, while FlushFileBuffers
  // requires write access and otherwise surfaces EPERM. A read/write handle
  // supplies that authority without changing directory contents. POSIX keeps
  // the conventional read-only directory descriptor.
  return platform === 'win32' ? 'r+' : 'r';
}

export async function syncScalePublicationDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, scalePublicationDirectorySyncOpenFlag());
    const info = await handle.stat();
    if (!info.isDirectory()) fail('publication directory durability target is not a directory');
    await handle.sync();
  } catch {
    fail('publication directory durability cannot be proven');
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function removeScalePublicationPathDurably(path, recursive = false) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) fail('publication cleanup path is invalid');
  try {
    await rm(path, { recursive, force: true });
  } catch {
    fail('publication cleanup cannot be proven');
  }
  await syncScalePublicationDirectory(dirname(path));
}

function retainedPublicationArtifact(path, content) {
  if (typeof content !== 'string' || !content.endsWith('\n') || content.includes('\0')) {
    fail(`retained publication artifact ${path} is invalid`);
  }
  const bytes = Buffer.from(content, 'utf8');
  if (bytes.byteLength < 2 || bytes.byteLength > SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM) {
    fail(`retained publication artifact ${path} is not bounded`);
  }
  return Object.freeze({
    path,
    mediaType: 'application/json',
    bytes: bytes.byteLength,
    sha256: sha256Bytes(bytes),
    content,
  });
}

export function retainedScalePublication({ implementation, manifestText, projectionText, reportText }) {
  implementationAuthority(implementation);
  const artifacts = Object.freeze([
    retainedPublicationArtifact('manifest.json', manifestText),
    retainedPublicationArtifact('projection.json', projectionText),
    retainedPublicationArtifact('report.json', reportText),
  ]);
  let manifest;
  try { manifest = JSON.parse(manifestText); } catch { fail('retained publication manifest is not JSON'); }
  const body = {
    schemaVersion: SCALE_RETAINED_PUBLICATION_SCHEMA_VERSION,
    implementation,
    bundleDigest: manifest.bundleDigest,
    artifacts,
  };
  return deepFreeze({
    ...body,
    publicationSha256: canonicalDigest(body, 'ogvcs.chunking-manifest/exact-scale-retained-publication/v1'),
  });
}

async function sourceTreePaths(relativeRoot) {
  const paths = [];
  async function visit(relative) {
    const absolute = resolve(SCALE_ROOT, relative);
    const info = await lstat(absolute);
    if (info.isSymbolicLink()) fail(`evidence source ${relative} must not be a symbolic link`);
    if (info.isFile()) { paths.push(relative); return; }
    if (!info.isDirectory()) fail(`evidence source ${relative} has an unsupported kind`);
    const entries = await readdir(absolute, { withFileTypes: true });
    entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) await visit(`${relative}/${entry.name}`);
  }
  await visit(relativeRoot);
  return paths;
}

export async function scaleEvidenceSourceInventory() {
  const paths = [...SCALE_EVIDENCE_SOURCE_PATHS];
  for (const root of SCALE_EVIDENCE_SOURCE_TREES) paths.push(...await sourceTreePaths(root));
  paths.sort();
  if (new Set(paths).size !== paths.length) fail('evidence source inventory contains duplicates');
  const rows = [];
  let totalBytes = 0;
  for (const path of paths) {
    const absolute = resolve(SCALE_ROOT, path);
    if (!isScaleEvidencePathWithinRoot(SCALE_ROOT, absolute)) fail(`evidence source ${path} escapes the source root`);
    const { bytes } = await loadBoundedRegular(absolute, 16 * 1024 * 1024, `evidence source ${path}`);
    totalBytes += bytes.byteLength;
    if (totalBytes > 128 * 1024 * 1024) fail('evidence source inventory exceeds its aggregate byte bound');
    rows.push({ path, bytes: bytes.byteLength, sha256: sha256Bytes(bytes) });
  }
  return deepFreeze(rows);
}

const HOST_PATH_API = Object.freeze({ isAbsolute, relative, sep });

export function isScaleEvidencePathWithinRoot(root, target, pathApi = HOST_PATH_API) {
  if (typeof root !== 'string' || root.length === 0 || typeof target !== 'string' || target.length === 0
      || typeof pathApi?.relative !== 'function' || typeof pathApi?.isAbsolute !== 'function'
      || typeof pathApi?.sep !== 'string' || pathApi.sep.length !== 1) return false;
  const descendant = pathApi.relative(root, target);
  return descendant.length > 0
    && descendant !== '..'
    && !descendant.startsWith(`..${pathApi.sep}`)
    && !pathApi.isAbsolute(descendant);
}

export async function scaleEvidenceSourceSetSha256() {
  return canonicalDigest(await scaleEvidenceSourceInventory(), 'ogvcs.chunking-manifest/exact-scale-evidence-source-set/v1');
}

export function exactScaleIoSource() { return IO_SOURCE; }
export function exactScaleResourceScope() { return RESOURCE_SCOPE; }
