#!/usr/bin/env node

import { mkdir, open, opendir, lstat } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalJson, deepFreeze } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM,
  SCALE_COMPARISON_SCHEMA_VERSION,
  SCALE_EVIDENCE_SCHEMA_VERSION,
  SCALE_RETAINED_PUBLICATION_BYTES_MAXIMUM,
  SCALE_RETAINED_PUBLICATION_SCHEMA_VERSION,
  SCALE_SOURCE_REVISION_BINDING,
  captureScalePublisherEnvironment,
  exactScaleProjection,
  exactKeys,
  implementationAuthority,
  loadBoundedRegular,
  loadScaleEvidenceAuthority,
  parseScaleReportText,
  retainedScalePublication,
  removeScalePublicationPathDurably,
  scaleEvidenceSourceSetSha256,
  sha256Bytes,
  syncScalePublicationDirectory,
} from './chunking-scale-evidence-common.mjs';

const VERIFIED = new WeakMap();

function fail(message) {
  throw new Error(`chunking exact-scale verification failure: ${message}`);
}

async function loadCanonical(path, maximum, label) {
  const link = await lstat(path).catch(() => null);
  if (!link?.isFile() || link.isSymbolicLink()) fail(`${label} must be a regular no-link file`);
  const { bytes } = await loadBoundedRegular(path, maximum, label);
  return parseCanonicalBytes(bytes, maximum, label);
}

function parseCanonicalBytes(bytes, maximum, label) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength < 2 || bytes.byteLength > maximum) fail(`${label} is not bounded`);
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(`${label} is not UTF-8`); }
  let value;
  try { value = JSON.parse(text); } catch { fail(`${label} is not JSON`); }
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) fail(`${label} is not canonical terminal-LF JSON`);
  return { bytes, text, value };
}

async function inventory(directory) {
  const root = await lstat(directory).catch(() => null);
  if (!root?.isDirectory() || root.isSymbolicLink()) fail('bundle root must be a regular no-link directory');
  const entries = [];
  const handle = await opendir(directory);
  for await (const entry of handle) {
    if (!entry.isFile() || entry.isSymbolicLink()) fail('bundle contains a non-regular artifact');
    entries.push(entry.name);
  }
  entries.sort();
  if (canonicalJson(entries) !== canonicalJson(['manifest.json', 'projection.json', 'report.json'])) fail('bundle inventory is incomplete or unexpected');
}

function validateArtifactRecords(records) {
  if (!Array.isArray(records) || records.length !== 2) fail('bundle artifact inventory is invalid');
  const expected = ['projection.json', 'report.json'];
  for (const [index, record] of records.entries()) {
    exactKeys(record, ['bytes', 'mediaType', 'path', 'sha256'], `bundle artifact ${index}`);
    if (record.path !== expected[index] || record.mediaType !== 'application/json'
        || !Number.isSafeInteger(record.bytes) || record.bytes < 2 || record.bytes > SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM
        || !/^[0-9a-f]{64}$/u.test(record.sha256)) fail('bundle artifact record is invalid');
  }
}

async function verifyChunkingScaleEvidenceBytes(contentBound, expectedImplementation) {
  implementationAuthority(expectedImplementation);
  const manifestRecord = parseCanonicalBytes(contentBound.get('manifest.json'), SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM, 'bundle manifest');
  const manifest = manifestRecord.value;
  exactKeys(manifest, ['artifacts', 'bundleDigest', 'contractManifestSha256', 'implementation', 'schemaVersion', 'sourceRevision', 'sourceRevisionBinding'], 'bundle manifest');
  validateArtifactRecords(manifest.artifacts);
  if (manifest.schemaVersion !== 'ogvcs.chunking-manifest/exact-scale-publication-manifest/v1'
      || manifest.implementation !== expectedImplementation
      || !/^[0-9a-f]{40}$/u.test(manifest.sourceRevision)
      || manifest.sourceRevisionBinding !== SCALE_SOURCE_REVISION_BINDING
      || manifest.bundleDigest !== canonicalDigest(manifest.artifacts, 'ogvcs.chunking-manifest/exact-scale-publication/v1')) fail('bundle manifest authority is invalid');
  const authority = await loadScaleEvidenceAuthority();
  if (manifest.contractManifestSha256 !== authority.manifestSha256) fail('bundle contract authority differs from current source');

  for (const record of manifest.artifacts) {
    const bytes = contentBound.get(record.path);
    if (!Buffer.isBuffer(bytes) || bytes.byteLength !== record.bytes || sha256Bytes(bytes) !== record.sha256) fail(`bundle artifact ${record.path} has a content digest mismatch`);
  }
  let reportText;
  try { reportText = new TextDecoder('utf-8', { fatal: true }).decode(contentBound.get('report.json')); } catch { fail('content-bound report is not UTF-8'); }
  const reportRecord = parseScaleReportText(reportText, expectedImplementation);
  if (manifest.sourceRevision !== reportRecord.report.sourceRevision) fail('bundle source revision differs from its report');

  const projectionRecord = parseCanonicalBytes(contentBound.get('projection.json'), SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM, 'content-bound projection');
  const projection = projectionRecord.value;
  const publisherEnvironment = captureScalePublisherEnvironment(reportRecord.report, projection.publisherEnvironment);
  const expectedProjection = exactScaleProjection({
    authority,
    implementation: expectedImplementation,
    publisherEnvironment,
    reportRecord,
    evidenceSourceSetSha256: await scaleEvidenceSourceSetSha256(),
  });
  if (canonicalJson(projection) !== canonicalJson(expectedProjection)
      || projection.schemaVersion !== SCALE_EVIDENCE_SCHEMA_VERSION
      || projection.reportSha256 !== reportRecord.reportSha256
      || projection.overallStatus !== 'passed') fail('content-bound projection does not reproduce');

  const retainedPublication = retainedScalePublication({
    implementation: expectedImplementation,
    manifestText: manifestRecord.text,
    projectionText: projectionRecord.text,
    reportText,
  });
  const details = deepFreeze({
    schemaVersion: SCALE_COMPARISON_SCHEMA_VERSION,
    authorityManifestSha256: authority.manifestSha256,
    bundleDigest: manifest.bundleDigest,
    implementation: expectedImplementation,
    projectionSha256: projection.projectionSha256,
    publicationSha256: retainedPublication.publicationSha256,
    publisherEnvironment,
    report: reportRecord.report,
    reportSha256: reportRecord.reportSha256,
    sourceRevision: reportRecord.report.sourceRevision,
    sourceRevisionBinding: projection.sourceRevisionBinding,
    thresholdEvaluations: projection.thresholdEvaluations,
  });
  const handle = Object.freeze({});
  VERIFIED.set(handle, details);
  return handle;
}

export async function verifyChunkingScaleEvidenceBundle(bundleDirectory, expectedImplementation) {
  implementationAuthority(expectedImplementation);
  await inventory(bundleDirectory);
  const contentBound = new Map();
  for (const path of ['manifest.json', 'projection.json', 'report.json']) {
    const artifact = await loadBoundedRegular(join(bundleDirectory, path), SCALE_BUNDLE_ARTIFACT_BYTES_MAXIMUM, `bundle artifact ${path}`);
    contentBound.set(path, artifact.bytes);
  }
  return verifyChunkingScaleEvidenceBytes(contentBound, expectedImplementation);
}

export async function verifyRetainedChunkingScalePublication(path, expectedImplementation) {
  implementationAuthority(expectedImplementation);
  const record = await loadCanonical(path, SCALE_RETAINED_PUBLICATION_BYTES_MAXIMUM, 'retained publication');
  const publication = record.value;
  exactKeys(publication, ['artifacts', 'bundleDigest', 'implementation', 'publicationSha256', 'schemaVersion'], 'retained publication');
  if (publication.schemaVersion !== SCALE_RETAINED_PUBLICATION_SCHEMA_VERSION
      || publication.implementation !== expectedImplementation
      || !Array.isArray(publication.artifacts) || publication.artifacts.length !== 3) fail('retained publication authority is invalid');
  const expectedPaths = ['manifest.json', 'projection.json', 'report.json'];
  const contentBound = new Map();
  for (const [index, artifact] of publication.artifacts.entries()) {
    exactKeys(artifact, ['bytes', 'content', 'mediaType', 'path', 'sha256'], `retained publication artifact ${index}`);
    if (artifact.path !== expectedPaths[index] || artifact.mediaType !== 'application/json'
        || typeof artifact.content !== 'string') fail(`retained publication artifact ${index} is invalid`);
    contentBound.set(artifact.path, Buffer.from(artifact.content, 'utf8'));
  }
  const reproduced = retainedScalePublication({
    implementation: expectedImplementation,
    manifestText: publication.artifacts[0].content,
    projectionText: publication.artifacts[1].content,
    reportText: publication.artifacts[2].content,
  });
  if (canonicalJson(reproduced) !== canonicalJson(publication)) fail('retained publication does not reproduce');
  const handle = await verifyChunkingScaleEvidenceBytes(contentBound, expectedImplementation);
  if (inspectVerifiedChunkingScaleEvidence(handle).publicationSha256 !== publication.publicationSha256) {
    fail('retained publication digest differs from verified artifacts');
  }
  return handle;
}

export function inspectVerifiedChunkingScaleEvidence(handle) {
  const details = VERIFIED.get(handle);
  if (!details) fail('verified evidence handle is invalid');
  return details;
}

async function writeCreateNew(path, text, optionsForTest = undefined) {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true });
  let handle;
  let created = false;
  try {
    handle = await open(path, 'wx', 0o600);
    created = true;
    await handle.writeFile(text, 'utf8');
    await handle.sync();
    if (optionsForTest?.failAfterPublish === true) throw new Error('injected validation parent-sync failure');
    await syncScalePublicationDirectory(parent);
  } catch (error) {
    await handle?.close().catch(() => {});
    if (created) await removeScalePublicationPathDurably(path);
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) fail('usage: --implementation <javascript|rust> (--bundle <bundle-dir>|--publication <publication.json>) --output <validation.json>');
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--implementation') options.implementation = value;
    else if (flag === '--bundle') options.bundle = resolve(process.cwd(), value);
    else if (flag === '--publication') options.publication = resolve(process.cwd(), value);
    else if (flag === '--output') options.output = resolve(process.cwd(), value);
    else fail(`unknown argument ${flag}`);
  }
  if (argv.length !== 6 || !options.implementation || Boolean(options.bundle) === Boolean(options.publication) || !options.output) fail('usage: --implementation <javascript|rust> (--bundle <bundle-dir>|--publication <publication.json>) --output <validation.json>');
  return options;
}

export function chunkingScaleEvidenceValidation(handle) {
  const details = inspectVerifiedChunkingScaleEvidence(handle);
  const body = {
    schemaVersion: 'ogvcs.chunking-manifest/exact-scale-validation/v1',
    authorityManifestSha256: details.authorityManifestSha256,
    bundleDigest: details.bundleDigest,
    implementation: details.implementation,
    projectionSha256: details.projectionSha256,
    publicationSha256: details.publicationSha256,
    reportSha256: details.reportSha256,
    sourceRevision: details.sourceRevision,
    sourceRevisionBinding: details.sourceRevisionBinding,
    verified: true,
  };
  return Object.freeze({ ...body, validationSha256: canonicalDigest(body, 'ogvcs.chunking-manifest/exact-scale-validation/v1') });
}

export async function writeChunkingScaleEvidenceValidation(path, handle, optionsForTest = undefined) {
  const record = chunkingScaleEvidenceValidation(handle);
  await writeCreateNew(path, `${canonicalJson(record)}\n`, optionsForTest);
  return record;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const handle = options.bundle
    ? await verifyChunkingScaleEvidenceBundle(options.bundle, options.implementation)
    : await verifyRetainedChunkingScalePublication(options.publication, options.implementation);
  const record = await writeChunkingScaleEvidenceValidation(options.output, handle);
  process.stdout.write(`${canonicalJson(record)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) await main();
