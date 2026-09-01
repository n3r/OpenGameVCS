#!/usr/bin/env node

import { lstat, mkdir, mkdtemp, open, rename, rm } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalJson, deepFreeze } from '../foundation/benchmark-fault-harness/src/index.mjs';
import {
  SCALE_EVIDENCE_SCHEMA_VERSION,
  SCALE_ROOT,
  SCALE_SOURCE_REVISION_BINDING,
  captureScalePublisherEnvironment,
  exactScaleProjection,
  implementationAuthority,
  loadScaleEvidenceAuthority,
  loadScaleReport,
  retainedScalePublication,
  scaleEvidenceSourceSetSha256,
  sha256Bytes,
} from './chunking-scale-evidence-common.mjs';
import { verifyChunkingScaleEvidenceBundle } from './verify-chunking-scale-evidence-bundle.mjs';

function fail(message) {
  throw new Error(`chunking exact-scale bundle failure: ${message}`);
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (index + 1 >= argv.length) fail('usage: --implementation <javascript|rust> --report <report.json> --output <bundle-dir>');
    const flag = argv[index];
    const value = argv[index + 1];
    if (typeof value !== 'string' || value.length === 0) fail(`${flag} value is missing`);
    if (flag === '--implementation') options.implementation = value;
    else if (flag === '--report') options.report = resolve(process.cwd(), value);
    else if (flag === '--output') options.output = resolve(process.cwd(), value);
    else fail(`unknown argument ${flag}`);
  }
  if (argv.length !== 6 || !options.implementation || !options.report || !options.output) {
    fail('usage: --implementation <javascript|rust> --report <report.json> --output <bundle-dir>');
  }
  implementationAuthority(options.implementation);
  return options;
}

function artifact(path, bytes, mediaType) {
  return Object.freeze({ path, bytes: bytes.byteLength, sha256: sha256Bytes(bytes), mediaType });
}

function buildManifest(authority, implementation, reportRecord, artifacts) {
  const body = {
    schemaVersion: 'ogvcs.chunking-manifest/exact-scale-publication-manifest/v1',
    contractManifestSha256: authority.manifestSha256,
    implementation,
    sourceRevision: reportRecord.report.sourceRevision,
    sourceRevisionBinding: SCALE_SOURCE_REVISION_BINDING,
    artifacts,
  };
  return deepFreeze({
    ...body,
    bundleDigest: canonicalDigest(artifacts, 'ogvcs.chunking-manifest/exact-scale-publication/v1'),
  });
}

export async function buildChunkingScaleEvidenceBundle(options) {
  const implementation = options?.implementation;
  implementationAuthority(implementation);
  const reportRecord = options?.reportRecord;
  if (!reportRecord || reportRecord.report?.implementation !== implementation) fail('report record does not match its declared implementation');
  const authority = options.authority ?? await loadScaleEvidenceAuthority();
  const publisherEnvironment = captureScalePublisherEnvironment(reportRecord.report, options.publisherEnvironmentForTest);
  const sourceSetSha256 = await scaleEvidenceSourceSetSha256();
  const projection = exactScaleProjection({
    authority,
    implementation,
    publisherEnvironment,
    reportRecord,
    evidenceSourceSetSha256: sourceSetSha256,
  });
  const projectionText = `${canonicalJson(projection)}\n`;
  const projectionBytes = Buffer.from(projectionText);
  const artifacts = Object.freeze([
    artifact('projection.json', projectionBytes, 'application/json'),
    artifact('report.json', reportRecord.bytes, 'application/json'),
  ]);
  const manifest = buildManifest(authority, implementation, reportRecord, artifacts);
  const manifestText = `${canonicalJson(manifest)}\n`;
  return Object.freeze({
    schemaVersion: SCALE_EVIDENCE_SCHEMA_VERSION,
    authority,
    implementation,
    manifest,
    manifestText,
    projection,
    projectionText,
    reportText: reportRecord.text,
  });
}

export function buildRetainedChunkingScalePublication(built) {
  if (built?.schemaVersion !== SCALE_EVIDENCE_SCHEMA_VERSION || built.manifest?.implementation !== built.implementation) {
    fail('retained publication source is invalid');
  }
  return retainedScalePublication({
    implementation: built.implementation,
    manifestText: built.manifestText,
    projectionText: built.projectionText,
    reportText: built.reportText,
  });
}

async function writeSynced(path, bytes) {
  let handle;
  let created = false;
  try {
    handle = await open(path, 'wx', 0o600);
    created = true;
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    await handle?.close().catch(() => {});
    if (created) await rm(path, { force: true }).catch(() => {});
    throw error;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function syncDirectory(path) {
  let handle;
  try {
    handle = await open(path, 'r');
    await handle.sync();
  } finally {
    await handle?.close().catch(() => {});
  }
}

export async function writeChunkingScaleEvidenceBundle(directory, built, optionsForTest = undefined) {
  if (typeof directory !== 'string' || directory.length === 0 || directory.includes('\0')) fail('bundle destination is invalid');
  if (built?.schemaVersion !== SCALE_EVIDENCE_SCHEMA_VERSION || built.manifest?.implementation !== built.implementation
      || built.manifest?.contractManifestSha256 !== built.authority?.manifestSha256
      || built.manifest?.sourceRevisionBinding !== SCALE_SOURCE_REVISION_BINDING
      || built.projection?.sourceRevisionBinding !== SCALE_SOURCE_REVISION_BINDING
      || built.manifest?.bundleDigest !== canonicalDigest(built.manifest.artifacts, 'ogvcs.chunking-manifest/exact-scale-publication/v1')) {
    fail('bundle projection is invalid');
  }
  const expected = [
    artifact('projection.json', Buffer.from(built.projectionText), 'application/json'),
    artifact('report.json', Buffer.from(built.reportText), 'application/json'),
  ];
  if (canonicalJson(expected) !== canonicalJson(built.manifest.artifacts)) fail('bundle artifacts differ from their manifest');
  const parent = dirname(directory);
  await mkdir(parent, { recursive: true });
  if (await lstat(directory).catch(() => null) !== null) fail('bundle destination already exists');
  const stage = await mkdtemp(join(parent, `.${basename(directory)}.ogvcs-scale-stage-`));
  let committed = false;
  try {
    await writeSynced(join(stage, 'projection.json'), Buffer.from(built.projectionText));
    await writeSynced(join(stage, 'report.json'), Buffer.from(built.reportText));
    await writeSynced(join(stage, 'manifest.json'), Buffer.from(built.manifestText));
    await syncDirectory(stage);
    await rename(stage, directory);
    committed = true;
    if (optionsForTest?.failAfterPublish === true) throw new Error('injected bundle parent-sync failure');
    await syncDirectory(parent);
    return deepFreeze({ directory, bundleDigest: built.manifest.bundleDigest });
  } catch (error) {
    await rm(committed ? directory : stage, { recursive: true, force: true }).catch(() => {});
    await syncDirectory(parent).catch(() => {});
    throw error;
  }
}

export async function writeRetainedChunkingScalePublication(path, publication, optionsForTest = undefined) {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) fail('retained publication destination is invalid');
  const reproduced = retainedScalePublication({
    implementation: publication?.implementation,
    manifestText: publication?.artifacts?.[0]?.content,
    projectionText: publication?.artifacts?.[1]?.content,
    reportText: publication?.artifacts?.[2]?.content,
  });
  if (canonicalJson(reproduced) !== canonicalJson(publication)) fail('retained publication does not reproduce');
  const parent = dirname(path);
  await mkdir(parent, { recursive: true });
  let created = false;
  try {
    await writeSynced(path, Buffer.from(`${canonicalJson(publication)}\n`));
    created = true;
    if (optionsForTest?.failAfterPublish === true) throw new Error('injected retained-publication parent-sync failure');
    await syncDirectory(parent);
  } catch (error) {
    if (created) await rm(path, { force: true }).catch(() => {});
    await syncDirectory(parent).catch(() => {});
    throw error;
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const reportRecord = await loadScaleReport(options.report, options.implementation);
  const built = await buildChunkingScaleEvidenceBundle({ implementation: options.implementation, reportRecord });
  await writeChunkingScaleEvidenceBundle(options.output, built);
  const verified = await verifyChunkingScaleEvidenceBundle(options.output, options.implementation);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 'ogvcs.chunking-manifest/exact-scale-publication/v1',
    bundleDigest: built.manifest.bundleDigest,
    implementation: options.implementation,
    reportSha256: reportRecord.reportSha256,
    sourceRevision: reportRecord.report.sourceRevision,
    sourceRevisionBinding: SCALE_SOURCE_REVISION_BINDING,
    verified: verified !== null,
  })}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) await main();
