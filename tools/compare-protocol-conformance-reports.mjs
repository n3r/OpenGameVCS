#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const EXPECTED_PACKAGES = new Map([
  ['@opengamevcs/authorization-contract', '1.0.0'],
  ['@opengamevcs/authorization-contract-v1', '1.0.0'],
  ['@opengamevcs/protocol-baseline', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-baseline-independent-adapter', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-contract-v1', '1.0.0-rc.1'],
  ['@opengamevcs/protocol-types-v1', '1.0.0-rc.1'],
]);
const EXPECTED_ADAPTERS = new Set(['ogvcs.protocol/reference-js@1', 'ogvcs.protocol/independent-js@1']);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new TypeError('report contains a noncanonical value');
}

function exactKeys(value, keys, label) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} has an invalid field set`);
}

function safeRelativePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16_384 || value.includes('\\') || value.startsWith('/') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new Error(`${label} is not a safe relative path`);
  }
  return value;
}

function validateResultRows(results, label) {
  const seen = new Set();
  for (const [index, result] of results.entries()) {
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error(`${label} result ${index} is not an object`);
    const keys = Object.keys(result).sort();
    const expectedKeys = [
      'code', 'id', 'mutationCount', 'preMutation', 'result', 'schemaVersion', 'traceDigest',
      ...(result.semanticDigest === undefined ? [] : ['semanticDigest']),
    ].sort();
    if (keys.length !== expectedKeys.length || keys.some((key, offset) => key !== expectedKeys[offset])) {
      throw new Error(`${label} result ${index} has an invalid field set`);
    }
    if (result.schemaVersion !== 'ogvcs.protocol/runner-result/v1'
        || typeof result.id !== 'string'
        || Buffer.byteLength(result.id, 'utf8') > 256
        || !/^[a-z0-9][a-z0-9._/-]*(?:@[0-9]+)?$/u.test(result.id)
        || seen.has(result.id)
        || !['accept', 'reject'].includes(result.result)
        || !/^[A-Z][A-Z0-9_]{0,63}$/u.test(result.code)
        || (result.result === 'accept') !== (result.code === 'NONE')
        || typeof result.preMutation !== 'boolean'
        || !Number.isSafeInteger(result.mutationCount)
        || result.mutationCount < 0
        || result.preMutation !== (result.mutationCount === 0)
        || !/^[0-9a-f]{64}$/u.test(result.traceDigest)
        || (result.semanticDigest !== undefined && !/^[0-9a-f]{64}$/u.test(result.semanticDigest))) {
      throw new Error(`${label} result ${index} is invalid`);
    }
    seen.add(result.id);
  }
}

async function validateReport(directory, record, evidence) {
  exactKeys(record, ['adapterId', 'filename', 'reportDigest', 'sha256'], `report record ${record.adapterId}`);
  if (!EXPECTED_ADAPTERS.has(record.adapterId) || basename(record.filename) !== record.filename || !/^[0-9a-f]{64}$/u.test(record.reportDigest) || !/^[0-9a-f]{64}$/u.test(record.sha256)) {
    throw new Error(`invalid protocol report record: ${record.adapterId}`);
  }
  const bytes = await readFile(join(directory, record.filename));
  if (sha256(bytes) !== record.sha256) throw new Error(`protocol report digest differs: ${record.filename}`);
  const report = JSON.parse(bytes);
  if (!bytes.equals(Buffer.from(`${canonicalJson(report)}\n`, 'utf8'))) throw new Error(`protocol report is not canonical JSON: ${record.filename}`);
  exactKeys(report, ['adapterId', 'contractManifestSha256', 'failed', 'passed', 'reportDigest', 'results', 'schemaVersion'], `protocol report ${record.filename}`);
  if (report.schemaVersion !== 'ogvcs.protocol/runner-report/v1'
      || report.adapterId !== record.adapterId
      || report.contractManifestSha256 !== evidence.contractManifestSha256
      || report.reportDigest !== record.reportDigest
      || report.passed !== evidence.scenarios
      || report.failed !== 0
      || !Array.isArray(report.results)
      || report.results.length !== evidence.scenarios
      || sha256(Buffer.from(canonicalJson(report.results), 'utf8')) !== report.reportDigest) {
    throw new Error(`invalid protocol report: ${record.filename}`);
  }
  validateResultRows(report.results, record.filename);
  return report;
}

async function validateOfflineSource(directory, evidence) {
  const root = join(directory, 'offline-source');
  const manifestBytes = await readFile(join(root, 'offline-source-manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  if (manifest.schemaVersion !== 'ogvcs.protocol/offline-source-manifest/v1'
      || manifest.license !== 'MIT'
      || manifest.sourceSetSha256 !== evidence.sourceSetSha256
      || !Array.isArray(manifest.files)
      || manifest.files.length === 0
      || sha256(Buffer.from(canonicalJson(manifest.files), 'utf8')) !== manifest.sourceSetSha256) {
    throw new Error(`invalid offline source manifest: ${directory}`);
  }
  const seen = new Set();
  let licenseFiles = 0;
  for (const entry of manifest.files) {
    exactKeys(entry, ['bytes', 'path', 'sha256'], `offline source entry ${entry.path}`);
    safeRelativePath(entry.path, 'offline source path');
    if (seen.has(entry.path) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !/^[0-9a-f]{64}$/u.test(entry.sha256)) throw new Error(`invalid offline source entry: ${entry.path}`);
    seen.add(entry.path);
    if (basename(entry.path) === 'LICENSE') {
      licenseFiles += 1;
      if (entry.sha256 !== evidence.licenseSha256) throw new Error(`offline source license differs: ${entry.path}`);
    }
    const bytes = await readFile(join(root, entry.path));
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) throw new Error(`offline source digest differs: ${entry.path}`);
  }
  if (licenseFiles === 0) throw new Error(`offline source contains no MIT license: ${directory}`);
  const actualFiles = [];
  const walk = async (current, segments = []) => {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
      const nextSegments = [...segments, entry.name];
      const relativePath = nextSegments.join('/');
      safeRelativePath(relativePath, 'offline source filesystem path');
      const absolutePath = join(current, entry.name);
      const metadata = await lstat(absolutePath);
      if (metadata.isSymbolicLink()) throw new Error(`offline source contains a symbolic link: ${relativePath}`);
      if (metadata.isDirectory()) {
        await walk(absolutePath, nextSegments);
      } else if (metadata.isFile()) {
        actualFiles.push(relativePath);
        if (actualFiles.length > 4096) throw new Error(`offline source contains too many files: ${directory}`);
      } else {
        throw new Error(`offline source contains a non-regular entry: ${relativePath}`);
      }
    }
  };
  await walk(root);
  const declaredFiles = [...seen, 'offline-source-manifest.json'].sort();
  actualFiles.sort();
  if (actualFiles.length !== declaredFiles.length || actualFiles.some((path, index) => path !== declaredFiles[index])) {
    throw new Error(`offline source contains undeclared or missing files: ${directory}`);
  }
  const bindingBytes = await readFile(join(root, 'foundation/protocol-baseline/bindings/manifest.json'));
  if (sha256(bindingBytes) !== evidence.bindingManifestSha256) throw new Error(`binding manifest digest differs: ${directory}`);
  return manifest;
}

async function validateEvidence(path) {
  const directory = dirname(path);
  const evidenceBytes = await readFile(path);
  const evidence = JSON.parse(evidenceBytes);
  if (!evidenceBytes.equals(Buffer.from(`${canonicalJson(evidence)}\n`, 'utf8'))) throw new Error(`packed evidence is not canonical JSON: ${path}`);
  const fields = [
    'adapterIsolation', 'bindingManifestSha256', 'bindingSetSha256', 'contractManifestSha256', 'contractVersion',
    'generatorSha256', 'license', 'licenseSha256', 'modelSha256', 'packages', 'platform', 'registrySetSha256',
    'reports', 'result', 'scenarios', 'schemaSetSha256', 'schemaVersion', 'sourceSetSha256', 'vectorSetSha256',
  ];
  exactKeys(evidence, fields, `packed evidence ${path}`);
  if (evidence.schemaVersion !== 'ogvcs.protocol/packed-evidence/v1'
      || evidence.adapterIsolation !== 'node-permission-isolated-package-staged-authority-v1'
      || evidence.contractVersion !== '1.0.0-rc.1'
      || evidence.license !== 'MIT'
      || !/^[0-9a-f]{64}$/u.test(evidence.licenseSha256)
      || evidence.result !== 'pass'
      || evidence.scenarios < 1
      || !['linux', 'macos', 'windows'].includes(evidence.platform)
      || !['bindingManifestSha256', 'bindingSetSha256', 'contractManifestSha256', 'generatorSha256', 'modelSha256', 'registrySetSha256', 'schemaSetSha256', 'sourceSetSha256', 'vectorSetSha256'].every((field) => /^[0-9a-f]{64}$/u.test(evidence[field]))) {
    throw new Error(`invalid packed protocol evidence: ${path}`);
  }
  if (!Array.isArray(evidence.packages) || evidence.packages.length !== EXPECTED_PACKAGES.size) throw new Error(`protocol package inventory is incomplete: ${path}`);
  const packageNames = new Set();
  for (const record of evidence.packages) {
    exactKeys(record, ['bytes', 'filename', 'name', 'sha256', 'version'], `package record ${record.name}`);
    if (packageNames.has(record.name) || EXPECTED_PACKAGES.get(record.name) !== record.version || basename(record.filename) !== record.filename || !Number.isSafeInteger(record.bytes) || record.bytes <= 0 || !/^[0-9a-f]{64}$/u.test(record.sha256)) throw new Error(`invalid protocol package record: ${record.name}`);
    packageNames.add(record.name);
    const bytes = await readFile(join(directory, 'packages', record.filename));
    if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256) throw new Error(`protocol package digest differs: ${record.name}`);
  }
  if (!Array.isArray(evidence.reports) || evidence.reports.length !== EXPECTED_ADAPTERS.size || new Set(evidence.reports.map(({ adapterId }) => adapterId)).size !== EXPECTED_ADAPTERS.size) throw new Error(`protocol adapter report inventory differs: ${path}`);
  const reports = await Promise.all(evidence.reports.map((record) => validateReport(directory, record, evidence)));
  if (reports[0].reportDigest !== reports[1].reportDigest || canonicalJson(reports[0].results) !== canonicalJson(reports[1].results)) throw new Error(`adapter results differ: ${path}`);
  const sourceManifest = await validateOfflineSource(directory, evidence);
  return { path, directory, evidence, reports, sourceManifest };
}

export async function compareProtocolConformanceReports(paths) {
  if (!Array.isArray(paths) || paths.length !== 3) throw new Error('exactly three packed evidence paths are required');
  const records = await Promise.all(paths.map((path) => validateEvidence(resolve(path))));
  const platforms = new Set(records.map(({ evidence }) => evidence.platform));
  if (platforms.size !== 3 || !['linux', 'macos', 'windows'].every((name) => platforms.has(name))) throw new Error('protocol evidence must cover Linux, macOS, and Windows exactly once');
  const authority = records[0];
  const stableFields = [
    'adapterIsolation', 'bindingManifestSha256', 'bindingSetSha256', 'contractManifestSha256', 'contractVersion',
    'generatorSha256', 'license', 'licenseSha256', 'modelSha256', 'registrySetSha256', 'scenarios', 'schemaSetSha256',
    'sourceSetSha256', 'vectorSetSha256',
  ];
  const packageProjection = ({ packages }) => packages.map(({ name, version, bytes, sha256: digest }) => ({ name, version, bytes, sha256: digest })).sort((left, right) => left.name.localeCompare(right.name));
  const reportProjection = ({ reports }) => reports.map(({ adapterId, reportDigest }) => ({ adapterId, reportDigest })).sort((left, right) => left.adapterId.localeCompare(right.adapterId));
  for (const record of records.slice(1)) {
    for (const field of stableFields) if (record.evidence[field] !== authority.evidence[field]) throw new Error(`protocol ${field} differs across operating systems`);
    if (canonicalJson(packageProjection(record.evidence)) !== canonicalJson(packageProjection(authority.evidence))) throw new Error('packed protocol package bytes differ across operating systems');
    if (canonicalJson(reportProjection(record.evidence)) !== canonicalJson(reportProjection(authority.evidence))) throw new Error('protocol adapter decisions differ across operating systems');
    if (canonicalJson(record.reports.map(({ results }) => results)) !== canonicalJson(authority.reports.map(({ results }) => results))) throw new Error('protocol result rows differ across operating systems');
  }
  return {
    schemaVersion: 'ogvcs.protocol/comparison/v1',
    platforms: [...platforms].sort(),
    reports: records.length * EXPECTED_ADAPTERS.size,
    adapters: [...EXPECTED_ADAPTERS].sort(),
    adapterIsolation: authority.evidence.adapterIsolation,
    contractVersion: authority.evidence.contractVersion,
    contractManifestSha256: authority.evidence.contractManifestSha256,
    bindingSetSha256: authority.evidence.bindingSetSha256,
    licenseSha256: authority.evidence.licenseSha256,
    sourceSetSha256: authority.evidence.sourceSetSha256,
    scenarios: authority.evidence.scenarios,
    result: 'equal',
  };
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  const paths = process.argv.slice(2);
  if (paths.length !== 3) throw new Error('usage: node tools/compare-protocol-conformance-reports.mjs <linux-evidence.json> <macos-evidence.json> <windows-evidence.json>');
  process.stdout.write(`${canonicalJson(await compareProtocolConformanceReports(paths))}\n`);
}
