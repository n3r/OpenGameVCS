#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { open, readdir } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

const MAX_METADATA_BYTES = 1_048_576;
const MAX_PACKAGE_BYTES = 536_870_912;
const MAX_PACKAGE_SET_BYTES = 1_073_741_824;
const SHA256 = /^[0-9a-f]{64}$/u;
const ARCHIVE_NAME = /^[A-Za-z0-9._-]+\.tgz$/u;
const EXPECTED_PACKAGES = Object.freeze([
  '@opengamevcs/authorization-contract@1.0.0', '@opengamevcs/authorization-contract-v1@1.0.0',
  '@opengamevcs/benchmark-fault-contract-v1@1.0.0-rc.2', '@opengamevcs/benchmark-fault-harness@1.0.0-rc.2',
  '@opengamevcs/fixture-generator@1.0.0', '@opengamevcs/path-contract-v1@1.0.0', '@opengamevcs/path-filesystem@1.1.0',
  '@opengamevcs/protocol-baseline@1.0.0-rc.1', '@opengamevcs/protocol-contract-v1@1.0.0-rc.1', '@opengamevcs/protocol-types-v1@1.0.0-rc.1',
]);

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function digest(value) { return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex'); }
function domainDigest(value, domain) { return createHash('sha256').update(domain, 'utf8').update(Buffer.from([0])).update(canonical(value), 'utf8').digest('hex'); }
function exactKeys(value, keys) { return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0'); }

async function readRegular(path, maximum) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > maximum) throw new Error('file is not a bounded regular artifact');
    const bytes = await handle.readFile(); const after = await handle.stat();
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || before.ino !== 0 && after.ino !== 0 && before.ino !== after.ino) throw new Error('file changed while reading');
    return bytes;
  } finally { await handle?.close().catch(() => {}); }
}

async function hashRegular(path, maximum) {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || before.size < 1 || before.size > maximum) throw new Error('package is not a bounded regular artifact');
    const hash = createHash('sha256'); const buffer = Buffer.allocUnsafe(64 * 1024); let offset = 0;
    while (offset < before.size) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, before.size - offset), offset);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || before.ino !== 0 && after.ino !== 0 && before.ino !== after.ino) throw new Error('package changed while hashing');
    return { bytes: before.size, sha256: hash.digest('hex') };
  } finally { await handle?.close().catch(() => {}); }
}

function parseCanonical(bytes, label) {
  let text; let value;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); value = JSON.parse(text); }
  catch (error) { throw new Error(`${label} is not UTF-8 JSON`, { cause: error }); }
  if (text !== `${canonical(value)}\n`) throw new Error(`${label} is not canonical JSON with one terminal LF`);
  return value;
}

async function authenticate(path) {
  const evidencePath = resolve(path); const root = dirname(evidencePath);
  const evidenceBytes = await readRegular(evidencePath, MAX_METADATA_BYTES); const value = parseCanonical(evidenceBytes, `packed evidence ${path}`);
  if (!exactKeys(value, ['schemaVersion', 'contractManifestSha256', 'profile', 'semanticResultsSha256', 'packageSetSha256', 'packages', 'report', 'platform', 'exactScaleExecuted', 'evidenceSha256'])) throw new Error(`invalid packed benchmark evidence envelope: ${path}`);
  const { evidenceSha256, ...body } = value;
  if (value.schemaVersion !== 'ogvcs.benchmark/packed-evidence/v1' || digest(body) !== evidenceSha256 || value.exactScaleExecuted !== false || !SHA256.test(value.contractManifestSha256) || !SHA256.test(value.semanticResultsSha256) || !SHA256.test(value.packageSetSha256)) throw new Error(`invalid packed benchmark evidence: ${path}`);
  if (!exactKeys(value.platform, ['os', 'architecture', 'node']) || Object.values(value.platform).some((entry) => typeof entry !== 'string' || entry.length < 1 || entry.length > 256)) throw new Error(`invalid packed benchmark platform: ${path}`);
  if (!Array.isArray(value.packages) || value.packages.length !== 10) throw new Error(`packed benchmark evidence must authenticate exactly ten packages: ${path}`);
  const packageNames = new Set(); const filenames = new Set(); let aggregatePackageBytes = 0;
  for (const entry of value.packages) {
    if (!exactKeys(entry, ['name', 'version', 'filename', 'sha256']) || typeof entry.name !== 'string' || entry.name.length < 1 || entry.name.length > 256 || typeof entry.version !== 'string' || entry.version.length < 1 || entry.version.length > 128 || typeof entry.filename !== 'string' || !ARCHIVE_NAME.test(entry.filename) || basename(entry.filename) !== entry.filename || !SHA256.test(entry.sha256) || packageNames.has(entry.name) || filenames.has(entry.filename)) throw new Error(`invalid packed package inventory: ${path}`);
    packageNames.add(entry.name); filenames.add(entry.filename);
    const authenticated = await hashRegular(join(root, 'packages', entry.filename), MAX_PACKAGE_BYTES);
    aggregatePackageBytes += authenticated.bytes;
    if (!Number.isSafeInteger(aggregatePackageBytes) || aggregatePackageBytes > MAX_PACKAGE_SET_BYTES || authenticated.sha256 !== entry.sha256) throw new Error(`packed package authentication failed: ${entry.filename}`);
  }
  const packageDirectory = await readdir(join(root, 'packages'), { withFileTypes: true });
  if (packageDirectory.length !== filenames.size || packageDirectory.some((entry) => !entry.isFile() || entry.isSymbolicLink() || !filenames.has(entry.name))) throw new Error(`packed package directory inventory differs: ${path}`);
  const packageSet = value.packages.map(({ name, version, sha256 }) => ({ name, version, sha256 })).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  const packageAuthority = packageSet.map(({ name, version }) => `${name}@${version}`);
  if (canonical(packageAuthority) !== canonical(EXPECTED_PACKAGES) || digest(packageSet) !== value.packageSetSha256) throw new Error(`packed package-set authority or digest differs: ${path}`);
  if (!exactKeys(value.report, ['path', 'sha256', 'reportSha256']) || value.report.path !== 'report/report.json' || !SHA256.test(value.report.sha256) || !SHA256.test(value.report.reportSha256)) throw new Error(`packed report authority is invalid: ${path}`);
  const reportBytes = await readRegular(join(root, value.report.path), MAX_METADATA_BYTES);
  const report = parseCanonical(reportBytes, `retained report ${path}`); const { reportSha256, ...reportBody } = report;
  if (digest(reportBytes) !== value.report.sha256 || reportSha256 !== value.report.reportSha256 || domainDigest(reportBody, 'ogvcs.benchmark/retained-report/v1') !== reportSha256 || report.contractManifestSha256 !== value.contractManifestSha256 || report.profile !== value.profile || report.semanticResultsSha256 !== value.semanticResultsSha256 || report.overallStatus !== 'passed' || report.results?.conformanceFailed !== 0 || report.results?.faultFailures !== 0 || report.results?.brokenMisses !== 0 || report.results?.securityMisses !== 0 || report.exactScaleExecuted !== false) throw new Error(`packed retained report is invalid or differs from its evidence: ${path}`);
  return { path: evidencePath, value };
}

const paths = process.argv.slice(2);
if (paths.length < 2 || paths.length > 8) throw new Error('usage: node tools/compare-benchmark-fault-reports.mjs <packed-evidence.json> <packed-evidence.json> [...]');
const rows = [];
for (const path of paths) rows.push(await authenticate(path));
for (const field of ['contractManifestSha256', 'profile', 'semanticResultsSha256', 'packageSetSha256']) {
  if (new Set(rows.map(({ value }) => value[field])).size !== 1) throw new Error(`cross-platform benchmark evidence differs: ${field}`);
}
const platformKeys = new Set(rows.map(({ value }) => `${value.platform.os}/${value.platform.architecture}`));
if (platformKeys.size !== rows.length) throw new Error('cross-platform benchmark evidence contains a duplicate platform');
const body = { schemaVersion: 'ogvcs.benchmark/cross-platform-comparison/v1', reports: rows.length, platforms: [...platformKeys].sort(), contractManifestSha256: rows[0].value.contractManifestSha256, profile: rows[0].value.profile, semanticResultsSha256: rows[0].value.semanticResultsSha256, packageSetSha256: rows[0].value.packageSetSha256, matched: true };
process.stdout.write(`${canonical({ ...body, comparisonSha256: digest(body) })}\n`);
