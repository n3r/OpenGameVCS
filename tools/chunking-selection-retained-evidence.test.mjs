import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import { ProtocolSchemaValidator } from '@opengamevcs/protocol-baseline';

const ROOT = resolve(import.meta.dirname, '..');
const REPORT_PATH = join(ROOT, 'docs/evidence/OGVCS-007/bounded-selection-report-2026-08-30.json');
const SPEC_ROOT = join(ROOT, 'spec/chunking-manifest/v1');
const PACKAGE_ROOT = join(ROOT, 'core/chunking-manifest/js');

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonicalJson(value)).digest('hex');
}

async function collectEntries(root, relativePath, results) {
  const absolutePath = join(root, relativePath);
  const directoryEntries = await readdir(absolutePath, { withFileTypes: true }).catch(() => null);
  if (directoryEntries === null) {
    const bytes = await readFile(absolutePath);
    results.push({ bytes: bytes.length, path: relativePath.replaceAll('\\', '/'), sha256: sha256(bytes) });
    return;
  }
  for (const entry of directoryEntries) {
    const entryPath = join(relativePath, entry.name);
    if (entry.isDirectory()) await collectEntries(root, entryPath, results);
    else if (entry.isFile()) {
      const bytes = await readFile(join(root, entryPath));
      results.push({ bytes: bytes.length, path: entryPath.replaceAll('\\', '/'), sha256: sha256(bytes) });
    }
  }
}

async function fileEntries(root, paths) {
  const results = [];
  for (const relativePath of paths) await collectEntries(root, relativePath, results);
  return results.sort((left, right) => left.path.localeCompare(right.path));
}

function digestEntries(entries, domain) {
  return sha256(entries.map(({ path, bytes, sha256: digest }) => ({ path, bytes, sha256: digest, domain })));
}

async function loadSchemaMap() {
  const names = [
    'selection-benchmark-thresholds.schema.json',
    'selection-benchmark-report.schema.json',
  ];
  return new Map(await Promise.all(names.map(async (name) => [name, JSON.parse(await readFile(join(SPEC_ROOT, 'schemas', name), 'utf8'))])));
}

test('retained chunking selection report authenticates its identities and self-hash', async () => {
  const report = JSON.parse(await readFile(REPORT_PATH, 'utf8'));
  const validator = new ProtocolSchemaValidator(await loadSchemaMap());
  validator.validate(report, 'selection-benchmark-report.schema.json');

  const reportBody = { ...report };
  delete reportBody.reportSha256;
  assert.equal(report.reportSha256, sha256(reportBody));

  const contractManifestBytes = await readFile(join(SPEC_ROOT, 'manifest.json'));
  assert.equal(report.contractManifestSha256, sha256(contractManifestBytes));

  const thresholdFile = JSON.parse(await readFile(join(SPEC_ROOT, 'thresholds/selection-bounded-v1.json'), 'utf8'));
  assert.equal(report.thresholdFileDigest, sha256(thresholdFile));
  assert.deepEqual(report.thresholdFile, thresholdFile);

  const workloadFile = JSON.parse(await readFile(join(SPEC_ROOT, 'vectors/selection-benchmark-workloads.json'), 'utf8'));
  assert.equal(report.workloadDefinitionsDigest, sha256(workloadFile.workloads));

  const packageJsonBytes = await readFile(join(PACKAGE_ROOT, 'package.json'));
  const packageJson = JSON.parse(packageJsonBytes);
  const packageEntries = await fileEntries(PACKAGE_ROOT, ['package.json', ...packageJson.files]);
  assert.equal(report.implementation.packageJsonSha256, sha256(packageJsonBytes));
  assert.equal(report.implementation.publishedFileCount, packageEntries.length);
  assert.equal(report.implementation.publishedFileSetSha256, digestEntries(packageEntries, 'ogvcs.chunking/package-files/v1'));

  const sourceEntries = await fileEntries(ROOT, [
    'core/chunking-manifest/js/LICENSE',
    'core/chunking-manifest/js/README.md',
    'core/chunking-manifest/js/package.json',
    'core/chunking-manifest/js/src',
    'spec/chunking-manifest/v1/docs',
    'spec/chunking-manifest/v1/manifest.json',
    'spec/chunking-manifest/v1/profiles',
    'spec/chunking-manifest/v1/registries',
    'spec/chunking-manifest/v1/schemas',
    'spec/chunking-manifest/v1/scripts',
    'spec/chunking-manifest/v1/thresholds',
    'spec/chunking-manifest/v1/vectors',
    'tools/chunking-selection-benchmark-report.mjs',
  ]);
  assert.equal(report.sourceIdentity.type, 'selection-benchmark-source-set/v1');
  assert.equal(report.sourceIdentity.entryCount, sourceEntries.length);
  assert.equal(report.sourceIdentity.sourceSetSha256, digestEntries(sourceEntries, 'ogvcs.chunking/selection-benchmark-source-set/v1'));

  assert.equal(report.exactScaleExecuted, false);
  assert.equal(report.summary.thresholdFailureCount, report.thresholdEvaluations.filter(({ status }) => status === 'failed').length);
  assert.equal(report.overallStatus, report.summary.thresholdFailureCount === 0 ? 'passed' : 'failed');
});
