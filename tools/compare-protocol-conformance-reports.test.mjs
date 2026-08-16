import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { compareProtocolConformanceReports } from './compare-protocol-conformance-reports.mjs';
import { runPackedProtocolConformance } from './run-packed-protocol-conformance.mjs';

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

test('comparison requires byte-identical packages, sources, and decisions on all three operating systems', { timeout: 120_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-compare-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }));
  const base = join(root, 'base');
  await runPackedProtocolConformance(base);
  const paths = [];
  for (const platform of ['linux', 'macos', 'windows']) {
    const destination = join(root, platform);
    await cp(base, destination, { recursive: true, force: false, errorOnExist: true });
    const evidencePath = join(destination, 'packed-evidence.json');
    const evidence = JSON.parse(await readFile(evidencePath));
    evidence.platform = platform;
    await writeFile(evidencePath, `${canonicalJson(evidence)}\n`, 'utf8');
    paths.push(evidencePath);
  }
  const comparison = await compareProtocolConformanceReports(paths);
  assert.equal(comparison.schemaVersion, 'ogvcs.protocol/comparison/v1');
  assert.equal(comparison.adapterIsolation, 'node-permission-isolated-package-staged-authority-v1');
  assert.deepEqual(comparison.platforms, ['linux', 'macos', 'windows']);
  assert.equal(comparison.reports, 6);
  assert.equal(comparison.scenarios, 360);
  assert.equal(comparison.result, 'equal');

  const originalWindowsEvidenceBytes = await readFile(paths[2]);
  const windowsEvidence = JSON.parse(originalWindowsEvidenceBytes);
  const reportRecord = windowsEvidence.reports[0];
  const reportPath = join(root, 'windows', reportRecord.filename);
  const originalReportBytes = await readFile(reportPath);
  const report = JSON.parse(originalReportBytes);
  report.results[0].preMutation = !report.results[0].preMutation;
  report.reportDigest = sha256(Buffer.from(canonicalJson(report.results), 'utf8'));
  const reportBytes = Buffer.from(`${canonicalJson(report)}\n`, 'utf8');
  reportRecord.reportDigest = report.reportDigest;
  reportRecord.sha256 = sha256(reportBytes);
  await writeFile(reportPath, reportBytes);
  await writeFile(paths[2], `${canonicalJson(windowsEvidence)}\n`, 'utf8');
  await assert.rejects(() => compareProtocolConformanceReports(paths), /result 0 is invalid/u);
  await writeFile(reportPath, originalReportBytes);
  await writeFile(paths[2], originalWindowsEvidenceBytes);

  const tarball = join(root, 'windows/packages', windowsEvidence.packages[0].filename);
  const bytes = await readFile(tarball);
  bytes[bytes.length - 1] ^= 1;
  await writeFile(tarball, bytes);
  await assert.rejects(() => compareProtocolConformanceReports(paths), /package digest differs/u);

  bytes[bytes.length - 1] ^= 1;
  await writeFile(tarball, bytes);
  await writeFile(join(root, 'windows/offline-source/foundation/protocol-baseline/bindings/rust/Cargo.lock'), '# undeclared build output\n', 'utf8');
  await assert.rejects(() => compareProtocolConformanceReports(paths), /undeclared or missing files/u);
});
