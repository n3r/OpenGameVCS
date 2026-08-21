import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
function run(script, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'tools', script), ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    const stdout = []; const stderr = [];
    child.stdout.on('data', (chunk) => stdout.push(chunk)); child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', reject); child.once('close', (code, signal) => resolvePromise({ code, signal, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') }));
  });
}
function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function digest(value) { return createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex'); }
function domainDigest(value, domain) { return createHash('sha256').update(domain, 'utf8').update(Buffer.from([0])).update(canonical(value), 'utf8').digest('hex'); }

async function packedEvidence(root, platform, semanticResultsSha256 = 'b'.repeat(64)) {
  await mkdir(join(root, 'packages'), { recursive: true }); await mkdir(join(root, 'report'), { recursive: true });
  const packages = [];
  const authorities = [
    ['@opengamevcs/authorization-contract', '1.0.0'], ['@opengamevcs/authorization-contract-v1', '1.0.0'],
    ['@opengamevcs/benchmark-fault-contract-v1', '1.0.0-rc.1'], ['@opengamevcs/benchmark-fault-harness', '1.0.0-rc.1'],
    ['@opengamevcs/fixture-generator', '1.0.0'], ['@opengamevcs/path-contract-v1', '1.0.0'], ['@opengamevcs/path-filesystem', '1.0.0'],
    ['@opengamevcs/protocol-baseline', '1.0.0-rc.1'], ['@opengamevcs/protocol-contract-v1', '1.0.0-rc.1'], ['@opengamevcs/protocol-types-v1', '1.0.0-rc.1'],
  ];
  for (let index = 0; index < authorities.length; index += 1) {
    const filename = `package-${index}.tgz`; const bytes = Buffer.from(`package-${index}\n`);
    await writeFile(join(root, 'packages', filename), bytes);
    packages.push({ name: authorities[index][0], version: authorities[index][1], filename, sha256: digest(bytes) });
  }
  const packageSet = packages.map(({ name, version, sha256 }) => ({ name, version, sha256 })).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  const reportBody = {
    schemaVersion: 'ogvcs.benchmark/retained-report/v1', contractManifestSha256: 'a'.repeat(64), profile: 'presubmit', semanticResultsSha256,
    overallStatus: 'passed', results: { conformanceFailed: 0, faultFailures: 0, brokenMisses: 0, securityMisses: 0 }, exactScaleExecuted: false,
  };
  const report = { ...reportBody, reportSha256: domainDigest(reportBody, 'ogvcs.benchmark/retained-report/v1') };
  const reportBytes = Buffer.from(`${canonical(report)}\n`); await writeFile(join(root, 'report', 'report.json'), reportBytes);
  const body = {
    schemaVersion: 'ogvcs.benchmark/packed-evidence/v1', contractManifestSha256: report.contractManifestSha256, profile: report.profile,
    semanticResultsSha256, packageSetSha256: digest(packageSet), packages,
    report: { path: 'report/report.json', sha256: digest(reportBytes), reportSha256: report.reportSha256 }, platform, exactScaleExecuted: false,
  };
  const evidence = { ...body, evidenceSha256: digest(body) }; const path = join(root, 'packed-evidence.json');
  await writeFile(path, `${canonical(evidence)}\n`); return path;
}

test('source report is a bounded complete five-corpus result', { timeout: 60_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-report-test-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const output = join(scratch, 'report'); const execution = await run('benchmark-fault-conformance-report.mjs', ['--output', output, '--profile', 'local-smoke']);
  assert.equal(execution.code, 0, execution.stderr);
  const report = JSON.parse(await readFile(join(output, 'report.json')));
  assert.deepEqual(report.counts, { brokenCases: 7, conformance: 35, corpora: 5, environments: 10, faultRows: 36, samples: 110, summaries: 110 });
  assert.deepEqual(report.results, { brokenMisses: 0, conformanceFailed: 0, conformancePassed: 35, faultFailures: 0, securityMisses: 0 });
  assert.equal(report.overallStatus, 'passed'); assert.equal(report.exactScaleExecuted, false);
});

test('all ten packed packages install and execute fully offline', { timeout: 120_000 }, async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-packed-test-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const output = join(scratch, 'evidence'); const execution = await run('run-packed-benchmark-fault-conformance.mjs', ['--output', output, '--profile', 'local-smoke']);
  assert.equal(execution.code, 0, execution.stderr);
  const evidence = JSON.parse(await readFile(join(output, 'packed-evidence.json'))); const report = JSON.parse(await readFile(join(output, 'report/report.json')));
  assert.equal(evidence.packages.length, 10); assert.equal(evidence.exactScaleExecuted, false); assert.equal(report.overallStatus, 'passed'); assert.equal(report.results.conformanceFailed, 0);
  assert.equal(new Set(evidence.packages.map(({ name }) => name)).size, 10);
});

test('cross-platform comparator accepts host variance but rejects semantic/package drift', async (t) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-compare-test-')); t.after(() => rm(scratch, { recursive: true, force: true }));
  const leftRoot = join(scratch, 'left'); const rightRoot = join(scratch, 'right');
  const left = await packedEvidence(leftRoot, { os: 'linux', architecture: 'x64', node: '22.0.0' });
  let right = await packedEvidence(rightRoot, { os: 'darwin', architecture: 'arm64', node: '22.0.0' });
  const accepted = await run('compare-benchmark-fault-reports.mjs', [left, right]); assert.equal(accepted.code, 0, accepted.stderr); assert.equal(JSON.parse(accepted.stdout).matched, true);
  await packedEvidence(rightRoot, { os: 'linux', architecture: 'x64', node: '22.0.0' });
  const duplicatePlatform = await run('compare-benchmark-fault-reports.mjs', [left, right]); assert.notEqual(duplicatePlatform.code, 0); assert.match(duplicatePlatform.stderr, /duplicate platform/u);
  right = await packedEvidence(rightRoot, { os: 'darwin', architecture: 'arm64', node: '22.0.0' });
  await writeFile(join(leftRoot, 'packages', 'package-0.tgz'), 'tampered\n');
  const tampered = await run('compare-benchmark-fault-reports.mjs', [left, right]); assert.notEqual(tampered.code, 0); assert.match(tampered.stderr, /package authentication/u);
  await packedEvidence(leftRoot, { os: 'linux', architecture: 'x64', node: '22.0.0' });
  right = await packedEvidence(rightRoot, { os: 'darwin', architecture: 'arm64', node: '22.0.0' }, 'f'.repeat(64));
  const rejected = await run('compare-benchmark-fault-reports.mjs', [left, right]); assert.notEqual(rejected.code, 0); assert.match(rejected.stderr, /semanticResultsSha256/u);
});
