import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  SANDBOX_CONFORMANCE_SOURCE_PATHS,
  comparePortableConformanceReports,
  readGitSourceEvidence,
  runPrivatePortableConformance,
  snapshotSourceEvidence,
} from '../core/untrusted-sandbox/js/src/internal/conformance-evidence.mjs';
import { canonicalJson, sha256 } from '../core/untrusted-sandbox/js/src/internal/reference-contract.mjs';
import { REFERENCE_SERVICE_HARD_KILL_BOUNDARIES } from '../core/untrusted-sandbox/js/src/internal/reference-service.mjs';

const root = resolve(import.meta.dirname, '..');
const modelRoot = join(root, 'docs/evidence/OGVCS-045/source-only-v2');
const execFileAsync = promisify(execFile);

const readCanonical = async (path) => {
  const bytes = await readFile(path);
  const value = JSON.parse(bytes.toString('utf8'));
  assert.equal(bytes.toString('utf8'), `${canonicalJson(value)}\n`, path);
  return value;
};

test('source-only conformance inventory is frozen, sorted, unique, present, and bounded', async () => {
  assert.equal(Object.isFrozen(SANDBOX_CONFORMANCE_SOURCE_PATHS), true);
  assert.deepEqual(SANDBOX_CONFORMANCE_SOURCE_PATHS, [...SANDBOX_CONFORMANCE_SOURCE_PATHS].sort());
  assert.equal(new Set(SANDBOX_CONFORMANCE_SOURCE_PATHS).size, SANDBOX_CONFORMANCE_SOURCE_PATHS.length);
  const sourceFiles = [];
  for (const path of SANDBOX_CONFORMANCE_SOURCE_PATHS) {
    const details = await stat(join(root, path));
    assert.equal(details.isFile(), true, path);
    assert.ok(details.size <= 16 * 1024 * 1024, path);
    const bytes = await readFile(join(root, path));
    sourceFiles.push({ bytes: bytes.length, path, sha256: sha256(bytes) });
  }
  const evidence = snapshotSourceEvidence({ sourceFiles, sourceRevision: '1'.repeat(40) });
  assert.equal(evidence.sourceFiles.length, SANDBOX_CONFORMANCE_SOURCE_PATHS.length);
  assert.match(evidence.sourceSetSha256, /^[0-9a-f]{64}$/u);
});

test('source-only generators have no upload, dispatch, or public-admission channel', async () => {
  for (const path of [
    'core/untrusted-sandbox/js/scripts/portable-conformance.mjs',
    'core/untrusted-sandbox/js/scripts/source-model-conformance.mjs',
    'core/untrusted-sandbox/js/scripts/kill-boundary-conformance.mjs',
    'tools/compare-untrusted-sandbox-conformance.mjs',
  ]) {
    const source = await readFile(join(root, path), 'utf8');
    assert.doesNotMatch(source, /actions\/upload-artifact|workflow_dispatch|repository_dispatch|\bfetch\s*\(|https?:\/\//u, path);
  }
});

test('committed portable target models are exact, equal, source-bound, and explicitly not hosted', async () => {
  const expectedFiles = [
    'kill-boundary-source-model.json',
    'linux-v2-source-only-schema-fixture.json',
    'portable-linux-source-model.json',
    'portable-macos-source-model.json',
    'portable-source-model-comparison.json',
    'portable-windows-source-model.json',
  ];
  assert.deepEqual((await readdir(modelRoot)).filter((name) => name.endsWith('.json')).sort(), expectedFiles);
  const reports = await Promise.all(['linux', 'macos', 'windows'].map((platform) => readCanonical(join(modelRoot, `portable-${platform}-source-model.json`))));
  const retainedSource = snapshotSourceEvidence({ sourceFiles: reports[0].sourceFiles, sourceRevision: reports[0].sourceRevision });
  const comparison = comparePortableConformanceReports(reports, retainedSource);
  assert.deepEqual(await readCanonical(join(modelRoot, 'portable-source-model-comparison.json')), comparison);
  assert.equal(reports.every((report) => report.evidenceKind === 'source-only-model'
    && report.retentionStatus === 'not-hosted'
    && report.platformBinding === 'declared-target-only'
    && report.claimBoundary.hostIsolation === false
    && report.claimBoundary.productionBroker === false
    && report.claimBoundary.publicAdmission === false
    && report.claimBoundary.repositoryPublication === false), true);
  assert.match(comparison.sourceRevision, /^[0-9a-f]{40}$/u);
  assert.equal(comparison.sourceSetSha256, retainedSource.sourceSetSha256);
  const { stdout: retainedCommit } = await execFileAsync('git', ['rev-parse', '--verify', `${comparison.sourceRevision}^{commit}`], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
  });
  assert.equal(retainedCommit, `${comparison.sourceRevision}\n`);
  await execFileAsync('git', ['merge-base', '--is-ancestor', comparison.sourceRevision, 'HEAD'], { cwd: root, windowsHide: true });
  await execFileAsync('git', ['diff', '--quiet', '--no-ext-diff', comparison.sourceRevision, 'HEAD', '--', ...SANDBOX_CONFORMANCE_SOURCE_PATHS], {
    cwd: root,
    windowsHide: true,
  });
  assert.deepEqual(reports[0].sourceFiles.map(({ path }) => path), SANDBOX_CONFORMANCE_SOURCE_PATHS);
  for (const file of reports[0].sourceFiles) {
    const bytes = await readFile(join(root, file.path));
    assert.equal(file.bytes, bytes.length, file.path);
    assert.equal(file.sha256, sha256(bytes), file.path);
  }
});

test('portable comparison CLI binds three paths to the exact checked-out source before writing one closed report', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-portable-compare-'));
  const output = join(scratch, 'comparison.json');
  const { stdout: headOutput } = await execFileAsync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8', windowsHide: true });
  const sourceRevision = headOutput.trim();
  const source = await readGitSourceEvidence({ repositoryRoot: root, sourceRevision });
  for (const platform of ['linux', 'macos', 'windows']) {
    const report = await runPrivatePortableConformance({ platform, sourceFiles: source.sourceFiles, sourceRevision });
    await writeFile(join(scratch, `${platform}.json`), Buffer.from(`${canonicalJson(report)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
  }
  const { stdout } = await execFileAsync(process.execPath, [
    join(root, 'tools/compare-untrusted-sandbox-conformance.mjs'),
    '--linux', join(scratch, 'linux.json'),
    '--macos', join(scratch, 'macos.json'),
    '--windows', join(scratch, 'windows.json'),
    '--source-revision', sourceRevision,
    '--output', output,
  ], { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024, windowsHide: true });
  const comparison = await readCanonical(output);
  assert.equal(comparison.result, 'equal');
  assert.equal(comparison.sourceRevision, sourceRevision);
  assert.equal(stdout, `${canonicalJson({ output, result: 'equal', sourceRevision })}\n`);

  const forgedSource = snapshotSourceEvidence({
    sourceFiles: [{ bytes: 1, path: 'source/forged.mjs', sha256: 'f'.repeat(64) }],
    sourceRevision: 'f'.repeat(40),
  });
  for (const platform of ['linux', 'macos', 'windows']) {
    const report = await runPrivatePortableConformance({ platform, sourceFiles: forgedSource.sourceFiles, sourceRevision: forgedSource.sourceRevision });
    await writeFile(join(scratch, `forged-${platform}.json`), Buffer.from(`${canonicalJson(report)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
  }
  await assert.rejects(execFileAsync(process.execPath, [
    join(root, 'tools/compare-untrusted-sandbox-conformance.mjs'),
    '--linux', join(scratch, 'forged-linux.json'),
    '--macos', join(scratch, 'forged-macos.json'),
    '--windows', join(scratch, 'forged-windows.json'),
    '--source-revision', sourceRevision,
    '--output', join(scratch, 'forged-comparison.json'),
  ], { cwd: root, encoding: 'utf8', maxBuffer: 1024 * 1024, windowsHide: true }), /expected source differs/u);
});

test('Linux v2 fixture preserves historical v1 cases and digests without inventing live runtime observations', async () => {
  const fixture = await readCanonical(join(modelRoot, 'linux-v2-source-only-schema-fixture.json'));
  assert.deepEqual(Object.keys(fixture).sort(), ['claimBoundary', 'evidenceKind', 'historicalV1', 'report', 'schemaVersion']);
  assert.equal(fixture.schemaVersion, 'ogvcs.untrusted-sandbox/linux-conformance-v2-schema-fixture/v1');
  assert.equal(fixture.evidenceKind, 'synthetic-source-only-schema-fixture');
  assert.deepEqual(fixture.claimBoundary, {
    completeControllerObservation: false,
    dockerExecution: false,
    hostedRetention: false,
    liveRuntimeObservation: false,
    publicAdmission: false,
  });
  const historicalPath = join(root, fixture.historicalV1.path);
  const historicalBytes = await readFile(historicalPath);
  const historical = JSON.parse(historicalBytes.toString('utf8'));
  assert.equal(fixture.historicalV1.sha256, sha256(historicalBytes));
  assert.equal(fixture.report.schemaVersion, 'ogvcs.untrusted-sandbox/linux-conformance-report/v2');
  assert.deepEqual(fixture.report.cases, historical.cases);
  assert.equal(fixture.report.failure, historical.failure);
  assert.equal(fixture.report.outcome, historical.outcome);
  assert.equal(fixture.report.runtimeDigest, historical.runtimeDigest);
  assert.equal(fixture.report.seccompProfileSha256, historical.seccompProfileSha256);
  assert.deepEqual(fixture.report.controls, {
    architecture: 'amd64',
    availableControllers: ['cpu', 'memory', 'pids'],
    cgroupNamespace: true,
    cgroupVersion: 2,
    operatingSystem: 'linux',
    rootless: false,
    runtimeBinaryBinding: 'unproven',
    runtimeCommit: 'unobserved',
    runtimeName: 'runc',
    runtimePathKind: 'relative-name',
    runtimeVersion: 'unobserved',
    seccomp: true,
  });
  const source = snapshotSourceEvidence({ sourceFiles: fixture.report.sourceFiles, sourceRevision: fixture.report.sourceRevision });
  assert.equal(fixture.report.sourceSetSha256, source.sourceSetSha256);
  const comparison = await readCanonical(join(modelRoot, 'portable-source-model-comparison.json'));
  assert.equal(fixture.report.sourceRevision, comparison.sourceRevision);
  assert.equal(fixture.report.sourceSetSha256, comparison.sourceSetSha256);
});

test('kill-boundary model is exact, non-executed, quarantine-only for represented resources, and claims zero cleanup', async () => {
  const model = await readCanonical(join(modelRoot, 'kill-boundary-source-model.json'));
  assert.deepEqual(Object.keys(model).sort(), ['cases', 'claimBoundary', 'evidenceKind', 'outcome', 'retentionStatus', 'schemaVersion', 'sourceFiles', 'sourceRevision', 'sourceSetSha256']);
  assert.equal(model.schemaVersion, 'ogvcs.untrusted-sandbox/kill-boundary-conformance-model/v1');
  assert.equal(model.evidenceKind, 'non-executed-source-model');
  assert.equal(model.outcome, 'not-executed');
  assert.equal(model.retentionStatus, 'not-hosted');
  assert.deepEqual(model.claimBoundary, { childExecution: false, dockerExecution: false, hostedRetention: false, publicAdmission: false });
  assert.deepEqual(model.cases.map(({ boundary }) => boundary), REFERENCE_SERVICE_HARD_KILL_BOUNDARIES);
  const quarantined = new Set(['after-worker', 'after-validating-state']);
  const committed = new Set(['after-output-commit', 'after-result-commit']);
  for (const entry of model.cases) {
    assert.deepEqual(Object.keys(entry).sort(), ['automaticDaemonCleanup', 'boundary', 'destructiveCalls', 'expectedDisposition', 'expectedOutputBeforeRestart', 'representedResource']);
    assert.equal(entry.automaticDaemonCleanup, false);
    assert.equal(entry.destructiveCalls, 0);
    assert.equal(entry.representedResource, quarantined.has(entry.boundary));
    assert.equal(entry.expectedOutputBeforeRestart, committed.has(entry.boundary));
    assert.equal(entry.expectedDisposition, quarantined.has(entry.boundary)
      ? 'quarantined-nonterminal'
      : entry.boundary === 'after-result-commit' ? 'replayed-validated' : 'recovered-denied');
  }
  const source = snapshotSourceEvidence({ sourceFiles: model.sourceFiles, sourceRevision: model.sourceRevision });
  assert.equal(model.sourceSetSha256, source.sourceSetSha256);
  const comparison = await readCanonical(join(modelRoot, 'portable-source-model-comparison.json'));
  assert.equal(model.sourceRevision, comparison.sourceRevision);
  assert.equal(model.sourceSetSha256, comparison.sourceSetSha256);
});

test('documentation keeps Linux restart, hosted retention, runtime identity, and every acceptance criterion open', async () => {
  const [modelReadme, review, prd] = await Promise.all([
    readFile(join(modelRoot, 'README.md'), 'utf8'),
    readFile(join(root, 'docs/reviews/OGVCS-045-conformance-closure-boundary-review.md'), 'utf8'),
    readFile(join(root, 'prd/todo/OGVCS-045-untrusted-parser-sandbox-credential-broker.md'), 'utf8'),
  ]);
  assert.match(modelReadme, /not a new hosted run, live-Docker evidence/u);
  assert.match(modelReadme, /runtimeBinaryBinding: "unproven"/u);
  assert.match(modelReadme, /Uploading or retaining those new reports remains unexecuted pending/u);
  assert.match(review, /Restart execution is Linux-only/u);
  assert.match(review, /no\s+such run was dispatched or retained/u);
  assert.match(review, /OGVCS-045 stays Todo and AC-01 through AC-05 remain open/u);
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  for (let index = 1; index <= 5; index += 1) assert.match(prd, new RegExp(`OGVCS-045-AC-0${index}:`, 'u'));
  assert.match(prd, /The Linux-only restart-disposition test was\s+skipped/u);
});
