import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { appendFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import * as productionBoundary from '../src/index.mjs';
import { referenceServiceTestHook } from '../src/internal/capability.mjs';
import {
  comparePortableConformanceReports,
  readGitSourceEvidence,
  runPrivatePortableConformance,
  snapshotSourceEvidence,
  sourceSetSha256,
} from '../src/internal/conformance-evidence.mjs';
import { dockerControlFactsForTesting } from '../src/internal/docker-reference.mjs';
import {
  buildLinuxConformanceReport,
  buildLinuxConformanceReportV2,
} from '../src/internal/linux-conformance-report.mjs';
import {
  runKillBoundaryCaseForTesting,
  runKillBoundarySelfKillCaseForTesting,
} from '../scripts/kill-boundary-conformance.mjs';
import {
  createReferenceServiceHardKillHookForTesting,
  referenceServiceHardKillBoundariesForTesting,
} from '../src/testing.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(import.meta.dirname, '../../../..');
const revision = '1'.repeat(40);
const sourceFiles = Object.freeze([Object.freeze({ bytes: 1, path: 'source/a.mjs', sha256: 'a'.repeat(64) })]);
const source = snapshotSourceEvidence({ sourceFiles, sourceRevision: revision });

const controls = Object.freeze({
  architecture: 'amd64',
  availableControllers: Object.freeze(['cpu', 'io', 'memory', 'pids']),
  cgroupNamespace: true,
  cgroupVersion: 2,
  operatingSystem: 'linux',
  rootless: false,
  runtimeBinaryBinding: 'unproven',
  runtimeCommit: 'v1.3.3-0-gd6d73eb8',
  runtimeName: 'runc',
  runtimePathKind: 'relative-name',
  runtimeVersion: '1.3.3',
  seccomp: true,
});

test('source evidence is exact, bounded, sorted, and domain-separated', () => {
  assert.equal(source.sourceRevision, revision);
  assert.equal(source.sourceSetSha256, sourceSetSha256(source.sourceFiles));
  assert.equal(Object.isFrozen(source), true);
  assert.throws(() => snapshotSourceEvidence({ sourceFiles: [...sourceFiles, sourceFiles[0]], sourceRevision: revision }), TypeError);
  assert.throws(() => snapshotSourceEvidence({ sourceFiles: [{ ...sourceFiles[0], rawPath: '/private' }], sourceRevision: revision }), TypeError);
  assert.throws(() => snapshotSourceEvidence({ sourceFiles: new Proxy([...sourceFiles], {}), sourceRevision: revision }), TypeError);
  const extended = [...sourceFiles];
  extended.extra = true;
  assert.throws(() => snapshotSourceEvidence({ sourceFiles: extended, sourceRevision: revision }), TypeError);
  assert.throws(() => snapshotSourceEvidence({ sourceFiles, sourceRevision: revision, extra: true }), TypeError);
});

test('private portable runner executes exactly importer and converter without credential or publication capability', async () => {
  const reports = [];
  for (const platform of ['windows', 'linux', 'macos']) {
    const report = await runPrivatePortableConformance({ platform, sourceFiles, sourceRevision: revision });
    assert.equal(report.outcome, 'passed');
    assert.equal(report.executionMode, 'source-only-private-model');
    assert.deepEqual(report.cases.map(({ toolClass }) => toolClass), ['importer', 'converter']);
    for (const entry of report.cases) {
      assert.equal(entry.resultCode, 'VALIDATED');
      assert.equal(entry.credentialCanaryAbsent, true);
      assert.equal(entry.publicationCapabilityPresent, false);
      assert.deepEqual(entry.requestKeys, ['arguments', 'environment', 'job', 'limits', 'stdin']);
    }
    assert.deepEqual(report.claimBoundary, { hostIsolation: false, productionBroker: false, publicAdmission: false, repositoryPublication: false });
    reports.push(report);
  }
  assert.deepEqual(comparePortableConformanceReports(reports).platforms, ['linux', 'macos', 'windows']);
  await assert.rejects(runPrivatePortableConformance({ platform: 'linux', sourceFiles, sourceRevision: revision, publish: () => {} }), TypeError);
});

test('portable comparison rejects identical forged, partial, and structurally hostile reports', async () => {
  const valid = await Promise.all(['linux', 'macos', 'windows'].map((platform) => runPrivatePortableConformance({ platform, sourceFiles, sourceRevision: revision })));
  const empty = valid.map((report) => ({ ...report, cases: [] }));
  assert.throws(() => comparePortableConformanceReports(empty), /report is invalid/u);
  assert.throws(() => comparePortableConformanceReports(valid.map((report) => ({ ...report, sourceSetSha256: 'f'.repeat(64) }))), /source binding differs/u);
  assert.throws(() => comparePortableConformanceReports(valid.map((report) => ({ ...report, claimBoundary: { ...report.claimBoundary, hostIsolation: true } }))), /report is invalid/u);
  assert.throws(() => comparePortableConformanceReports([valid[0], valid[0], valid[0]]), /reports differ/u);
  const extendedCases = [...valid[0].cases];
  extendedCases.extra = true;
  assert.throws(() => comparePortableConformanceReports([{ ...valid[0], cases: extendedCases }, valid[1], valid[2]]), /report is invalid/u);
  assert.throws(() => comparePortableConformanceReports(new Proxy(valid, {})), TypeError);
});

test('Linux report v2 binds closed controls and source inventory while v1 remains unchanged', () => {
  const legacy = buildLinuxConformanceReport({
    cases: [{ command: 'importer', elapsedMilliseconds: 1, resultCode: 'VALIDATED' }],
    failure: null,
    outcome: 'passed',
    runtimeDigest: 'b'.repeat(64),
    seccompProfileSha256: 'e'.repeat(64),
  });
  assert.equal(legacy.schemaVersion, 'ogvcs.untrusted-sandbox/linux-conformance-report/v1');
  assert.deepEqual(Object.keys(legacy).sort(), ['cases', 'failure', 'outcome', 'profile', 'runtimeDigest', 'schemaVersion', 'seccompProfileSha256'].sort());
  const report = buildLinuxConformanceReportV2({
    cases: legacy.cases,
    controls,
    failure: null,
    outcome: 'passed',
    runtimeDigest: legacy.runtimeDigest,
    seccompProfileSha256: legacy.seccompProfileSha256,
    sourceFiles,
    sourceRevision: revision,
  });
  assert.equal(report.schemaVersion, 'ogvcs.untrusted-sandbox/linux-conformance-report/v2');
  assert.equal(report.controls.runtimeBinaryBinding, 'unproven');
  assert.equal(report.sourceSetSha256, source.sourceSetSha256);
  for (const mutation of [
    { runtimeBinaryBinding: 'proven' },
    { runtimePathKind: '/usr/bin/runc' },
    { runtimeCommit: 'SECRET=/private/runc' },
    { availableControllers: ['cpu', 'memory'] },
  ]) assert.throws(() => buildLinuxConformanceReportV2({
    cases: legacy.cases,
    controls: { ...controls, ...mutation },
    failure: null,
    outcome: 'passed',
    runtimeDigest: legacy.runtimeDigest,
    seccompProfileSha256: legacy.seccompProfileSha256,
    sourceFiles,
    sourceRevision: revision,
  }), TypeError);
});

test('Docker facts retain only allowlisted controls and never claim daemon runtime binary identity', () => {
  const server = {
    Arch: 'amd64',
    Components: [{ Details: { GitCommit: 'v1.3.3-0-gd6d73eb8' }, Name: 'runc', Version: '1.3.3' }],
    Os: 'linux',
  };
  const details = {
    CgroupVersion: 2,
    OSType: 'linux',
    Runtimes: { runc: { path: 'runc', status: { hostile: '/private/daemon' } } },
    SecurityOptions: ['name=seccomp,profile=builtin', 'name=cgroupns'],
  };
  const facts = dockerControlFactsForTesting(server, details, 'cpu io memory pids');
  assert.deepEqual(facts, controls);
  assert.equal(JSON.stringify(facts).includes('/private'), false);
  assert.equal(facts.runtimeBinaryBinding, 'unproven');
  assert.equal(dockerControlFactsForTesting(server, details, 'cpu io memory pids future-secret'), null);
  assert.equal(dockerControlFactsForTesting(server, { ...details, Runtimes: { runc: { path: '../runc' } } }, 'cpu memory pids'), null);
  assert.equal(dockerControlFactsForTesting({ ...server, Components: [{ ...server.Components[0], Version: '/private/runc' }] }, details, 'cpu memory pids'), null);
  const absolute = dockerControlFactsForTesting(server, { ...details, Runtimes: { runc: { path: '/usr/bin/runc' } } }, 'cpu memory pids');
  assert.equal(absolute.runtimePathKind, 'absolute-path');
  assert.equal(absolute.runtimeBinaryBinding, 'unproven');
});

test('hard-kill boundaries are single-sourced, exact, one-shot, test-only, and typo-closed', () => {
  assert.deepEqual(referenceServiceHardKillBoundariesForTesting(), [
    'after-admission',
    'after-acquisition-state',
    'after-input-stage',
    'after-stage',
    'after-running-state',
    'after-worker',
    'after-validating-state',
    'after-output-collection',
    'after-validation',
    'after-committing-state',
    'before-output-commit',
    'after-output-commit',
    'after-result-commit',
  ]);
  assert.equal(Object.isFrozen(referenceServiceHardKillBoundariesForTesting()), true);
  assert.throws(() => createReferenceServiceHardKillHookForTesting('after-output-comit', () => {}), TypeError);
  let markers = 0;
  let kills = 0;
  const originalKill = process.kill;
  process.kill = (pid, signal) => {
    assert.equal(pid, process.pid);
    assert.equal(signal, 'SIGKILL');
    kills += 1;
    return true;
  };
  try {
    const capability = createReferenceServiceHardKillHookForTesting('after-admission', () => { markers += 1; });
    const hook = referenceServiceTestHook(capability);
    hook('after-stage');
    hook('after-admission');
    assert.throws(() => hook('after-admission'), /already fired/u);
  } finally { process.kill = originalKill; }
  assert.equal(markers, 1);
  assert.equal(kills, 1);
  assert.deepEqual(Object.keys(productionBoundary).sort(), ['CandidateCredentialBroker', 'CandidateSandboxSupervisor']);
});

test('all 13 child boundaries self-SIGKILL before the parent watchdog without unwinding', { skip: process.platform === 'win32' }, async () => {
  const cases = [];
  for (const boundary of referenceServiceHardKillBoundariesForTesting()) cases.push(await runKillBoundarySelfKillCaseForTesting(boundary));
  assert.equal(cases.length, 13);
  for (const entry of cases) {
    assert.equal(entry.childTermination, 'SIGKILL');
    assert.equal(entry.watchdogFired, false);
    assert.equal(entry.outputBeforeRestart, ['after-output-commit', 'after-result-commit'].includes(entry.boundary));
  }
});

test('test-only child hard-kill matrix preserves the closed restart dispositions', { skip: process.platform !== 'linux' }, async () => {
  const expectedDispositions = Object.freeze({
    'after-acquisition-state': 'recovered-denied',
    'after-admission': 'recovered-denied',
    'after-committing-state': 'recovered-denied',
    'after-input-stage': 'recovered-denied',
    'after-output-collection': 'recovered-denied',
    'after-output-commit': 'recovered-denied',
    'after-result-commit': 'replayed-validated',
    'after-running-state': 'recovered-denied',
    'after-stage': 'recovered-denied',
    'after-validating-state': 'quarantined-nonterminal',
    'after-validation': 'recovered-denied',
    'after-worker': 'quarantined-nonterminal',
    'before-output-commit': 'recovered-denied',
  });
  const cases = [];
  for (const boundary of referenceServiceHardKillBoundariesForTesting()) cases.push(await runKillBoundaryCaseForTesting(boundary));
  assert.equal(cases.length, 13);
  for (const entry of cases) {
    assert.equal(entry.disposition, expectedDispositions[entry.boundary]);
    assert.equal(entry.childTermination, 'SIGKILL');
    assert.equal(entry.watchdogFired, false);
    assert.equal(entry.automaticDaemonCleanup, false);
    assert.equal(entry.destructiveCalls, 0);
    assert.equal(entry.representedResource, ['after-worker', 'after-validating-state'].includes(entry.boundary));
    assert.equal(entry.resultCode, entry.boundary === 'after-result-commit' ? 'VALIDATED' : entry.representedResource ? null : 'SANDBOX_UNAVAILABLE');
    assert.equal(entry.outputAvailable, entry.boundary === 'after-result-commit');
    assert.equal(entry.outputBeforeRestart, ['after-output-commit', 'after-result-commit'].includes(entry.boundary));
  }
});

test('git source evidence requires exact checked-out HEAD and exact executing bytes', async (context) => {
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-sandbox-source-binding-'));
  context.after(() => rm(scratch, { recursive: true, force: true }));
  const clone = join(scratch, 'repo');
  await execFileAsync('git', ['clone', '--quiet', '--no-hardlinks', repositoryRoot, clone], { maxBuffer: 1024 * 1024, windowsHide: true });
  const { stdout: headOutput } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: clone, encoding: 'utf8', windowsHide: true });
  const head = headOutput.trim();
  const evidence = await readGitSourceEvidence({ repositoryRoot: clone, sourceRevision: head });
  assert.equal(evidence.sourceRevision, head);
  await assert.rejects(readGitSourceEvidence({ repositoryRoot: clone, sourceRevision: 'HEAD' }), TypeError);
  await assert.rejects(readGitSourceEvidence({ repositoryRoot: clone, sourceRevision: 'refs/heads/ogvcs-source-binding' }), TypeError);
  const { stdout: parentOutput } = await execFileAsync('git', ['rev-parse', 'HEAD^'], { cwd: clone, encoding: 'utf8', windowsHide: true });
  await assert.rejects(readGitSourceEvidence({ repositoryRoot: clone, sourceRevision: parentOutput.trim() }), /not the checked-out HEAD/u);
  await appendFile(join(clone, 'core/untrusted-sandbox/js/src/internal/capability.mjs'), '\n');
  await assert.rejects(readGitSourceEvidence({ repositoryRoot: clone, sourceRevision: head }), /executing source differs/u);
});
