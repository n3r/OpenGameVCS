#!/usr/bin/env node

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  readGitSourceEvidence,
} from '../src/internal/conformance-evidence.mjs';
import { canonicalJson, sha256 } from '../src/internal/reference-contract.mjs';
import {
  REFERENCE_SERVICE_HARD_KILL_BOUNDARIES,
  ReferenceSandboxService,
} from '../src/internal/reference-service.mjs';
import {
  KillBoundaryFixtureAdapter,
  killBoundaryMarkerPath,
  killBoundaryServiceConfiguration,
  outputBundleExists,
  readKillBoundaryFixture,
} from '../test/fixtures/kill-boundary-child.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const childPath = resolve(dirname(fileURLToPath(import.meta.url)), '../test/fixtures/kill-boundary-child.mjs');
const quarantineBoundaries = new Set(['after-worker', 'after-validating-state']);
const replayBoundary = 'after-result-commit';
const preRestartStates = Object.freeze({
  'after-admission': 'queued',
  'after-acquisition-state': 'acquiring',
  'after-input-stage': 'acquiring',
  'after-stage': 'staged',
  'after-running-state': 'running',
  'after-worker': 'running',
  'after-validating-state': 'validating',
  'after-output-collection': 'validating',
  'after-validation': 'validating',
  'after-committing-state': 'committing',
  'before-output-commit': 'committing',
  'after-output-commit': 'committing',
  'after-result-commit': 'validated',
});

const runChild = (root, boundary) => new Promise((resolveChild, reject) => {
  const child = spawn(process.execPath, [childPath, '--root', root, '--boundary', boundary], {
    cwd: repositoryRoot,
    env: Object.freeze({ LANG: 'C', LC_ALL: 'C', PATH: process.env.PATH ?? '' }),
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
  const errors = [];
  let errorBytes = 0;
  let watchdogFired = false;
  const timer = setTimeout(() => { watchdogFired = true; child.kill('SIGKILL'); }, 15_000);
  child.stderr.on('data', (chunk) => {
    errorBytes += chunk.length;
    if (errorBytes <= 64 * 1024) errors.push(Buffer.from(chunk));
  });
  child.once('error', (error) => { clearTimeout(timer); reject(error); });
  child.once('close', (code, signal) => {
    clearTimeout(timer);
    resolveChild(Object.freeze({ code, signal, stderr: Buffer.concat(errors).toString('utf8'), watchdogFired }));
  });
});

const jobRecord = async (root) => JSON.parse(await readFile(join(root, 'state', 'jobs', 'kill.boundary.1.json'), 'utf8'));

const withHardKilledBoundary = async (boundary, operation) => {
  if (!REFERENCE_SERVICE_HARD_KILL_BOUNDARIES.includes(boundary)) throw new TypeError('hard-kill boundary is invalid');
  const root = await mkdtemp(join(tmpdir(), `ogvcs-kill-${boundary}-`));
  try {
    const termination = await runChild(root, boundary);
    assert.deepEqual({ code: termination.code, signal: termination.signal }, { code: null, signal: 'SIGKILL' }, termination.stderr);
    assert.equal(termination.watchdogFired, false, 'hard-kill child reached the parent watchdog');
    assert.equal((await readFile(killBoundaryMarkerPath(root), 'utf8')).trim(), boundary);
    const fixture = await readKillBoundaryFixture(root);
    const before = await jobRecord(root);
    assert.equal(before.state, preRestartStates[boundary]);
    const outputBeforeRestart = await outputBundleExists(root);
    return await operation(Object.freeze({ before, fixture, outputBeforeRestart, root, termination }));
  } finally { await rm(root, { recursive: true, force: true }); }
};

export const runKillBoundarySelfKillCaseForTesting = async (boundary) => withHardKilledBoundary(boundary, async ({ before, outputBeforeRestart, termination }) => Object.freeze({
  boundary,
  childTermination: termination.signal,
  outputBeforeRestart,
  preRestartState: before.state,
  watchdogFired: termination.watchdogFired,
}));

export const runKillBoundaryCaseForTesting = async (boundary) => {
  if (process.platform !== 'linux') throw new Error('hard-kill restart conformance requires Linux lease recovery');
  return withHardKilledBoundary(boundary, async ({ before, fixture, outputBeforeRestart, root, termination }) => {
    const representedResource = quarantineBoundaries.has(boundary);
    const reconciliationReport = representedResource
      ? Object.freeze({
        diagnosticCodes: Object.freeze(['AUTHENTICATED_ORPHANS_REQUIRE_SETTLEMENT']),
        resourceFingerprints: Object.freeze([sha256(Buffer.from(`kill-boundary-resource\0${boundary}`, 'utf8'))]),
        schemaVersion: 'ogvcs.untrusted-sandbox/daemon-reconciliation/v1',
        status: 'quarantined',
      })
      : null;
    const adapter = new KillBoundaryFixtureAdapter({ reconciliationReport });
    let disposition;
    let outputAvailable;
    let resultCode = null;
    if (representedResource) {
      await assert.rejects(ReferenceSandboxService.open(killBoundaryServiceConfiguration({ adapter, fixture, root })), /daemon orphan reconciliation failed/u);
      const after = await jobRecord(root);
      assert.equal(after.state, before.state);
      assert.deepEqual(after.result ?? null, before.result ?? null);
      const quarantine = (await readdir(join(root, 'state', 'quarantine'))).filter((name) => name.startsWith('daemon.'));
      assert.equal(quarantine.length, 1);
      disposition = 'quarantined-nonterminal';
      outputAvailable = await outputBundleExists(root);
    } else {
      const service = await ReferenceSandboxService.open(killBoundaryServiceConfiguration({ adapter, fixture, root }));
      try {
        const result = await service.run(fixture.job, fixture.acquisition);
        resultCode = result.code;
        outputAvailable = await outputBundleExists(root);
        if (boundary === replayBoundary) {
          assert.deepEqual(result, before.result);
          assert.equal(result.code, 'VALIDATED');
          assert.equal(outputAvailable, true);
          disposition = 'replayed-validated';
        } else {
          assert.equal(result.code, 'SANDBOX_UNAVAILABLE');
          assert.equal(outputAvailable, false);
          const after = await jobRecord(root);
          assert.equal(after.state, 'denied');
          disposition = 'recovered-denied';
        }
      } finally { await service.close(); }
    }
    assert.deepEqual(adapter.destructiveCalls, []);
    assert.equal(adapter.discardCalls, 0);
    return Object.freeze({
      automaticDaemonCleanup: false,
      boundary,
      childTermination: 'SIGKILL',
      destructiveCalls: 0,
      disposition,
      outputAvailable,
      outputBeforeRestart,
      preRestartState: before.state,
      representedResource,
      resultCode,
      watchdogFired: termination.watchdogFired,
    });
  });
};

const main = async () => {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== '--output' || args[2] !== '--source-revision') {
    throw new Error('usage: node scripts/kill-boundary-conformance.mjs --output <report.json> --source-revision <40-hex>');
  }
  if (process.platform !== 'linux') throw new Error('hard-kill conformance requires Linux lease-recovery and SIGKILL semantics');
  if (Number.parseInt(process.versions.node.split('.')[0], 10) !== 24) throw new Error('hard-kill conformance requires Node 24');
  const output = resolve(args[1]);
  const sourceRevision = args[3];
  const source = await readGitSourceEvidence({ repositoryRoot, sourceRevision });
  const cases = [];
  for (const boundary of REFERENCE_SERVICE_HARD_KILL_BOUNDARIES) cases.push(await runKillBoundaryCaseForTesting(boundary));
  const report = Object.freeze({
    cases: Object.freeze(cases),
    claimBoundary: Object.freeze({
      automaticDaemonCleanup: false,
      dockerExecution: false,
      publicAdmission: false,
      testOnly: true,
    }),
    evidenceKind: 'test-only-child-execution',
    executionMode: 'local-test-child-model',
    nodeMajor: 24,
    outcome: cases.length === 13 && cases.every((entry) => entry.childTermination === 'SIGKILL' && entry.destructiveCalls === 0 && entry.watchdogFired === false) ? 'passed' : 'failed',
    platform: 'linux',
    retentionStatus: 'not-hosted',
    schemaVersion: 'ogvcs.untrusted-sandbox/kill-boundary-conformance-report/v1',
    ...source,
  });
  await writeFile(output, Buffer.from(`${canonicalJson(report)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
  process.stdout.write(`${canonicalJson({ cases: report.cases.length, outcome: report.outcome, output, sourceRevision })}\n`);
  if (report.outcome !== 'passed') process.exitCode = 1;
};

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
