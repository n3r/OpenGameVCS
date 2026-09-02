import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const reportUrl = new URL('docs/evidence/OGVCS-010/atomic-submit-hard-restart-report-2026-09-02.jsonl', root);
const runUrl = new URL('docs/evidence/OGVCS-010/github-actions-run-33579298064.json', root);
const readmeUrl = new URL('docs/evidence/OGVCS-010/README.md', root);
const prdUrl = new URL('prd/todo/OGVCS-010-atomic-submit-transaction.md', root);
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const isDigest = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
const exactKeys = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());

const boundaries = Object.freeze([
  'before-bridge',
  'after-bridge',
  'after-file-id-consumption',
  'after-snapshot-marker',
  'after-branch-cas',
  'after-audit',
  'after-outbox-event',
  'after-consistency-token',
  'after-final-outcome',
  'after-reconciliation',
  'before-commit',
  'commit-io',
  'after-commit-before-response',
]);

test('retained atomic-submit restart evidence is exact, complete, and closed', async () => {
  const bytes = await readFile(reportUrl);
  assert.equal(bytes.length, 10_094);
  assert.equal(digest(bytes), 'ac29199527a8c0d2c44f03b8d57e0a6cc400f652dd0dbfea8421cc0d1e8a74e1');
  assert.equal(bytes.at(-1), 0x0a);
  const records = bytes.toString('utf8').trimEnd().split('\n').map(JSON.parse);
  assert.equal(records.length, boundaries.length + 1);
  const cases = records.slice(0, -1);
  const summary = records.at(-1);
  assert.deepEqual(cases.map(({ boundary }) => boundary), boundaries);
  assert.equal(new Set(cases.map(({ boundary }) => boundary)).size, boundaries.length);
  assert.equal(new Set(cases.map(({ recovery }) => recovery.resultDigest)).size, boundaries.length);

  for (const record of cases) {
    exactKeys(record, [
      'backendPidObserved', 'boundary', 'dockerPidChanged', 'exit137Observed',
      'pgSleepObserved', 'postmasterStartChanged', 'postgresImage',
      'postgresVersion', 'queryClass', 'recovery', 'schemaVersion', 'signal',
      'status',
    ]);
    assert.equal(record.schemaVersion, 'ogvcs.repository-metadata/restart-case-evidence/v1');
    assert.equal(record.status, 'passed');
    assert.equal(record.postgresImage, 'postgres@sha256:5d1d70e254e3c5d7d76847a9deebb18478cd518df37abf6b278d4bdb1fe5d96c');
    assert.equal(record.postgresVersion, '150019');
    assert.equal(record.signal, 'SIGKILL');
    assert.equal(record.exit137Observed, true);
    assert.equal(record.backendPidObserved, true);
    assert.equal(record.pgSleepObserved, true);
    assert.equal(record.dockerPidChanged, true);
    assert.equal(record.postmasterStartChanged, true);
    assert.equal(record.queryClass, record.boundary === 'commit-io' ? 'commit' : 'rendezvous-select');
    exactKeys(record.recovery, [
      'boundary', 'fileIdConsumptions', 'finalOutcomes', 'identityConsumptions',
      'initialState', 'lifecycleApplications', 'resultDigest', 'schemaVersion',
    ]);
    assert.equal(record.recovery.schemaVersion, 'ogvcs.repository-metadata/restart-case-result/v1');
    assert.equal(record.recovery.boundary, record.boundary);
    assert.equal(record.recovery.fileIdConsumptions, 1);
    assert.equal(record.recovery.finalOutcomes, 1);
    assert.equal(record.recovery.identityConsumptions, 1);
    assert.equal(record.recovery.lifecycleApplications, 1);
    assert.equal(isDigest(record.recovery.resultDigest), true);
    assert.equal(['old', 'new'].includes(record.recovery.initialState), true);
  }
  assert.equal(cases.at(-1).recovery.initialState, 'new');
  assert.equal(cases.slice(0, -1).every(({ recovery }) => recovery.initialState === 'old'), true);

  exactKeys(summary, [
    'allDockerPidsChanged', 'allObservedExit137', 'allPostmasterStartsChanged',
    'boundaries', 'caseCount', 'postgresImage', 'postgresVersion',
    'schemaVersion', 'status',
  ]);
  assert.equal(summary.schemaVersion, 'ogvcs.repository-metadata/restart-matrix-summary/v1');
  assert.equal(summary.status, 'passed');
  assert.equal(summary.caseCount, boundaries.length);
  assert.deepEqual(summary.boundaries, boundaries);
  assert.equal(summary.allObservedExit137, true);
  assert.equal(summary.allDockerPidsChanged, true);
  assert.equal(summary.allPostmasterStartsChanged, true);
  assert.equal(summary.postgresImage, cases[0].postgresImage);
  assert.equal(summary.postgresVersion, cases[0].postgresVersion);
});

test('hosted run and PRD bind the retained subset without a completion claim', async () => {
  const [run, readme, prd] = await Promise.all([
    readFile(runUrl, 'utf8').then(JSON.parse),
    readFile(readmeUrl, 'utf8'),
    readFile(prdUrl, 'utf8'),
  ]);
  assert.equal(run.schemaVersion, 'ogvcs.atomic-submit/hosted-evidence/v1');
  assert.equal(run.status, 'bounded-exact-plan-binding-passed');
  assert.equal(run.sourceRevision, '3d793383c0289ddf0b3acc5887a79bc006b93e55');
  assert.equal(run.workflow.runId, 33579298064);
  assert.equal(run.workflow.headBranch, 'r1-foundation-integration');
  assert.equal(run.exactScaleExecuted, false);
  assert.equal(run.jobs.length, 4);
  assert.equal(run.jobs.every(({ conclusion }) => conclusion === 'success'), true);
  assert.equal(new Set(run.jobs.map(({ id }) => id)).size, 4);
  const artifact = run.artifacts.find(({ retainedReport }) => retainedReport === 'atomic-submit-hard-restart-report-2026-09-02.jsonl');
  assert.ok(artifact);
  assert.equal(artifact.reportBytes, 10_094);
  assert.equal(artifact.reportSha256, 'ac29199527a8c0d2c44f03b8d57e0a6cc400f652dd0dbfea8421cc0d1e8a74e1');
  assert.equal(artifact.caseCount, boundaries.length);
  assert.equal(run.result.hardRestartCaseCount, boundaries.length);
  assert.equal(run.supersededFailedAttempt.countedAsSuccessEvidence, false);
  assert.equal(run.nonClaims.includes('no public atomic-submit contract or route'), true);
  assert.equal(run.nonClaims.includes('no request-root issuance, expansion, or ratification'), true);
  assert.equal(run.nonClaims.includes('no 100-finalizer concurrency campaign'), true);
  assert.equal(run.nonClaims.includes('no exact-scale execution'), true);

  assert.match(readme, /not completion evidence/iu);
  assert.match(readme, /OGVCS-010 remains \*\*Todo\*\*/u);
  assert.match(prd, /^\*\*Status:\*\* Todo\s*$/mu);
  assert.match(prd, /33579298064/u);
  assert.match(prd, /ac29199527a8c0d2c44f03b8d57e0a6cc400f652dd0dbfea8421cc0d1e8a74e1/u);
  assert.match(prd, /not the complete OGVCS-005 fault matrix/iu);
  assert.match(prd, /not the complete OGVCS-005 fault matrix,[\s\S]*?100-finalizer race/iu);
  assert.match(prd, /not the complete OGVCS-005 fault matrix,[\s\S]*?exact-scale result/iu);
  assert.match(prd, /no acceptance criterion is\s+closed/iu);
});
