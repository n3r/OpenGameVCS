import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { buildLinuxConformanceReport } from '../core/untrusted-sandbox/js/src/internal/linux-conformance-report.mjs';
import { canonicalJson } from '../core/untrusted-sandbox/js/src/internal/reference-contract.mjs';

const root = new URL('../', import.meta.url);
const reportUrl = new URL('docs/evidence/OGVCS-045/linux-reference-conformance-2026-09-01.json', root);
const runUrl = new URL('docs/evidence/OGVCS-045/github-actions-run-33484044441.json', root);
const latestReportUrl = new URL('docs/evidence/OGVCS-045/linux-reference-conformance-2026-09-02-run-33636956770.json', root);
const latestRunUrl = new URL('docs/evidence/OGVCS-045/github-actions-run-33636956770.json', root);
const prdUrl = new URL('prd/todo/OGVCS-045-untrusted-parser-sandbox-credential-broker.md', root);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('retained Linux reference evidence is exact, closed, successful, and candid', async () => {
  const [reportBytes, run, prd] = await Promise.all([
    readFile(reportUrl),
    readFile(runUrl, 'utf8').then(JSON.parse),
    readFile(prdUrl, 'utf8'),
  ]);
  assert.equal(reportBytes.length, 3_620);
  assert.equal(sha256(reportBytes), '27ff15154b4a6cfadd6626fed323a359b9907b3dc2b3c3eb9ac43a3fbce0b0fb');
  const report = JSON.parse(reportBytes);
  const rebuilt = buildLinuxConformanceReport({
    cases: report.cases,
    failure: report.failure,
    outcome: report.outcome,
    runtimeDigest: report.runtimeDigest,
    seccompProfileSha256: report.seccompProfileSha256,
  });
  assert.equal(canonicalJson(report), canonicalJson(rebuilt));
  assert.equal(report.outcome, 'passed');
  assert.equal(report.failure, null);
  assert.equal(report.cases.length, 43);
  const resultCounts = Object.create(null);
  for (const entry of report.cases) resultCounts[entry.resultCode] = (resultCounts[entry.resultCode] ?? 0) + 1;
  assert.deepEqual({ ...resultCounts }, {
    VALIDATED: 33,
    SANDBOX_VALIDATION_FAILED: 5,
    SANDBOX_TIMEOUT: 2,
    SANDBOX_RESOURCE_LIMIT: 2,
    SANDBOX_OUTPUT_LIMIT: 1,
  });
  for (const command of ['network', 'credential', 'host', 'sibling', 'undeclared', 'traversal', 'device', 'namespace', 'clone-namespace', 'clone3-namespace']) {
    assert.equal(report.cases.some((entry) => entry.command === command && entry.resultCode === 'VALIDATED'), true, command);
  }
  for (const command of ['symlink', 'recursion', 'disk', 'bomb', 'crash']) {
    assert.equal(report.cases.some((entry) => entry.command === command && entry.resultCode === 'SANDBOX_VALIDATION_FAILED'), true, command);
  }
  assert.equal(run.sourceRevision, '8e863b503bf2c0ebc66d1f80cf7935e1575575d0');
  assert.equal(run.workflow.runId, 33484044441);
  assert.equal(run.jobs.length, 4);
  assert.equal(run.jobs.every(({ conclusion }) => conclusion === 'success'), true);
  assert.equal(run.artifact.retainedSha256, sha256(reportBytes));
  assert.equal(run.artifact.caseCount, report.cases.length);
  assert.equal(run.completionClaimed, false);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
});

test('retained restart-hardening run is exact, source-bound, and makes no settlement claim', async () => {
  const [reportBytes, run, prd] = await Promise.all([
    readFile(latestReportUrl),
    readFile(latestRunUrl, 'utf8').then(JSON.parse),
    readFile(prdUrl, 'utf8'),
  ]);
  assert.equal(reportBytes.length, 3_621);
  assert.equal(sha256(reportBytes), 'b3e292a64173ac76857c04545e3c41fb2a6b0a7c76e63b0271c380b050e7c472');
  const report = JSON.parse(reportBytes);
  assert.equal(canonicalJson(report), canonicalJson(buildLinuxConformanceReport({
    cases: report.cases,
    failure: report.failure,
    outcome: report.outcome,
    runtimeDigest: report.runtimeDigest,
    seccompProfileSha256: report.seccompProfileSha256,
  })));
  assert.equal(report.outcome, 'passed');
  assert.equal(report.failure, null);
  assert.equal(report.cases.length, 43);
  assert.equal(report.runtimeDigest, 'bf38726fc60cc07db34e002508747d90822390e6453d805eaa3f756902a6b2a7');
  assert.equal(report.seccompProfileSha256, 'd25dfdd48dbfccb7fcb30e1468f0f2adb4974d26e3bd205231abac0bd062f1f0');
  const resultCounts = Object.create(null);
  for (const entry of report.cases) resultCounts[entry.resultCode] = (resultCounts[entry.resultCode] ?? 0) + 1;
  assert.deepEqual({ ...resultCounts }, run.artifact.resultCounts);
  assert.equal(run.sourceRevision, '3563167763a54b97eb8166ded1db895aa3a5b7cd');
  assert.equal(run.workflow.runId, 33636956770);
  assert.equal(run.workflow.runAttempt, 1);
  assert.equal(run.workflow.event, 'workflow_dispatch');
  assert.equal(run.workflow.path, '.github/workflows/untrusted-sandbox.yml');
  assert.equal(run.jobs.length, 4);
  assert.equal(run.jobs.every(({ conclusion }) => conclusion === 'success'), true);
  assert.deepEqual(run.jobs.map(({ name }) => name), [
    'Linux reference isolation and hostile canaries',
    'Credential-free protocol (ubuntu-latest)',
    'Credential-free protocol (macos-latest)',
    'Credential-free protocol (windows-latest)',
  ]);
  assert.equal(run.artifact.id, 9849210156);
  assert.equal(run.artifact.archiveDigest, 'sha256:fe6b57254b697ce9cf73e8f7e898a598db0fa2040df75963443e315a7a9d03d5');
  assert.equal(run.artifact.retainedSha256, sha256(reportBytes));
  assert.equal(run.artifact.retainedBytes, reportBytes.length);
  assert.equal(run.artifact.caseCount, report.cases.length);
  assert.equal(run.completionClaimed, false);
  assert.deepEqual(run.claimBoundary, {
    privateCandidateOnly: true,
    automaticSettlement: false,
    publicConstructor: false,
    acceptanceCriterion: false,
    releaseEvidence: false,
  });
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
});
