import assert from 'node:assert/strict';
import { access, cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildResultBundle, canonicalDigest, compareResultBundles, runReferenceHarness, verifyResultBundle, writeResultBundle } from '../src/index.mjs';
import { canonicalSequenceDigest } from '../src/canonical.mjs';
import { contract, fixedMeasurement, FIXED_OVERHEAD } from './helpers.mjs';

test('pre-cancelled reference harness rejects before creating its workspace', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-cancelled-')); t.after(() => rm(root, { recursive: true, force: true }));
  const workspace = join(root, 'workspace');
  const controller = new AbortController(); controller.abort();
  await assert.rejects(runReferenceHarness({ contract: await contract(), workspace, signal: controller.signal }), (error) => error.code === 'HARNESS_CANCELLED');
  await assert.rejects(access(workspace));
});

test('five-corpus reference smoke publishes raw authenticated reproducible evidence', { timeout: 60_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-reference-')); t.after(() => rm(root, { recursive: true, force: true }));
  const authority = await contract(); const output = join(root, 'result');
  const run = await runReferenceHarness({
    contract: authority, workspace: join(root, 'workspace'), output, seed: 'reference-test-v1', operator: 'test-operator',
    clock: () => new Date('2026-08-21T00:00:00.000Z'), measurementFactory: () => fixedMeasurement(), overhead: FIXED_OVERHEAD,
    simulateNetworkDelay: false, command: 'ogvcs-benchmark --access-token command-credential-canary', publicMetadata: { partnerId: 'partner-canary', accessToken: 'credential-canary', safe: 'retained' },
  });
  assert.deepEqual({ corpora: run.corpora.length, samples: run.matrix.samples.length, conformance: run.conformance.passed, conformanceFailed: run.conformance.failed, faults: run.faultMatrix.rows.length, faultFailed: run.faultMatrix.failed, status: run.publication.result.overallStatus }, { corpora: 5, samples: 110, conformance: 35, conformanceFailed: 0, faults: 36, faultFailed: 0, status: 'passed' });
  const verified = await verifyResultBundle(output, authority);
  assert.equal(verified.verified, true); assert.equal(verified.manifest.artifacts.length, 6); assert.equal(verified.evidenceReport.brokenServices.cases.length, 7); assert.equal(verified.evidenceReport.security.misses, 0);
  const alternateIdentity = buildResultBundle(authority, run.matrix, { evidenceReport: run.publication.evidenceReport, faultSchedules: run.publication.result.faultSchedules, conformanceReport: run.publication.conformanceReport, seed: 'reference-test-v1', operator: 'test-operator', classification: 'synthetic', publicMetadata: { variant: 'alternate-run-identity' }, clock: () => new Date('2026-08-21T00:00:00.000Z') });
  assert.notEqual(alternateIdentity.result.runId, verified.result.runId);
  const comparison = compareResultBundles(authority, verified, verified, { tolerancePartsPerMillion: 0 });
  assert.equal(comparison.reproduced, true); assert.equal(comparison.rows.length, 110);
  const callerMatrix = structuredClone(run.matrix);
  const callerSample = callerMatrix.samples[0];
  const snapshotted = buildResultBundle(authority, callerMatrix, { evidenceReport: run.publication.evidenceReport, faultSchedules: run.publication.result.faultSchedules, conformanceReport: run.publication.conformanceReport, seed: 'reference-test-v1', operator: 'test-operator', classification: 'synthetic', clock: () => new Date('2026-08-21T00:00:00.000Z') });
  assert.equal(Object.isFrozen(callerMatrix), false); assert.equal(Object.isFrozen(callerSample), false);
  assert.notEqual(snapshotted.samples, callerMatrix.samples); assert.notEqual(snapshotted.samples[0], callerSample);
  callerSample.wallMicroseconds += 1;
  assert.notEqual(snapshotted.samples[0].wallMicroseconds, callerSample.wallMicroseconds);
  let comparisonTrapCalls = 0;
  const comparisonProxy = new Proxy({}, { get() { comparisonTrapCalls += 1; throw new Error('comparison input trap must not run'); } });
  assert.throws(() => compareResultBundles(authority, comparisonProxy, verified), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(comparisonTrapCalls, 0);
  let scheduleTrapCalls = 0;
  const scheduleProxy = new Proxy([], { get() { scheduleTrapCalls += 1; throw new Error('fault schedule trap must not run'); } });
  assert.throws(() => buildResultBundle(authority, run.matrix, { evidenceReport: run.publication.evidenceReport, faultSchedules: scheduleProxy }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(scheduleTrapCalls, 0);
  const evidenceMismatch = compareResultBundles(authority, verified, { ...verified, result: { ...verified.result, evidenceReportDigest: '0'.repeat(64) } }, { tolerancePartsPerMillion: 0 });
  assert.equal(evidenceMismatch.reproduced, false); assert.ok(evidenceMismatch.reasons.includes('evidence-authority-differs'));
  const changedSummaries = verified.summaries.map((row, index) => index === 0 ? { ...row, durationMicroseconds: { ...row.durationMicroseconds, medianAbsoluteDeviation: row.durationMicroseconds.medianAbsoluteDeviation + 1 } } : row);
  const dispersionMismatch = compareResultBundles(authority, verified, { ...verified, result: { ...verified.result, summarySetDigest: canonicalSequenceDigest(changedSummaries, 'ogvcs.benchmark/summary-set/v1') }, summaries: changedSummaries }, { tolerancePartsPerMillion: 0 });
  const changedKey = `${changedSummaries[0].taskId}/${changedSummaries[0].corpusId}/${changedSummaries[0].cacheState}/${changedSummaries[0].networkProfile}`;
  assert.equal(dispersionMismatch.reproduced, false); assert.equal(dispersionMismatch.rows.find(({ key }) => key === changedKey).withinTolerance, false);
  assert.throws(() => compareResultBundles(authority, verified, verified, { tolerancePartsPerMillion: authority.thresholds['default-v1'].comparisonTolerancePartsPerMillion + 1 }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedTolerance = { ...verified, result: { ...verified.result, reproduction: { ...verified.result.reproduction, tolerancePartsPerMillion: 1_000_000 } } };
  assert.throws(() => compareResultBundles(authority, forgedTolerance, verified), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  assert.throws(() => buildResultBundle(authority, run.matrix, { evidenceReport: run.publication.evidenceReport, tolerancePartsPerMillion: 1_000_000 }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedMatrix = { ...run.matrix, thresholdEvaluations: run.matrix.thresholdEvaluations.map((row, index) => index === 0 ? { ...row, actual: row.actual + 1 } : row) };
  assert.throws(() => buildResultBundle(authority, forgedMatrix, { evidenceReport: run.publication.evidenceReport }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedFaultRows = run.publication.evidenceReport.faultMatrix.rows.slice(1);
  const forgedEvidence = { ...run.publication.evidenceReport, faultMatrix: { ...run.publication.evidenceReport.faultMatrix, rows: forgedFaultRows } };
  assert.throws(() => buildResultBundle(authority, run.matrix, { evidenceReport: forgedEvidence, faultSchedules: run.publication.result.faultSchedules }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedBroken = { ...run.publication.evidenceReport, brokenServices: { ...run.publication.evidenceReport.brokenServices, cases: run.publication.evidenceReport.brokenServices.cases.slice(1) } };
  assert.throws(() => buildResultBundle(authority, run.matrix, { evidenceReport: forgedBroken, faultSchedules: run.publication.result.faultSchedules }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedSecurity = { ...run.publication.evidenceReport, security: { ...run.publication.evidenceReport.security, pathCases: run.publication.evidenceReport.security.pathCases.slice(1) } };
  assert.throws(() => buildResultBundle(authority, run.matrix, { evidenceReport: forgedSecurity, faultSchedules: run.publication.result.faultSchedules }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  const forgedAuthority = { ...run.publication, result: { ...run.publication.result, contractManifestSha256: '0'.repeat(64) } };
  const rejectedOutput = join(root, 'rejected-authority');
  await assert.rejects(writeResultBundle(rejectedOutput, authority, forgedAuthority), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  await assert.rejects(access(rejectedOutput));
  const forgedRunIdentity = { ...run.publication, result: { ...run.publication.result, runId: `run/${'0'.repeat(64)}` } };
  await assert.rejects(writeResultBundle(join(root, 'rejected-run-identity'), authority, forgedRunIdentity), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  const forgedConformanceRows = run.publication.conformanceReport.rows.map((row, index) => index === 0 ? { ...row, id: `forged-${row.id}` } : row);
  const forgedConformance = { ...run.publication.conformanceReport, rows: forgedConformanceRows, resultsDigest: canonicalDigest(forgedConformanceRows, 'ogvcs.benchmark/conformance-results/v1') };
  const forgedConformancePublication = { ...run.publication, result: { ...run.publication.result, conformanceReportDigest: canonicalDigest(forgedConformance, 'ogvcs.benchmark/conformance-report/v1') }, conformanceReport: forgedConformance };
  await assert.rejects(writeResultBundle(join(root, 'rejected-conformance'), authority, forgedConformancePublication), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  const forgedCommand = { ...run.publication, result: { ...run.publication.result, reproduction: { ...run.publication.result.reproduction, command: 'caller-owned --access-token credential-canary' } } };
  await assert.rejects(writeResultBundle(join(root, 'rejected-command'), authority, forgedCommand), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  const forgedPublicMetadata = { ...run.publication, result: { ...run.publication.result, publicMetadata: { accessToken: 'credential-canary' } } };
  await assert.rejects(writeResultBundle(join(root, 'rejected-public-metadata'), authority, forgedPublicMetadata), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  const mutablePublication = structuredClone(run.publication); const unstableOutput = join(root, 'rejected-unstable-input');
  const unstableWrite = writeResultBundle(unstableOutput, authority, mutablePublication); mutablePublication.samples[0].wallMicroseconds += 1;
  await assert.rejects(unstableWrite, (error) => error.code === 'HARNESS_BUNDLE_INVALID');
  await assert.rejects(access(unstableOutput));
  let sampleInventoryTrapCalls = 0;
  const sampleInventoryProxy = new Proxy([], { get() { sampleInventoryTrapCalls += 1; throw new Error('sample inventory trap must not run'); } });
  await assert.rejects(writeResultBundle(join(root, 'rejected-hostile-inventory'), authority, { ...run.publication, samples: sampleInventoryProxy }), (error) => error.code === 'HARNESS_INPUT_INVALID');
  assert.equal(sampleInventoryTrapCalls, 0);
  const published = Buffer.concat(await Promise.all(['result.json', 'evidence.json', 'environments.jsonl', 'samples.jsonl', 'summaries.jsonl'].map((name) => readFile(join(output, name))))).toString('utf8');
  assert.doesNotMatch(published, /partner-canary|credential-canary|command-credential-canary/u); assert.match(published, /retained/u);

  const tampered = join(root, 'tampered'); await cp(output, tampered, { recursive: true });
  const target = join(tampered, 'samples.jsonl'); const bytes = await readFile(target); bytes[0] ^= 1; await writeFile(target, bytes);
  await assert.rejects(verifyResultBundle(tampered, authority), (error) => error.code === 'HARNESS_BUNDLE_INVALID');
});
