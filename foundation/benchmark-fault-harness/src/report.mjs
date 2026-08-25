import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canonicalDigest, canonicalJson, canonicalSequenceDigest, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { loadBenchmarkContract } from './contract.mjs';
import { runReferenceHarness } from './harness.mjs';
import { snapshotOptions } from './input.mjs';

const REPORT_PROFILES = new Set(['local-smoke', 'presubmit', 'nightly']);

function fixedMeasurement() {
  let wall = 0n; let user = 0;
  return { clock: () => { wall += 1_000_000n; return wall; }, cpu: () => { user += 500; return { user, system: 0 }; }, memory: () => 1_048_576, sampleIntervalMs: 1_000 };
}

function sampleSemantics(sample) {
  return { id: sample.id, taskId: sample.taskId, corpusId: sample.corpusId, repetition: sample.repetition, cacheState: sample.cacheState, networkProfile: sample.networkProfile, status: sample.status, failureCode: sample.failureCode, diskReadBytes: sample.diskReadBytes, diskWriteBytes: sample.diskWriteBytes, networkReadBytes: sample.networkReadBytes, networkWriteBytes: sample.networkWriteBytes, logicalBytes: sample.logicalBytes, uniqueBytes: sample.uniqueBytes, retries: sample.retries, assertions: sample.assertions, faultScheduleDigest: sample.faultScheduleDigest };
}

function summarySemantics(summary) {
  const { durationMicroseconds: _duration, ...semantic } = summary;
  return semantic;
}

export async function runBenchmarkReport(options = {}) {
  options = snapshotOptions(options, 'benchmark report options');
  if (typeof options.output !== 'string' || options.output.length < 1 || options.output.includes('\0')) harnessFail('HARNESS_INPUT_INVALID', 'benchmark report output directory is required');
  const profile = options.harnessProfile ?? 'presubmit';
  if (!REPORT_PROFILES.has(profile)) harnessFail('HARNESS_PRIVILEGE_REQUIRED', 'retained reports permit only unprivileged bounded profiles');
  const contract = options.contract ?? await loadBenchmarkContract({ ...(options.contractRoot ? { root: options.contractRoot } : {}), cache: false });
  await mkdir(options.output, { recursive: true });
  const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-report-'));
  try {
    const run = await runReferenceHarness({
      contract, workspace: join(scratch, 'workspace'), output: join(options.output, 'bundle'), harnessProfile: profile,
      seed: options.seed ?? 'ogvcs-benchmark-retained-report-v1', operator: options.operator ?? 'retained-report-operator',
      classification: 'synthetic', clock: () => new Date('2026-08-21T00:00:00.000Z'), filesystem: options.filesystem ?? 'ci-controlled',
      implementationCommit: options.implementationCommit ?? 'retained-report-candidate', iterations: options.iterations, concurrency: options.concurrency ?? 4,
      measurementFactory: () => fixedMeasurement(), overhead: { measuredBasisPoints: 0, correctionApplied: false, correctionMicroseconds: 0, method: 'measured-below-threshold' },
      simulateNetworkDelay: false, command: `ogvcs-benchmark retained-report --profile ${profile}`,
      publicMetadata: { reportKind: 'bounded-retained-conformance', exactScale: false },
    });
    const sampleSemanticsDigest = canonicalSequenceDigest(run.matrix.samples.map(sampleSemantics), 'ogvcs.benchmark/report-sample-semantics/v1');
    const summarySemanticsDigest = canonicalSequenceDigest(run.matrix.summaries.map(summarySemantics), 'ogvcs.benchmark/report-summary-semantics/v1');
    const semanticBasis = {
      contractManifestSha256: contract.manifestSha256, profile, sampleSemanticsDigest, summarySemanticsDigest,
      conformanceResultsDigest: run.conformance.resultsDigest,
      evidenceReportDigest: run.publication.result.evidenceReportDigest,
      thresholdFileDigest: run.publication.result.thresholdFileDigest,
      overallStatus: run.publication.result.overallStatus,
    };
    const body = {
      schemaVersion: 'ogvcs.benchmark/retained-report/v1',
      ...semanticBasis,
      semanticResultsSha256: canonicalDigest(semanticBasis, 'ogvcs.benchmark/retained-report-semantics/v1'),
      bundleDigest: run.written.manifest.bundleDigest,
      runId: run.publication.result.runId,
      counts: { corpora: run.corpora.length, samples: run.matrix.samples.length, summaries: run.matrix.summaries.length, environments: run.matrix.environmentRecords.length, conformance: run.conformance.cases, faultRows: run.faultMatrix.rows.length, brokenCases: run.brokenServices.cases.length },
      results: { conformancePassed: run.conformance.passed, conformanceFailed: run.conformance.failed, faultFailures: run.faultMatrix.failed, brokenMisses: run.brokenServices.missed, securityMisses: run.security.misses },
      host: { os: process.platform, architecture: process.arch, node: process.versions.node },
      exactScaleExecuted: false,
    };
    const report = deepFreeze({ ...body, reportSha256: canonicalDigest(body, 'ogvcs.benchmark/retained-report/v1') });
    await writeFile(join(options.output, 'report.json'), `${canonicalJson(report)}\n`, { encoding: 'utf8', flag: 'wx' });
    return report;
  } finally { await rm(scratch, { recursive: true, force: true }); }
}
