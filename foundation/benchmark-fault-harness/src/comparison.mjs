import { canonicalDigest, canonicalJson, canonicalSequenceDigest, codeUnitCompare, deepFreeze } from './canonical.mjs';
import { validateBenchmarkValue } from './contract.mjs';
import { harnessFail } from './errors.mjs';
import { snapshotData, snapshotOptions } from './input.mjs';

function key(row) { return `${row.taskId}/${row.corpusId}/${row.cacheState}/${row.networkProfile}`; }

function view(contract, input, label) {
  input = snapshotData(input, `${label} comparison input`);
  if (!input || !input.result || !Array.isArray(input.summaries) || !Array.isArray(input.environmentRecords)) harnessFail('HARNESS_INPUT_INVALID', `${label} comparison input must include its authenticated raw summaries and environments`);
  const result = validateBenchmarkValue(contract, 'BenchmarkResultBundle.schema.json', input.result);
  for (const row of input.summaries) validateBenchmarkValue(contract, 'TaskSummary.schema.json', row);
  for (const row of input.environmentRecords) validateBenchmarkValue(contract, 'EnvironmentRecord.schema.json', row);
  if (input.summaries.length !== result.summaryCount || canonicalSequenceDigest(input.summaries, 'ogvcs.benchmark/summary-set/v1') !== result.summarySetDigest || input.environmentRecords.length !== result.environmentCount || canonicalSequenceDigest(input.environmentRecords, 'ogvcs.benchmark/environment-set/v1') !== result.environmentSetDigest) harnessFail('HARNESS_BUNDLE_INVALID', `${label} raw comparison sets differ from their result envelope`);
  const thresholdDigest = canonicalDigest(result.thresholdFile, 'ogvcs.benchmark/thresholds/v1');
  if (thresholdDigest !== result.thresholdFileDigest || result.reproduction.tolerancePartsPerMillion !== result.thresholdFile.comparisonTolerancePartsPerMillion) harnessFail('HARNESS_BUNDLE_INVALID', `${label} comparison tolerance differs from its threshold authority`);
  const summaryMap = new Map();
  for (const row of input.summaries) { const identity = key(row); if (summaryMap.has(identity)) harnessFail('HARNESS_BUNDLE_INVALID', `${label} summary identities are duplicated`); summaryMap.set(identity, row); }
  return { result, summaries: input.summaries, environmentRecords: input.environmentRecords, summaryMap };
}

function environmentProjection(rows) {
  return rows.map((row) => ({
    classification: row.classification,
    implementation: row.implementation,
    corpus: row.corpus,
    configuration: row.configuration,
    hardware: row.hardware,
    platform: row.platform,
    topology: row.topology,
    network: row.network,
    cacheInspection: row.cacheInspection,
  })).sort((left, right) => codeUnitCompare(canonicalJson(left), canonicalJson(right)));
}

function semanticProjection(row) {
  return {
    sampleCount: row.sampleCount,
    succeeded: row.succeeded,
    failed: row.failed,
    incomplete: row.incomplete,
    retries: row.retries,
    bytes: row.bytes,
    correctnessFailures: row.correctnessFailures,
    successRatePartsPerMillion: row.successRatePartsPerMillion,
  };
}

function deltaPartsPerMillion(baseline, candidate) {
  if (baseline === 0) return candidate === 0 ? 0 : Number.MAX_SAFE_INTEGER;
  const delta = (BigInt(candidate) - BigInt(baseline)) * 1_000_000n / BigInt(baseline);
  const maximum = BigInt(Number.MAX_SAFE_INTEGER);
  if (delta > maximum) return Number.MAX_SAFE_INTEGER;
  if (delta < -maximum) return -Number.MAX_SAFE_INTEGER;
  return Number(delta);
}

export function compareResultBundles(contract, baselineInput, candidateInput, options = {}) {
  options = snapshotOptions(options, 'comparison options');
  const baseline = view(contract, baselineInput, 'baseline');
  const candidate = view(contract, candidateInput, 'candidate');
  const authorityTolerance = Math.min(baseline.result.thresholdFile.comparisonTolerancePartsPerMillion, candidate.result.thresholdFile.comparisonTolerancePartsPerMillion);
  const tolerance = options.tolerancePartsPerMillion ?? authorityTolerance;
  if (!Number.isSafeInteger(tolerance) || tolerance < 0 || tolerance > authorityTolerance) harnessFail('HARNESS_INPUT_INVALID', 'comparison tolerance is invalid or exceeds the authenticated threshold authority');
  const reasons = new Set();
  const expectedWorkloadDigest = canonicalDigest(contract.registries.tasks.entries, 'ogvcs.benchmark/workload-definitions/v1');
  if (baseline.result.contractManifestSha256 !== candidate.result.contractManifestSha256 || baseline.result.contractManifestSha256 !== contract.manifestSha256) reasons.add('contract-authority-differs');
  if (baseline.result.workloadDefinitionsDigest !== candidate.result.workloadDefinitionsDigest || baseline.result.workloadDefinitionsDigest !== expectedWorkloadDigest) reasons.add('workload-definitions-differ');
  if (baseline.result.thresholdFileDigest !== candidate.result.thresholdFileDigest) reasons.add('threshold-authority-differs');
  if (baseline.result.evidenceReportDigest !== candidate.result.evidenceReportDigest || canonicalJson(baseline.result.evidence) !== canonicalJson(candidate.result.evidence)) reasons.add('evidence-authority-differs');
  if (baseline.result.conformanceReportDigest !== candidate.result.conformanceReportDigest) reasons.add('conformance-authority-differs');
  if (canonicalJson(baseline.result.faultSchedules) !== canonicalJson(candidate.result.faultSchedules)) reasons.add('fault-schedules-differ');
  if (baseline.result.reproduction.harnessProfile !== candidate.result.reproduction.harnessProfile || baseline.result.reproduction.seed !== candidate.result.reproduction.seed || baseline.result.classification !== candidate.result.classification) reasons.add('reproduction-authority-differs');
  if (baseline.result.sampleCount !== candidate.result.sampleCount || baseline.result.summaryCount !== candidate.result.summaryCount || baseline.result.environmentCount !== candidate.result.environmentCount) reasons.add('result-inventory-differs');
  if (canonicalJson(environmentProjection(baseline.environmentRecords)) !== canonicalJson(environmentProjection(candidate.environmentRecords))) reasons.add('reference-environment-differs');
  if (baseline.summaryMap.size !== candidate.summaryMap.size || [...baseline.summaryMap.keys()].some((value) => !candidate.summaryMap.has(value))) reasons.add('summary-inventory-differs');
  const rows = [];
  for (const [name, leftRow] of [...baseline.summaryMap].sort(([a], [b]) => codeUnitCompare(a, b))) {
    const rightRow = candidate.summaryMap.get(name); if (!rightRow) continue;
    const p50 = deltaPartsPerMillion(leftRow.durationMicroseconds.p50, rightRow.durationMicroseconds.p50);
    const p95 = deltaPartsPerMillion(leftRow.durationMicroseconds.p95, rightRow.durationMicroseconds.p95);
    const p99 = deltaPartsPerMillion(leftRow.durationMicroseconds.p99, rightRow.durationMicroseconds.p99);
    const medianAbsoluteDeviation = deltaPartsPerMillion(leftRow.durationMicroseconds.medianAbsoluteDeviation, rightRow.durationMicroseconds.medianAbsoluteDeviation);
    const semanticEqual = canonicalJson(semanticProjection(leftRow)) === canonicalJson(semanticProjection(rightRow));
    rows.push({
      key: name,
      baselineP50: leftRow.durationMicroseconds.p50, candidateP50: rightRow.durationMicroseconds.p50, p50DeltaPartsPerMillion: p50,
      baselineP95: leftRow.durationMicroseconds.p95, candidateP95: rightRow.durationMicroseconds.p95, p95DeltaPartsPerMillion: p95,
      baselineP99: leftRow.durationMicroseconds.p99, candidateP99: rightRow.durationMicroseconds.p99, p99DeltaPartsPerMillion: p99,
      baselineMedianAbsoluteDeviation: leftRow.durationMicroseconds.medianAbsoluteDeviation, candidateMedianAbsoluteDeviation: rightRow.durationMicroseconds.medianAbsoluteDeviation, medianAbsoluteDeviationDeltaPartsPerMillion: medianAbsoluteDeviation,
      semanticEqual, withinTolerance: semanticEqual && [p50, p95, p99, medianAbsoluteDeviation].every((delta) => Math.abs(delta) <= tolerance),
    });
  }
  const comparable = reasons.size === 0;
  const report = {
    schemaVersion: 'ogvcs.benchmark/comparison/v1',
    baselineDigest: canonicalDigest({ result: baseline.result, summaries: baseline.summaries, environmentRecords: baseline.environmentRecords }, 'ogvcs.benchmark/result-view/v1'),
    candidateDigest: canonicalDigest({ result: candidate.result, summaries: candidate.summaries, environmentRecords: candidate.environmentRecords }, 'ogvcs.benchmark/result-view/v1'),
    tolerancePartsPerMillion: tolerance,
    comparable,
    reproduced: comparable && rows.every(({ withinTolerance }) => withinTolerance) && baseline.result.overallStatus === 'passed' && candidate.result.overallStatus === 'passed',
    rows,
    reasons: [...reasons].sort(),
  };
  return deepFreeze(validateBenchmarkValue(contract, 'ComparisonReport.schema.json', report));
}
