import { canonicalDigest, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';
import { HARNESS_LIMITS, checkedAdd } from './limits.mjs';

const METRICS = new Set(['successRatePartsPerMillion', 'correctnessFailures', 'failed', 'incomplete', 'overheadBasisPoints', 'faultInvariantFailures', 'securityNegativeMisses', 'protocolFailures']);

function actualMetric(entry, summaryIndex, evidence) {
  if (['overheadBasisPoints', 'faultInvariantFailures', 'securityNegativeMisses', 'protocolFailures'].includes(entry.metric)) {
    const value = evidence[entry.metric];
    if (!Number.isSafeInteger(value) || value < 0) harnessFail('HARNESS_INPUT_INVALID', `threshold evidence ${entry.metric} is invalid`);
    return value;
  }
  const selected = entry.taskId === '*' ? summaryIndex.all : (summaryIndex.byTask.get(entry.taskId) ?? []);
  if (selected.length === 0) return { actual: 0, samples: 0 };
  const samples = selected.reduce((sum, row) => checkedAdd(sum, row.sampleCount, 'threshold sample count'), 0);
  if (entry.metric === 'successRatePartsPerMillion') {
    let actual = 1_000_000;
    for (const row of selected) actual = Math.min(actual, row.successRatePartsPerMillion);
    return { actual, samples };
  }
  return { actual: selected.reduce((sum, row) => checkedAdd(sum, row[entry.metric], `threshold ${entry.metric}`), 0), samples };
}

export function evaluateThresholds(thresholdFile, summaries, context) {
  if (!thresholdFile || !Array.isArray(thresholdFile.entries) || thresholdFile.entries.length < 1 || thresholdFile.entries.length > HARNESS_LIMITS.maxThresholds || !Array.isArray(summaries) || summaries.length > HARNESS_LIMITS.maxSamples || !context || typeof context.harnessProfile !== 'string') harnessFail('HARNESS_INPUT_INVALID', 'threshold file or evaluation context is invalid');
  const summaryIndex = { all: summaries, byTask: new Map() };
  for (const summary of summaries) {
    if (!summary || typeof summary.taskId !== 'string') harnessFail('HARNESS_INPUT_INVALID', 'threshold summary input is invalid');
    if (!summaryIndex.byTask.has(summary.taskId)) summaryIndex.byTask.set(summary.taskId, []);
    summaryIndex.byTask.get(summary.taskId).push(summary);
  }
  const identities = new Set();
  const rows = thresholdFile.entries.map((entry) => {
    if (!entry || typeof entry.id !== 'string' || typeof entry.requirementId !== 'string' || typeof entry.taskId !== 'string' || !METRICS.has(entry.metric) || !['maximum', 'minimum'].includes(entry.operator) || !Number.isSafeInteger(entry.value) || entry.value < 0 || !Number.isSafeInteger(entry.minimumSamples) || entry.minimumSamples < 0 || !['gate', 'warning'].includes(entry.severity) || !Array.isArray(entry.profiles) || entry.profiles.some((profile) => typeof profile !== 'string')) harnessFail('HARNESS_INPUT_INVALID', 'threshold entry is invalid');
    if (identities.has(entry.id)) harnessFail('HARNESS_INPUT_INVALID', 'threshold identities must be unique');
    identities.add(entry.id);
    if (!entry.profiles.includes(context.harnessProfile)) return { schemaVersion: 'ogvcs.benchmark/threshold-evaluation/v1', thresholdId: entry.id, requirementId: entry.requirementId, metric: entry.metric, actual: 0, expected: entry.value, operator: entry.operator, severity: entry.severity, status: 'not-applicable' };
    const result = actualMetric(entry, summaryIndex, context);
    const { actual, samples = 0 } = typeof result === 'number' ? { actual: result, samples: Number.MAX_SAFE_INTEGER } : result;
    const comparison = entry.operator === 'maximum' ? actual <= entry.value : actual >= entry.value;
    return { schemaVersion: 'ogvcs.benchmark/threshold-evaluation/v1', thresholdId: entry.id, requirementId: entry.requirementId, metric: entry.metric, actual, expected: entry.value, operator: entry.operator, severity: entry.severity, status: samples >= entry.minimumSamples && comparison ? 'passed' : 'failed' };
  });
  return deepFreeze({ thresholdFileDigest: canonicalDigest(thresholdFile, 'ogvcs.benchmark/thresholds/v1'), rows, gateFailed: rows.some(({ severity, status }) => severity === 'gate' && status === 'failed'), warnings: rows.filter(({ severity, status }) => severity === 'warning' && status === 'failed').map(({ thresholdId }) => thresholdId) });
}
