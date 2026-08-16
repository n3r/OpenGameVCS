import assert from 'node:assert/strict';
import test from 'node:test';

import {
  collectProtocolScenarios,
  executeReferenceProtocolCase,
  loadProtocolContract,
  runProtocolConformance,
  scenarioForAdapter,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

test('scenario collection is closed, bounded, unique, and deterministic', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const scenarios = collectProtocolScenarios(contract);
  assert.equal(scenarios.length, contract.manifest.counts.scenarios);
  assert.deepEqual(scenarios.map(({ id }) => id), scenarios.map(({ id }) => id).toSorted());
  const supplied = scenarioForAdapter(scenarios[0], contract);
  assert.equal(Object.hasOwn(supplied, 'expected'), false);
  assert.equal(Object.hasOwn(supplied, 'forbiddenResponseFields'), false);
  assert.equal(Object.hasOwn(supplied, 'requirementIds'), false);
  const duplicate = { ...contract, vectors: { one: { cases: [scenarios[0], scenarios[0]] } } };
  assert.throws(() => collectProtocolScenarios(duplicate), /duplicated/u);
  assert.throws(() => collectProtocolScenarios(contract, { maxCases: 1 }), /ceiling/u);
});

test('reference runner receives no oracle fields and emits exact RunnerReport', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  let observed = 0;
  const report = await runProtocolConformance(contract, async (runnerCase, context) => {
    observed += 1;
    assert.deepEqual(Object.keys(runnerCase).filter((key) => ['expected', 'requirementIds', 'forbiddenResponseFields'].includes(key)), []);
    return executeReferenceProtocolCase(runnerCase, context);
  }, { adapterId: 'ogvcs.protocol/reference-js@1' });
  assert.equal(observed, contract.manifest.counts.scenarios);
  assert.equal(report.passed, observed);
  assert.equal(report.failed, 0);
  assert.equal(report.results.length, observed);
  assert.deepEqual(Object.keys(report), ['adapterId', 'contractManifestSha256', 'failed', 'passed', 'reportDigest', 'results', 'schemaVersion']);
  assert.match(report.reportDigest, /^[0-9a-f]{64}$/u);
});

test('outcome mismatch is counted while out-of-schema adapter disclosure is rejected', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  let first = true;
  const report = await runProtocolConformance(contract, async (runnerCase, context) => {
    const actual = await executeReferenceProtocolCase(runnerCase, context);
    if (!first) return actual;
    first = false;
    return { ...actual, result: 'reject', code: 'INTERNAL_ERROR' };
  }, { adapterId: 'ogvcs.protocol/reference-js@1' });
  assert.equal(report.failed, 1);
  await assert.rejects(() => runProtocolConformance(contract, async (runnerCase, context) => ({
    ...await executeReferenceProtocolCase(runnerCase, context), response: { secret: 'must-not-leak' },
  }), { adapterId: 'ogvcs.protocol/hostile-js@1' }), /invalid result/u);
});
