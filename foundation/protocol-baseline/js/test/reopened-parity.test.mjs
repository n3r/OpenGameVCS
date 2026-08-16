import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadAuthority } from '../../adapters/js-independent/src/core.mjs';
import { evaluateIndependentCase } from '../../adapters/js-independent/src/engine.mjs';
import {
  canonicalJson,
  collectProtocolScenarios,
  executeReferenceProtocolCase,
  loadProtocolContract,
  scenarioForAdapter,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const REOPENED_CASES = Object.freeze([
  'cursor-scope-missing-operation',
  'cursor-scope-unknown-field',
  'cursor-issued-at-max-expiry-overflow',
  'idempotency-zero-tombstone-retention-first-execution',
  'idempotency-attempt-projection-index-out-of-range',
  'idempotency-initial-authorization-denied',
  'idempotency-key-expires-at-field-mismatch',
  'idempotency-key-issued-at-field-mismatch',
  'idempotency-key-required',
  'idempotency-projection-missing-schema-version',
  'idempotency-projection-unknown-field',
  'idempotency-retry-only-unused-key-first-execution',
  'idempotency-route-retryable-required',
  'negotiation-receipt-expired-invalid-mac',
  'negotiation-cleartext-loopback-rejected',
  'negotiation-extension-selection-deterministic',
  'negotiation-required-safe-extension-not-offered',
  'negotiation-required-safe-extension-selected',
  'negotiation-server-nonce-noncanonical-base64url',
  'negotiation-server-nonce-max-64-bytes',
  'negotiation-server-nonce-max-plus-one-65-bytes',
  'malformed-negotiation-zero-receipt-lifetime',
  'malformed-cursor-zero-ttl',
  'malformed-decreasing-clock-samples',
  'stream-empty-eof-incomplete',
  'stream-frame-missing-kind',
  'stream-frame-missing-schema-version',
  'stream-frame-missing-stream-id',
  'stream-frame-unknown-field',
  'stream-mid-frame-eof-incomplete',
  'envelope-hard-default-operation-time-expired',
  'transfer-authz-wrong-permission',
  'transfer-grant-explicit-object-count-negative',
  'transfer-explicit-object-list',
  'transfer-grant-explicit-object-count-max-safe',
  'transfer-configured-grant-bytes-then-malformed-shape',
  'transfer-invalid-range-before-invalid-grant',
  'transfer-malformed-non-grant-before-invalid-grant',
  'transfer-http-no-range-open-end-200',
  'transfer-http-negative-total-bytes',
  'transfer-resume-without-validator',
  'transfer-result-interrupted-zero-progress',
]);

test('reopened cursor, idempotency, negotiation, stream, and transfer cases have exact cross-engine parity', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenarios = new Map(collectProtocolScenarios(contract).map((scenario) => [scenario.id, scenario]));

  for (const id of REOPENED_CASES) {
    const scenario = scenarios.get(id);
    assert.ok(scenario, `missing generated scenario ${id}`);
    const runnerCase = scenarioForAdapter(scenario, contract);
    const [reference, independent] = await Promise.all([
      executeReferenceProtocolCase(runnerCase, { contract }),
      evaluateIndependentCase(authority, runnerCase),
    ]);
    const expected = {
      code: scenario.expected.code,
      mutationCount: scenario.expected.mutationCount,
      preMutation: scenario.expected.preMutation,
      result: scenario.expected.result,
    };
    assert.deepEqual({
      code: reference.code,
      mutationCount: reference.mutationCount,
      preMutation: reference.preMutation,
      result: reference.result,
    }, expected, `reference outcome for ${id}`);
    assert.deepEqual({
      code: independent.code,
      mutationCount: independent.mutationCount,
      preMutation: independent.preMutation,
      result: independent.result,
    }, expected, `independent outcome for ${id}`);
    assert.equal(canonicalJson(independent.trace), canonicalJson(reference.trace), `trace parity for ${id}`);
  }

  const firstExecution = scenarios.get('idempotency-retry-only-unused-key-first-execution');
  const firstResult = await executeReferenceProtocolCase(scenarioForAdapter(firstExecution, contract), { contract });
  assert.deepEqual(firstResult.trace.semanticOutput, { firstExecution: true, replay: false });
});
