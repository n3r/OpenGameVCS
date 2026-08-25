import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadAuthority } from '../../adapters/js-independent/src/core.mjs';
import { evaluateIndependentCase } from '../../adapters/js-independent/src/engine.mjs';
import {
  buildBaselineOffer,
  executeReferenceProtocolCase,
  HARD_LIMITS,
  loadProtocolContract,
  NegotiationReceiptCodec,
  ProtocolNegotiator,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

const principal = Object.freeze({ subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 3, sessionId: 'session-00000001' });

async function fixture(overrides = {}) {
  const contract = await loadProtocolContract({ root: protocolRoot });
  let now = 1000;
  const receiptCodec = new NegotiationReceiptCodec({ contract, key: Buffer.alloc(32, 7), keyId: 'receipt-key@1', now: () => now });
  const negotiator = new ProtocolNegotiator({
    contract, receiptCodec, now: () => now, randomBytes: () => Buffer.alloc(16, 8),
    authenticate: overrides.authenticate ?? (async () => principal),
    repositoryRequirements: overrides.repositoryRequirements,
    minimumCapabilities: overrides.minimumCapabilities,
  });
  return { contract, negotiator, setNow: (value) => { now = value; } };
}

test('all capability axes select independently and receipt binds authenticated principal/session', async () => {
  const { contract, negotiator } = await fixture();
  const offer = buildBaselineOffer(contract, { clientNonce: 'A'.repeat(22), correlationId: 'correlation-0001' });
  const result = await negotiator.negotiate(offer);
  assert.equal(result.selection.pathContract, 'ogvcs.path-filesystem@1');
  assert.equal(result.selection.authorizationRegistrySha256, contract.manifest.predecessorPins.authorization.registrySetSha256);
  const claims = negotiator.verifyMutationReceipt(result.receipt, principal, { selection: result.selection, atUnixMs: 1001 });
  assert.equal(claims.sessionId, principal.sessionId);
});

test('mutation receipt requires and binds the current negotiated tuple', async () => {
  const { contract, negotiator } = await fixture();
  const result = await negotiator.negotiate(buildBaselineOffer(contract));
  assert.throws(
    () => negotiator.verifyMutationReceipt(result.receipt, principal, { atUnixMs: 1001 }),
    (error) => error.code === 'PROTOCOL_STATE_CONFLICT',
  );
  const otherSelection = { ...result.selection, extensions: [] };
  assert.throws(
    () => negotiator.verifyMutationReceipt(result.receipt, principal, { selection: otherSelection, atUnixMs: 1001 }),
    (error) => error.code === 'PROTOCOL_STATE_CONFLICT',
  );
});

test('authentication happens before repository-specific requirements are accessed', async () => {
  const order = [];
  const { contract, negotiator } = await fixture({
    authenticate: async () => { order.push('authenticate'); return principal; },
    repositoryRequirements: async () => { order.push('repository'); return { requiredCapabilities: [] }; },
  });
  await negotiator.negotiate(buildBaselineOffer(contract));
  assert.deepEqual(order, ['authenticate', 'repository']);
});

test('authentication and repository callbacks cannot execute proxy traps through their returned data', async () => {
  let traps = 0;
  const hostile = () => new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('callback trap'); },
  });
  const authentication = await fixture({ authenticate: async () => hostile() });
  await assert.rejects(
    () => authentication.negotiator.negotiate(buildBaselineOffer(authentication.contract)),
    (error) => error.code === 'AUTHORIZATION_DENIED',
  );
  const requirements = await fixture({ repositoryRequirements: async () => hostile() });
  await assert.rejects(
    () => requirements.negotiator.negotiate(buildBaselineOffer(requirements.contract)),
    (error) => error.code === 'AUTHORIZATION_DENIED',
  );
  assert.equal(traps, 0);
});

test('unknown optional extension is ignored while unknown required and empty axes reject', async () => {
  const { contract, negotiator } = await fixture();
  const baseline = buildBaselineOffer(contract);
  const optional = { ...baseline, capabilities: { ...baseline.capabilities, extensions: [...baseline.capabilities.extensions, 'example.vendor/opaque@1'] } };
  const accepted = await negotiator.negotiate(optional);
  assert.deepEqual(accepted.selection.extensions, baseline.capabilities.extensions);

  const required = { ...baseline, capabilities: { ...baseline.capabilities, requiredCapabilities: [...baseline.capabilities.requiredCapabilities, 'example.required@1'] } };
  await assert.rejects(() => negotiator.negotiate(required), (error) => error.code === 'NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN');
  const noProtocol = { ...baseline, capabilities: { ...baseline.capabilities, protocolVersions: ['example.invalid@9'] } };
  await assert.rejects(() => negotiator.negotiate(noProtocol), (error) => error.code === 'NEGOTIATION_NO_COMMON_VERSION');
});

test('optional extension selection is compatibility-ordered and independent of offer order', async () => {
  const { contract, negotiator } = await fixture();
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const baseline = buildBaselineOffer(contract);
  const safe = 'ogvcs.extension.safe-optional@1';
  const audit = 'ogvcs.extension.audit-optional@1';
  const scenario = contract.vectors.negotiation.cases.find(({ id }) => id === 'negotiation-exact-baseline');
  assert.ok(scenario);

  for (const [offered, requireSafe, expected, suffix] of [
    [[safe], true, [safe], 'safe'],
    [[audit, safe], false, [safe, audit], 'reversed'],
  ]) {
    const offer = {
      ...baseline,
      capabilities: {
        ...baseline.capabilities,
        extensions: offered,
        requiredCapabilities: requireSafe
          ? [...baseline.capabilities.requiredCapabilities, safe]
          : baseline.capabilities.requiredCapabilities,
      },
    };
    const reference = await negotiator.negotiate(offer);
    assert.deepEqual(reference.selection.extensions, expected, suffix);
    const independent = await evaluateIndependentCase(authority, {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${(suffix === 'safe' ? '2' : '3').repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input: { ...scenario.input, offer },
      control: scenario.control,
    });
    assert.equal(independent.result, 'accept', suffix);
    assert.deepEqual(independent.trace.semanticOutput.extensions, expected, suffix);
  }

  const unavailableRequired = {
    ...baseline,
    capabilities: {
      ...baseline.capabilities,
      extensions: [],
      requiredCapabilities: [...baseline.capabilities.requiredCapabilities, safe],
    },
  };
  await assert.rejects(
    () => negotiator.negotiate(unavailableRequired),
    (error) => error.code === 'NEGOTIATION_NO_COMMON_VERSION',
  );
  const independent = await evaluateIndependentCase(authority, {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'4'.repeat(32)}`,
    operation: scenario.operation,
    inputKind: scenario.inputKind,
    input: { ...scenario.input, offer: unavailableRequired },
    control: scenario.control,
  });
  assert.equal(independent.result, 'reject');
  assert.equal(independent.code, 'NEGOTIATION_NO_COMMON_VERSION');
});

test('server nonce and receipt lifetime boundaries have exact cross-engine parity', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.negotiation.cases.find(({ id }) => id === 'negotiation-exact-baseline');
  assert.ok(scenario);
  for (const [label, input, expected] of [
    ['nonce-64', { ...scenario.input, serverNonce: Buffer.alloc(64, 7).toString('base64url') }, 'NONE'],
    ['nonce-65', { ...scenario.input, serverNonce: Buffer.alloc(65, 7).toString('base64url') }, 'PROTOCOL_MALFORMED'],
    ['zero-lifetime', { ...scenario.input, receiptLifetimeMs: 0 }, 'PROTOCOL_MALFORMED'],
  ]) {
    const runnerCase = {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${label === 'nonce-64' ? '5'.repeat(32) : label === 'nonce-65' ? '6'.repeat(32) : '7'.repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input,
      control: scenario.control,
    };
    const [reference, independent] = await Promise.all([
      executeReferenceProtocolCase(runnerCase, { contract }),
      evaluateIndependentCase(authority, runnerCase),
    ]);
    assert.equal(reference.code, expected, `reference ${label}`);
    assert.equal(independent.code, expected, `independent ${label}`);
  }
});

test('loopback conformance never authorizes cleartext negotiation', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.negotiation.cases.find(({ id }) => id === 'negotiation-exact-baseline');
  assert.ok(scenario);
  const runnerCase = {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'d'.repeat(32)}`,
    operation: scenario.operation,
    inputKind: scenario.inputKind,
    input: {
      ...scenario.input,
      loopbackConformance: true,
      transportScheme: 'http',
    },
    control: scenario.control,
  };
  const [reference, independent] = await Promise.all([
    executeReferenceProtocolCase(runnerCase, { contract }),
    evaluateIndependentCase(authority, runnerCase),
  ]);
  for (const result of [reference, independent]) {
    assert.equal(result.result, 'reject');
    assert.equal(result.code, 'NEGOTIATION_DOWNGRADE_REJECTED');
  }
});

test('runner execution clocks are monotonic and enforce the default hard deadline in both engines', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.negotiation.cases.find(({ id }) => id === 'negotiation-exact-baseline');
  assert.ok(scenario);
  for (const [label, clockSamplesUnixMs, expected] of [
    ['decreasing', [1000, 999], 'PROTOCOL_MALFORMED'],
    ['default-expired', [1000, 1000 + HARD_LIMITS.timeoutMs], 'DEADLINE_EXCEEDED'],
  ]) {
    const runnerCase = {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${(label === 'decreasing' ? 'f' : '0').repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input: scenario.input,
      control: { ...scenario.control, clockSamplesUnixMs },
    };
    const [reference, independent] = await Promise.all([
      executeReferenceProtocolCase(runnerCase, { contract }),
      evaluateIndependentCase(authority, runnerCase),
    ]);
    assert.equal(reference.code, expected, `reference ${label}`);
    assert.equal(independent.code, expected, `independent ${label}`);
  }
});

test('trusted client minimum removal rejects as downgrade and no receipt is issued', async () => {
  const { contract, negotiator } = await fixture({ minimumCapabilities: ['ogvcs.receipt.hmac-sha256@1'] });
  const baseline = buildBaselineOffer(contract);
  const stripped = { ...baseline, capabilities: { ...baseline.capabilities, requiredCapabilities: baseline.capabilities.requiredCapabilities.filter((value) => value !== 'ogvcs.receipt.hmac-sha256@1') } };
  await assert.rejects(() => negotiator.negotiate(stripped), (error) => error.code === 'NEGOTIATION_DOWNGRADE_REJECTED');
});

test('minimum capability configuration is finite inert data and never invokes an iterable getter', async () => {
  let traps = 0;
  const minimumCapabilities = {};
  Object.defineProperty(minimumCapabilities, Symbol.iterator, {
    enumerable: true,
    get() { traps += 1; throw new Error('must not execute'); },
  });
  await assert.rejects(
    () => fixture({ minimumCapabilities }),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );
  assert.equal(traps, 0);
});

test('deprecated compatibility tuples remain readable but are never selected for a new session', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const deprecatedCompatibility = {
    ...contract.registries.compatibility,
    entries: contract.registries.compatibility.entries.map((entry) => ({ ...entry, state: 'deprecated' })),
  };
  const mutatedContract = {
    ...contract,
    registries: { ...contract.registries, compatibility: deprecatedCompatibility },
  };
  const receiptCodec = new NegotiationReceiptCodec({ contract, key: Buffer.alloc(32, 7), keyId: 'receipt-key@1', now: () => 1000 });
  const negotiator = new ProtocolNegotiator({
    contract: mutatedContract,
    receiptCodec,
    now: () => 1000,
    randomBytes: () => Buffer.alloc(16, 8),
    authenticate: async () => principal,
  });
  const offer = buildBaselineOffer(contract, { clientNonce: 'A'.repeat(22), correlationId: 'correlation-0001' });
  await assert.rejects(() => negotiator.negotiate(offer), (error) => error.code === 'NEGOTIATION_NO_COMMON_VERSION');
  assert.throws(() => buildBaselineOffer(mutatedContract), (error) => error.code === 'PROTOCOL_CONTRACT_INVALID');

  const scenarioSet = JSON.parse(await readFile(new URL('../../../../spec/protocols/v1/vectors/negotiation.json', import.meta.url), 'utf8'));
  const scenario = scenarioSet.cases.find((entry) => entry.id === 'negotiation-exact-baseline');
  assert.ok(scenario);
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const mutatedAuthority = {
    ...authority,
    registries: { ...authority.registries, compatibility: deprecatedCompatibility },
  };
  const independent = await evaluateIndependentCase(mutatedAuthority, {
    schemaVersion: 'ogvcs.protocol/runner-case/v1',
    id: `case-${'1'.repeat(32)}`,
    operation: scenario.operation,
    inputKind: scenario.inputKind,
    input: scenario.input,
    control: scenario.control,
  });
  assert.equal(independent.result, 'reject');
  assert.equal(independent.code, 'NEGOTIATION_NO_COMMON_VERSION');
});
