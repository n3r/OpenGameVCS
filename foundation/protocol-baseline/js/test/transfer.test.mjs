import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { loadAuthority } from '../../adapters/js-independent/src/core.mjs';
import { evaluateIndependentCase } from '../../adapters/js-independent/src/engine.mjs';
import {
  executeReferenceProtocolCase,
  loadProtocolContract,
  rfc9530Sha256,
  strongRepresentationValidator,
  SyntheticTransferProbe,
  validateTransferHttpRangeCarrier,
  validateTransferProbeResult,
} from '../src/index.mjs';
import { protocolRoot } from './roots.mjs';

test('synthetic probe emits identity-encoded sequential ranges with strong validators and digests', () => {
  const bytes = Buffer.from('abcdefghij');
  const probe = new SyntheticTransferProbe(bytes, { maxRangeBytes: 4 });
  const descriptor = probe.descriptor();
  assert.equal(descriptor.etagHeader, `"${descriptor.validatorTag}"`);
  assert.equal(descriptor.contentDigestHeader, rfc9530Sha256(bytes));
  const first = probe.read({ contentEncoding: 'identity', offset: 0, length: 4, validator: null });
  assert.equal(Buffer.from(first.contentBase64, 'base64').toString(), 'abcd');
  assert.equal(first.complete, false);
  const second = probe.read({ contentEncoding: 'identity', offset: 4, length: 4, validator: first.validator });
  const last = probe.read({ contentEncoding: 'identity', offset: 8, length: 4, validator: first.validator });
  assert.equal(last.complete, true);
  assert.deepEqual(probe.verifyComplete([first.contentBase64, second.contentBase64, last.contentBase64]), {
    complete: true, length: 10, representationDigest: descriptor.contentDigestHeader, validator: strongRepresentationValidator(bytes),
  });
});

test('resume rejects stale/missing validators, content coding, invalid ranges and corrupt assembly', () => {
  const probe = new SyntheticTransferProbe(Buffer.from('abcdef'), { maxRangeBytes: 3 });
  assert.throws(() => probe.read({ contentEncoding: 'gzip', offset: 0, length: 2, validator: null }), /identity/u);
  assert.throws(() => probe.read({ contentEncoding: 'identity', offset: 2, length: 2, validator: null }), /stale or missing/u);
  assert.throws(() => probe.read({ contentEncoding: 'identity', offset: 2, length: 2, validator: '"wrong"' }), /stale or missing/u);
  assert.throws(() => probe.read({ contentEncoding: 'identity', offset: 6, length: 1, validator: probe.descriptor().etagHeader }), /outside/u);
  assert.throws(() => probe.read({ contentEncoding: 'identity', offset: 0, length: 4, validator: null }), /ceiling/u);
  assert.throws(() => probe.verifyComplete([Buffer.from('abc').toString('base64')]), /incomplete or corrupt/u);
});

test('range and representation ceilings are validated before allocation or response', () => {
  assert.throws(() => new SyntheticTransferProbe(Buffer.alloc(5), { maxRepresentationBytes: 4 }), /byte ceiling/u);
  const probe = new SyntheticTransferProbe(Buffer.alloc(4), { maxRangeBytes: 2 });
  assert.throws(() => probe.read({ contentEncoding: 'identity', offset: 0, length: 2, validator: null, extra: true }), /fields/u);
  assert.throws(() => probe.verifyComplete(['!!!!']), /canonical base64/u);
  assert.throws(() => strongRepresentationValidator(Buffer.alloc(4), { maxWorkingMemoryBytes: 1 }), /working-memory/u);
  assert.throws(() => rfc9530Sha256(Buffer.alloc(4), { maxWorkingMemoryBytes: 1 }), /working-memory/u);
});

test('assembly streams its digest within the configured working-memory ceiling', () => {
  const bytes = Buffer.from('abcdefghij');
  const encoded = bytes.toString('base64');
  const probe = new SyntheticTransferProbe(bytes, { maxRangeBytes: bytes.length });
  const exactLiveCeiling = bytes.length + 512 + bytes.length;
  assert.equal(probe.verifyComplete([encoded], { maxWorkingMemoryBytes: exactLiveCeiling }).complete, true);
  assert.throws(
    () => probe.verifyComplete([encoded], { maxWorkingMemoryBytes: exactLiveCeiling - 1 }),
    (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED',
  );
});

test('range emission reserves retained bytes and base64 output before encoding', () => {
  const bytes = Buffer.from('abcdefghij');
  const probe = new SyntheticTransferProbe(bytes, { maxRangeBytes: bytes.length });
  const encodedBytes = Math.ceil(bytes.length / 3) * 4;
  const exactLiveCeiling = bytes.length + encodedBytes + 1024;
  assert.equal(probe.read({ contentEncoding: 'identity', offset: 0, length: bytes.length, validator: null }, { maxWorkingMemoryBytes: exactLiveCeiling }).complete, true);
  assert.throws(
    () => probe.read({ contentEncoding: 'identity', offset: 0, length: bytes.length, validator: null }, { maxWorkingMemoryBytes: exactLiveCeiling - 1 }),
    (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED',
  );
});

test('copy and digest passes stop at a pre-expired cooperative deadline', () => {
  const expired = () => {
    let now = 0;
    return { timeoutMs: 1, now: () => now++ };
  };
  assert.throws(() => strongRepresentationValidator(Buffer.alloc(16), expired()), (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED');
  assert.throws(() => rfc9530Sha256(Buffer.alloc(16), expired()), (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED');
  assert.throws(() => new SyntheticTransferProbe(Buffer.alloc(16), expired()), (error) => error.code === 'PROTOCOL_DEADLINE_EXCEEDED');
});

test('constructor keeps one trusted representation copy within working memory', () => {
  const bytes = Buffer.alloc(16, 7);
  const exactLiveCeiling = bytes.length + 2048;
  assert.equal(new SyntheticTransferProbe(bytes, { maxWorkingMemoryBytes: exactLiveCeiling }).descriptor().length, bytes.length);
  assert.throws(
    () => new SyntheticTransferProbe(bytes, { maxWorkingMemoryBytes: exactLiveCeiling - 1 }),
    (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED',
  );
});

test('HTTP Range authenticates carried body bytes with mandatory canonical ETag and Content-Digest', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const cases = new Map(contract.vectors.transfer.cases.map((scenario) => [scenario.id, scenario]));
  const carrier = (id) => {
    const input = cases.get(id)?.input;
    assert.ok(input, id);
    return {
      probe: input.probe,
      requestHeaders: input.requestHeaders,
      responseHeaders: input.responseHeaders,
      responseStatus: input.responseStatus,
      responseBodyHex: input.responseBodyHex,
      transportResponse: input.transportResponse,
    };
  };
  const accepted = validateTransferHttpRangeCarrier(contract, carrier('transfer-http-range-roundtrip-206'));
  assert.match(accepted.validatorTag, /^[A-Za-z0-9._~-]{16,256}$/u);
  assert.match(accepted.contentSha256, /^[0-9a-f]{64}$/u);
  const openEnded = validateTransferHttpRangeCarrier(contract, carrier('transfer-http-no-range-open-end-200'));
  assert.equal(openEnded.status, 200);
  assert.equal(openEnded.acceptedStart, 0);
  assert.equal(openEnded.acceptedEndExclusive, openEnded.totalBytes);

  const largeBody = Buffer.alloc(33 * 1024, 0x5a);
  const largeValidator = strongRepresentationValidator(largeBody);
  const largeSha256 = largeValidator.slice('"sha256-'.length, -1);
  const largeCarrier = carrier('transfer-http-no-range-open-end-200');
  largeCarrier.probe = { ...largeCarrier.probe, expectedSha256: largeSha256 };
  largeCarrier.responseBodyHex = largeBody.toString('hex');
  largeCarrier.responseHeaders = [
    { name: 'etag', value: largeValidator },
    { name: 'content-digest', value: rfc9530Sha256(largeBody) },
    { name: 'content-length', value: String(largeBody.length) },
  ];
  largeCarrier.transportResponse = { rangeBytes: largeBody.length, totalBytes: largeBody.length };
  assert.ok(largeCarrier.responseBodyHex.length > 64 * 1024);
  assert.equal(validateTransferHttpRangeCarrier(contract, largeCarrier).acceptedEndExclusive, largeBody.length);

  let traps = 0;
  const hostileCarrier = new Proxy({}, {
    ownKeys() { traps += 1; throw new Error('must not execute'); },
  });
  assert.throws(
    () => validateTransferHttpRangeCarrier(contract, hostileCarrier),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );
  assert.equal(traps, 0);

  for (const id of [
    'transfer-http-content-digest-missing',
    'transfer-http-content-digest-malformed-present',
    'transfer-http-content-digest-duplicate-case-folded',
    'transfer-http-etag-missing',
    'transfer-http-etag-weak',
    'transfer-http-etag-malformed',
    'transfer-http-etag-duplicate-case-folded',
    'transfer-http-unsatisfied-etag-forbidden',
  ]) {
    assert.throws(() => validateTransferHttpRangeCarrier(contract, carrier(id)), (error) => error.code === 'PROTOCOL_INPUT_INVALID', id);
  }
  for (const id of [
    'transfer-http-content-digest-body-mismatch',
    'transfer-http-content-digest-expected-mismatch',
    'transfer-http-etag-resume-mismatch',
  ]) {
    assert.throws(() => validateTransferHttpRangeCarrier(contract, carrier(id)), (error) => error.code === 'TRANSFER_VALIDATOR_MISMATCH', id);
  }
  const unsatisfied = carrier('transfer-http-unsatisfied-range-416');
  assert.throws(
    () => validateTransferHttpRangeCarrier(contract, {
      ...unsatisfied,
      responseHeaders: [...unsatisfied.responseHeaders, { name: 'etag', value: '"validator-000001"' }],
    }),
    (error) => error.code === 'PROTOCOL_INPUT_INVALID',
  );

  const baseline = cases.get('transfer-http-range-roundtrip-206');
  assert.ok(baseline);
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  for (const [index, responseStatus] of [201, 400, 500].entries()) {
    const direct = { ...carrier('transfer-http-range-roundtrip-206'), responseStatus };
    assert.throws(
      () => validateTransferHttpRangeCarrier(contract, direct),
      (error) => error.code === 'PROTOCOL_INPUT_INVALID',
      `reference status ${responseStatus}`,
    );
    const independent = await evaluateIndependentCase(authority, {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${String(index + 1).repeat(32)}`,
      operation: baseline.operation,
      inputKind: baseline.inputKind,
      input: { ...baseline.input, responseStatus },
      control: baseline.control,
    });
    assert.equal(independent.result, 'reject', `independent status ${responseStatus}`);
    assert.equal(independent.code, 'PROTOCOL_MALFORMED', `independent status ${responseStatus}`);
  }
});

test('interrupted results may report zero progress while partial results remain strictly progressive', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.transfer.cases.find(({ id }) => id === 'transfer-result-interrupted');
  assert.ok(scenario);
  const interrupted = {
    ...scenario.input.probeResult,
    acceptedEndExclusive: scenario.input.probeResult.acceptedStart,
  };
  assert.doesNotThrow(() => validateTransferProbeResult(contract, interrupted));
  const partial = { ...interrupted, status: 'partial' };
  assert.throws(() => validateTransferProbeResult(contract, partial), (error) => error.code === 'PROTOCOL_INPUT_INVALID');
  for (const [label, probeResult, expected] of [
    ['interrupted', interrupted, 'NONE'],
    ['partial', partial, 'PROTOCOL_MALFORMED'],
  ]) {
    const runnerCase = {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${(label === 'interrupted' ? '8' : '9').repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input: { ...scenario.input, probeResult },
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

test('numeric transfer shape faults select the structural and grant stages in both engines', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const grantScenario = contract.vectors.transfer.cases.find(({ id }) => id === 'transfer-authz-valid-request-root');
  const rangeScenario = contract.vectors.transfer.cases.find(({ id }) => id === 'transfer-http-range-roundtrip-206');
  assert.ok(grantScenario);
  assert.ok(rangeScenario);

  const cases = [
    ...[-1, 1, Number.MAX_SAFE_INTEGER].map((explicitObjectCount, index) => ({
      expected: 'TRANSFER_GRANT_INVALID',
      input: {
        ...grantScenario.input,
        probe: {
          ...grantScenario.input.probe,
          grant: { ...grantScenario.input.probe.grant, explicitObjectCount },
        },
      },
      scenario: grantScenario,
      suffix: String(index + 1),
    })),
    {
      expected: 'PROTOCOL_MALFORMED',
      input: {
        ...rangeScenario.input,
        transportResponse: { ...rangeScenario.input.transportResponse, totalBytes: -1 },
      },
      scenario: rangeScenario,
      suffix: '4',
    },
  ];
  for (const { expected, input, scenario, suffix } of cases) {
    const runnerCase = {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${suffix.repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input,
      control: scenario.control,
    };
    const [reference, independent] = await Promise.all([
      executeReferenceProtocolCase(runnerCase, { contract }),
      evaluateIndependentCase(authority, runnerCase),
    ]);
    assert.equal(reference.code, expected, `reference ${suffix}`);
    assert.equal(independent.code, expected, `independent ${suffix}`);
  }
});

test('configured grant-byte measurement never preempts carrier-shape mapping', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const authority = await loadAuthority(fileURLToPath(protocolRoot));
  const scenario = contract.vectors.transfer.cases.find(({ id }) => id === 'transfer-authz-valid-request-root');
  assert.ok(scenario);
  const validGrant = scenario.input.probe.grant;
  const envelopeBytes = Buffer.from(validGrant.envelope, 'base64url').length;
  const { representation: _representation, ...missingRepresentation } = validGrant;
  const malformed = [
    { ...validGrant, explicitObjectCount: 1 },
    { ...validGrant, scheme: 'Not-OGVCS-Grant' },
    missingRepresentation,
    { ...validGrant, unknownCarrierField: true },
  ];
  for (const [index, grant] of malformed.entries()) {
    const runnerCase = {
      schemaVersion: 'ogvcs.protocol/runner-case/v1',
      id: `case-${String(index + 5).repeat(32)}`,
      operation: scenario.operation,
      inputKind: scenario.inputKind,
      input: { ...scenario.input, probe: { ...scenario.input.probe, grant } },
      configuredLimits: { maxGrantBytes: envelopeBytes },
      control: scenario.control,
    };
    const [reference, independent] = await Promise.all([
      executeReferenceProtocolCase(runnerCase, { contract }),
      evaluateIndependentCase(authority, runnerCase),
    ]);
    assert.equal(reference.code, 'TRANSFER_GRANT_INVALID', `reference shape ${index}`);
    assert.equal(independent.code, 'TRANSFER_GRANT_INVALID', `independent shape ${index}`);
  }
});
