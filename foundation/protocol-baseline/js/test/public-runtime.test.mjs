import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import test from 'node:test';

import { loadAuthorizationContract, verifyTransferGrant } from '@opengamevcs/authorization-contract';

import {
  PROTOCOL_LIMITS_BY_NAME,
  ProtocolProblemCatalog,
  SyntheticTransferProbe,
  createCompactTransferGrant,
  createIdempotencyDescriptor,
  createPageEnvelope,
  encodeRequestEnvelope,
  loadAuthorizationGrantContract,
  loadProtocolContract,
  parseCanonicalStream,
  parseRequestEnvelope,
  semanticIdempotencyFingerprint,
  validateCompactTransferGrant,
  validateIdempotencyDescriptor,
  validateRequestEnvelope,
  writeCanonicalStream,
} from '../src/index.mjs';
import { authorizationRoot, protocolRoot } from './roots.mjs';

const principal = Object.freeze({ subjectDigest: '11'.repeat(32), tenantDigest: '22'.repeat(32), authorityEpoch: 7, sessionId: 'session-00000001' });

function receipt(contract) {
  return {
    algorithm: 'HMAC-SHA-256', keyId: 'fixture-key@1',
    claims: {
      schemaVersion: 'ogvcs.protocol/negotiation-receipt-claims/v1', selection: contract.registries.compatibility.entries[0].selection,
      ...principal, clientNonce: 'A'.repeat(22), serverNonce: Buffer.alloc(16, 1).toString('base64url'), issuedAtUnixMs: 1000, expiresAtUnixMs: 2000,
    },
    mac: 'A'.repeat(43),
  };
}

function request(contract, overrides = {}) {
  return {
    schemaVersion: 'ogvcs.protocol/request-envelope/v1', operation: 'repository.example/mutate@1',
    correlationId: 'correlation-0001', negotiationReceipt: receipt(contract), body: { a: 1, b: 2 }, extensions: {}, ...overrides,
  };
}

function authorizationEnvelope() {
  return {
    schemaVersion: 'ogvcs.authorization/transfer-grant/v1', algorithm: 'Ed25519', keyId: 'test-key',
    claims: {
      schemaVersion: 'ogvcs.authorization/transfer-grant-claims/v1', issuer: 'issuer', keyId: 'test-key', keyGeneration: 1,
      authorityEpoch: 2, subject: 'subject', tenant: 'tenant', repository: 'repository', permission: 'content.materialize',
      operation: 'download', audience: 'transfer', issuedAt: 10, expiresAt: 20, nonce: 'nonce', replay: 'single-use',
      objectIds: [], requestRoot: `sha256:${'ab'.repeat(32)}`,
    },
    signature: 'A'.repeat(86),
  };
}

test('runtime hard ceilings reproduce all 35 normative limit assignments', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  assert.equal(Object.keys(PROTOCOL_LIMITS_BY_NAME).length, 35);
  assert.deepEqual(Object.fromEntries(contract.registries.limits.entries.map(({ name, value }) => [name, value])), PROTOCOL_LIMITS_BY_NAME);
});

test('public envelopes are canonical, closed, deadline bounded, and idempotency uses the normative semantic golden', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const value = request(contract);
  const encoded = encodeRequestEnvelope(contract, value, { atUnixMs: 1000 });
  assert.deepEqual(parseRequestEnvelope(contract, encoded, { requireCanonical: true, atUnixMs: 1000 }), validateRequestEnvelope(contract, value, { atUnixMs: 1000 }));
  const golden = contract.vectors.idempotency.goldens[0];
  assert.equal(semanticIdempotencyFingerprint(golden.left), golden.fingerprint);
  assert.equal(semanticIdempotencyFingerprint(golden.right), golden.fingerprint);
  const descriptor = createIdempotencyDescriptor(contract, 'ik1.1000.1100.AAAAAAAAAAAAAAAAAAAAAA', value);
  assert.equal(validateIdempotencyDescriptor(contract, descriptor, { ...value, correlationId: 'correlation-0002' }).fingerprint, descriptor.fingerprint);
  assert.throws(() => validateIdempotencyDescriptor(contract, descriptor, { ...value, body: { a: 2 } }), /does not match/u);
  assert.throws(() => validateRequestEnvelope(contract, { ...value, future: true }, { atUnixMs: 1000 }), /registered property/u);
  assert.throws(() => validateRequestEnvelope(contract, { ...value, deadlineUnixMs: 999 }, { atUnixMs: 1000 }), (error) => error.code === 'DEADLINE_EXCEEDED');
  assert.throws(() => validateRequestEnvelope(contract, value, { atUnixMs: 1000, redirectStatus: 302 }), (error) => error.code === 'REDIRECT_FORBIDDEN');
  assert.doesNotThrow(() => validateRequestEnvelope(contract, value, { atUnixMs: 1000, redirectStatus: 302, allowSameOriginRedirect: true, originChanged: false }));
  assert.throws(() => validateRequestEnvelope(contract, value, { atUnixMs: 1000, redirectStatus: 302, allowSameOriginRedirect: true, originChanged: true }), (error) => error.code === 'REDIRECT_FORBIDDEN');
});

test('page state is explicit and empty pages never imply completion', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const complete = createPageEnvelope(contract, { correlationId: 'correlation-0001', items: [], state: 'complete' });
  assert.equal(complete.state, 'complete');
  const more = createPageEnvelope(contract, { correlationId: 'correlation-0001', items: [], state: 'more', nextCursor: { token: 'cursor-token-0001' } });
  assert.equal(more.nextCursor.token, 'cursor-token-0001');
  const problem = new ProtocolProblemCatalog(contract).create('CURSOR_GAP', { correlationId: 'correlation-0001' });
  assert.equal(createPageEnvelope(contract, { correlationId: 'correlation-0001', items: [], state: 'gap', problem }).problem.code, 'CURSOR_GAP');
  assert.throws(() => createPageEnvelope(contract, { correlationId: 'correlation-0001', items: [], state: 'more' }), /allOf|next cursor/u);
});

test('public stream schemas require kind-specific bodies and delayed writes remain untrusted on timeout', async () => {
  const contract = await loadProtocolContract({ root: protocolRoot });
  const frames = [
    { schemaVersion: 'ogvcs.protocol/stream-frame/v1', streamId: 'public-stream-01', sequence: 0, kind: 'data', payload: { value: 1 } },
    { schemaVersion: 'ogvcs.protocol/stream-frame/v1', streamId: 'public-stream-01', sequence: 1, kind: 'terminal' },
  ];
  const chunks = [];
  const destination = new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } });
  await writeCanonicalStream(frames, destination, { contract });
  assert.equal(parseCanonicalStream(Buffer.concat(chunks), { contract }).summary.terminalKind, 'terminal');
  await assert.rejects(() => writeCanonicalStream([{ ...frames[1], payload: {} }], new Writable({ write(_chunk, _encoding, callback) { callback(); } }), { contract }), /allOf|oneOf/u);
  let writes = 0;
  const slow = new Writable({ write(_chunk, _encoding, callback) { writes += 1; setTimeout(callback, 25); } });
  await assert.rejects(() => writeCanonicalStream(frames, slow, { contract, timeoutMs: 2 }), /deadline/u);
  assert.equal(writes, 1, 'destination bytes are staging and are not trusted when the operation fails');
});

test('compact transfer carrier is request-root-only and synthetic range/resume returns exact public results', async () => {
  const [contract, authorization] = await Promise.all([
    loadProtocolContract({ root: protocolRoot }), loadAuthorizationGrantContract({ root: authorizationRoot }),
  ]);
  const carrier = createCompactTransferGrant(contract, authorization, authorizationEnvelope());
  let verifierCalls = 0;
  await validateCompactTransferGrant(contract, authorization, carrier, async () => { verifierCalls += 1; return { result: 'allow', code: 'ALLOW_EXPLICIT' }; }, { operation: 'read' });
  assert.equal(verifierCalls, 1);
  const synthetic = new SyntheticTransferProbe(Buffer.from('abcdefgh'), { maxRangeBytes: 8 });
  const base = {
    schemaVersion: 'ogvcs.protocol/transfer-probe/v1', operation: 'read', grant: carrier, resourceTag: 'resource-tag-0001',
    startOffset: 0, endOffsetExclusive: 4, contentEncoding: 'identity', followRedirects: false,
  };
  const grantOptions = {
    authorizationContract: authorization,
    authorizationContext: {},
    verifyGrant: async () => ({ result: 'allow', code: 'ALLOW_EXPLICIT' }),
    resourceTag: base.resourceTag,
  };
  const first = await synthetic.execute(contract, base, grantOptions);
  assert.equal(first.status, 'partial');
  for (const code of ['ALLOW_PUBLIC', 'ALLOW_FAKE']) {
    await assert.rejects(
      () => synthetic.execute(contract, base, { ...grantOptions, verifyGrant: async () => ({ result: 'allow', code }) }),
      /grant is invalid/u,
      code,
    );
  }
  const second = await synthetic.execute(contract, { ...base, startOffset: 4, endOffsetExclusive: 8, validatorTag: first.validatorTag }, grantOptions);
  assert.equal(second.status, 'complete');
  assert.equal(second.terminal, true);
  await assert.rejects(() => synthetic.execute(contract, { ...base, startOffset: 4, endOffsetExclusive: 8, validatorTag: 'wrong-validator-01' }, grantOptions), /stale/u);
});

test('compact transfer validation binds directly to the public OGVCS-003 verifier outcome', async () => {
  const [contract, authorization, predecessor] = await Promise.all([
    loadProtocolContract({ root: protocolRoot }), loadAuthorizationGrantContract({ root: authorizationRoot }), loadAuthorizationContract(),
  ]);
  const valid = predecessor.vectors.grants.cases.find(({ id }) => id === 'valid-request-root');
  const denied = predecessor.vectors.grants.cases.find(({ id }) => id === 'request-root-object-not-member');
  const carrier = createCompactTransferGrant(contract, authorization, valid.envelope);
  const verify = (envelope, context) => verifyTransferGrant(envelope, context, predecessor.vectors.grants.key.publicJwk);
  await assert.doesNotReject(() => validateCompactTransferGrant(contract, authorization, carrier, verify, valid.context));
  await assert.rejects(() => validateCompactTransferGrant(contract, authorization, carrier, verify, denied.context), /grant is invalid/u);
  await assert.rejects(() => validateCompactTransferGrant(contract, authorization, carrier, async () => true, valid.context), /grant is invalid/u);
});

test('every carried OGVCS-003 grant witness is evaluated or rejected as an inapplicable explicit-object carrier', async () => {
  const [contract, authorization] = await Promise.all([
    loadProtocolContract({ root: protocolRoot }), loadAuthorizationGrantContract({ root: authorizationRoot }),
  ]);
  const cases = contract.vectors.transfer.cases.filter((scenario) => scenario.predecessorCase !== undefined);
  assert.equal(cases.length, 18);
  let requestRootWitnesses = 0;
  for (const scenario of cases) {
    const envelope = JSON.parse(Buffer.from(scenario.input.probe.grant.envelope, 'base64url').toString('utf8'));
    const isRequestRoot = envelope.claims.objectIds.length === 0 && /^sha256:[0-9a-f]{64}$/u.test(envelope.claims.requestRoot ?? '');
    if (isRequestRoot) requestRootWitnesses += 1;
    let verifierCalls = 0;
    const verify = (envelope, context) => {
      verifierCalls += 1;
      return verifyTransferGrant(envelope, context, scenario.input.authorizationPublicJwk);
    };
    const validation = validateCompactTransferGrant(
      contract,
      authorization,
      scenario.input.probe.grant,
      verify,
      scenario.input.authorizationContext,
    );
    if (scenario.expected.code === 'NONE') await assert.doesNotReject(() => validation, scenario.id);
    else await assert.rejects(() => validation, undefined, scenario.id);
    assert.equal(
      verifierCalls,
      isRequestRoot ? 1 : 0,
      scenario.id,
    );
  }
  assert.equal(requestRootWitnesses, 16, 'all predecessor witnesses except the two explicit-object exclusions must reach the verifier');
});
