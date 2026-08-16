import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ACTOR_CLASSES,
  AUDIT_CLASSES,
  AUDIT_CLASS_PERMISSIONS,
  CONTRACT_VERSION,
  CREDENTIAL_CLASSES,
  DECISION_CODES,
  PERMISSIONS,
  REGISTRY_SET_SHA256,
  MANIFEST_SHA256,
  REGISTRY_ASSIGNMENT_SHA256,
  RESOURCE_TYPES,
  buildAuthorizedView,
  evaluateFixturePolicy,
  evaluateSandboxAttempt,
  loadAuthorizationContract,
  requestRootForObjectIds,
  signConformanceGrant,
  verifyTransferGrant,
  validateAuditEvent,
  validateAuthorizationDecision,
} from '../src/index.mjs';

test('generated bindings and independently hashed packaged contract agree', async () => {
  const contract = await loadAuthorizationContract();
  assert.equal(CONTRACT_VERSION, '1.0.0');
  assert.equal(contract.manifest.registrySetSha256, REGISTRY_SET_SHA256);
  assert.equal(contract.manifestSha256, MANIFEST_SHA256);
  assert.deepEqual(Object.keys(REGISTRY_ASSIGNMENT_SHA256).sort(), Object.keys(contract.registries).sort());
  assert.equal(Object.isFrozen(contract), true);
  assert.equal(Object.isFrozen(contract.registries.permissions.entries), true);
  assert.deepEqual(PERMISSIONS, contract.registries.permissions.entries.map(({ name }) => name));
  assert.deepEqual(RESOURCE_TYPES, contract.registries.resources.entries.map(({ name }) => name));
  assert.deepEqual(DECISION_CODES, contract.registries['decision-codes'].entries.map(({ name }) => name));
  assert.deepEqual(ACTOR_CLASSES, contract.registries['actor-classes'].entries.map(({ name }) => name));
  assert.deepEqual(AUDIT_CLASSES, contract.registries['audit-classes'].entries.map(({ name }) => name));
  assert.deepEqual(AUDIT_CLASS_PERMISSIONS, Object.fromEntries(contract.registries['audit-classes'].entries.map(({ name, permission }) => [name, permission])));
  assert.deepEqual(CREDENTIAL_CLASSES, contract.registries['credential-classes'].entries.map(({ name }) => name));
  assert.equal(contract.registries['roadmap-surfaces'].entries.length, 45);
});

test('decision and audit-event bindings enforce their frozen relationships', async () => {
  const contract = await loadAuthorizationContract();
  const decision = contract.vectors.decisions.cases[0].expected;
  assert.deepEqual(validateAuthorizationDecision(decision), decision);
  assert.throws(() => validateAuthorizationDecision({ ...decision, allowed: !decision.allowed }), /code\/allowed relationship/);

  const auditClass = contract.registries['audit-classes'].entries[0];
  const event = {
    schemaVersion: 'ogvcs.authorization/audit-event/v1',
    eventId: 'audit-0001',
    eventClass: auditClass.name,
    occurredAt: 2_000_000_100,
    tenant: 'tenant-alpha',
    repository: 'game-main',
    actorClass: 'administrator',
    actorPseudonym: 'pseudonym:0123456789abcdef0123456789abcdef',
    permission: auditClass.permission,
    reason: 'conformance policy change',
    outcomeCode: 'ALLOW_EXPLICIT',
    correlationId: 'correlation-0001',
    details: { targetClass: 'policy', changeRef: 'change-0001' },
  };
  assert.deepEqual(validateAuditEvent(event), event);
  assert.throws(() => validateAuditEvent({ ...event, permission: 'audit.read' }), /permission does not match/);
  assert.throws(() => validateAuditEvent({ ...event, actorPseudonym: 'studio-admin' }), /actorPseudonym/);
});

test('both reference policies reproduce all 40 golden decisions exactly', async () => {
  const contract = await loadAuthorizationContract();
  const covered = new Map(Object.keys(contract.policies).map((name) => [name, new Set()]));
  for (const vector of contract.vectors.decisions.cases) {
    const actual = evaluateFixturePolicy(contract.policies[vector.policy], vector.request);
    assert.deepEqual(actual, vector.expected, vector.id);
    covered.get(vector.policy).add(vector.request.permission);
    for (const forbidden of ['path', 'fileId', 'objectId', 'policy', 'claims']) assert.equal(Object.hasOwn(actual, forbidden), false);
  }
  for (const permissions of covered.values()) assert.deepEqual(permissions, new Set(PERMISSIONS));
  assert.equal(contract.vectors.decisions.cases.find(({ id }) => id === 'outsourcer-restricted-read').expected.code, 'DENY_NOT_AUTHORIZED');
  assert.equal(contract.vectors.decisions.cases.find(({ id }) => id === 'deny-overrides-overlapping-allow').expected.code, 'DENY_NOT_AUTHORIZED');
});

test('invalid or incomplete request fails closed without echoing hostile context', async () => {
  const contract = await loadAuthorizationContract();
  const policy = contract.policies['restricted-outsourcer.json'];
  const first = evaluateFixturePolicy(policy, { requestId: 'bad-request', path: 'Game/Restricted/Secret.uasset' });
  const second = evaluateFixturePolicy(policy, { requestId: 'bad-request', path: 'different-secret' });
  assert.equal(first.allowed, false);
  assert.equal(first.code, 'DENY_CONTEXT_INCOMPLETE');
  assert.equal(first.requestId, 'bad-request');
  assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first).includes('Secret'), false);
});

test('authorized views are filtered before pagination and never disclose cache or hidden records', async () => {
  const contract = await loadAuthorizationContract();
  const fixture = contract.vectors.authorizedViews;
  const options = {
    policy: contract.policies[fixture.policy],
    repository: contract.vectors.goldenRepository,
    actorId: fixture.actor,
    permission: fixture.permission,
    candidates: fixture.input,
    pageSize: 2,
    maxCandidates: fixture.input.length,
  };
  const first = buildAuthorizedView(options);
  const second = buildAuthorizedView({ ...options, cursor: first.nextCursor });
  const third = buildAuthorizedView({ ...options, cursor: second.nextCursor });
  const ids = [...first.items, ...second.items, ...third.items].map(({ id }) => id);
  assert.deepEqual(ids, fixture.expectedVisibleIds);
  for (const hidden of ['repository-root', 'restricted-hero', 'shared-cache', 'game-search', 'game-events']) assert.equal(ids.includes(hidden), false);
  for (const page of [first, second, third]) {
    assert.deepEqual(Object.keys(page).sort(), ['items', 'nextCursor']);
    for (const forbidden of fixture.forbiddenAggregateFields) assert.equal(Object.hasOwn(page, forbidden), false);
    for (const item of page.items) assert.equal(Object.hasOwn(item, 'visibility'), false);
  }
  assert.equal(third.nextCursor, null);
  assert.throws(() => buildAuthorizedView({ ...options, candidates: [fixture.input[0], { ...fixture.input[0], path: 'Game/Restricted/Leak.uasset' }] }), /candidate IDs contain duplicates/);
});

test('all signed grant vectors verify and conformance signing is deterministic', async () => {
  const contract = await loadAuthorizationContract();
  const vectors = contract.vectors.grants;
  for (const vector of vectors.cases) {
    assert.deepEqual(verifyTransferGrant(vector.envelope, vector.context, vectors.key.publicJwk), vector.expected, vector.id);
  }
  const valid = vectors.cases.find(({ id }) => id === 'valid-download');
  assert.deepEqual(signConformanceGrant(valid.envelope.claims, vectors.key.privateJwk, { conformanceOnly: true }), valid.envelope);
  assert.throws(() => signConformanceGrant(valid.envelope.claims, vectors.key.privateJwk), /conformanceOnly/);

  const requestObjectIds = [
    valid.context.objectId,
    'ogvcs:v1:chunk:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  ];
  const rootClaims = {
    ...structuredClone(valid.envelope.claims), nonce: 'grant-root-idempotent', replay: 'idempotent',
    objectIds: [], requestRoot: requestRootForObjectIds(requestObjectIds),
  };
  const rootEnvelope = signConformanceGrant(rootClaims, vectors.key.privateJwk, { conformanceOnly: true });
  const rootContext = {
    ...structuredClone(valid.context), requestObjectIds, consumedNonces: ['grant-root-idempotent'],
  };
  assert.deepEqual(verifyTransferGrant(rootEnvelope, rootContext, vectors.key.publicJwk), { result: 'allow', code: 'ALLOW_EXPLICIT' });
  assert.deepEqual(verifyTransferGrant(rootEnvelope, {
    ...rootContext,
    requestObjectIds: [requestObjectIds[0], 'ogvcs:v1:chunk:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
  }, vectors.key.publicJwk), { result: 'deny', code: 'DENY_RESOURCE_SCOPE' });
  assert.deepEqual(verifyTransferGrant(rootEnvelope, {
    ...rootContext,
    objectId: 'ogvcs:v1:chunk:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
  }, vectors.key.publicJwk), { result: 'deny', code: 'DENY_RESOURCE_SCOPE' });
});

test('all four sandbox profiles deny their executable escape vector', async () => {
  const contract = await loadAuthorizationContract();
  const profiles = contract.registries['sandbox-profiles'].entries;
  assert.deepEqual(new Set(profiles.map(({ toolClass }) => toolClass)), new Set(['hook', 'merge-driver', 'import-parser', 'preview-parser']));
  for (const profile of profiles) {
    assert.deepEqual(evaluateSandboxAttempt(profile, { network: 'allow' }), { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' });
    assert.deepEqual(evaluateSandboxAttempt(profile, { processes: profile.runtime.processes + 1 }), { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' });
    assert.deepEqual(evaluateSandboxAttempt(profile, { network: 'deny', credentials: 'none', processes: 1 }), { result: 'allow', code: 'ALLOW_EXPLICIT' });
    assert.deepEqual(evaluateSandboxAttempt(profile, { network: 'deny', credentials: 'none', futureEscape: true }), { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' });
  }
});
