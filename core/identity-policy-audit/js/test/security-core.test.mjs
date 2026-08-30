import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  signConformanceGrant,
} from '@opengamevcs/authorization-contract';
import {
  ProtocolProblemCatalog,
  loadProtocolContract,
} from '@opengamevcs/protocol-baseline';

import {
  AuditLedger,
  AuthorityState,
  CredentialAuthority,
  FixedWindowRateLimiter,
  IdentityPolicyRuntime,
  IdentityProviderBroker,
  PolicyEngine,
  RUNTIME_LIMITS,
  TransferGrantAuthority,
  identityPolicyContract,
  metadataOperationAuthority,
  validatePolicyDocument,
} from '../src/index.mjs';
import {
  MemoryAuditStore,
  MemoryCredentialStore,
  MemoryGrantNonceLedger,
  deterministicSecretSource,
  fakeIdentityProviderAdapter,
} from '../src/testing.mjs';

const vectorDocument = JSON.parse(await readFile(new URL('../../../../spec/identity-policy-audit/v1/vectors/security-core.json', import.meta.url)));
const limitDocument = JSON.parse(await readFile(new URL('../../../../spec/identity-policy-audit/v1/registries/limits.json', import.meta.url)));
const protocolProblems = new ProtocolProblemCatalog(await loadProtocolContract());
const NOW = 1_700_000_000;
const OBJECT_ID = `ogvcs:v1:chunk:sha256:${'ab'.repeat(32)}`;

function policy(authorityEpoch = 1, additions = {}) {
  return {
    schemaVersion: 'ogvcs.identity-policy/policy/v1',
    id: 'studio.policy',
    version: 'v1',
    generation: additions.generation ?? 1,
    authorityEpoch,
    pathProfile: 'path.opengamevcs/portable@1',
    caseMode: 'case-folded',
    default: 'deny',
    composition: 'deny-overrides-v1',
    rules: additions.rules ?? [
      {
        id: 'deny.secret', effect: 'deny',
        subjects: { identities: [], groups: [], actorClasses: [] },
        tenant: 'studio', repository: 'game', references: ['main'],
        pathPrefixes: ['Game/Public/Secret'],
        resourceTypes: ['path', 'tree', 'content'],
        permissions: ['discover', 'metadata.read', 'content.materialize'],
      },
      {
        id: 'allow.artists', effect: 'allow',
        subjects: { identities: [], groups: ['artists'], actorClasses: ['human'] },
        tenant: 'studio', repository: 'game', references: ['main'],
        pathPrefixes: ['Game/Public'],
        resourceTypes: ['path', 'tree', 'content'],
        permissions: ['discover', 'metadata.read', 'content.materialize'],
      },
      {
        id: 'allow.build', effect: 'allow',
        subjects: { identities: ['build.bot'], groups: [], actorClasses: ['service'] },
        tenant: 'studio', repository: 'game', references: ['main'],
        pathPrefixes: ['Game/Public'],
        resourceTypes: ['path', 'content'],
        permissions: ['discover', 'metadata.read', 'content.materialize'],
      },
      {
        id: 'allow.admin.audit', effect: 'allow',
        subjects: { identities: ['admin.user'], groups: [], actorClasses: ['administrator'] },
        tenant: 'studio', repository: 'game', references: [], pathPrefixes: [],
        resourceTypes: ['audit', 'policy'], permissions: ['audit.read', 'policy.administer'],
      },
    ],
  };
}

function request({ path = 'Game/Public/asset.uasset', tenant = 'studio', repository = 'game', permission = 'metadata.read', type = 'path', epoch = 1, generation = 1, requestId = 'request.same', reason = null } = {}) {
  return {
    schemaVersion: 'ogvcs.authorization/request/v1', requestId,
    actor: { id: 'anonymous', class: 'anonymous', groups: [], credentialClass: 'anonymous', credentialGeneration: 1, credentialStatus: 'revoked', authorityEpoch: epoch },
    tenant, repository, permission, reason,
    resource: { type, path, fileId: null, objectId: type === 'content' ? OBJECT_ID : null, name: null },
    context: { reference: 'main', snapshot: 'snapshot.main', policyGeneration: generation, authorityEpoch: epoch },
  };
}

function scope(permissions = ['discover', 'metadata.read', 'content.materialize']) {
  return { tenants: ['studio'], repositories: ['game'], references: ['main'], pathPrefixes: [''], permissions };
}

function event(id, overrides = {}) {
  return {
    schemaVersion: 'ogvcs.authorization/audit-event/v1', eventId: id,
    eventClass: overrides.eventClass ?? 'grant.revoked', occurredAt: NOW,
    tenant: 'studio', repository: overrides.repository ?? 'game', actorClass: 'administrator',
    actorPseudonym: `pseudonym:${'12'.repeat(16)}`,
    permission: overrides.permission ?? 'policy.administer', reason: overrides.reason ?? 'security administration',
    outcomeCode: 'ALLOW_EXPLICIT', correlationId: id,
    details: { targetClass: overrides.targetClass ?? 'credential', changeRef: overrides.changeRef ?? id },
  };
}

function fixture({ authorityEpoch = 1, failureHook, rateLimit = 100 } = {}) {
  const clock = { now: NOW };
  const state = new AuthorityState({ authorityEpoch, keyGeneration: authorityEpoch });
  const credentialStore = new MemoryCredentialStore({ maxCredentials: 100 });
  const credentials = new CredentialAuthority({
    store: credentialStore, authorityState: state,
    secretSource: deterministicSecretSource(`epoch-${authorityEpoch}`), clock: () => clock.now,
    pathProfile: 'path.opengamevcs/portable@1', caseMode: 'case-folded',
  });
  const engine = new PolicyEngine(policy(authorityEpoch), { failureHook });
  const rate = new FixedWindowRateLimiter({ limit: rateLimit, windowSeconds: 60, maxBuckets: 100, clock: () => clock.now });
  const runtime = new IdentityPolicyRuntime({ policyEngine: engine, credentialAuthority: credentials, rateLimiter: rate, protocolProblems });
  return { clock, state, credentialStore, credentials, engine, rate, runtime };
}

function issueArtist(context) {
  return context.credentials.issue({
    credentialClass: 'session', subject: 'artist.one', actorClass: 'human', groups: ['artists'],
    ttlSeconds: 600, scope: scope(),
  });
}

function issueService(context) {
  return context.credentials.issue({
    credentialClass: 'service-token', subject: 'build.bot', actorClass: 'service', groups: [],
    ttlSeconds: 300, scope: scope(),
  });
}

function grantAuthority(context, { claimsTransform = (claims) => claims } = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  return new TransferGrantAuthority({
    authorityState: context.state, credentialAuthority: context.credentials, policyEngine: context.engine,
    nonceLedger: new MemoryGrantNonceLedger({ maximum: 100 }),
    issuer: 'identity.service', keyId: 'grant.key', clock: () => context.clock.now,
    signer: { sign: (claims) => signConformanceGrant(claimsTransform(claims), privateJwk, { conformanceOnly: true }) },
    keyResolver: () => publicJwk,
  });
}

function issueGrant(context, authority, principal, nonce = 'nonce.one') {
  const authorizationRequest = request({ permission: 'content.materialize', type: 'content' });
  return authority.issue(principal, {
    authorizationRequest, tenant: 'studio', repository: 'game', permission: 'content.materialize',
    operation: 'download', audience: 'object.service', ttlSeconds: 60, nonce, replay: 'single-use',
    objectIds: [OBJECT_ID], requestRoot: null,
  });
}

function grantContext(subject = 'artist.one') {
  return {
    schemaVersion: 'ogvcs.authorization/transfer-grant-context/v1', issuer: 'untrusted', keyId: 'untrusted',
    subject, permission: 'content.materialize', operation: 'download', audience: 'object.service',
    tenant: 'studio', repository: 'game', authorityEpoch: 999, keyGeneration: 999, now: 0,
    objectId: OBJECT_ID, requestObjectIds: [], consumedNonces: [],
  };
}

const scenarios = {
  'canonical-path-allow': () => {
    const context = fixture(); const issued = issueArtist(context); const outcome = context.runtime.authorizeToken(issued.token, request());
    assert.equal(outcome.decision.code, 'ALLOW_EXPLICIT');
  },
  'explicit-deny-overrides': () => {
    const context = fixture(); const issued = issueArtist(context);
    assert.equal(context.runtime.authorizeToken(issued.token, request({ path: 'Game/Public/Secret/plan.txt' })).decision.code, 'DENY_NOT_AUTHORIZED');
  },
  'malformed-path-fails-closed': () => {
    const context = fixture(); const issued = issueArtist(context);
    assert.equal(context.runtime.authorizeToken(issued.token, request({ path: 'Game/../Secret' })).decision.code, 'DENY_CONTEXT_INCOMPLETE');
    const hostile = new Proxy({}, { get() { throw new Error('hostile accessor'); }, ownKeys() { throw new Error('hostile keys'); } });
    assert.equal(context.engine.authorize(hostile).code, 'DENY_CONTEXT_INCOMPLETE');
  },
  'evaluator-failure-fails-closed': () => {
    const context = fixture({ failureHook: () => { throw new Error('policy dependency down'); } }); const issued = issueArtist(context);
    assert.equal(context.runtime.authorizeToken(issued.token, request()).decision.code, 'DENY_POLICY_UNAVAILABLE');
  },
  'authorized-view-hides-paths-and-counts': () => {
    const context = fixture(); const issued = issueArtist(context);
    const result = context.runtime.authorizedView(issued.token, {
      request: request({ path: 'Game/Public', type: 'tree' }),
      candidates: [
        { id: 'visible', path: 'Game/Public/a.txt' },
        { id: 'secret', path: 'Game/Public/Secret/b.txt' },
        { id: 'outside', path: 'Engine/Internal/c.txt' },
      ],
      resourceFor: (candidate) => ({ type: 'path', path: candidate.path, fileId: null, objectId: null, name: null }),
    });
    assert.deepEqual(result.view.items.map(({ id }) => id), ['visible']);
    assert.equal(result.view.partialView, true);
    assert.doesNotMatch(JSON.stringify(result.view), /secret|outside|total|hidden/iu);
  },
  'session-stale-epoch': () => {
    const context = fixture(); const issued = issueArtist(context);
    context.state.promote({ authorityEpoch: 2, keyGeneration: 2, audit: () => {} });
    const engine = new PolicyEngine(policy(2));
    const runtime = new IdentityPolicyRuntime({ policyEngine: engine, credentialAuthority: context.credentials, rateLimiter: context.rate, protocolProblems });
    assert.equal(runtime.authorizeToken(issued.token, request({ epoch: 2 })).authorizationCode, 'DENY_EPOCH_STALE');
  },
  'service-token-revoked': () => {
    const context = fixture(); const issued = issueService(context);
    context.credentials.revoke(issued.descriptor.id, { audit: () => {} });
    assert.equal(context.runtime.authorizeToken(issued.token, request()).decision.code, 'DENY_NOT_AUTHORIZED');
  },
  'transfer-grant-stale-epoch': () => {
    const context = fixture(); const issued = issueArtist(context); const principal = context.credentials.authenticate(issued.token);
    const authority = grantAuthority(context); const envelope = issueGrant(context, authority, principal);
    context.state.promote({ authorityEpoch: 2, keyGeneration: 2, audit: () => {} });
    assert.equal(authority.verify(envelope, grantContext()).code, 'DENY_EPOCH_STALE');
  },
  'transfer-grant-revoked': () => {
    const context = fixture(); const issued = issueArtist(context); const principal = context.credentials.authenticate(issued.token);
    const authority = grantAuthority(context); const envelope = issueGrant(context, authority, principal);
    authority.revokeNonce('nonce.one', { audit: () => {} });
    assert.equal(authority.verify(envelope, grantContext()).code, 'DENY_GRANT_INVALID');
  },
  'authority-promotion-audited': () => {
    const context = fixture(); const issued = issueArtist(context);
    const store = new MemoryAuditStore(); const ledger = new AuditLedger({ store });
    context.state.promote({ authorityEpoch: 2, keyGeneration: 2, audit: () => ledger.append(event('epoch.2', { eventClass: 'authority.epoch-changed', changeRef: 'epoch.2', targetClass: 'authority' })) });
    assert.deepEqual(ledger.verify('studio'), { valid: true, records: 1, tailHash: store.tail('studio').recordHash });
    assert.throws(() => context.credentials.authenticate(issued.token), ({ code }) => code === 'EPOCH_STALE');
  },
  'audit-chain-tamper': () => {
    for (const mutation of ['remove', 'insert', 'reorder', 'modify']) {
      const store = new MemoryAuditStore(); const ledger = new AuditLedger({ store });
      ledger.append(event('audit.one')); ledger.append(event('audit.two'));
      const records = store.list('studio', 10);
      if (mutation === 'remove') records.shift();
      if (mutation === 'insert') records.splice(1, 0, structuredClone(records[0]));
      if (mutation === 'reorder') records.reverse();
      if (mutation === 'modify') records[0].event.reason = 'changed after append';
      store.unsafeReplaceForTest('studio', records);
      assert.throws(() => ledger.verify('studio'), ({ code }) => code === 'AUDIT_INTEGRITY', mutation);
    }
    const trustedStore = new MemoryAuditStore(); const trusted = new AuditLedger({ store: trustedStore });
    trusted.append(event('audit.one')); trusted.append(event('audit.two'));
    const checkpoint = trusted.checkpoint('studio');
    const rewrittenStore = new MemoryAuditStore(); const rewritten = new AuditLedger({ store: rewrittenStore });
    rewritten.append(event('audit.one', { reason: 'rewritten history' })); rewritten.append(event('audit.two'));
    trustedStore.unsafeReplaceForTest('studio', rewrittenStore.list('studio', 10));
    assert.throws(() => trusted.verify('studio', { expectedCheckpoint: checkpoint }), ({ code }) => code === 'AUDIT_INTEGRITY', 'full rewrite');
  },
  'cross-tenant-path-enumeration': () => {
    const context = fixture(); const issued = issueArtist(context);
    const outcomes = [
      request({ path: 'Game/Public/Secret/known.txt' }),
      request({ path: 'Game/Public/Secret/unknown.txt' }),
      request({ path: 'Game/Public/asset.uasset', tenant: 'other' }),
    ].map((candidate) => context.runtime.authorizeToken(issued.token, candidate));
    assert.ok(outcomes.every(({ decision }) => decision.code === 'DENY_NOT_AUTHORIZED'));
    assert.ok(outcomes.every(({ problem }) => JSON.stringify(problem) === JSON.stringify(outcomes[0].problem)));
  },
  'rate-limit-before-lookup': () => {
    const run = (secondPath) => {
      const context = fixture({ rateLimit: 1 }); const issued = issueArtist(context);
      context.runtime.authorizeToken(issued.token, request({ path: 'Game/Public/a.txt' }));
      return context.runtime.authorizeToken(issued.token, request({ path: secondPath }));
    };
    const known = run('Game/Public/Secret/known.txt'); const unknown = run('Game/Public/Secret/unknown.txt');
    assert.equal(known.decision.code, 'DENY_RATE_LIMITED'); assert.equal(unknown.decision.code, 'DENY_RATE_LIMITED');
    assert.deepEqual(known.problem, unknown.problem);
  },
  'policy-rule-resource-bound': () => {
    const base = policy(); const rule = base.rules[1];
    const rules = Array.from({ length: 1_025 }, (_, index) => ({ ...structuredClone(rule), id: `rule.${index}` }));
    assert.throws(() => validatePolicyDocument({ ...base, rules }), ({ code }) => code === 'LIMIT_EXCEEDED');
  },
  'authorized-view-resource-bound': () => {
    const context = fixture(); const issued = issueArtist(context);
    assert.throws(() => context.runtime.authorizedView(issued.token, {
      request: request({ path: 'Game/Public', type: 'tree' }), candidates: [{ path: 'Game/Public/a' }, { path: 'Game/Public/b' }, { path: 'Game/Public/c' }],
      maxCandidates: 2,
      resourceFor: (candidate) => ({ type: 'path', path: candidate.path, fileId: null, objectId: null, name: null }),
    }), ({ code }) => code === 'LIMIT_EXCEEDED');
  },
};

for (const vector of vectorDocument.cases) {
  test(`security vector: ${vector.id}`, async () => {
    assert.equal(typeof scenarios[vector.id], 'function', `missing executor for ${vector.id}`);
    await scenarios[vector.id]();
  });
}

test('runtime imports exact metadata assignments and candidate contract pins', () => {
  assert.equal(identityPolicyContract.contractVersion, '0.1.0');
  assert.deepEqual(
    { permission: metadataOperationAuthority('tree.page').permission, resourceType: metadataOperationAuthority('tree.page').resourceType },
    { permission: 'metadata.read', resourceType: 'tree' },
  );
  assert.throws(() => metadataOperationAuthority('outbox.claim'), ({ code }) => code === 'INPUT_INVALID');
});

test('runtime resource limits exactly match the authenticated contract registry', () => {
  assert.deepEqual(
    RUNTIME_LIMITS,
    Object.fromEntries(limitDocument.entries.map(({ name, value }) => [name, value])),
  );
});

test('stored credential state contains a digest but never the returned secret', () => {
  const context = fixture(); const issued = issueService(context); const stored = context.credentialStore.get(issued.descriptor.id);
  assert.match(stored.secretDigest, /^[0-9a-f]{64}$/u);
  assert.equal(Object.hasOwn(stored, 'token'), false);
  assert.equal(JSON.stringify(stored).includes(issued.token), false);
});

test('direct principal checks reject expired and forged authenticated attributes', () => {
  const context = fixture(); const issued = issueArtist(context);
  const principal = context.credentials.authenticate(issued.token);
  assert.equal(context.credentials.authorizePrincipal(principal, request()), true);
  assert.equal(context.credentials.authorizePrincipal(structuredClone(principal), request()), false);
  const forged = structuredClone(principal);
  forged.actor.groups = ['artists', 'administrators'];
  assert.equal(context.credentials.authorizePrincipal(forged, request()), false);
  context.clock.now = issued.descriptor.expiresAt;
  assert.equal(context.credentials.authorizePrincipal(principal, request()), false);
});

test('an exact structural principal forgery cannot issue a transfer grant', () => {
  const context = fixture(); const issued = issueArtist(context);
  const forged = structuredClone(context.credentials.authenticate(issued.token));
  assert.throws(
    () => issueGrant(context, grantAuthority(context), forged),
    ({ code }) => code === 'AUTHENTICATION_DENIED',
  );
});

test('single-use replay state is authority-owned and consumed atomically', () => {
  const context = fixture(); const issued = issueArtist(context);
  const principal = context.credentials.authenticate(issued.token);
  const authority = grantAuthority(context); const envelope = issueGrant(context, authority, principal);
  const hostileContext = { ...grantContext(), consumedNonces: ['nonce.one'] };
  assert.equal(authority.verify(envelope, hostileContext).code, 'ALLOW_EXPLICIT');
  assert.equal(authority.verify(envelope, grantContext()).code, 'DENY_GRANT_REPLAY');
});

test('oversized credential tokens share the bounded invalid rate class', () => {
  const context = fixture({ rateLimit: 1 });
  const oversized = 'x'.repeat(2_048);
  assert.equal(context.runtime.authorizeToken(oversized, request()).decision.code, 'DENY_NOT_AUTHORIZED');
  assert.equal(context.runtime.authorizeToken(`${oversized}y`, request()).decision.code, 'DENY_RATE_LIMITED');
});

test('grant signer output must bind the exact post-policy claims', () => {
  const context = fixture(); const issued = issueArtist(context);
  const principal = context.credentials.authenticate(issued.token);
  const authority = grantAuthority(context, {
    claimsTransform: (claims) => ({ ...claims, subject: 'substituted.subject' }),
  });
  assert.throws(
    () => issueGrant(context, authority, principal),
    ({ code }) => code === 'POLICY_UNAVAILABLE',
  );
});

test('audit reads require a fresh audit.read decision, not a caller-supplied allow value', () => {
  const context = fixture();
  const adminScope = { ...scope(['audit.read', 'policy.administer']), pathPrefixes: [] };
  const admin = context.credentials.issue({ credentialClass: 'session', subject: 'admin.user', actorClass: 'administrator', groups: [], ttlSeconds: 600, scope: adminScope });
  const artist = issueArtist(context);
  const store = new MemoryAuditStore(); const ledger = new AuditLedger({ store }); ledger.append(event('audit.readable'));
  const checkpoint = ledger.checkpoint('studio');
  const auditRequest = request({ path: null, permission: 'audit.read', type: 'audit', reason: 'security review' });
  const adminPrincipal = context.credentials.authenticate(admin.token);
  assert.equal(ledger.viewForAuthorizedRequest('studio', {
    engine: context.engine, principal: adminPrincipal, credentialAuthority: context.credentials,
    request: auditRequest, expectedCheckpoint: checkpoint,
  }).items.length, 1);
  const artistPrincipal = context.credentials.authenticate(artist.token);
  assert.throws(() => ledger.viewForAuthorizedRequest('studio', {
    engine: context.engine, principal: artistPrincipal, credentialAuthority: context.credentials,
    request: auditRequest, expectedCheckpoint: checkpoint,
  }), ({ code }) => code === 'AUTHENTICATION_DENIED');
});

test('OIDC surfaces remain behind an injected adapter and bounded fake', async () => {
  const broker = new IdentityProviderBroker([fakeIdentityProviderAdapter()]);
  const started = await broker.begin('fake-oidc', 'authorization-code-pkce', { redirect: 'loopback' });
  const completed = await broker.complete('fake-oidc', 'authorization-code-pkce', { handle: started.handle });
  assert.equal(completed.subject, 'user.test');
  await assert.rejects(() => broker.begin('missing', 'device-code', {}), ({ code }) => code === 'AUTHENTICATION_DENIED');
});

test('policy profiles are validated even when every rule is repository-scoped', () => {
  const source = policy();
  source.pathProfile = 'path.unknown/missing@1';
  source.rules = source.rules.map((rule) => ({ ...rule, pathPrefixes: [] }));
  assert.throws(() => validatePolicyDocument(source), ({ code }) => code === 'INPUT_INVALID');
});

test('audited mutations reject async and reentrant callbacks before changing state', () => {
  const context = fixture(); const issued = issueService(context);
  assert.throws(
    () => context.credentials.revoke(issued.descriptor.id, { audit: () => Promise.resolve() }),
    ({ code }) => code === 'POLICY_UNAVAILABLE',
  );
  assert.equal(context.credentials.authenticate(issued.token).actor.id, 'build.bot');
  assert.throws(
    () => context.state.promote({ authorityEpoch: 2, keyGeneration: 2, audit: () => context.state.promote({ authorityEpoch: 2, keyGeneration: 2, audit: () => {} }) }),
    ({ code }) => code === 'POLICY_UNAVAILABLE',
  );
  assert.equal(context.state.authorityEpoch, 1);
});

test('credential revocation is idempotent and does not enumerate unknown identifiers', () => {
  const context = fixture(); let audits = 0;
  assert.equal(context.credentials.revoke('credential.ffffffffffffffffffffffff', { audit: () => { audits += 1; } }), true);
  assert.equal(audits, 1);
  const issued = issueService(context);
  assert.equal(context.credentials.revoke(issued.descriptor.id, { audit: () => { audits += 1; } }), true);
  assert.equal(context.credentials.revoke(issued.descriptor.id, { audit: () => { audits += 1; } }), true);
  assert.equal(audits, 2);
});

test('transfer grants cannot widen the object authorized by the policy request', () => {
  const context = fixture(); const issued = issueArtist(context); const principal = context.credentials.authenticate(issued.token);
  const authority = grantAuthority(context);
  const otherObject = `ogvcs:v1:chunk:sha256:${'cd'.repeat(32)}`;
  assert.throws(() => authority.issue(principal, {
    authorizationRequest: request({ permission: 'content.materialize', type: 'content' }),
    tenant: 'studio', repository: 'game', permission: 'content.materialize', operation: 'download',
    audience: 'object.service', ttlSeconds: 60, nonce: 'nonce.other', replay: 'single-use',
    objectIds: [otherObject], requestRoot: null,
  }), ({ code }) => code === 'AUTHENTICATION_DENIED');
});

test('rate buckets expire within their bounded window instead of permanently denying new subjects', () => {
  let now = NOW;
  const limiter = new FixedWindowRateLimiter({ limit: 10, windowSeconds: 60, maxBuckets: 1, clock: () => now });
  assert.equal(limiter.consume('first', 'auth').allowed, true);
  assert.equal(limiter.consume('second', 'auth').allowed, false);
  now += 60;
  assert.equal(limiter.consume('second', 'auth').allowed, true);
});

test('authorized views bound candidate bytes before cloning or projection', () => {
  const context = fixture(); const issued = issueArtist(context);
  assert.throws(() => context.runtime.authorizedView(issued.token, {
    request: request({ path: 'Game/Public', type: 'tree' }),
    candidates: [{ path: 'Game/Public/asset', padding: 'x'.repeat(70 * 1024) }],
    resourceFor: (candidate) => ({ type: 'path', path: candidate.path, fileId: null, objectId: null, name: null }),
  }), ({ code }) => code === 'LIMIT_EXCEEDED');
});

test('storage, clock, and rate adapter failures are stable and fail closed', () => {
  const state = new AuthorityState();
  const credentials = new CredentialAuthority({
    store: { get() { throw new Error('offline'); }, put() {}, nextGeneration() { return 1; } },
    authorityState: state,
    secretSource: deterministicSecretSource(),
  });
  assert.throws(() => credentials.issue({
    credentialClass: 'service-token', subject: 'build.bot', actorClass: 'service', groups: [],
    ttlSeconds: 10, scope: scope(),
  }), ({ code, name }) => code === 'POLICY_UNAVAILABLE' && name === 'IdentityPolicyError');

  const context = fixture(); const issued = issueArtist(context);
  const runtime = new IdentityPolicyRuntime({
    policyEngine: context.engine,
    credentialAuthority: context.credentials,
    rateLimiter: { consume() { throw new Error('offline'); } },
    protocolProblems,
  });
  assert.equal(runtime.authorizeToken(issued.token, request()).decision.code, 'DENY_POLICY_UNAVAILABLE');
  const limiter = new FixedWindowRateLimiter({ limit: 1, windowSeconds: 60, clock: () => { throw new Error('offline'); } });
  assert.deepEqual(limiter.consume('subject', 'auth'), { allowed: false, retryAfterSeconds: 60 });
});

test('audit views verify the checkpoint and hide cross-repository chain gaps', () => {
  const context = fixture();
  const adminScope = { ...scope(['audit.read', 'policy.administer']), pathPrefixes: [] };
  const admin = context.credentials.issue({ credentialClass: 'session', subject: 'admin.user', actorClass: 'administrator', groups: [], ttlSeconds: 600, scope: adminScope });
  const principal = context.credentials.authenticate(admin.token);
  const store = new MemoryAuditStore(); const ledger = new AuditLedger({ store });
  ledger.append(event('audit.other', { repository: 'other' })); ledger.append(event('audit.game'));
  const checkpoint = ledger.checkpoint('studio');
  const auditRequest = request({ path: null, permission: 'audit.read', type: 'audit', reason: 'security review' });
  const view = ledger.viewForAuthorizedRequest('studio', {
    engine: context.engine, principal, credentialAuthority: context.credentials,
    request: auditRequest, expectedCheckpoint: checkpoint,
  });
  assert.equal(view.items.length, 1); assert.equal(view.items[0].repository, 'game');
  assert.doesNotMatch(JSON.stringify(view), /audit\.other|sequence|previousHash|recordHash|tailHash|hidden|count/iu);
  assert.deepEqual(view.items[0].disclosure, { targetClass: 'credential' });
  assert.doesNotMatch(JSON.stringify(view.items[0]), /actorPseudonym|reason|changeRef|eventId/iu);
  assert.equal(ledger.verify('studio').records, 2);
});

test('audit views fail closed on reordered linkage before returning a projection', () => {
  const context = fixture();
  const adminScope = { ...scope(['audit.read', 'policy.administer']), pathPrefixes: [] };
  const admin = context.credentials.issue({ credentialClass: 'session', subject: 'admin.user', actorClass: 'administrator', groups: [], ttlSeconds: 600, scope: adminScope });
  const principal = context.credentials.authenticate(admin.token);
  const store = new MemoryAuditStore(); const ledger = new AuditLedger({ store });
  ledger.append(event('audit.one')); ledger.append(event('audit.two'));
  const checkpoint = ledger.checkpoint('studio');
  store.unsafeReplaceForTest('studio', store.list('studio', 10).reverse());
  const auditRequest = request({ path: null, permission: 'audit.read', type: 'audit', reason: 'security review' });
  assert.throws(() => ledger.viewForAuthorizedRequest('studio', {
    engine: context.engine, principal, credentialAuthority: context.credentials,
    request: auditRequest, expectedCheckpoint: checkpoint,
  }), ({ code }) => code === 'AUDIT_INTEGRITY');
});
