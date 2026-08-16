#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CONTRACT_VERSION,
  REGISTRY_SCHEMA,
  abuseCases,
  actorClasses,
  auditClasses,
  contract,
  credentialClasses,
  dataFlows,
  decisionCodes,
  goldenRepository,
  grantFixture,
  permissions,
  policies,
  resources,
  revocationClasses,
  roadmapSurfaces,
  sandboxProfiles,
  threats,
  trustZones,
} from '../source/contract.mjs';
import { allSchemas } from '../source/schemas.mjs';
import {
  canonicalBytes,
  canonicalJson,
  evaluatePolicy,
  makeRequest,
  requestRootForObjectIds,
  sha256,
  signGrantFixture,
} from '../source/reference.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.slice(2).includes('--check');
if (process.argv.length > 3 || (process.argv.length === 3 && !CHECK)) {
  throw new Error('usage: node scripts/generate.mjs [--check]');
}

function bytes(value) {
  return `${canonicalJson(value)}\n`;
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

function registry(registryName, entries) {
  return {
    schemaVersion: REGISTRY_SCHEMA,
    registry: registryName,
    version: 1,
    entries,
  };
}

const registryDocuments = {
  'abuse-cases.json': registry('abuse-cases', abuseCases),
  'actor-classes.json': registry('actor-classes', actorClasses),
  'audit-classes.json': registry('audit-classes', auditClasses),
  'credential-classes.json': registry('credential-classes', credentialClasses),
  'data-flows.json': registry('data-flows', dataFlows),
  'decision-codes.json': registry('decision-codes', decisionCodes),
  'permissions.json': registry('permissions', permissions),
  'resources.json': registry('resources', resources),
  'revocation-classes.json': registry('revocation-classes', revocationClasses),
  'roadmap-surfaces.json': registry('roadmap-surfaces', roadmapSurfaces),
  'sandbox-profiles.json': registry('sandbox-profiles', sandboxProfiles),
  'threats.json': registry('threats', threats),
  'trust-zones.json': registry('trust-zones', trustZones),
};

const permissionResource = Object.freeze({
  discover: 'public-readme',
  'metadata.read': 'shared-object',
  'content.materialize': 'shared-crate',
  'content.upload': 'shared-crate',
  'lock.create': 'outsourcer-lock',
  submit: 'main-reference',
  review: 'outsourcer-review',
  export: 'fidelity-export',
  'policy.administer': 'repository-policy',
  'lock.force-unlock': 'outsourcer-lock',
  repair: 'repository-repair',
  'retention.delete': 'repository-retention',
  'audit.read': 'repository-audit',
  impersonate: 'repository-policy',
});

function reasonFor(permission) {
  return permissions.find(({ name }) => name === permission)?.reasonRequired
    ? 'conformance privileged action'
    : null;
}

function decisionCase(id, policyName, actorId, permission, resourceId = permissionResource[permission], overrides = {}) {
  const policy = policies[policyName];
  const request = makeRequest(goldenRepository, id, actorId, resourceId, permission, {
    reason: reasonFor(permission),
    ...structuredClone(overrides),
  });
  return {
    id,
    policy: policyName,
    request,
    expected: evaluatePolicy(policy, request),
  };
}

const decisionCases = [];
for (const permission of permissions.map(({ name }) => name)) {
  const actor = permissions.find(({ name }) => name === permission).privileged ? 'studio-admin' : 'internal-alice';
  decisionCases.push(decisionCase(`internal-${permission.replaceAll('.', '-')}`, 'internal-team.json', actor, permission));
  decisionCases.push(decisionCase(`restricted-${permission.replaceAll('.', '-')}`, 'restricted-outsourcer.json', actor, permission));
}
decisionCases.push(
  decisionCase('outsourcer-shared-read', 'restricted-outsourcer.json', 'outsourcer-bob', 'content.materialize', 'shared-crate'),
  decisionCase('outsourcer-own-review', 'restricted-outsourcer.json', 'outsourcer-bob', 'review', 'outsourcer-review'),
  decisionCase('outsourcer-restricted-read', 'restricted-outsourcer.json', 'outsourcer-bob', 'content.materialize', 'restricted-hero'),
  decisionCase('outsourcer-internal-policy', 'internal-team.json', 'outsourcer-bob', 'metadata.read', 'shared-object'),
  decisionCase('anonymous-discovery', 'restricted-outsourcer.json', 'anonymous', 'discover', 'public-readme'),
  decisionCase('build-declared-path', 'restricted-outsourcer.json', 'build-ci', 'metadata.read', 'build-config'),
  decisionCase('build-restricted-path', 'restricted-outsourcer.json', 'build-ci', 'metadata.read', 'restricted-hero'),
  decisionCase('force-unlock-no-reason', 'restricted-outsourcer.json', 'studio-admin', 'lock.force-unlock', 'outsourcer-lock', { reason: null }),
  decisionCase('stale-actor-epoch', 'restricted-outsourcer.json', 'internal-alice', 'metadata.read', 'shared-object', {
    actor: { ...structuredClone(goldenRepository.actors.find(({ id }) => id === 'internal-alice')), authorityEpoch: 2 },
  }),
  decisionCase('revoked-session', 'restricted-outsourcer.json', 'outsourcer-bob', 'metadata.read', 'outsourced-npc', {
    actor: { ...structuredClone(goldenRepository.actors.find(({ id }) => id === 'outsourcer-bob')), credentialStatus: 'revoked' },
  }),
  decisionCase('policy-generation-mismatch', 'restricted-outsourcer.json', 'internal-alice', 'metadata.read', 'shared-object', {
    context: { reference: 'main', snapshot: 'snapshot-main-0001', policyGeneration: 6, authorityEpoch: 3 },
  }),
  decisionCase('deny-overrides-overlapping-allow', 'restricted-outsourcer.json', 'outsourcer-bob', 'metadata.read', 'outsourced-npc', {
    resource: {
      type: 'content', path: 'Game/Outsource/Restricted/NPC.uasset',
      fileId: '00000000000000000000000000000003',
      objectId: 'ogvcs:v1:chunk:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      name: null,
    },
  }),
);

const grantEnvelope = signGrantFixture(grantFixture);
function grantContext(overrides = {}) {
  return {
    schemaVersion: 'ogvcs.authorization/transfer-grant-context/v1',
    issuer: grantFixture.claims.issuer,
    keyId: grantFixture.claims.keyId,
    subject: grantFixture.claims.subject,
    permission: grantFixture.claims.permission,
    operation: grantFixture.claims.operation,
    audience: grantFixture.claims.audience,
    tenant: grantFixture.claims.tenant,
    repository: grantFixture.claims.repository,
    authorityEpoch: grantFixture.claims.authorityEpoch,
    keyGeneration: grantFixture.claims.keyGeneration,
    now: 2000000100,
    objectId: grantFixture.claims.objectIds[0],
    requestObjectIds: [],
    consumedNonces: [],
    ...overrides,
  };
}
const requestRootObjectIds = Object.freeze([
  grantFixture.claims.objectIds[0],
  'ogvcs:v1:chunk:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
]);
const rootClaims = {
  ...structuredClone(grantFixture.claims),
  nonce: 'grant-root-idempotent',
  replay: 'idempotent',
  objectIds: [],
  requestRoot: requestRootForObjectIds(requestRootObjectIds),
};
const rootEnvelope = signGrantFixture({ ...grantFixture, claims: rootClaims });
const grantCases = [
  {
    id: 'valid-download',
    envelope: grantEnvelope,
    context: grantContext(),
    expected: { result: 'allow', code: 'ALLOW_EXPLICIT' },
  },
  {
    id: 'wrong-audience',
    envelope: grantEnvelope,
    context: grantContext({ audience: 'cache-europe-1' }),
    expected: { result: 'deny', code: 'DENY_AUDIENCE_MISMATCH' },
  },
  {
    id: 'expired',
    envelope: grantEnvelope,
    context: grantContext({ now: 2000000301 }),
    expected: { result: 'deny', code: 'DENY_GRANT_EXPIRED' },
  },
  {
    id: 'replayed',
    envelope: grantEnvelope,
    context: grantContext({ consumedNonces: [grantFixture.claims.nonce] }),
    expected: { result: 'deny', code: 'DENY_GRANT_REPLAY' },
  },
  {
    id: 'stale-epoch',
    envelope: grantEnvelope,
    context: grantContext({ authorityEpoch: 4 }),
    expected: { result: 'deny', code: 'DENY_EPOCH_STALE' },
  },
  {
    id: 'stale-key-generation',
    envelope: grantEnvelope,
    context: grantContext({ keyGeneration: 12 }),
    expected: { result: 'deny', code: 'DENY_EPOCH_STALE' },
  },
  {
    id: 'stale-key-id',
    envelope: grantEnvelope,
    context: grantContext({ keyId: 'conformance-key-2' }),
    expected: { result: 'deny', code: 'DENY_EPOCH_STALE' },
  },
  {
    id: 'wrong-repository',
    envelope: grantEnvelope,
    context: grantContext({ repository: 'game-other' }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'wrong-object',
    envelope: grantEnvelope,
    context: grantContext({ objectId: 'ogvcs:v1:chunk:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'altered-claims',
    envelope: { ...structuredClone(grantEnvelope), claims: { ...structuredClone(grantEnvelope.claims), subject: 'internal-alice' } },
    context: grantContext(),
    expected: { result: 'deny', code: 'DENY_GRANT_INVALID' },
  },
  {
    id: 'wrong-subject',
    envelope: grantEnvelope,
    context: grantContext({ subject: 'internal-alice' }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'wrong-issuer',
    envelope: grantEnvelope,
    context: grantContext({ issuer: 'control-secondary' }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'wrong-operation',
    envelope: grantEnvelope,
    context: grantContext({ permission: 'content.upload', operation: 'upload' }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'valid-request-root',
    envelope: rootEnvelope,
    context: grantContext({ objectId: requestRootObjectIds[0], requestObjectIds: requestRootObjectIds, consumedNonces: [rootClaims.nonce] }),
    expected: { result: 'allow', code: 'ALLOW_EXPLICIT' },
  },
  {
    id: 'request-root-object-not-member',
    envelope: rootEnvelope,
    context: grantContext({
      objectId: 'ogvcs:v1:chunk:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
      requestObjectIds: requestRootObjectIds,
    }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
  {
    id: 'wrong-request-root-plan',
    envelope: rootEnvelope,
    context: grantContext({
      objectId: requestRootObjectIds[0],
      requestObjectIds: [requestRootObjectIds[0], 'ogvcs:v1:chunk:sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
    }),
    expected: { result: 'deny', code: 'DENY_RESOURCE_SCOPE' },
  },
];

const forbiddenResponseFields = Object.freeze([
  'path', 'fileId', 'objectId', 'size', 'hash', 'history', 'message', 'thumbnail',
  'dependency', 'lockOwner', 'branch', 'searchHit', 'event', 'policy', 'claims',
]);

function authorizationVector(abuseCase, policyName, actor, permission, resource, overrides = {}) {
  const caseValue = decisionCase(`vector-${abuseCase.name}`, policyName, actor, permission, resource, overrides);
  return {
    schemaVersion: 'ogvcs.authorization/threat-vector/v1',
    id: `vector-${abuseCase.name}`,
    abuseCase: abuseCase.name,
    category: abuseCase.category,
    kind: abuseCase.kind,
    input: { policy: policyName, request: caseValue.request },
    expected: {
      result: caseValue.expected.allowed ? 'allow' : 'deny',
      code: caseValue.expected.code,
    },
    forbiddenResponseFields,
  };
}

function grantVector(abuseCase, grantCaseId) {
  const fixture = grantCases.find(({ id }) => id === grantCaseId);
  return {
    schemaVersion: 'ogvcs.authorization/threat-vector/v1',
    id: `vector-${abuseCase.name}`,
    abuseCase: abuseCase.name,
    category: abuseCase.category,
    kind: abuseCase.kind,
    input: { envelope: fixture.envelope, context: fixture.context, publicJwk: grantFixture.publicJwk },
    expected: fixture.expected,
    forbiddenResponseFields,
  };
}

function genericVector(abuseCase, input, expected) {
  return {
    schemaVersion: 'ogvcs.authorization/threat-vector/v1',
    id: `vector-${abuseCase.name}`,
    abuseCase: abuseCase.name,
    category: abuseCase.category,
    kind: abuseCase.kind,
    input,
    expected,
    forbiddenResponseFields,
  };
}

const vectorFactories = {
  'guessed-object-hash': (item) => authorizationVector(item, 'internal-team.json', 'outsourcer-bob', 'content.materialize', 'shared-crate'),
  'path-enumeration': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'discover', 'restricted-hero'),
  'restricted-path-read': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'metadata.read', 'restricted-hero'),
  'search-enumeration': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'outsourcer-bob', permission: 'discover', candidates: goldenRepository.resources }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'event-enumeration': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'outsourcer-bob', permission: 'metadata.read', candidates: goldenRepository.resources }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'mixed-history': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'outsourcer-bob', permission: 'metadata.read', candidates: goldenRepository.resources }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'mixed-review': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'outsourcer-bob', permission: 'review', candidates: goldenRepository.resources }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'fidelity-export-incomplete-authorization': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'export', 'fidelity-export', { reason: 'fixture export' }),
  'projection-export-redaction': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'outsourcer-bob', permission: 'metadata.read', candidates: goldenRepository.resources, projectionIdentity: 'distinct' }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'cross-tenant-dedup': (item) => genericVector(item, { tenant: 'tenant-beta', probedTenant: 'tenant-alpha', objectId: grantFixture.claims.objectIds[0] }, { result: 'deny', code: 'DENY_TENANT_BOUNDARY' }),
  'cache-grant-replay': (item) => grantVector(item, 'replayed'),
  'wrong-cache-audience': (item) => grantVector(item, 'wrong-audience'),
  'stale-authority-epoch': (item) => grantVector(item, 'stale-epoch'),
  'expired-transfer-grant': (item) => grantVector(item, 'expired'),
  'wrong-repository-grant': (item) => grantVector(item, 'wrong-repository'),
  'altered-transfer-grant': (item) => grantVector(item, 'altered-claims'),
  'revoked-session': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'metadata.read', 'outsourced-npc', { actor: { ...structuredClone(goldenRepository.actors.find(({ id }) => id === 'outsourcer-bob')), credentialStatus: 'revoked' } }),
  'revoked-service-token': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'build-ci', 'metadata.read', 'build-config', { actor: { ...structuredClone(goldenRepository.actors.find(({ id }) => id === 'build-ci')), credentialStatus: 'revoked' } }),
  'stale-cache-decision': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'regional-cache', 'content.materialize', 'shared-cache', { actor: { ...structuredClone(goldenRepository.actors.find(({ id }) => id === 'regional-cache')), authorityEpoch: 2 } }),
  'build-token-overreach': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'build-ci', 'metadata.read', 'restricted-hero'),
  'service-token-wrong-operation': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'build-ci', 'submit', 'build-config'),
  'force-unlock-without-reason': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'studio-admin', 'lock.force-unlock', 'outsourcer-lock', { reason: null }),
  'audit-detail-enumeration': (item) => genericVector(item, { policy: 'restricted-outsourcer.json', actor: 'studio-admin', permission: 'audit.read', auditClass: 'policy.changed' }, { result: 'allow', code: 'ALLOW_EXPLICIT' }),
  'hook-network-escape': (item) => genericVector(item, { profile: 'hook-default', attempt: { network: 'allow' } }, { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' }),
  'preview-parser-escape': (item) => genericVector(item, { profile: 'preview-parser-default', attempt: { processes: 9 } }, { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' }),
  'import-parser-escape': (item) => genericVector(item, { profile: 'import-parser-default', attempt: { credentials: 'acquisition-token' } }, { result: 'deny', code: 'DENY_SANDBOX_REQUIREMENTS' }),
  'timing-class-probe': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'discover', 'restricted-hero'),
  'content-derived-key': (item) => genericVector(item, { tenant: 'tenant-alpha', keyDerivation: 'content-hash' }, { result: 'deny', code: 'DENY_TENANT_BOUNDARY' }),
  'cross-tenant-key': (item) => authorizationVector(item, 'restricted-outsourcer.json', 'outsourcer-bob', 'content.materialize', 'shared-crate', { tenant: 'tenant-beta' }),
  'request-root-membership': (item) => grantVector(item, 'request-root-object-not-member'),
};

const threatVectors = abuseCases.map((item) => {
  const factory = vectorFactories[item.name];
  if (!factory) throw new Error(`no vector factory for ${item.name}`);
  return factory(item);
});

const authorizedViewFixture = {
  schemaVersion: 'ogvcs.authorization/authorized-view-fixture/v1',
  policy: 'restricted-outsourcer.json',
  actor: 'outsourcer-bob',
  permission: 'metadata.read',
  input: goldenRepository.resources,
  expectedVisibleIds: ['shared-object', 'shared-crate', 'outsourced-npc', 'outsourcer-lock', 'outsourcer-review'],
  forbiddenAggregateFields: ['inputCount', 'hiddenCount', 'hiddenPositions', 'globalRank', 'globalCursor'],
  pagination: { algorithm: 'authorized-set-cursor-v1', pageSize: 2 },
};

const outputs = new Map();
for (const [filename, value] of Object.entries(allSchemas(contract))) {
  outputs.set(`schemas/${filename}`, bytes(value));
}
for (const [filename, value] of Object.entries(registryDocuments)) {
  outputs.set(`registries/${filename}`, bytes(value));
}
for (const [filename, value] of Object.entries(policies)) {
  outputs.set(`policies/${filename}`, bytes(value));
}
outputs.set('vectors/golden-repository.json', bytes(goldenRepository));
outputs.set('vectors/decisions.json', bytes({
  schemaVersion: 'ogvcs.authorization/decision-vectors/v1',
  cases: decisionCases,
}));
outputs.set('vectors/grants.json', bytes({
  schemaVersion: 'ogvcs.authorization/grant-vectors/v1',
  conformanceOnly: true,
  key: {
    keyId: grantFixture.claims.keyId,
    privateJwk: grantFixture.privateJwk,
    publicJwk: grantFixture.publicJwk,
  },
  cases: grantCases,
}));
outputs.set('vectors/authorized-views.json', bytes(authorizedViewFixture));
outputs.set('vectors/abuse-catalog.json', bytes({
  schemaVersion: 'ogvcs.authorization/abuse-vectors/v1',
  cases: threatVectors,
}));

const registrySetInput = Object.entries(registryDocuments)
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([filename]) => Buffer.concat([
    Buffer.from(filename, 'utf8'),
    Buffer.from([0]),
    Buffer.from(outputs.get(`registries/${filename}`), 'utf8'),
  ]));
const registrySetSha256 = sha256(Buffer.concat(registrySetInput));

const vectorPaths = [...outputs.keys()].filter((path) => path.startsWith('vectors/')).sort();
const vectorManifest = {
  schemaVersion: 'ogvcs.authorization/vector-manifest/v1',
  contractVersion: CONTRACT_VERSION,
  registrySetSha256,
  vectors: vectorPaths.map((path) => ({
    path,
    sha256: digest(outputs.get(path)),
  })),
};
outputs.set('vectors/manifest.json', bytes(vectorManifest));

const artifactPaths = [...outputs.keys()].sort();
const manifest = {
  schemaVersion: 'ogvcs.authorization/manifest/v1',
  contractVersion: CONTRACT_VERSION,
  registrySetSha256,
  schemas: Object.keys(allSchemas(contract)).length,
  registries: Object.keys(registryDocuments).length,
  policies: Object.keys(policies).length,
  decisionVectors: decisionCases.length,
  abuseVectors: threatVectors.length,
  grantVectors: grantCases.length,
  artifacts: artifactPaths.map((path) => ({ path, sha256: digest(outputs.get(path)) })),
};
outputs.set('manifest.json', bytes(manifest));

let drift = false;
for (const [relativePath, content] of outputs) {
  const destination = resolve(ROOT, relativePath);
  if (CHECK) {
    let actual;
    try {
      actual = await readFile(destination, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      actual = null;
    }
    if (actual !== content) {
      process.stderr.write(`generated artifact differs: ${relativePath}\n`);
      drift = true;
    }
  } else {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, content);
  }
}

if (CHECK && drift) process.exitCode = 1;
if (!CHECK) {
  process.stdout.write(`${JSON.stringify({
    schema: 'ogvcs.authorization.generator-result/v1',
    artifacts: outputs.size,
    registrySetSha256,
    decisionVectors: decisionCases.length,
    abuseVectors: threatVectors.length,
    grantVectors: grantCases.length,
    manifestSha256: digest(outputs.get('manifest.json')),
  })}\n`);
}
