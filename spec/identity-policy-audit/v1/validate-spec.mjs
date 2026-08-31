#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultRoot = dirname(fileURLToPath(import.meta.url));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const unique = (values) => new Set(values).size === values.length;
const ordered = (value) => Array.isArray(value) ? value.map(ordered)
  : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, ordered(value[key])]))
    : value;
const canonical = (value) => `${JSON.stringify(ordered(value))}\n`;
const setDigest = (entries) => digest(canonical(entries
  .map(({ path, sha256 }) => ({ path, sha256 }))
  .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)));

// These literals deliberately do not import the generator model. They are the
// independent compatibility boundary for the candidate authority.
const EXPECTED_LIMITS = Object.freeze({
  maxPolicyRules: 1_024,
  maxRuleSubjects: 128,
  maxRulePathPrefixes: 128,
  maxAuthorizedViewCandidates: 10_000,
  maxAuthorizedViewItems: 1_000,
  maxCredentials: 100_000,
  maxAuditRecordBytes: 16_384,
  maxAuditQueryRecords: 10_000,
  maxRateBuckets: 100_000,
  maxTokenBytes: 1_024,
  maxAuthenticationTransactions: 100_000,
  maxOidcResponseBytes: 262_144,
  maxOidcGroups: 128,
  maxPolicyPreviewRequests: 1_000,
  maxBatchAuthorizationResources: 1_000,
  maxDecisionCommitmentBytes: 2_048,
  maxBootstrapFailedAttempts: 10,
  authorizationCodeTtlSeconds: 600,
  deviceCodeTtlSeconds: 900,
  oidcClockSkewSeconds: 60,
  oidcNetworkTimeoutMilliseconds: 10_000,
  revocationMaximumLagSeconds: 5,
  sessionMaxTtlSeconds: 28_800,
  serviceTokenMaxTtlSeconds: 3_600,
  transferGrantMaxTtlSeconds: 300,
});

const EXPECTED_SCHEMAS = Object.freeze([
  'AuditChainRecord.schema.json',
  'AuditCheckpoint.schema.json',
  'AuthenticationTransaction.schema.json',
  'AuthorityState.schema.json',
  'AuthorizationInvocation.schema.json',
  'AuthorizedAuditEvent.schema.json',
  'AuthorizedAuditView.schema.json',
  'BootstrapState.schema.json',
  'CredentialRecord.schema.json',
  'EpochPromotionReceipt.schema.json',
  'OidcProvider.schema.json',
  'PolicyDocument.schema.json',
  'PolicyMutation.schema.json',
  'RevocationReceipt.schema.json',
  'TransactionAuthorizedView.schema.json',
  'TransactionCredentialEvidence.schema.json',
  'TransactionDecisionCommitment.schema.json',
]);

const EXPECTED_VECTORS = Object.freeze({
  'security-core.json': Object.freeze({
    'canonical-path-allow': 'allow',
    'explicit-deny-overrides': 'DENY_NOT_AUTHORIZED',
    'malformed-path-fails-closed': 'DENY_CONTEXT_INCOMPLETE',
    'evaluator-failure-fails-closed': 'DENY_POLICY_UNAVAILABLE',
    'authorized-view-hides-paths-and-counts': 'non-disclosing',
    'session-stale-epoch': 'DENY_EPOCH_STALE',
    'service-token-revoked': 'DENY_NOT_AUTHORIZED',
    'transfer-grant-stale-epoch': 'DENY_EPOCH_STALE',
    'transfer-grant-revoked': 'DENY_GRANT_INVALID',
    'authority-promotion-audited': 'verified',
    'audit-chain-tamper': 'tamper-detected',
    'cross-tenant-path-enumeration': 'same-safe-error',
    'rate-limit-before-lookup': 'DENY_RATE_LIMITED',
    'policy-rule-resource-bound': 'LIMIT_EXCEEDED',
    'authorized-view-resource-bound': 'LIMIT_EXCEEDED',
  }),
  'production-boundaries.json': Object.freeze({
    'oidc-pkce-code-success': 'session-issued',
    'oidc-state-replay-denied': 'AUTHENTICATION_DENIED',
    'oidc-id-token-signature-invalid': 'AUTHENTICATION_DENIED',
    'oidc-outage-no-local-fallback': 'AUTHENTICATION_DENIED',
    'device-flow-slow-down': 'pending',
    'bootstrap-disable-requires-recovery': 'STATE_CONFLICT',
    'policy-preview-cas-audit': 'committed',
    'policy-change-lost-race': 'STATE_CONFLICT',
    'transaction-credential-caller-epoch-ignored': 'DENY_EPOCH_STALE',
    'transaction-view-resource-substitution': 'DENY_NOT_AUTHORIZED',
    'transaction-decision-commitment-same-tx': 'committed',
    'trusted-checkpoint-request-substitution': 'AUDIT_INTEGRITY',
    'revocation-receipt-bounded': 'revoked',
    'rotating-invalid-token-source-rate': 'DENY_RATE_LIMITED',
  }),
});

const schema = async (root, name) => JSON.parse(await readFile(resolve(root, 'schemas', name)));
const exactKeys = (value, expected, message) => {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assert(JSON.stringify(actual) === JSON.stringify(wanted), message);
};

export async function validateIdentityPolicyContract(root = defaultRoot) {
  const manifestBytes = await readFile(resolve(root, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes);
  assert(manifest.schemaVersion === 'ogvcs.identity-policy/contract-manifest/v1', 'manifest schema is invalid');
  assert(manifest.contractVersion === '0.2.0' && manifest.state === 'candidate', 'contract lifecycle differs');
  assert(manifest.packageName === '@opengamevcs/identity-policy-audit-contract-v1'
    && manifest.license === 'MIT', 'contract identity differs');
  assert(manifest.protocolBinding === 'unassigned-future-release-required', 'candidate claimed a frozen protocol assignment');
  assert(manifest.counts.artifacts === 21 && manifest.counts.registries === 2
    && manifest.counts.schemas === 17 && manifest.counts.vectors === 29
    && manifest.counts.limits === 25, 'manifest counts differ');
  assert(unique(manifest.artifacts.map(({ path }) => path)), 'artifact paths repeat');

  const expectedArtifactPaths = [
    'registries/limits.json', 'registries/schemas.json',
    ...EXPECTED_SCHEMAS.map((name) => `schemas/${name}`),
    ...Object.keys(EXPECTED_VECTORS).map((name) => `vectors/${name}`),
  ].sort();
  assert(JSON.stringify(manifest.artifacts.map(({ path }) => path).sort()) === JSON.stringify(expectedArtifactPaths),
    'artifact inventory differs');
  for (const artifact of manifest.artifacts) {
    assert(artifact.mediaType === 'application/json', `artifact media type differs: ${artifact.path}`);
    const bytes = await readFile(resolve(root, artifact.path));
    assert(bytes.length === artifact.bytes, `artifact length differs: ${artifact.path}`);
    assert(digest(bytes) === artifact.sha256, `artifact authentication failed: ${artifact.path}`);
  }
  assert(setDigest(manifest.artifacts) === manifest.artifactSetSha256, 'artifact set digest differs');
  assert(setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('registries/'))) === manifest.registrySetSha256,
    'registry set digest differs');
  assert(setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('schemas/'))) === manifest.schemaSetSha256,
    'schema set digest differs');
  assert(setDigest(manifest.artifacts.filter(({ path }) => path.startsWith('vectors/'))) === manifest.vectorSetSha256,
    'vector set digest differs');
  const [modelBytes, generatorBytes] = await Promise.all([
    readFile(resolve(root, 'source/model.mjs')),
    readFile(resolve(root, 'source/generate.mjs')),
  ]);
  assert(manifest.generatedBy.modelSha256 === digest(modelBytes)
    && manifest.generatedBy.generatorSha256 === digest(generatorBytes), 'generator source binding differs');

  const limits = JSON.parse(await readFile(resolve(root, 'registries/limits.json')));
  assert(limits.schemaVersion === 'ogvcs.identity-policy/registry/v1'
    && limits.registry === 'limits' && limits.version === 1 && limits.license === 'MIT', 'limit registry identity differs');
  assert(limits.entries.length === manifest.counts.limits, 'limit registry differs');
  assert(unique(limits.entries.map(({ code }) => code)) && unique(limits.entries.map(({ name }) => name)), 'limit assignments repeat');
  assert(limits.entries.every(({ code }, index) => code === index + 1), 'limit codes are not contiguous');
  const byName = Object.fromEntries(limits.entries.map(({ name, value }) => [name, value]));
  exactKeys(byName, Object.keys(EXPECTED_LIMITS), 'limit names differ');
  for (const [name, value] of Object.entries(EXPECTED_LIMITS)) assert(byName[name] === value, `limit differs: ${name}`);

  const schemaRegistry = JSON.parse(await readFile(resolve(root, 'registries/schemas.json')));
  assert(schemaRegistry.schemaVersion === 'ogvcs.identity-policy/registry/v1'
    && schemaRegistry.registry === 'schemas' && schemaRegistry.version === 1 && schemaRegistry.license === 'MIT',
  'schema registry identity differs');
  assert(schemaRegistry.entries.length === EXPECTED_SCHEMAS.length
    && schemaRegistry.entries.every(({ state }) => state === 'candidate'), 'schema registry lifecycle differs');
  assert(JSON.stringify(schemaRegistry.entries.map(({ path }) => path).sort())
    === JSON.stringify(EXPECTED_SCHEMAS.map((name) => `schemas/${name}`).sort()), 'schema registry inventory differs');
  for (const entry of schemaRegistry.entries) {
    const artifact = manifest.artifacts.find(({ path }) => path === entry.path);
    assert(artifact && artifact.bytes === entry.bytes && artifact.sha256 === entry.sha256,
      `schema registry authentication differs: ${entry.path}`);
  }

  const policy = await schema(root, 'PolicyDocument.schema.json');
  assert(policy.properties.default.const === 'deny' && policy.properties.composition.const === 'deny-overrides-v1', 'policy does not fail closed');
  assert(policy.properties.rules.maxItems === byName.maxPolicyRules, 'policy bound differs');
  assert(policy['x-ogvcs-imported-assignments'].permissions === 'ogvcs.authorization@1/permissions', 'policy duplicated permission authority');
  assert(!Object.hasOwn(policy.properties.rules.items.properties, 'operations'), 'policy invented an operation vocabulary');
  const credential = await schema(root, 'CredentialRecord.schema.json');
  assert(Object.hasOwn(credential.properties, 'secretDigest') && !Object.hasOwn(credential.properties, 'secret'), 'credential schema persists plaintext');
  const audit = await schema(root, 'AuditChainRecord.schema.json');
  assert(audit.properties.event.$ref.endsWith('/AuditEvent.schema.json'), 'audit event does not import OGVCS-003');
  assert(audit.properties.previousHash.oneOf.some(({ type }) => type === 'null'), 'audit genesis is undefined');
  const checkpoint = await schema(root, 'AuditCheckpoint.schema.json');
  assert(checkpoint.properties.tailHash.oneOf.some(({ type }) => type === 'null')
    && checkpoint['x-ogvcs-trust-boundary'].includes('outside'), 'audit checkpoint trust boundary is undefined');
  const auditView = await schema(root, 'AuthorizedAuditView.schema.json');
  const auditEvent = await schema(root, 'AuthorizedAuditEvent.schema.json');
  assert(auditView.properties.items.maxItems === byName.maxAuditQueryRecords
    && auditView['x-ogvcs-requires'].includes('externally retained checkpoint'), 'authorized audit view bound differs');
  assert(auditEvent['x-ogvcs-privacy'].includes('no tenant-global chain position')
    && !Object.hasOwn(auditEvent.properties, 'sequence')
    && !Object.hasOwn(auditEvent.properties, 'recordHash'), 'authorized audit event exposes chain position');

  const oidc = await schema(root, 'OidcProvider.schema.json');
  for (const name of ['issuer', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri', 'redirectUri']) {
    assert(oidc.properties[name].pattern.startsWith('^https://'), `OIDC endpoint is not HTTPS-only: ${name}`);
  }
  assert(JSON.stringify(oidc.properties.signingAlgorithms.items.enum) === JSON.stringify(['RS256', 'ES256'])
    && oidc.properties.subjectClaim.const === 'sub'
    && oidc['x-ogvcs-network-boundary'].includes('no redirect'), 'OIDC provider boundary differs');
  const authTransaction = await schema(root, 'AuthenticationTransaction.schema.json');
  assert(authTransaction.properties.state.enum.join(',') === 'pending,claimed,complete,failed'
    && Object.hasOwn(authTransaction.properties, 'stateDigest')
    && Object.hasOwn(authTransaction.properties, 'nonceDigest')
    && Object.hasOwn(authTransaction.properties, 'state')
    && !Object.hasOwn(authTransaction.properties, 'verifier')
    && authTransaction['x-ogvcs-secret-field-policy'].includes('atomic private transaction compartment'),
  'authentication transaction secret boundary differs');
  const bootstrap = await schema(root, 'BootstrapState.schema.json');
  assert(Object.hasOwn(bootstrap.properties, 'externalRecoveryConfigured')
    && bootstrap['x-ogvcs-invariant'].includes('only after a recovery path'), 'bootstrap recovery invariant differs');
  const mutation = await schema(root, 'PolicyMutation.schema.json');
  assert(mutation.properties.nextPolicy.$ref === 'PolicyDocument.schema.json'
    && mutation.properties.previewRequests.maxItems === byName.maxPolicyPreviewRequests
    && Object.hasOwn(mutation.properties, 'repository')
    && mutation['x-ogvcs-atomicity'].includes('compare-and-swap'), 'policy mutation boundary differs');
  const evidence = await schema(root, 'TransactionCredentialEvidence.schema.json');
  assert(Object.hasOwn(evidence.properties, 'authenticatedScopeDigest')
    && Object.hasOwn(evidence.properties, 'subjectDigest')
    && evidence['x-ogvcs-trust-boundary'].includes('request callers cannot select'), 'transaction evidence boundary differs');
  const transactionView = await schema(root, 'TransactionAuthorizedView.schema.json');
  for (const field of ['transactionId', 'evidenceDigest', 'subjectDigest', 'authenticatedScopeDigest', 'requestFingerprint',
    'decisionDigest', 'tenant', 'repository', 'permission', 'authorityEpoch', 'credentialGeneration', 'policyGeneration', 'expiresAt']) {
    assert(Object.hasOwn(transactionView.properties, field), `transaction view field missing: ${field}`);
  }
  assert(transactionView['x-ogvcs-invariant'].includes('same database transaction'), 'transaction view is not transaction-bound');
  const commitment = await schema(root, 'TransactionDecisionCommitment.schema.json');
  assert(commitment.properties.resourceSetDigest.pattern === '^[0-9a-f]{64}$'
    && commitment.properties.resultDigest.pattern === '^[0-9a-f]{64}$'
    && commitment['x-ogvcs-separation'].includes('not a substitute'), 'decision commitment boundary differs');
  const revocation = await schema(root, 'RevocationReceipt.schema.json');
  assert(revocation['x-ogvcs-bound'].includes('revocationMaximumLagSeconds')
    && Object.hasOwn(revocation.properties, 'maximumAuthorizingUntil'), 'revocation bound differs');
  const promotion = await schema(root, 'EpochPromotionReceipt.schema.json');
  assert(Object.hasOwn(promotion.properties, 'recoveryBoundaryDigest')
    && promotion['x-ogvcs-invariant'].includes('advance atomically'), 'epoch promotion boundary differs');

  const allVectors = [];
  for (const [name, expected] of Object.entries(EXPECTED_VECTORS)) {
    const document = JSON.parse(await readFile(resolve(root, 'vectors', name)));
    assert(document.schemaVersion === 'ogvcs.identity-policy/vectors/v1', `vector schema differs: ${name}`);
    const actual = Object.fromEntries(document.cases.map(({ id, expected: outcome }) => [id, outcome]));
    assert(unique(document.cases.map(({ id }) => id)), `vector identifiers repeat: ${name}`);
    assert(JSON.stringify(actual) === JSON.stringify(expected), `vector inventory differs: ${name}`);
    assert(document.cases.every(({ requirementIds }) => Array.isArray(requirementIds) && requirementIds.length > 0
      && requirementIds.every((id) => /^OGVCS-009-(?:FR|NFR|AC)-[0-9]{2}$/u.test(id))), `vector traceability differs: ${name}`);
    allVectors.push(...document.cases);
  }
  assert(allVectors.length === manifest.counts.vectors && unique(allVectors.map(({ id }) => id)), 'combined vector inventory differs');

  const workspace = resolve(root, '../../..');
  const expectedPins = {
    authorization: ['ogvcs.authorization@1', 'spec/authorization/v1/manifest.json'],
    metadata: ['ogvcs.repository-metadata@1', 'spec/repository-metadata/v1/manifest.json'],
    path: ['ogvcs.path-filesystem@1', 'spec/path-filesystem/v1/manifest.json'],
    protocol: ['ogvcs.protocol@1', 'spec/protocols/v1/manifest.json'],
  };
  exactKeys(manifest.predecessorPins, Object.keys(expectedPins), 'predecessor pin inventory differs');
  for (const [name, pin] of Object.entries(manifest.predecessorPins)) {
    assert(pin.authority === expectedPins[name][0] && pin.manifestPath === expectedPins[name][1], `predecessor assignment differs: ${name}`);
    const bytes = await readFile(resolve(workspace, pin.manifestPath));
    const value = JSON.parse(bytes);
    assert(digest(bytes) === pin.manifestSha256, `predecessor pin drifted: ${pin.authority}`);
    assert(pin.contractVersion === (value.contractVersion ?? value.version)
      && pin.registrySetSha256 === (value.registrySetSha256 ?? null), `predecessor metadata differs: ${pin.authority}`);
  }
  return Object.freeze({ manifestSha256: digest(manifestBytes), artifacts: manifest.artifacts.length, vectors: allVectors.length });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await validateIdentityPolicyContract();
  process.stdout.write(`validated identity-policy contract ${result.manifestSha256}: ${result.artifacts} artifacts, ${result.vectors} vectors\n`);
}
