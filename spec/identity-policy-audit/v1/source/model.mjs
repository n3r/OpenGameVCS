export const CONTRACT_VERSION = '0.1.0';
export const PACKAGE_NAME = '@opengamevcs/identity-policy-audit-contract-v1';
export const SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';

const ID = '^[a-z][a-z0-9.-]{0,127}$';
const OPAQUE = '^[A-Za-z0-9._:-]{1,256}$';
const SHA256 = '^[0-9a-f]{64}$';
const PATH_PROFILE = '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+/[a-z][a-z0-9]*(?:-[a-z0-9]+)*@[1-9][0-9]{0,9}$';
const AUTHORIZATION_REQUEST = 'https://schemas.opengamevcs.org/authorization/v1/AuthorizationRequest.schema.json';
const AUDIT_EVENT = 'https://schemas.opengamevcs.org/authorization/v1/AuditEvent.schema.json';

const text = (maximum = 256, minimum = 1, pattern) => ({
  type: 'string', minLength: minimum, maxLength: maximum, ...(pattern ? { pattern } : {}),
});
const uint = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER) => ({ type: 'integer', minimum, maximum });
const array = (items, maxItems, minItems = 0) => ({ type: 'array', items, minItems, maxItems });
const closed = (properties, required = Object.keys(properties)) => ({
  type: 'object', additionalProperties: false, properties, required,
});

export const LIMITS = Object.freeze({
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
  sessionMaxTtlSeconds: 28_800,
  serviceTokenMaxTtlSeconds: 3_600,
  transferGrantMaxTtlSeconds: 300,
});

const subjectScope = closed({
  identities: array(text(128, 1, ID), LIMITS.maxRuleSubjects),
  groups: array(text(128, 1, ID), LIMITS.maxRuleSubjects),
  actorClasses: array(text(128, 1, ID), 32),
});

const rule = closed({
  id: text(128, 1, ID),
  effect: { enum: ['allow', 'deny'] },
  subjects: subjectScope,
  tenant: text(128, 1, ID),
  repository: text(128, 1, ID),
  references: array(text(128, 1, ID), 128),
  pathPrefixes: array(text(4_096, 0), LIMITS.maxRulePathPrefixes),
  resourceTypes: array(text(128, 1, ID), 64, 1),
  permissions: array(text(128, 1, '^[a-z][a-z0-9.-]{0,127}$'), 64, 1),
});

const credentialScope = closed({
  tenants: array(text(128, 1, ID), 16, 1),
  repositories: array(text(128, 1, ID), 128, 1),
  references: array(text(128, 1, ID), 128),
  pathPrefixes: array(text(4_096, 0), LIMITS.maxRulePathPrefixes),
  permissions: array(text(128, 1, '^[a-z][a-z0-9.-]{0,127}$'), 64, 1),
});

export const SCHEMAS = {
  'PolicyDocument.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/PolicyDocument.schema.json',
    title: 'IdentityPolicyDocumentV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/policy/v1' },
      id: text(128, 1, ID),
      version: text(64, 1, ID),
      generation: uint(1),
      authorityEpoch: uint(1),
      pathProfile: text(328, 1, PATH_PROFILE),
      caseMode: { enum: ['case-sensitive', 'case-folded'] },
      default: { const: 'deny' },
      composition: { const: 'deny-overrides-v1' },
      rules: array(rule, LIMITS.maxPolicyRules, 1),
    }),
    'x-ogvcs-imported-assignments': {
      permissions: 'ogvcs.authorization@1/permissions',
      resourceTypes: 'ogvcs.authorization@1/resources',
      actorClasses: 'ogvcs.authorization@1/actor-classes',
      paths: 'ogvcs.path-filesystem@1',
    },
    'x-ogvcs-license': 'MIT',
  },
  'CredentialRecord.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/CredentialRecord.schema.json',
    title: 'IdentityCredentialRecordV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/credential-record/v1' },
      id: text(128, 1, ID),
      subject: text(128, 1, ID),
      actorClass: text(128, 1, ID),
      credentialClass: { enum: ['session', 'service-token'] },
      generation: uint(1),
      authorityEpoch: uint(1),
      issuedAt: uint(),
      expiresAt: uint(1),
      state: { enum: ['active', 'revoked'] },
      groups: array(text(128, 1, ID), 64),
      scope: credentialScope,
      secretDigest: text(64, 64, SHA256),
    }),
    'x-ogvcs-secret-field-policy': 'digest-only; plaintext is returned once and never persisted',
    'x-ogvcs-license': 'MIT',
  },
  'AuthorityState.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/AuthorityState.schema.json',
    title: 'IdentityAuthorityStateV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/authority-state/v1' },
      authorityEpoch: uint(1),
      keyGeneration: uint(1),
    }),
    'x-ogvcs-license': 'MIT',
  },
  'AuditChainRecord.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/AuditChainRecord.schema.json',
    title: 'IdentityAuditChainRecordV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/audit-chain-record/v1' },
      tenant: text(128, 1, ID),
      sequence: uint(1),
      previousHash: { oneOf: [{ type: 'null' }, text(64, 64, SHA256)] },
      eventHash: text(64, 64, SHA256),
      recordHash: text(64, 64, SHA256),
      event: { $ref: AUDIT_EVENT },
    }),
    'x-ogvcs-chain-domain': 'OGVCS-IDENTITY-AUDIT-CHAIN-V1',
    'x-ogvcs-license': 'MIT',
  },
  'AuditCheckpoint.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/AuditCheckpoint.schema.json',
    title: 'IdentityAuditCheckpointV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/audit-checkpoint/v1' },
      tenant: text(128, 1, ID),
      records: uint(),
      tailHash: { oneOf: [{ type: 'null' }, text(64, 64, SHA256)] },
    }),
    'x-ogvcs-trust-boundary': 'retain outside the mutable audit-record store',
    'x-ogvcs-license': 'MIT',
  },
  'AuthorizationInvocation.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/identity-policy-audit/v1/AuthorizationInvocation.schema.json',
    title: 'IdentityAuthorizationInvocationV1',
    ...closed({
      schemaVersion: { const: 'ogvcs.identity-policy/authorization-invocation/v1' },
      credentialToken: text(LIMITS.maxTokenBytes),
      request: { $ref: AUTHORIZATION_REQUEST },
    }),
    'x-ogvcs-license': 'MIT',
  },
};

export const REGISTRIES = {
  limits: {
    schemaVersion: 'ogvcs.identity-policy/registry/v1', registry: 'limits', version: 1,
    license: 'MIT', entries: Object.entries(LIMITS).map(([name, value], index) => ({ code: index + 1, name, value })),
  },
};

export const VECTORS = {
  'security-core.json': {
    schemaVersion: 'ogvcs.identity-policy/vectors/v1',
    cases: [
      ['canonical-path-allow', 'allow', ['OGVCS-009-FR-03', 'OGVCS-009-FR-04']],
      ['explicit-deny-overrides', 'DENY_NOT_AUTHORIZED', ['OGVCS-009-FR-03']],
      ['malformed-path-fails-closed', 'DENY_CONTEXT_INCOMPLETE', ['OGVCS-009-FR-04']],
      ['evaluator-failure-fails-closed', 'DENY_POLICY_UNAVAILABLE', ['OGVCS-009-FR-04']],
      ['authorized-view-hides-paths-and-counts', 'non-disclosing', ['OGVCS-009-FR-05']],
      ['session-stale-epoch', 'DENY_EPOCH_STALE', ['OGVCS-009-FR-10', 'OGVCS-009-NFR-04']],
      ['service-token-revoked', 'DENY_NOT_AUTHORIZED', ['OGVCS-009-FR-02', 'OGVCS-009-NFR-02']],
      ['transfer-grant-stale-epoch', 'DENY_EPOCH_STALE', ['OGVCS-009-FR-06', 'OGVCS-009-NFR-04']],
      ['transfer-grant-revoked', 'DENY_GRANT_INVALID', ['OGVCS-009-FR-06', 'OGVCS-009-NFR-02']],
      ['authority-promotion-audited', 'verified', ['OGVCS-009-FR-10', 'OGVCS-009-FR-11']],
      ['audit-chain-tamper', 'tamper-detected', ['OGVCS-009-FR-08', 'OGVCS-009-NFR-03']],
      ['cross-tenant-path-enumeration', 'same-safe-error', ['OGVCS-009-FR-05', 'OGVCS-009-FR-09']],
      ['rate-limit-before-lookup', 'DENY_RATE_LIMITED', ['OGVCS-009-FR-09']],
      ['policy-rule-resource-bound', 'LIMIT_EXCEEDED', ['OGVCS-009-FR-03']],
      ['authorized-view-resource-bound', 'LIMIT_EXCEEDED', ['OGVCS-009-FR-05']],
    ].map(([id, expected, requirementIds]) => ({ id, expected, requirementIds })),
  },
};
