const IDENTIFIER = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^[a-z][a-z0-9.-]*$',
});

const POLICY_COMPONENT = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 63,
  pattern: '^[a-z][a-z0-9.-]*$',
});

const CODE = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^[A-Z][A-Z0-9_]*$',
});

const FIELD_NAME = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 128,
  pattern: '^[A-Za-z][A-Za-z0-9.-]*$',
});

const OPAQUE_ID = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 256,
  pattern: '^[A-Za-z0-9._:-]+$',
});

const SHA256 = Object.freeze({
  type: 'string',
  pattern: '^[0-9a-f]{64}$',
});

const REQUEST_ROOT = Object.freeze({
  type: 'string',
  minLength: 71,
  maxLength: 71,
  pattern: '^sha256:[0-9a-f]{64}$',
  description: 'Domain-separated SHA-256 root of a canonical sorted unique transfer-plan object-ID set.',
});

const OBJECT_ID = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 160,
  pattern: '^[A-Za-z0-9:._-]+$',
});

const SAFE_TEXT = Object.freeze({
  type: 'string',
  minLength: 1,
  maxLength: 256,
  pattern: '^[^\\u0000-\\u001F\\u007F]+$',
  'x-ogvcs-maxUtf8Bytes': 256,
});

const NON_NEGATIVE = Object.freeze({
  type: 'integer',
  minimum: 0,
  maximum: Number.MAX_SAFE_INTEGER,
});

const POSITIVE = Object.freeze({
  type: 'integer',
  minimum: 1,
  maximum: Number.MAX_SAFE_INTEGER,
});

function base(title, id, properties, required, extra = {}) {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: `https://schemas.opengamevcs.org/authorization/v1/${id}.schema.json`,
    title,
    type: 'object',
    additionalProperties: false,
    required,
    properties,
    ...extra,
  };
}

export function authorizationRequestSchema(permissionNames, resourceNames, actorClasses, credentialClasses) {
  return base('AuthorizationRequestV1', 'AuthorizationRequest', {
    schemaVersion: { const: 'ogvcs.authorization/request/v1' },
    requestId: OPAQUE_ID,
    actor: {
      type: 'object',
      additionalProperties: false,
      required: ['id', 'class', 'groups', 'credentialClass', 'credentialGeneration', 'credentialStatus', 'authorityEpoch'],
      properties: {
        id: IDENTIFIER,
        class: { enum: actorClasses },
        groups: {
          type: 'array',
          maxItems: 64,
          uniqueItems: true,
          items: IDENTIFIER,
        },
        credentialClass: { enum: credentialClasses },
        credentialGeneration: POSITIVE,
        credentialStatus: { enum: ['active', 'revoked'] },
        authorityEpoch: POSITIVE,
      },
    },
    tenant: IDENTIFIER,
    repository: IDENTIFIER,
    permission: { enum: permissionNames },
    reason: { oneOf: [{ type: 'null' }, SAFE_TEXT] },
    resource: {
      type: 'object',
      additionalProperties: false,
      required: ['type', 'path', 'fileId', 'objectId', 'name'],
      properties: {
        type: { enum: resourceNames },
        path: {
          oneOf: [
            { type: 'null' },
            {
              type: 'string',
              minLength: 1,
              maxLength: 4096,
              pattern: '^(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))[^\\\\\\u0000-\\u001F\\u007F]*[^/\\\\\\u0000-\\u001F\\u007F]$',
              'x-ogvcs-normalization': 'NFC',
              'x-ogvcs-maxUtf8Bytes': 4096,
              'x-ogvcs-maxSegments': 256,
              'x-ogvcs-maxSegmentUtf8Bytes': 255,
            },
          ],
        },
        fileId: {
          oneOf: [
            { type: 'null' },
            { type: 'string', pattern: '^[0-9a-f]{32}$' },
          ],
        },
        objectId: {
          oneOf: [
            { type: 'null' },
            { type: 'string', minLength: 1, maxLength: 160, pattern: '^[A-Za-z0-9:._-]+$' },
          ],
        },
        name: {
          oneOf: [
            { type: 'null' },
            SAFE_TEXT,
          ],
        },
      },
    },
    context: {
      type: 'object',
      additionalProperties: false,
      required: ['reference', 'snapshot', 'policyGeneration', 'authorityEpoch'],
      properties: {
        reference: { oneOf: [{ type: 'null' }, IDENTIFIER] },
        snapshot: { oneOf: [{ type: 'null' }, OPAQUE_ID] },
        policyGeneration: POSITIVE,
        authorityEpoch: POSITIVE,
      },
    },
  }, ['schemaVersion', 'requestId', 'actor', 'tenant', 'repository', 'permission', 'reason', 'resource', 'context']);
}

export function authorizationDecisionSchema(decisionEntries) {
  const decisionCodes = decisionEntries.map(({ name }) => name);
  const allowCodes = decisionEntries.filter(({ allowed }) => allowed).map(({ name }) => name);
  const denyCodes = decisionEntries.filter(({ allowed }) => !allowed).map(({ name }) => name);
  return base('AuthorizationDecisionV1', 'AuthorizationDecision', {
    schemaVersion: { const: 'ogvcs.authorization/decision/v1' },
    requestId: OPAQUE_ID,
    allowed: { type: 'boolean' },
    code: { enum: decisionCodes },
    policyVersion: IDENTIFIER,
    policyGeneration: POSITIVE,
    decisionFingerprint: SHA256,
  }, ['schemaVersion', 'requestId', 'allowed', 'code', 'policyVersion', 'policyGeneration', 'decisionFingerprint'], {
    allOf: [{
      oneOf: [
        { properties: { allowed: { const: true }, code: { enum: allowCodes } } },
        { properties: { allowed: { const: false }, code: { enum: denyCodes } } },
      ],
    }],
  });
}

export function policyFixtureSchema(permissionNames, resourceNames, actorClasses) {
  const stringSet = (items, maximum = 128) => ({
    type: 'array',
    minItems: 1,
    maxItems: maximum,
    uniqueItems: true,
    items,
  });
  return base('AuthorizationPolicyFixtureV1', 'PolicyFixture', {
    schemaVersion: { const: 'ogvcs.authorization/policy-fixture/v1' },
    id: POLICY_COMPONENT,
    version: POLICY_COMPONENT,
    policyGeneration: POSITIVE,
    authorityEpoch: POSITIVE,
    default: { const: 'deny' },
    composition: { const: 'deny-overrides-v1' },
    rules: {
      type: 'array',
      minItems: 1,
      maxItems: 1024,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'effect', 'actors', 'groups', 'actorClasses', 'tenants', 'repositories', 'references', 'pathPrefixes', 'resourceTypes', 'permissions'],
        properties: {
          id: IDENTIFIER,
          effect: { enum: ['allow', 'deny'] },
          actors: { type: 'array', maxItems: 128, uniqueItems: true, items: IDENTIFIER },
          groups: { type: 'array', maxItems: 128, uniqueItems: true, items: IDENTIFIER },
          actorClasses: { type: 'array', maxItems: 32, uniqueItems: true, items: { enum: actorClasses } },
          tenants: stringSet(IDENTIFIER),
          repositories: stringSet(IDENTIFIER),
          references: { type: 'array', maxItems: 128, uniqueItems: true, items: IDENTIFIER },
          pathPrefixes: {
            type: 'array',
            maxItems: 128,
            uniqueItems: true,
            items: { type: 'string', maxLength: 4096, pattern: '^(?:$|(?!/)(?!.*//)(?!.*(?:^|/)\\.{1,2}(?:/|$))[^\\\\\\u0000-\\u001F\\u007F]*[^/\\\\\\u0000-\\u001F\\u007F])$', 'x-ogvcs-normalization': 'NFC', 'x-ogvcs-maxUtf8Bytes': 4096, 'x-ogvcs-maxSegments': 256, 'x-ogvcs-maxSegmentUtf8Bytes': 255 },
          },
          resourceTypes: stringSet({ enum: resourceNames }),
          permissions: stringSet({ enum: permissionNames }),
        },
      },
    },
  }, ['schemaVersion', 'id', 'version', 'policyGeneration', 'authorityEpoch', 'default', 'composition', 'rules']);
}

export function transferGrantClaimsSchema() {
  return base('TransferGrantClaimsV1', 'TransferGrantClaims', {
    schemaVersion: { const: 'ogvcs.authorization/transfer-grant-claims/v1' },
    issuer: IDENTIFIER,
    keyId: IDENTIFIER,
    keyGeneration: POSITIVE,
    authorityEpoch: POSITIVE,
    subject: IDENTIFIER,
    tenant: IDENTIFIER,
    repository: IDENTIFIER,
    permission: { enum: ['content.materialize', 'content.upload'] },
    operation: { enum: ['upload', 'download'] },
    audience: IDENTIFIER,
    issuedAt: NON_NEGATIVE,
    expiresAt: POSITIVE,
    nonce: OPAQUE_ID,
    replay: { enum: ['single-use', 'idempotent'] },
    objectIds: {
      type: 'array',
      maxItems: 4096,
      uniqueItems: true,
      items: OBJECT_ID,
    },
    requestRoot: {
      oneOf: [
        { type: 'null' },
        REQUEST_ROOT,
      ],
    },
  }, ['schemaVersion', 'issuer', 'keyId', 'keyGeneration', 'authorityEpoch', 'subject', 'tenant', 'repository', 'permission', 'operation', 'audience', 'issuedAt', 'expiresAt', 'nonce', 'replay', 'objectIds', 'requestRoot'], {
    'x-ogvcs-maxValiditySeconds': 300,
    oneOf: [
      {
        properties: { objectIds: { minItems: 1 }, requestRoot: { type: 'null' } },
      },
      {
        properties: { objectIds: { maxItems: 0 }, requestRoot: REQUEST_ROOT },
      },
    ],
    allOf: [{
      oneOf: [
        { properties: { permission: { const: 'content.materialize' }, operation: { const: 'download' } } },
        { properties: { permission: { const: 'content.upload' }, operation: { const: 'upload' } } },
      ],
    }],
  });
}

export function transferGrantContextSchema() {
  return base('TransferGrantContextV1', 'TransferGrantContext', {
    schemaVersion: { const: 'ogvcs.authorization/transfer-grant-context/v1' },
    issuer: IDENTIFIER,
    keyId: IDENTIFIER,
    subject: IDENTIFIER,
    permission: { enum: ['content.materialize', 'content.upload'] },
    operation: { enum: ['upload', 'download'] },
    audience: IDENTIFIER,
    tenant: IDENTIFIER,
    repository: IDENTIFIER,
    authorityEpoch: POSITIVE,
    keyGeneration: POSITIVE,
    now: NON_NEGATIVE,
    objectId: OBJECT_ID,
    requestObjectIds: {
      type: 'array',
      maxItems: 32_768,
      uniqueItems: true,
      items: OBJECT_ID,
    },
    consumedNonces: {
      type: 'array',
      maxItems: 4096,
      uniqueItems: true,
      items: OPAQUE_ID,
    },
  }, ['schemaVersion', 'issuer', 'keyId', 'subject', 'permission', 'operation', 'audience', 'tenant', 'repository', 'authorityEpoch', 'keyGeneration', 'now', 'objectId', 'requestObjectIds', 'consumedNonces'], {
    allOf: [{
      oneOf: [
        { properties: { permission: { const: 'content.materialize' }, operation: { const: 'download' } } },
        { properties: { permission: { const: 'content.upload' }, operation: { const: 'upload' } } },
      ],
    }],
  });
}

export function transferGrantEnvelopeSchema() {
  return base('TransferGrantEnvelopeV1', 'TransferGrantEnvelope', {
    schemaVersion: { const: 'ogvcs.authorization/transfer-grant/v1' },
    algorithm: { const: 'Ed25519' },
    keyId: IDENTIFIER,
    claims: { $ref: 'https://schemas.opengamevcs.org/authorization/v1/TransferGrantClaims.schema.json' },
    signature: { type: 'string', minLength: 86, maxLength: 86, pattern: '^[A-Za-z0-9_-]+$' },
  }, ['schemaVersion', 'algorithm', 'keyId', 'claims', 'signature']);
}

export function auditEventSchema(auditEntries, permissionNames, actorClasses, decisionCodes) {
  const auditClasses = auditEntries.map(({ name }) => name);
  return base('AuthorizationAuditEventV1', 'AuditEvent', {
    schemaVersion: { const: 'ogvcs.authorization/audit-event/v1' },
    eventId: OPAQUE_ID,
    eventClass: { enum: auditClasses },
    occurredAt: NON_NEGATIVE,
    tenant: IDENTIFIER,
    repository: IDENTIFIER,
    actorClass: { enum: actorClasses },
    actorPseudonym: { type: 'string', pattern: '^pseudonym:[0-9a-f]{32}$' },
    permission: { enum: permissionNames },
    reason: SAFE_TEXT,
    outcomeCode: { enum: decisionCodes },
    correlationId: OPAQUE_ID,
    details: {
      type: 'object',
      additionalProperties: false,
      required: ['targetClass', 'changeRef'],
      properties: {
        targetClass: IDENTIFIER,
        changeRef: { oneOf: [{ type: 'null' }, OPAQUE_ID] },
      },
    },
  }, ['schemaVersion', 'eventId', 'eventClass', 'occurredAt', 'tenant', 'repository', 'actorClass', 'actorPseudonym', 'permission', 'reason', 'outcomeCode', 'correlationId', 'details'], {
    allOf: [{
      oneOf: auditEntries.map(({ name, permission }) => ({
        properties: { eventClass: { const: name }, permission: { const: permission } },
      })),
    }],
  });
}

export function threatVectorSchema(decisionCodes) {
  return base('AuthorizationThreatVectorV1', 'ThreatVector', {
    schemaVersion: { const: 'ogvcs.authorization/threat-vector/v1' },
    id: IDENTIFIER,
    abuseCase: IDENTIFIER,
    category: IDENTIFIER,
    kind: { enum: ['authorization', 'authorized-view', 'transfer-grant', 'deduplication', 'sandbox'] },
    input: { type: 'object' },
    expected: {
      type: 'object',
      additionalProperties: false,
      required: ['result', 'code'],
      properties: {
        result: { enum: ['allow', 'deny'] },
        code: { enum: decisionCodes },
      },
    },
    forbiddenResponseFields: {
      type: 'array',
      minItems: 1,
      maxItems: 64,
      uniqueItems: true,
      items: FIELD_NAME,
    },
  }, ['schemaVersion', 'id', 'abuseCase', 'category', 'kind', 'input', 'expected', 'forbiddenResponseFields']);
}

export function runnerReportSchema() {
  return base('AuthorizationRunnerReportV1', 'RunnerReport', {
    schemaVersion: { const: 'ogvcs.authorization/runner-report/v1' },
    contractVersion: { const: '1.0.0' },
    manifestSha256: SHA256,
    registrySetSha256: SHA256,
    adapter: IDENTIFIER,
    vectors: POSITIVE,
    passed: NON_NEGATIVE,
    failed: NON_NEGATIVE,
    resultsSha256: SHA256,
    rows: {
      type: 'array',
      minItems: 1,
      maxItems: 10000,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'status', 'expectedCode', 'actualCode'],
        properties: {
          id: IDENTIFIER,
          status: { enum: ['passed', 'failed'] },
          expectedCode: CODE,
          actualCode: CODE,
        },
      },
    },
  }, ['schemaVersion', 'contractVersion', 'manifestSha256', 'registrySetSha256', 'adapter', 'vectors', 'passed', 'failed', 'resultsSha256', 'rows']);
}

export function sandboxRequirementsSchema() {
  return base('SandboxRequirementsV1', 'SandboxRequirements', {
    schemaVersion: { const: 'ogvcs.authorization/sandbox-requirements/v1' },
    id: IDENTIFIER,
    toolClass: { enum: ['hook', 'merge-driver', 'import-parser', 'preview-parser'] },
    runtime: {
      type: 'object',
      additionalProperties: false,
      required: ['cpuMilliseconds', 'elapsedMilliseconds', 'memoryBytes', 'outputBytes', 'fanout', 'processes'],
      properties: {
        cpuMilliseconds: POSITIVE,
        elapsedMilliseconds: POSITIVE,
        memoryBytes: POSITIVE,
        outputBytes: POSITIVE,
        fanout: POSITIVE,
        processes: POSITIVE,
      },
    },
    filesystem: {
      type: 'object',
      additionalProperties: false,
      required: ['declaredInputsReadOnly', 'isolatedScratch', 'scratchBytes', 'hostPaths'],
      properties: {
        declaredInputsReadOnly: { const: true },
        isolatedScratch: { const: true },
        scratchBytes: POSITIVE,
        hostPaths: { const: false },
      },
    },
    network: {
      type: 'object',
      additionalProperties: false,
      required: ['default'],
      properties: { default: { const: 'deny' } },
    },
    credentials: { const: 'none' },
    toolchain: {
      type: 'object',
      additionalProperties: false,
      required: ['pinned', 'signatureRequired'],
      properties: { pinned: { const: true }, signatureRequired: { const: true } },
    },
  }, ['schemaVersion', 'id', 'toolClass', 'runtime', 'filesystem', 'network', 'credentials', 'toolchain']);
}

export function allSchemas(contract) {
  const permissionNames = contract.permissions.map(({ name }) => name);
  const resourceNames = contract.resources.map(({ name }) => name);
  const actorClasses = contract.actorClasses.map(({ name }) => name);
  const credentialClasses = contract.credentialClasses.map(({ name }) => name);
  const decisionCodes = contract.decisionCodes.map(({ name }) => name);
  return {
    'AuditEvent.schema.json': auditEventSchema(contract.auditClasses, permissionNames, actorClasses, decisionCodes),
    'AuthorizationDecision.schema.json': authorizationDecisionSchema(contract.decisionCodes),
    'AuthorizationRequest.schema.json': authorizationRequestSchema(permissionNames, resourceNames, actorClasses, credentialClasses),
    'PolicyFixture.schema.json': policyFixtureSchema(permissionNames, resourceNames, actorClasses),
    'RunnerReport.schema.json': runnerReportSchema(),
    'SandboxRequirements.schema.json': sandboxRequirementsSchema(),
    'ThreatVector.schema.json': threatVectorSchema(decisionCodes),
    'TransferGrantClaims.schema.json': transferGrantClaimsSchema(),
    'TransferGrantContext.schema.json': transferGrantContextSchema(),
    'TransferGrantEnvelope.schema.json': transferGrantEnvelopeSchema(),
  };
}
