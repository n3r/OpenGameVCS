export const CONTRACT_VERSION = '0.2.0';
export const PACKAGE_NAME = '@opengamevcs/repository-metadata-contract-v1';
export const SCHEMA_DIALECT = 'https://json-schema.org/draft/2020-12/schema';

const UUID = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const OBJECT_REF = '^ogvcs:v1:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:sha256:[0-9a-f]{64}$';
const FILE_ID = '^fid:[0-9a-f]{32}$';
const CURSOR_TOKEN = '^cur1\\.[A-Za-z0-9_-]{43}$';
const CONSISTENCY_TOKEN = '^ct1\\.[A-Za-z0-9_-]{43}$';
const ALLOCATION_RECEIPT = '^far1\\.[A-Za-z0-9_-]{43}$';
const SHA256 = '^[0-9a-f]{64}$';
const PROFILE_REF = '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+/[a-z][a-z0-9]*(?:-[a-z0-9]+)*@[1-9][0-9]{0,9}$';

const text = (maximum = 256, minimum = 1) => ({ type: 'string', minLength: minimum, maxLength: maximum });
const uuid = () => ({ type: 'string', pattern: UUID, maxLength: 36 });
const objectRef = () => ({ type: 'string', pattern: OBJECT_REF, maxLength: 144 });
const fileId = () => ({ type: 'string', pattern: FILE_ID, maxLength: 36 });
const profileRef = () => ({ type: 'string', pattern: PROFILE_REF, maxLength: 328 });
const uint = (maximum = Number.MAX_SAFE_INTEGER) => ({ type: 'integer', minimum: 0, maximum });
const array = (items, maxItems, minItems = 0) => ({ type: 'array', items, minItems, maxItems });
const closed = (properties, required = Object.keys(properties)) => ({ type: 'object', additionalProperties: false, properties, required });

const scope = {
  tenantId: uuid(),
  repositoryId: uuid(),
};
const consistentScope = {
  ...scope,
  minimumConsistencyToken: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CONSISTENCY_TOKEN, maxLength: 47 }] },
};

export const LIMITS = Object.freeze({
  maxPageItems: 10_000,
  maxHistoryDepth: 100_000,
  maxReferenceNameBytes: 512,
  maxOutboxClaimItems: 1_000,
  maxCanonicalMetadataBytes: 536_870_912,
  maxTokenTtlSeconds: 86_400,
});

const repositorySettings = closed({
  schemaVersion: { const: 'ogvcs.repository-metadata/repository-settings/v1' },
  repositoryFormat: { const: 'ogvcs.repository-format@1' },
  requiredFeatures: { ...array(uint(65_535), 128), uniqueItems: true },
  caseMode: { enum: ['case-sensitive', 'case-folded'] },
  pathProfile: profileRef(),
  platformProfile: profileRef(),
  contentPolicyProfile: profileRef(),
  structuralLimits: closed({
    maxTreeEntries: uint(1_000_000),
    maxPathBytes: uint(4_096),
    maxPathSegments: uint(256),
    maxSnapshotParents: uint(8),
  }),
  tenantBoundary: uuid(),
});

const expectedReference = {
  oneOf: [
    closed({ state: { const: 'absent' } }),
    closed({ state: { const: 'present' }, target: objectRef(), generation: uint() }),
  ],
};

const allocationReceipt = () => ({ type: 'string', pattern: ALLOCATION_RECEIPT, maxLength: 48 });
const nativeFileIdRegistration = closed({
  ...scope,
  fileId: fileId(),
  origin: { enum: ['create', 'copy'] },
  allocationReceipt: allocationReceipt(),
  ownerKind: { enum: ['published', 'draft', 'shelf'] },
  ownerId: text(256),
});
const restoreFileIdRegistration = closed({
  ...scope,
  fileId: fileId(),
  origin: { const: 'restore' },
  allocationReceipt: { type: 'null' },
  ownerKind: { enum: ['published', 'draft', 'shelf'] },
  ownerId: text(256),
});

const bodySchemas = {
  'repository.create': closed({ tenantId: uuid(), projectId: uuid(), repositoryId: uuid(), settings: repositorySettings, rootSnapshot: objectRef(), defaultReference: text(LIMITS.maxReferenceNameBytes) }),
  'repository.get-settings': closed(consistentScope),
  'repository.list': closed({ tenantId: uuid(), projectId: uuid(), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'object.put': closed({ ...scope, objectRef: objectRef(), canonicalByteLength: uint(LIMITS.maxCanonicalMetadataBytes), streamDigestSha256: { type: 'string', pattern: SHA256 } }),
  'object.get': closed({ ...consistentScope, objectRef: objectRef() }),
  'tree.page': closed({ ...consistentScope, snapshot: objectRef(), tree: objectRef(), prefix: array(text(255), 256), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'reference.read': closed({ ...consistentScope, referenceKind: { enum: ['branch', 'tag'] }, referenceName: text(LIMITS.maxReferenceNameBytes) }),
  'reference.list': closed({ ...consistentScope, referenceKind: { enum: ['branch', 'tag', 'all'] }, pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'reference.compare-and-swap': closed({ ...scope, referenceKind: { enum: ['branch', 'tag'] }, referenceName: text(LIMITS.maxReferenceNameBytes), expected: expectedReference, desired: { anyOf: [{ type: 'null' }, objectRef()] } }),
  'history.ancestry-page': closed({ ...consistentScope, snapshot: objectRef(), maxDepth: uint(LIMITS.maxHistoryDepth), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'history.file-id-page': closed({ ...consistentScope, snapshot: objectRef(), fileId: fileId(), maxDepth: uint(LIMITS.maxHistoryDepth), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'history.path-page': closed({ ...consistentScope, snapshot: objectRef(), path: array(text(255), 256, 1), maxDepth: uint(LIMITS.maxHistoryDepth), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'file-id.allocate': closed(scope),
  'file-id.register': { oneOf: [nativeFileIdRegistration, restoreFileIdRegistration] },
  'file-id.register-import': closed({ ...scope, fileId: fileId(), importerProfile: profileRef(), sourceNamespaceDigest: { type: 'string', pattern: SHA256 }, sourceIdentityDigest: { type: 'string', pattern: SHA256 }, ownerKind: { enum: ['published', 'draft', 'shelf'] }, ownerId: text(256) }),
  'file-id.tombstone': closed({ ...scope, fileId: fileId(), expectedState: { enum: ['active', 'reserved'] } }),
  'file-id.history': closed({ ...consistentScope, fileId: fileId(), pageSize: uint(LIMITS.maxPageItems), cursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] } }),
  'idempotency.status': closed({ ...scope, operation: text(128), idempotencyKey: text(512) }),
  'consistency.issue-token': closed({ ...scope, ttlSeconds: uint(LIMITS.maxTokenTtlSeconds) }),
  'outbox.claim': closed({ consumerId: text(256), maximumItems: uint(LIMITS.maxOutboxClaimItems), leaseSeconds: uint(3_600) }),
  'outbox.acknowledge': closed({ consumerId: text(256), eventId: uuid(), leaseId: uuid() }),
  'outbox.release': closed({ consumerId: text(256), eventId: uuid(), leaseId: uuid(), retryAfterSeconds: uint(86_400) }),
};

const operationRows = [
  ['repository.create', 'mutation', 'submit', 'repository', true, 'json'],
  ['repository.get-settings', 'query', 'metadata.read', 'repository', false, 'json'],
  ['repository.list', 'query', 'discover', 'repository', false, 'json'],
  ['object.put', 'mutation', 'submit', 'snapshot', true, 'canonical-metadata-byte-stream'],
  ['object.get', 'query', 'metadata.read', 'snapshot', false, 'canonical-metadata-byte-stream'],
  ['tree.page', 'query', 'metadata.read', 'tree', false, 'json'],
  ['reference.read', 'query', 'metadata.read', 'reference', false, 'json'],
  ['reference.list', 'query', 'discover', 'reference', false, 'json'],
  ['reference.compare-and-swap', 'mutation', 'submit', 'reference', true, 'json'],
  ['history.ancestry-page', 'query', 'metadata.read', 'snapshot', false, 'json'],
  ['history.file-id-page', 'query', 'metadata.read', 'path', false, 'json'],
  ['history.path-page', 'query', 'metadata.read', 'path', false, 'json'],
  ['file-id.allocate', 'mutation', 'submit', 'path', true, 'json'],
  ['file-id.register', 'mutation', 'submit', 'path', true, 'json'],
  ['file-id.register-import', 'mutation', 'submit', 'path', true, 'json'],
  ['file-id.tombstone', 'mutation', 'submit', 'path', true, 'json'],
  ['file-id.history', 'query', 'metadata.read', 'path', false, 'json'],
  ['idempotency.status', 'query', 'submit', 'repository', false, 'json'],
  ['consistency.issue-token', 'query', 'metadata.read', 'repository', false, 'json'],
  ['outbox.claim', 'internal-mutation', 'service-internal', 'event', true, 'json'],
  ['outbox.acknowledge', 'internal-mutation', 'service-internal', 'event', true, 'json'],
  ['outbox.release', 'internal-mutation', 'service-internal', 'event', true, 'json'],
];

export const OPERATIONS = operationRows.map(([name, className, permission, resourceType, idempotencyRequired, payloadCarrier], index) => ({
  code: index + 1,
  name,
  class: className,
  permission,
  resourceType,
  idempotencyRequired,
  payloadCarrier,
  requestSchema: 'MetadataOperationRequest.schema.json',
  state: 'candidate',
}));

const errorRows = [
  ['REPOSITORY_SETTINGS_IMMUTABLE', 409, false, 'immutable-settings', []],
  ['OBJECT_INVALID', 422, false, 'validation', []],
  ['OBJECT_ID_COLLISION', 409, false, 'security-corruption', []],
  ['REFERENCE_CONFLICT', 409, false, 'compare-and-swap', ['currentGeneration']],
  ['FILEID_CONFLICT', 409, false, 'lifetime-identity', []],
  ['HISTORY_LIMIT_REACHED', 409, true, 'bounded-incomplete', []],
  ['CONSISTENCY_TOKEN_UNSATISFIED', 409, true, 'replica-lag', ['retryAfterMs']],
  ['MIGRATION_INCOMPATIBLE', 503, false, 'schema-compatibility', []],
  ['MIGRATION_CHECKSUM_MISMATCH', 500, false, 'schema-integrity', []],
  ['METADATA_NOT_FOUND_OR_DENIED', 404, false, 'non-disclosure', []],
  ['TRANSACTION_RETRY_EXHAUSTED', 503, true, 'transaction', ['retryAfterMs']],
];

export const DOMAIN_ERRORS = errorRows.map(([name, status, retryable, resultClass, safeParameters], index) => ({
  code: 1001 + index,
  name,
  status,
  retryable,
  resultClass,
  safeParameters,
  protocolBinding: 'unassigned',
  state: 'candidate',
}));

export const EVENTS = [
  ['repository.created', 'repository'],
  ['metadata.object-accepted', 'snapshot'],
  ['reference.changed', 'reference'],
  ['file-id.state-changed', 'path'],
].map(([name, resourceType], index) => ({ code: index + 1, name, resourceType, version: 1, delivery: 'at-least-once', state: 'candidate' }));

const requestVariants = OPERATIONS.map((operation) => closed({
  schemaVersion: { const: 'ogvcs.repository-metadata/operation-request/v1' },
  operation: { const: operation.name },
  body: bodySchemas[operation.name],
  idempotencyKey: operation.idempotencyRequired ? text(512) : { type: 'null' },
}));

const pageOperations = [
  'repository.list',
  'tree.page',
  'reference.list',
  'history.ancestry-page',
  'history.file-id-page',
  'history.path-page',
  'file-id.history',
];
const genericJsonResultOperations = OPERATIONS
  .map(({ name }) => name)
  .filter((name) => !pageOperations.includes(name)
    && name !== 'file-id.allocate'
    && name !== 'idempotency.status'
    && name !== 'object.get');

const pageResult = closed({
  schemaVersion: { const: 'ogvcs.repository-metadata/page-result/v1' },
  operation: { enum: pageOperations },
  state: { enum: ['more', 'complete', 'incomplete'] },
  items: array({}, LIMITS.maxPageItems),
  nextCursor: { anyOf: [{ type: 'null' }, { type: 'string', pattern: CURSOR_TOKEN }] },
  incompleteReason: { anyOf: [{ type: 'null' }, { enum: ['depth-limit', 'work-limit', 'retention-gap'] }] },
  consistencyToken: { type: 'string', pattern: CONSISTENCY_TOKEN },
});

const fileIdAllocation = closed({
  schemaVersion: { const: 'ogvcs.repository-metadata/file-id-allocation/v1' },
  repositoryId: uuid(),
  fileId: fileId(),
  allocationReceipt: allocationReceipt(),
  expiresAtUnixMs: uint(),
});

const idempotencyStatus = {
  oneOf: [
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/idempotency-status/v1' },
      state: { const: 'absent' },
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/idempotency-status/v1' },
      state: { const: 'reserved' },
      expiresAtUnixMs: uint(),
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/idempotency-status/v1' },
      state: { const: 'committed' },
      expiresAtUnixMs: uint(),
      safeResult: {},
    }),
  ],
};

const metadataHttpResponse = {
  oneOf: [
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { enum: pageOperations },
      outcome: { const: 'success' },
      carrier: { const: 'page-result' },
      body: { $ref: 'PageResult.schema.json' },
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { const: 'file-id.allocate' },
      outcome: { const: 'success' },
      carrier: { const: 'json' },
      body: { $ref: 'FileIdAllocation.schema.json' },
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { const: 'idempotency.status' },
      outcome: { const: 'success' },
      carrier: { const: 'json' },
      body: { $ref: 'IdempotencyStatus.schema.json' },
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { const: 'object.get' },
      outcome: { const: 'success' },
      carrier: { const: 'canonical-metadata-byte-stream' },
      body: closed({
        objectRef: objectRef(),
        canonicalByteLength: uint(LIMITS.maxCanonicalMetadataBytes),
        streamDigestSha256: { type: 'string', pattern: SHA256 },
      }),
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { enum: genericJsonResultOperations },
      outcome: { const: 'success' },
      carrier: { const: 'json' },
      body: { type: 'object', maxProperties: 128 },
    }),
    closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/http-response/v1' },
      operation: { enum: OPERATIONS.map(({ name }) => name) },
      outcome: { const: 'domain-error' },
      carrier: { const: 'domain-error' },
      body: { $ref: 'MetadataDomainError.schema.json' },
    }),
  ],
};

function errorVariant(error) {
  const properties = Object.fromEntries(error.safeParameters.map((name) => [name,
    name === 'currentGeneration' ? uint() : uint(86_400_000)]));
  return closed({
    schemaVersion: { const: 'ogvcs.repository-metadata/domain-error/v1' },
    code: { const: error.name },
    numericCode: { const: error.code },
    retryable: { const: error.retryable },
    safeParameters: closed(properties, []),
  });
}

export const SCHEMAS = {
  'RepositorySettings.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/RepositorySettings.schema.json',
    title: 'RepositorySettings',
    ...repositorySettings,
    'x-ogvcs-license': 'MIT',
  },
  'MetadataOperationRequest.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/MetadataOperationRequest.schema.json',
    title: 'MetadataOperationRequest',
    oneOf: requestVariants,
    'x-ogvcs-license': 'MIT',
  },
  'MetadataDomainError.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/MetadataDomainError.schema.json',
    title: 'MetadataDomainError',
    oneOf: DOMAIN_ERRORS.map(errorVariant),
    'x-ogvcs-license': 'MIT',
  },
  'PageResult.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/PageResult.schema.json',
    title: 'PageResult',
    ...pageResult,
    'x-ogvcs-license': 'MIT',
  },
  'FileIdAllocation.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/FileIdAllocation.schema.json',
    title: 'FileIdAllocation',
    ...fileIdAllocation,
    'x-ogvcs-license': 'MIT',
  },
  'IdempotencyStatus.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/IdempotencyStatus.schema.json',
    title: 'IdempotencyStatus',
    ...idempotencyStatus,
    'x-ogvcs-license': 'MIT',
  },
  'MetadataHttpResponse.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/MetadataHttpResponse.schema.json',
    title: 'MetadataHttpResponse',
    ...metadataHttpResponse,
    'x-ogvcs-license': 'MIT',
  },
  'OutboxEvent.schema.json': {
    $schema: SCHEMA_DIALECT,
    $id: 'https://schemas.opengamevcs.dev/repository-metadata/v1/OutboxEvent.schema.json',
    title: 'OutboxEvent',
    ...closed({
      schemaVersion: { const: 'ogvcs.repository-metadata/outbox-event/v1' },
      eventId: uuid(),
      eventType: { enum: EVENTS.map(({ name }) => name) },
      eventVersion: { const: 1 },
      tenantId: uuid(),
      repositoryId: uuid(),
      commitSequence: uint(),
      correlationId: uuid(),
      resourceRef: closed({
        resourceType: { enum: ['repository', 'reference', 'snapshot', 'tree', 'path'] },
        opaqueId: { type: 'string', pattern: '^rr1\\.[A-Za-z0-9_-]{43}$', maxLength: 47 },
      }),
    }),
    'x-ogvcs-license': 'MIT',
  },
};

export const REGISTRIES = {
  operations: { schemaVersion: 'ogvcs.repository-metadata/registry/v1', registry: 'operations', version: 1, license: 'MIT', entries: OPERATIONS },
  'domain-errors': { schemaVersion: 'ogvcs.repository-metadata/registry/v1', registry: 'domain-errors', version: 1, license: 'MIT', entries: DOMAIN_ERRORS, forbiddenParameters: ['detail', 'instance', 'path', 'fileId', 'objectRef', 'message'] },
  events: { schemaVersion: 'ogvcs.repository-metadata/registry/v1', registry: 'events', version: 1, license: 'MIT', entries: EVENTS },
  limits: { schemaVersion: 'ogvcs.repository-metadata/registry/v1', registry: 'limits', version: 1, license: 'MIT', entries: Object.entries(LIMITS).map(([name, value], index) => ({ code: index + 1, name, value })) },
};

const zeroUuid = '00000000-0000-4000-8000-000000000001';
const repositoryId = '00000000-0000-4000-8000-000000000002';
const tree = `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`;
const snapshot = `ogvcs:v1:snapshot:sha256:${'02'.repeat(32)}`;

export const VECTORS = {
  'contract.json': {
    schemaVersion: 'ogvcs.repository-metadata/vectors/v1',
    cases: [
      { id: 'repository-settings-portable', requirementIds: ['OGVCS-006-FR-01'], result: 'accept', operation: 'repository.create', input: { tenantId: zeroUuid, projectId: '00000000-0000-4000-8000-000000000003', repositoryId, settings: { schemaVersion: 'ogvcs.repository-metadata/repository-settings/v1', repositoryFormat: 'ogvcs.repository-format@1', requiredFeatures: [], caseMode: 'case-sensitive', pathProfile: 'path.opengamevcs/portable@1', platformProfile: 'path.opengamevcs/portable@1', contentPolicyProfile: 'content-policy.test/opaque@1', structuralLimits: { maxTreeEntries: 1000000, maxPathBytes: 4096, maxPathSegments: 256, maxSnapshotParents: 8 }, tenantBoundary: zeroUuid }, rootSnapshot: snapshot, defaultReference: 'main' } },
      { id: 'object-exact-replay', requirementIds: ['OGVCS-006-FR-02', 'OGVCS-006-FR-03', 'OGVCS-006-AC-01'], result: 'idempotent', operation: 'object.put', objectRef: tree },
      { id: 'object-identity-collision', requirementIds: ['OGVCS-006-FR-03', 'OGVCS-006-AC-01'], result: 'OBJECT_ID_COLLISION', operation: 'object.put', objectRef: tree },
      { id: 'reference-cas-single-winner', requirementIds: ['OGVCS-006-FR-04', 'OGVCS-006-AC-02', 'OGVCS-006-NFR-03'], result: 'REFERENCE_CONFLICT', operation: 'reference.compare-and-swap', input: { tenantId: zeroUuid, repositoryId, referenceKind: 'branch', referenceName: 'main', expected: { state: 'present', target: snapshot, generation: 1 }, desired: `ogvcs:v1:snapshot:sha256:${'03'.repeat(32)}` } },
      { id: 'tree-page-immutable-binding', requirementIds: ['OGVCS-006-FR-05', 'OGVCS-006-NFR-02', 'OGVCS-006-AC-04'], result: 'accept', operation: 'tree.page' },
      { id: 'history-depth-incomplete', requirementIds: ['OGVCS-006-FR-06'], result: 'HISTORY_LIMIT_REACHED', operation: 'history.ancestry-page' },
      { id: 'outbox-same-transaction', requirementIds: ['OGVCS-006-FR-07', 'OGVCS-006-AC-03', 'OGVCS-006-NFR-03'], result: 'accept', operation: 'reference.compare-and-swap' },
      { id: 'migration-checksum-mismatch', requirementIds: ['OGVCS-006-FR-08', 'OGVCS-006-AC-05'], result: 'MIGRATION_CHECKSUM_MISMATCH', operation: 'repository.get-settings' },
      { id: 'fileid-concurrent-collision', requirementIds: ['OGVCS-006-FR-09', 'OGVCS-006-AC-06'], result: 'FILEID_CONFLICT', operation: 'file-id.register', input: { tenantId: zeroUuid, repositoryId, fileId: `fid:${'04'.repeat(16)}`, origin: 'copy', allocationReceipt: `far1.${'A'.repeat(43)}`, ownerKind: 'draft', ownerId: 'draft-1' } },
      { id: 'replica-token-behind', requirementIds: ['OGVCS-006-NFR-01'], result: 'CONSISTENCY_TOKEN_UNSATISFIED', operation: 'consistency.issue-token' },
    ],
  },
};

export const BODY_SCHEMAS = bodySchemas;
