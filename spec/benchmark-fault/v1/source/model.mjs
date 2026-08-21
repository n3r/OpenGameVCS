const DRAFT = 'https://json-schema.org/draft/2020-12/schema';
const BASE = 'https://schemas.opengamevcs.dev/benchmark-fault/v1/';

export const CONTRACT_VERSION = '1.0.0-rc.1';
export const PACKAGE_NAME = '@opengamevcs/benchmark-fault-contract-v1';
export const TEST_PROFILE_ID = 'ogvcs.benchmark-fault-driver.test@1';
export const CONTROL_PROFILE_ID = 'ogvcs.control.https-json@1';

export const LIMITS = Object.freeze({
  maxControlMessageBytes: 1_048_576,
  maxCorpora: 64,
  maxFaultEvents: 4_096,
  maxIterations: 1_000,
  maxResultBundleBytes: 67_108_864,
  maxSamples: 100_000,
  maxStreamBytes: 67_108_864,
  maxTaskTimeMs: 120_000,
  maxTasks: 64,
  maxThresholds: 4_096,
  maxTraceEvents: 4_096,
  maxWorkingMemoryBytes: 268_435_456,
});

export const ERROR_ENTRIES = Object.freeze([
  ['HARNESS_OK', 0, 'success', false],
  ['HARNESS_INPUT_INVALID', 1, 'input', false],
  ['HARNESS_LIMIT_EXCEEDED', 2, 'resource', false],
  ['HARNESS_NEGOTIATION_INCOMPATIBLE', 3, 'negotiation', false],
  ['HARNESS_PROTOCOL_MALFORMED', 4, 'protocol', false],
  ['HARNESS_DRIVER_FAILED', 5, 'driver', false],
  ['HARNESS_RETRYABLE', 6, 'driver', true],
  ['HARNESS_TASK_INCOMPLETE', 7, 'task', true],
  ['HARNESS_ASSERTION_FAILED', 8, 'correctness', false],
  ['HARNESS_FAULT_INVARIANT_FAILED', 9, 'fault', false],
  ['HARNESS_THRESHOLD_FAILED', 10, 'threshold', false],
  ['HARNESS_BUNDLE_INVALID', 11, 'publication', false],
  ['HARNESS_CACHE_STATE_INVALID', 12, 'cache', false],
  ['HARNESS_PRIVILEGE_REQUIRED', 13, 'network', false],
  ['HARNESS_DEADLINE_EXCEEDED', 14, 'resource', true],
  ['HARNESS_CANCELLED', 15, 'resource', true],
  ['HARNESS_IO', 16, 'io', true],
]);

export const TASK_ENTRIES = Object.freeze([
  task('setup', false, 'empty isolated run workspace', 'configured repository is ready', ['workspace-isolated', 'repository-ready'], ['durable.write', 'metadata.commit']),
  task('status', false, 'repository and workspace are ready', 'status is complete and generation-bound', ['status-complete', 'no-hidden-mutation'], []),
  task('sync', false, 'requested immutable snapshot and cache state are declared', 'requested projection is materialized and verified', ['content-complete', 'cache-state-observed'], ['durable.write', 'object.finalize']),
  task('submit', true, 'expected branch head, content closure, policy and lock facts are fixed', 'one visible branch generation names only available content', ['content-complete', 'authorized', 'single-visible-commit'], ['durable.write', 'object.finalize', 'policy.decision', 'branch.cas', 'metadata.commit', 'event.publish', 'index.cursor']),
  task('lock', true, 'FileID, branch domain, owner and expected generation are fixed', 'one fenced lock generation is visible', ['single-hard-lock', 'lock-generation-fenced'], ['policy.decision', 'lock.mutation', 'metadata.commit', 'event.publish']),
  task('merge', true, 'base, source and target snapshots are immutable and declared', 'merge result is verified and publication is atomic', ['content-complete', 'merge-base-bound', 'single-visible-commit'], ['durable.write', 'object.finalize', 'policy.decision', 'branch.cas', 'metadata.commit', 'event.publish', 'index.cursor']),
  task('ci', false, 'immutable snapshot and selection are declared', 'CI projection is content-complete and digest-verified', ['content-complete', 'snapshot-bound'], ['object.finalize', 'index.cursor']),
  task('verify', true, 'repository generation is fixed', 'all reached objects and mutable invariants are checked and unreachable objects are swept', ['content-complete', 'references-verifiable'], ['gc.mark', 'gc.sweep', 'index.cursor']),
  task('backup', true, 'metadata generation and content inventory are fixed', 'independently verifiable backup generation is published', ['backup-verifiable', 'content-complete'], ['backup.generate', 'metadata.commit']),
  task('restore', true, 'verified backup generation and empty target are fixed', 'restored target verifies before activation', ['backup-verifiable', 'content-complete', 'activation-atomic'], ['durable.write', 'object.finalize', 'metadata.commit']),
  task('export', true, 'source snapshot and export mode are fixed', 'independently verifiable export is finalized', ['export-verifiable', 'content-complete'], ['durable.write', 'export.finalize']),
]);

export const FAULT_ENTRIES = Object.freeze([
  fault('durable.write', 'durable-write', ['setup', 'sync', 'submit', 'merge', 'restore', 'export']),
  fault('object.finalize', 'object-finalize', ['sync', 'submit', 'merge', 'ci', 'restore']),
  fault('policy.decision', 'policy-decision', ['submit', 'lock', 'merge']),
  fault('branch.cas', 'branch-compare-and-swap', ['submit', 'merge']),
  fault('lock.mutation', 'lock-mutation', ['lock']),
  fault('metadata.commit', 'metadata-commit', ['setup', 'submit', 'lock', 'merge', 'backup', 'restore']),
  fault('event.publish', 'event-publication', ['submit', 'lock', 'merge']),
  fault('index.cursor', 'index-cursor', ['submit', 'merge', 'ci', 'verify']),
  fault('backup.generate', 'backup-generation', ['backup']),
  fault('export.finalize', 'export-finalize', ['export']),
  fault('gc.mark', 'gc-mark', ['verify']),
  fault('gc.sweep', 'gc-sweep', ['verify']),
]);

export const CACHE_STATES = Object.freeze([
  { id: 'cold', localBytes: 0, regionalBytes: 0, requiredObservation: 'both-empty' },
  { id: 'warm-local-cache', localBytes: 65_536, regionalBytes: 0, requiredObservation: 'local-nonempty' },
  { id: 'warm-regional-cache', localBytes: 0, regionalBytes: 65_536, requiredObservation: 'regional-nonempty' },
  { id: 'mixed-cache', localBytes: 32_768, regionalBytes: 65_536, requiredObservation: 'both-nonempty' },
]);

export const NETWORK_PROFILES = Object.freeze([
  network('loopback-simulated', 0, 0, 0, 0, 0, 0, 'simulated'),
  network('studio-near-20ms', 20, 100_000_000, 0, 0, 0, 0, 'simulated'),
  network('regional-80ms', 80, 25_000_000, 1_000, 0, 0, 0, 'simulated'),
  network('intercontinental-200ms', 200, 5_000_000, 5_000, 7, 11, 3, 'simulated'),
  network('privileged-netem-80ms', 80, 25_000_000, 1_000, 7, 11, 3, 'privileged'),
]);

export const HARNESS_PROFILES = Object.freeze([
  harnessProfile('local-smoke', 1, ['cold', 'warm-local-cache'], ['loopback-simulated'], false),
  harnessProfile('presubmit', 3, CACHE_STATES.map(({ id }) => id), ['loopback-simulated', 'studio-near-20ms'], true),
  harnessProfile('nightly', 10, CACHE_STATES.map(({ id }) => id), NETWORK_PROFILES.filter(({ mode }) => mode === 'simulated').map(({ id }) => id), true),
  harnessProfile('release', 30, CACHE_STATES.map(({ id }) => id), NETWORK_PROFILES.map(({ id }) => id), true),
]);

export const DRIVER_PROFILE = Object.freeze({
  schemaVersion: 'ogvcs.benchmark/driver-profile/v1',
  id: TEST_PROFILE_ID,
  version: 1,
  state: 'candidate',
  license: 'MIT',
  baseProtocolProfile: CONTROL_PROFILE_ID,
  framing: 'bounded-canonical-jsonl-v1',
  testModeOnly: true,
  authentication: 'explicit-local-test-mode-or-authenticated-test-service',
  versions: [1],
  requiredCapabilities: ['cache-control', 'deterministic-faults', 'invariant-check', 'lifecycle', 'metrics', 'task-execution'],
  operations: ['negotiate', 'configure', 'reset-cache', 'start', 'run-task', 'arm-fault', 'check-invariants', 'stop'],
  limits: LIMITS,
  productionFaultHooks: 'forbidden',
});

const errorCodes = ERROR_ENTRIES.map(([name]) => name);
const taskIds = TASK_ENTRIES.map(({ id }) => id);
const faultIds = FAULT_ENTRIES.map(({ id }) => id);
const cacheIds = CACHE_STATES.map(({ id }) => id);
const networkIds = NETWORK_PROFILES.map(({ id }) => id);
const operationIds = DRIVER_PROFILE.operations;

const defs = {
  id: { type: 'string', minLength: 1, maxLength: 256, pattern: '^[a-z0-9][a-z0-9._/-]*(?:@[0-9]+)?$', 'x-ogvcs-maxUtf8Bytes': 256 },
  sha256: { type: 'string', minLength: 64, maxLength: 64, pattern: '^[0-9a-f]{64}$', 'x-ogvcs-maxUtf8Bytes': 64 },
  nonNegative: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
  positive: { type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER },
  nullableString: { type: ['string', 'null'], maxLength: 4096, 'x-ogvcs-maxUtf8Bytes': 4096 },
  jsonValue: {
    anyOf: [
      { type: 'null' }, { type: 'boolean' },
      { type: 'integer', minimum: -Number.MAX_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER },
      { type: 'string', maxLength: 65_536, 'x-ogvcs-maxUtf8Bytes': 65_536 },
      { type: 'array', maxItems: 4_096, items: { $ref: '#/$defs/jsonValue' } },
      { type: 'object', maxProperties: 256, propertyNames: { maxLength: 256, 'x-ogvcs-maxUtf8Bytes': 256 }, additionalProperties: { $ref: '#/$defs/jsonValue' } },
    ],
    'x-ogvcs-maxDepth': 32,
    'x-ogvcs-maxNodes': 10_000,
  },
};

function schema(name, body) {
  return { $schema: DRAFT, $id: `${BASE}${name}.schema.json`, title: name, ...body, 'x-ogvcs-license': 'MIT' };
}

function objectSchema(name, version, properties, required = Object.keys(properties), extra = {}) {
  return schema(name, {
    type: 'object', additionalProperties: false,
    properties: { schemaVersion: { const: version }, ...properties },
    required: ['schemaVersion', ...required],
    ...extra,
  });
}

export const SCHEMAS = Object.freeze({
  'Common.schema.json': schema('Common', { $defs: defs }),
  'DriverHello.schema.json': objectSchema('DriverHello', 'ogvcs.benchmark/driver-hello/v1', {
    driverId: ref('id'),
    contractManifestSha256: ref('sha256'),
    protocolProfile: { const: CONTROL_PROFILE_ID },
    testProfile: { const: TEST_PROFILE_ID },
    versions: { type: 'array', minItems: 1, maxItems: 8, uniqueItems: true, items: { type: 'integer', minimum: 1, maximum: 65_535 } },
    capabilities: { type: 'array', minItems: 1, maxItems: 32, uniqueItems: true, items: ref('id') },
    maximumMessageBytes: { type: 'integer', minimum: 1, maximum: LIMITS.maxControlMessageBytes },
    mutationCount: ref('nonNegative'),
    faultHooksEnabled: { const: false },
  }),
  'DriverCommand.schema.json': objectSchema('DriverCommand', 'ogvcs.benchmark/driver-command/v1', {
    id: ref('id'),
    version: { type: 'integer', minimum: 1, maximum: 65_535 },
    operation: { enum: operationIds },
    idempotencyKey: { type: 'string', minLength: 16, maxLength: 256, pattern: '^[A-Za-z0-9._~-]+$', 'x-ogvcs-maxUtf8Bytes': 256 },
    payload: jsonRef(),
  }),
  'DriverTraceEvent.schema.json': objectSchema('DriverTraceEvent', 'ogvcs.benchmark/driver-trace-event/v1', {
    sequence: ref('nonNegative'), operation: { enum: operationIds }, phase: ref('id'), code: { enum: errorCodes },
    preMutation: { type: 'boolean' }, mutationCount: ref('nonNegative'), detail: jsonRef(),
  }),
  'DriverResult.schema.json': objectSchema('DriverResult', 'ogvcs.benchmark/driver-result/v1', {
    id: ref('id'), result: { enum: ['accept', 'reject'] }, code: { enum: errorCodes }, preMutation: { type: 'boolean' },
    mutationCount: ref('nonNegative'), retryable: { type: 'boolean' }, output: jsonRef(),
    trace: { type: 'array', maxItems: LIMITS.maxTraceEvents, items: { $ref: 'DriverTraceEvent.schema.json' } },
  }),
  'EnvironmentRecord.schema.json': objectSchema('EnvironmentRecord', 'ogvcs.benchmark/environment/v1', {
    capturedAt: { type: 'string', format: 'date-time', maxLength: 64 },
    classification: { enum: ['synthetic', 'partner-derived'] }, operatorDigest: ref('sha256'),
    implementation: strict({ id: ref('id'), version: { type: 'string', minLength: 1, maxLength: 128 }, commit: ref('sha256') }),
    corpus: strict({ profileId: { enum: ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio'] }, profileVersion: { const: '2.0.0' }, requestDigest: ref('sha256'), manifestDigest: ref('sha256'), generatorVersion: { const: '1.0.0' } }),
    configuration: strict({ harnessVersion: { const: CONTRACT_VERSION }, harnessProfile: { enum: HARNESS_PROFILES.map(({ id }) => id) }, thresholdDigest: ref('sha256'), seedDigest: ref('sha256'), iterations: { type: 'integer', minimum: 1, maximum: LIMITS.maxIterations }, concurrency: { type: 'integer', minimum: 1, maximum: 1024 }, cacheState: { enum: cacheIds }, networkProfile: { enum: networkIds } }),
    hardware: strict({ architecture: { type: 'string', minLength: 1, maxLength: 128 }, cpuModel: { type: 'string', minLength: 1, maxLength: 512 }, cpuCount: { type: 'integer', minimum: 1, maximum: 4096 }, memoryBytes: ref('positive') }),
    platform: strict({ os: { enum: ['linux', 'darwin', 'win32', 'other'] }, release: { type: 'string', minLength: 1, maxLength: 256 }, filesystem: { type: 'string', minLength: 1, maxLength: 128 }, nodeVersion: { type: 'string', minLength: 1, maxLength: 64 } }),
    topology: strict({ clientRegion: ref('id'), serviceRegion: ref('id'), cacheRegion: ref('id') }),
    network: strict({ rttMs: { type: 'integer', minimum: 0, maximum: 200 }, bandwidthBytesPerSecond: ref('nonNegative'), lossPartsPerMillion: { type: 'integer', minimum: 0, maximum: 1_000_000 }, interruptionEvery: ref('nonNegative'), duplicateEvery: ref('nonNegative'), reorderWindow: { type: 'integer', minimum: 0, maximum: 1024 }, mode: { enum: ['simulated', 'privileged'] } }),
    cacheInspection: strict({ state: { enum: cacheIds }, localBytes: ref('nonNegative'), regionalBytes: ref('nonNegative'), stateDigest: ref('sha256') }),
  }),
  'WorkloadDefinition.schema.json': objectSchema('WorkloadDefinition', 'ogvcs.benchmark/workload-definition/v1', {
    id: { enum: taskIds }, mutating: { type: 'boolean' }, startCondition: { type: 'string', minLength: 1, maxLength: 1024 }, endCondition: { type: 'string', minLength: 1, maxLength: 1024 },
    assertions: { type: 'array', minItems: 1, maxItems: 32, uniqueItems: true, items: ref('id') },
    faultPoints: { type: 'array', maxItems: 32, uniqueItems: true, items: { enum: faultIds } },
    requirementIds: requirementIds(),
  }),
  'FaultSchedule.schema.json': objectSchema('FaultSchedule', 'ogvcs.benchmark/fault-schedule/v1', {
    seedDigest: ref('sha256'),
    events: { type: 'array', maxItems: LIMITS.maxFaultEvents, items: strict({ ordinal: ref('nonNegative'), faultPoint: { enum: faultIds }, action: { enum: ['crash-before', 'crash-after', 'error', 'interrupt', 'duplicate', 'reorder'] }, occurrence: ref('positive') }) },
    scheduleDigest: ref('sha256'),
  }),
  'BenchmarkSample.schema.json': objectSchema('BenchmarkSample', 'ogvcs.benchmark/sample/v1', {
    id: ref('id'), taskId: { enum: taskIds }, corpusId: ref('id'), repetition: ref('nonNegative'), cacheState: { enum: cacheIds }, networkProfile: { enum: networkIds },
    status: { enum: ['success', 'failed', 'incomplete'] }, failureCode: { anyOf: [{ enum: errorCodes }, { type: 'null' }] },
    wallMicroseconds: ref('nonNegative'), cpuMicroseconds: ref('nonNegative'), peakMemoryBytes: ref('nonNegative'), diskReadBytes: ref('nonNegative'), diskWriteBytes: ref('nonNegative'), networkReadBytes: ref('nonNegative'), networkWriteBytes: ref('nonNegative'), logicalBytes: ref('nonNegative'), uniqueBytes: ref('nonNegative'), retries: ref('nonNegative'),
    assertions: { type: 'array', minItems: 1, maxItems: 64, items: strict({ id: ref('id'), passed: { type: 'boolean' } }) },
    faultScheduleDigest: { anyOf: [ref('sha256'), { type: 'null' }] },
  }, undefined, { allOf: [{ if: { properties: { status: { const: 'success' } }, required: ['status'] }, then: { properties: { failureCode: { type: 'null' }, assertions: { items: strict({ id: ref('id'), passed: { const: true } }) } } }, else: { properties: { failureCode: { enum: errorCodes.filter((name) => name !== 'HARNESS_OK') } } } }] }),
  'TaskSummary.schema.json': objectSchema('TaskSummary', 'ogvcs.benchmark/task-summary/v1', {
    taskId: { enum: taskIds }, corpusId: ref('id'), cacheState: { enum: cacheIds }, networkProfile: { enum: networkIds },
    sampleCount: ref('nonNegative'), succeeded: ref('nonNegative'), failed: ref('nonNegative'), incomplete: ref('nonNegative'), retries: ref('nonNegative'),
    durationMicroseconds: strict({ p50: ref('nonNegative'), p95: ref('nonNegative'), p99: ref('nonNegative'), minimum: ref('nonNegative'), maximum: ref('nonNegative'), medianAbsoluteDeviation: ref('nonNegative') }),
    bytes: strict({ diskRead: ref('nonNegative'), diskWrite: ref('nonNegative'), networkRead: ref('nonNegative'), networkWrite: ref('nonNegative'), logical: ref('nonNegative'), unique: ref('nonNegative'), logicalUniqueRatioMilli: ref('nonNegative') }),
    correctnessFailures: ref('nonNegative'), successRatePartsPerMillion: { type: 'integer', minimum: 0, maximum: 1_000_000 },
  }),
  'ThresholdFile.schema.json': objectSchema('ThresholdFile', 'ogvcs.benchmark/thresholds/v1', {
    version: { type: 'integer', minimum: 1, maximum: 65_535 }, owner: ref('id'),
    comparisonTolerancePartsPerMillion: { type: 'integer', minimum: 0, maximum: 1_000_000 },
    entries: { type: 'array', minItems: 1, maxItems: LIMITS.maxThresholds, items: strict({ id: ref('id'), requirementId: requirementId(), taskId: { anyOf: [{ enum: taskIds }, { const: '*' }] }, metric: { enum: ['successRatePartsPerMillion', 'correctnessFailures', 'failed', 'incomplete', 'overheadBasisPoints', 'faultInvariantFailures', 'securityNegativeMisses', 'protocolFailures'] }, operator: { enum: ['maximum', 'minimum'] }, value: ref('nonNegative'), minimumSamples: ref('nonNegative'), severity: { enum: ['gate', 'warning'] }, profiles: { type: 'array', minItems: 1, maxItems: 8, uniqueItems: true, items: { enum: HARNESS_PROFILES.map(({ id }) => id) } } }) },
  }),
  'ThresholdEvaluation.schema.json': objectSchema('ThresholdEvaluation', 'ogvcs.benchmark/threshold-evaluation/v1', {
    thresholdId: ref('id'), requirementId: requirementId(), metric: { enum: ['successRatePartsPerMillion', 'correctnessFailures', 'failed', 'incomplete', 'overheadBasisPoints', 'faultInvariantFailures', 'securityNegativeMisses', 'protocolFailures'] }, actual: ref('nonNegative'), expected: ref('nonNegative'), operator: { enum: ['maximum', 'minimum'] }, severity: { enum: ['gate', 'warning'] }, status: { enum: ['passed', 'failed', 'not-applicable'] },
  }),
  'HarnessEvidence.schema.json': objectSchema('HarnessEvidence', 'ogvcs.benchmark/evidence/v1', {
    faultMatrix: strict({
      rows: { type: 'array', minItems: 1, maxItems: LIMITS.maxFaultEvents, items: strict({ faultPoint: { enum: faultIds }, action: { enum: ['crash-before', 'crash-after', 'error'] }, taskId: { enum: taskIds }, injected: { type: 'boolean' }, taskStatus: { enum: ['success', 'failed', 'incomplete'] }, invariantPassed: { type: 'boolean' }, invariantFailures: { type: 'array', maxItems: 64, uniqueItems: true, items: ref('id') }, scheduleDigest: ref('sha256') }) },
      failed: ref('nonNegative'), scheduleSetDigest: ref('sha256'),
    }),
    brokenServices: strict({ cases: { type: 'array', minItems: 1, maxItems: 64, items: strict({ mode: ref('id'), expectedInvariant: ref('id'), detected: { type: 'boolean' }, failures: { type: 'array', maxItems: 64, uniqueItems: true, items: ref('id') } }) }, missed: ref('nonNegative') }),
    security: strict({ authorizationManifestSha256: ref('sha256'), authorizationRegistrySetSha256: ref('sha256'), authorizationAdapter: { const: 'reference-fixture' }, authorizationResultsSha256: ref('sha256'), authorizationVectors: ref('nonNegative'), authorizationPassed: ref('nonNegative'), authorizationFailed: ref('nonNegative'), authorizationRows: { type: 'array', minItems: 1, maxItems: 4_096, items: strict({ id: ref('id'), status: { enum: ['passed', 'failed'] }, expectedCode: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Z][A-Z0-9_]*$' }, actualCode: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Z][A-Z0-9_]*$' } }) }, pathManifestSha256: ref('sha256'), enumerationDetected: { type: 'boolean' }, workspaceEscapeDetected: { type: 'boolean' }, pathCases: { type: 'array', minItems: 1, maxItems: 64, items: strict({ caseDigest: ref('sha256'), rejected: { type: 'boolean' }, code: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Z][A-Z0-9_]*$' } }) }, misses: ref('nonNegative') }),
    deterministicFaults: { type: 'boolean' },
  }),
  'BenchmarkResultBundle.schema.json': objectSchema('BenchmarkResultBundle', 'ogvcs.benchmark/result-bundle/v1', {
    contractManifestSha256: ref('sha256'), runId: ref('id'), createdAt: { type: 'string', format: 'date-time', maxLength: 64 }, classification: { enum: ['synthetic', 'partner-derived'] },
    conformanceReportDigest: { anyOf: [ref('sha256'), { type: 'null' }] }, evidenceReportDigest: ref('sha256'),
    environmentCount: { type: 'integer', minimum: 1, maximum: LIMITS.maxCorpora * CACHE_STATES.length * NETWORK_PROFILES.length }, environmentSetDigest: ref('sha256'),
    workloadDefinitionsDigest: ref('sha256'), faultSchedules: { type: 'array', maxItems: LIMITS.maxFaultEvents, items: { $ref: 'FaultSchedule.schema.json' } },
    sampleCount: { type: 'integer', minimum: 1, maximum: LIMITS.maxSamples }, sampleSetDigest: ref('sha256'),
    summaryCount: { type: 'integer', minimum: 1, maximum: LIMITS.maxSamples }, summarySetDigest: ref('sha256'),
    thresholdFile: { $ref: 'ThresholdFile.schema.json' }, thresholdFileDigest: ref('sha256'), thresholdEvaluations: { type: 'array', maxItems: LIMITS.maxThresholds, items: { $ref: 'ThresholdEvaluation.schema.json' } },
    overallStatus: { enum: ['passed', 'failed', 'incomplete'] },
    overhead: strict({ measuredBasisPoints: ref('nonNegative'), correctionApplied: { type: 'boolean' }, correctionMicroseconds: ref('nonNegative'), method: { enum: ['measured-below-threshold', 'measured-and-corrected', 'reported-uncorrected'] } }),
    evidence: strict({ faultInvariantFailures: ref('nonNegative'), securityNegativeMisses: ref('nonNegative'), protocolFailures: ref('nonNegative'), cacheStatesInspected: { type: 'array', minItems: 1, maxItems: 4, uniqueItems: true, items: { enum: cacheIds } } }),
    reproduction: strict({ command: { type: 'string', minLength: 1, maxLength: 4096 }, seed: { type: 'string', minLength: 1, maxLength: 1024 }, harnessProfile: { enum: HARNESS_PROFILES.map(({ id }) => id) }, tolerancePartsPerMillion: { type: 'integer', minimum: 0, maximum: 1_000_000 } }),
    publicMetadata: jsonRef(),
    redaction: strict({ retentionDays: { type: 'integer', minimum: 1, maximum: 365 }, expiresAt: { type: 'string', format: 'date-time', maxLength: 64 } }),
  }),
  'BundleManifest.schema.json': objectSchema('BundleManifest', 'ogvcs.benchmark/publication-manifest/v1', {
    contractManifestSha256: ref('sha256'), bundleDigest: ref('sha256'),
    artifacts: { type: 'array', minItems: 5, maxItems: 16, items: strict({ path: { type: 'string', minLength: 1, maxLength: 256, pattern: '^[A-Za-z0-9._/-]+$' }, bytes: ref('positive'), sha256: ref('sha256'), mediaType: { enum: ['application/json', 'application/jsonl'] } }) },
  }),
  'ComparisonReport.schema.json': objectSchema('ComparisonReport', 'ogvcs.benchmark/comparison/v1', {
    baselineDigest: ref('sha256'), candidateDigest: ref('sha256'), tolerancePartsPerMillion: { type: 'integer', minimum: 0, maximum: 1_000_000 }, comparable: { type: 'boolean' }, reproduced: { type: 'boolean' },
    rows: { type: 'array', maxItems: LIMITS.maxSamples, items: strict({ key: { type: 'string', minLength: 1, maxLength: 1024 }, baselineP50: ref('nonNegative'), candidateP50: ref('nonNegative'), p50DeltaPartsPerMillion: { type: 'integer', minimum: -Number.MAX_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER }, baselineP95: ref('nonNegative'), candidateP95: ref('nonNegative'), p95DeltaPartsPerMillion: { type: 'integer', minimum: -Number.MAX_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER }, baselineP99: ref('nonNegative'), candidateP99: ref('nonNegative'), p99DeltaPartsPerMillion: { type: 'integer', minimum: -Number.MAX_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER }, baselineMedianAbsoluteDeviation: ref('nonNegative'), candidateMedianAbsoluteDeviation: ref('nonNegative'), medianAbsoluteDeviationDeltaPartsPerMillion: { type: 'integer', minimum: -Number.MAX_SAFE_INTEGER, maximum: Number.MAX_SAFE_INTEGER }, semanticEqual: { type: 'boolean' }, withinTolerance: { type: 'boolean' } }) },
    reasons: { type: 'array', maxItems: 64, uniqueItems: true, items: ref('id') },
  }),
  'ConformanceReport.schema.json': objectSchema('ConformanceReport', 'ogvcs.benchmark/conformance-report/v1', {
    contractManifestSha256: ref('sha256'), implementation: ref('id'), cases: ref('nonNegative'), passed: ref('nonNegative'), failed: ref('nonNegative'), resultsDigest: ref('sha256'),
    rows: { type: 'array', maxItems: 4096, items: strict({ id: ref('id'), requirementIds: requirementIds(), status: { enum: ['passed', 'failed'] }, code: { enum: errorCodes }, preMutation: { type: 'boolean' } }) },
  }),
});

export const REGISTRIES = Object.freeze({
  tasks: registry('tasks', TASK_ENTRIES),
  faults: registry('faults', FAULT_ENTRIES),
  errors: registry('errors', ERROR_ENTRIES.map(([name, code, stage, retryable]) => ({ name, code, stage, retryable }))),
  limits: registry('limits', Object.entries(LIMITS).map(([name, value], index) => ({ code: index + 1, name, value, enforcement: 'preflight-or-before-growth' }))),
  'cache-states': registry('cache-states', CACHE_STATES),
  networks: registry('networks', NETWORK_PROFILES),
  'harness-profiles': registry('harness-profiles', HARNESS_PROFILES),
});

export const PROFILES = Object.freeze({ 'benchmark-fault-driver-v1.json': DRIVER_PROFILE });

export const THRESHOLDS = Object.freeze({
  'default-v1.json': {
    schemaVersion: 'ogvcs.benchmark/thresholds/v1', version: 1, owner: 'ogvcs-005', comparisonTolerancePartsPerMillion: 100_000,
    entries: [
      threshold('all-tasks-succeed', 'OGVCS-005-FR-02', '*', 'successRatePartsPerMillion', 'minimum', 1_000_000, 1, 'gate'),
      threshold('no-correctness-failures', 'OGVCS-005-FR-02', '*', 'correctnessFailures', 'maximum', 0, 1, 'gate'),
      threshold('no-failed-samples', 'OGVCS-005-AC-01', '*', 'failed', 'maximum', 0, 1, 'gate'),
      threshold('no-incomplete-samples', 'OGVCS-005-FR-02', '*', 'incomplete', 'maximum', 0, 1, 'gate'),
      threshold('fault-invariants-hold', 'OGVCS-005-AC-03', '*', 'faultInvariantFailures', 'maximum', 0, 0, 'gate'),
      threshold('negative-suites-detect-defects', 'OGVCS-005-AC-04', '*', 'securityNegativeMisses', 'maximum', 0, 0, 'gate'),
      threshold('driver-conformance-passes', 'OGVCS-005-AC-07', '*', 'protocolFailures', 'maximum', 0, 0, 'gate'),
      threshold('measurement-overhead-five-percent', 'OGVCS-005-NFR-02', '*', 'overheadBasisPoints', 'maximum', 500, 0, 'warning'),
    ],
  },
});

export const VECTORS = Object.freeze({
  'conformance.json': {
    schemaVersion: 'ogvcs.benchmark/conformance-corpus/v1',
    cases: [
      vector('environment-record-complete', ['OGVCS-005-FR-01'], 'environment', 'HARNESS_OK', true),
      vector('task-start-end-and-assertions', ['OGVCS-005-FR-02'], 'tasks', 'HARNESS_TASK_INCOMPLETE', true),
      vector('task-assertion-inventory-complete', ['OGVCS-005-FR-02'], 'tasks', 'HARNESS_PROTOCOL_MALFORMED', false),
      vector('task-status-retryability-consistent', ['OGVCS-005-FR-02'], 'tasks', 'HARNESS_PROTOCOL_MALFORMED', false),
      vector('network-range-and-fault-controls', ['OGVCS-005-FR-04'], 'network', 'HARNESS_OK', true),
      vector('statistics-and-byte-accounting', ['OGVCS-005-FR-07'], 'statistics', 'HARNESS_OK', true),
      vector('all-five-corpora-smoke', ['OGVCS-005-AC-01'], 'corpora', 'HARNESS_OK', false),
      vector('second-operator-tolerance', ['OGVCS-005-AC-05'], 'comparison', 'HARNESS_OK', true),
      vector('comparison-tolerance-authority', ['OGVCS-005-FR-08', 'OGVCS-005-AC-05'], 'comparison', 'HARNESS_INPUT_INVALID', true),
      vector('tiered-matrix-without-code-edit', ['OGVCS-005-AC-06'], 'matrix', 'HARNESS_OK', true),
      vector('driver-compatible-negotiation', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_OK', true),
      vector('driver-incompatible-before-mutation', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_NEGOTIATION_INCOMPATIBLE', true),
      vector('driver-malformed-line-bounded', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_PROTOCOL_MALFORMED', true),
      vector('driver-message-limit-before-mutation', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_LIMIT_EXCEEDED', true),
      vector('driver-retry-idempotent', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_OK', false),
      vector('driver-lifecycle-fault-hook-executed', ['OGVCS-005-FR-10', 'OGVCS-005-AC-07'], 'driver', 'HARNESS_OK', false),
      vector('fault-schedule-repeatable', ['OGVCS-005-NFR-01'], 'faults', 'HARNESS_OK', true),
      vector('fault-matrix-healthy', ['OGVCS-005-FR-05', 'OGVCS-005-FR-06'], 'faults', 'HARNESS_OK', false),
      vector('broken-submit-detected', ['OGVCS-005-AC-03'], 'faults', 'HARNESS_FAULT_INVARIANT_FAILED', false),
      vector('authorization-enumeration-detected', ['OGVCS-005-AC-04'], 'security', 'HARNESS_ASSERTION_FAILED', true),
      vector('workspace-escape-detected', ['OGVCS-005-AC-04'], 'security', 'HARNESS_ASSERTION_FAILED', true),
      vector('cache-state-independent-inspection', ['OGVCS-005-FR-03', 'OGVCS-005-AC-02'], 'cache', 'HARNESS_OK', true),
      vector('threshold-requirement-binding', ['OGVCS-005-FR-08'], 'thresholds', 'HARNESS_THRESHOLD_FAILED', true),
      vector('public-bundle-tamper-detected', ['OGVCS-005-FR-09'], 'bundle', 'HARNESS_BUNDLE_INVALID', true),
      vector('public-bundle-derived-claims-recomputed', ['OGVCS-005-FR-02', 'OGVCS-005-FR-08', 'OGVCS-005-FR-09'], 'bundle', 'HARNESS_INPUT_INVALID', true),
      vector('public-bundle-evidence-claims-recomputed', ['OGVCS-005-FR-05', 'OGVCS-005-FR-06', 'OGVCS-005-FR-09', 'OGVCS-005-AC-03', 'OGVCS-005-AC-04'], 'bundle', 'HARNESS_INPUT_INVALID', true),
      vector('public-bundle-security-authority-binding', ['OGVCS-005-FR-09', 'OGVCS-005-AC-04'], 'bundle', 'HARNESS_INPUT_INVALID', true),
      vector('public-bundle-authority-binding', ['OGVCS-005-FR-09'], 'bundle', 'HARNESS_BUNDLE_INVALID', true),
      vector('public-bundle-input-stability', ['OGVCS-005-FR-09'], 'bundle', 'HARNESS_BUNDLE_INVALID', true),
      vector('public-bundle-conformance-inventory', ['OGVCS-005-FR-09', 'OGVCS-005-AC-07'], 'bundle', 'HARNESS_BUNDLE_INVALID', true),
      vector('public-bundle-public-fields-owned', ['OGVCS-005-FR-09'], 'bundle', 'HARNESS_BUNDLE_INVALID', true),
      vector('partner-identifier-redacted', ['OGVCS-005-FR-09'], 'bundle', 'HARNESS_OK', true),
      vector('privileged-network-isolated', ['OGVCS-005-NFR-03'], 'network', 'HARNESS_PRIVILEGE_REQUIRED', true),
      vector('privileged-network-apply-rollback', ['OGVCS-005-NFR-03'], 'network', 'HARNESS_IO', true),
      vector('measurement-overhead-reported-or-corrected', ['OGVCS-005-NFR-02'], 'measurement', 'HARNESS_OK', true),
    ],
  },
});

function task(id, mutating, startCondition, endCondition, assertions, faultPoints) {
  return { schemaVersion: 'ogvcs.benchmark/workload-definition/v1', id, mutating, startCondition, endCondition, assertions, faultPoints, requirementIds: ['OGVCS-005-FR-02'] };
}

function fault(id, boundary, tasks) {
  return { id, boundary, tasks, testModeOnly: true, actions: ['crash-before', 'crash-after', 'error'] };
}

function network(id, rttMs, bandwidthBytesPerSecond, lossPartsPerMillion, interruptionEvery, duplicateEvery, reorderWindow, mode) {
  return { id, rttMs, bandwidthBytesPerSecond, lossPartsPerMillion, interruptionEvery, duplicateEvery, reorderWindow, mode };
}

function harnessProfile(id, repetitions, cacheStates, networkProfiles, faults) {
  return { id, repetitions, cacheStates, networkProfiles, tasks: TASK_ENTRIES.map(({ id: taskId }) => taskId), corpora: ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'], faults, privileged: networkProfiles.some((name) => name.startsWith('privileged-')) };
}

function registry(name, entries) {
  return { schemaVersion: 'ogvcs.benchmark/registry/v1', registry: name, version: 1, license: 'MIT', entries };
}

function ref(name) { return { $ref: `Common.schema.json#/$defs/${name}` }; }
function jsonRef() { return { $ref: 'Common.schema.json#/$defs/jsonValue' }; }
function strict(properties, required = Object.keys(properties)) { return { type: 'object', additionalProperties: false, properties, required }; }
function requirementId() { return { type: 'string', pattern: '^OGVCS-[0-9]{3}-(?:FR|NFR|AC)-[0-9]{2}$', minLength: 15, maxLength: 20 }; }
function requirementIds() { return { type: 'array', minItems: 1, maxItems: 32, uniqueItems: true, items: requirementId() }; }
function threshold(id, requirementIdValue, taskId, metric, operator, value, minimumSamples, severity) { return { id, requirementId: requirementIdValue, taskId, metric, operator, value, minimumSamples, severity, profiles: HARNESS_PROFILES.map(({ id: profileId }) => profileId) }; }
function vector(id, requirementIdsValue, kind, expectedCode, preMutation) { return { id, requirementIds: requirementIdsValue, kind, expected: { code: expectedCode, preMutation } }; }
