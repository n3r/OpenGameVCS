export const CONTRACT_VERSION = '0.1.0-rc.1';
export const OWNER = 'ogvcs-007';
export const PROFILE = 'chunking.opengamevcs/gear-fastcdc-1m@1';
export const LOGICAL_BYTES = 100 * 1024 * 1024 * 1024;
export const SOURCE_REVISION_BINDING = 'workflow-supplied-not-git-bound';

export const SOURCE = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/scale-source-repeated-lcg-v1',
  logicalBytes: String(LOGICAL_BYTES),
  patternBytes: 8_388_608,
  repetitions: 12_800,
  patternSha256: 'b4798e6f4c78cbeb0b69d6a83b60dfb1bb68196f8c7913dec1bf1bc6fa3921a4',
  seed: 1_330_075_203,
  multiplier: 1_664_525,
  increment: 1_013_904_223,
  outputByte: 'state-bits-31-through-24-after-step',
});

export const BOUNDS = Object.freeze({
  wallTimeMillisecondsMaximum: 18_000_000,
  cpuTimeMicrosecondsMaximum: 36_000_000_000,
  processWriteBytesMaximum: 536_870_912,
  peakRssBytesMaximum: 536_870_912,
  ledgerMemoryBytesMaximum: 1_048_576,
  ledgerScratchBytesMaximum: 67_108_864,
  manifestBytesMaximum: 67_110_912,
  temporaryWholeFileAllowed: false,
});

export const AUTHORITY = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/exact-scale-authority/v1',
  owner: OWNER,
  corpus: Object.freeze({
    id: 'chunking-exact-scale',
    generatorVersion: '1.0.0',
    profile: PROFILE,
    source: SOURCE,
  }),
  task: Object.freeze({
    id: 'chunking-exact-scale-verify',
    startCondition: 'one implementation begins from the exact source recipe with an empty bounded ledger and scratch root',
    completionCondition: 'the campaign has run each implementation over exactly 100 GiB; each emitted one canonical manifest through a bounded sink, accounted for every chunk and the whole file, and satisfied resource and cleanup bounds; the independent comparator accepted exactly matching result projections',
    assertions: Object.freeze([
      'chunking-exact-source-bound',
      'chunking-exact-byte-accounting',
      'chunking-exact-canonical-manifest-emitted',
      'chunking-exact-cross-implementation-result-parity',
      'chunking-exact-resource-bounds',
      'chunking-exact-no-whole-file-copy',
      'chunking-exact-report-content-bound',
    ]),
  }),
  profile: Object.freeze({
    id: 'chunking-exact-scale-release',
    implementations: Object.freeze(['javascript', 'rust']),
    repetitions: 1,
    releaseOnly: true,
    exactScaleExecutedRequired: true,
    ordinaryDispatchAllowed: false,
    sourceRevisionBinding: SOURCE_REVISION_BINDING,
  }),
});

export const THRESHOLD = Object.freeze({
  schemaVersion: 'ogvcs.chunking-manifest/exact-scale-thresholds/v1',
  id: 'chunking-exact-scale-release-v1',
  owner: OWNER,
  profile: AUTHORITY.profile.id,
  entries: Object.freeze([
    Object.freeze({ id: 'exact-scale-executed', requirementId: 'OGVCS-007-AC-03', metric: 'exactScaleExecuted', operator: 'equal', value: true }),
    Object.freeze({ id: 'exact-logical-bytes', requirementId: 'OGVCS-007-AC-03', metric: 'logicalBytes', operator: 'equal', value: String(LOGICAL_BYTES) }),
    Object.freeze({ id: 'wall-time-bound', requirementId: 'OGVCS-007-NFR-02', metric: 'wallTimeMilliseconds', operator: 'maximum', value: BOUNDS.wallTimeMillisecondsMaximum }),
    Object.freeze({ id: 'cpu-time-bound', requirementId: 'OGVCS-007-NFR-02', metric: 'cpuMicroseconds', operator: 'maximum', value: BOUNDS.cpuTimeMicrosecondsMaximum }),
    Object.freeze({ id: 'process-write-bound', requirementId: 'OGVCS-007-NFR-02', metric: 'processWriteBytes', operator: 'maximum', value: BOUNDS.processWriteBytesMaximum }),
    Object.freeze({ id: 'peak-rss-bound', requirementId: 'OGVCS-007-NFR-02', metric: 'peakRssBytes', operator: 'maximum', value: BOUNDS.peakRssBytesMaximum }),
    Object.freeze({ id: 'ledger-memory-bound', requirementId: 'OGVCS-007-FR-03', metric: 'ledgerPeakMemoryBytes', operator: 'maximum', value: BOUNDS.ledgerMemoryBytesMaximum }),
    Object.freeze({ id: 'ledger-scratch-bound', requirementId: 'OGVCS-007-FR-03', metric: 'ledgerPeakScratchBytes', operator: 'maximum', value: BOUNDS.ledgerScratchBytesMaximum }),
    Object.freeze({ id: 'manifest-byte-bound', requirementId: 'OGVCS-007-FR-03', metric: 'manifestBytes', operator: 'maximum', value: BOUNDS.manifestBytesMaximum }),
    Object.freeze({ id: 'scratch-cleaned', requirementId: 'OGVCS-007-FR-03', metric: 'scratchArtifactsAfter', operator: 'equal', value: 0 }),
    Object.freeze({ id: 'no-whole-file-temporary', requirementId: 'OGVCS-007-NFR-02', metric: 'temporaryWholeFileAllowed', operator: 'equal', value: false }),
  ]),
});

const strict = (properties, required = Object.keys(properties)) => ({
  type: 'object',
  additionalProperties: false,
  required,
  properties,
});
const integer = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER) => ({ type: 'integer', minimum, maximum });
const sha256 = { type: 'string', pattern: '^[0-9a-f]{64}$' };

export const REPORT_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://schemas.opengamevcs.dev/chunking-scale-evidence/v1/scale-report.schema.json',
  title: 'OGVCS-007 exact-scale implementation report',
  ...strict({
    schemaVersion: { const: 'ogvcs.chunking-manifest/scale-report/v1' },
    implementation: { enum: ['javascript', 'rust'] },
    profile: { const: PROFILE },
    sourceRevision: { type: 'string', pattern: '^[0-9a-f]{40}$' },
    exactScaleExecuted: { const: true },
    runtime: strict({ os: { const: 'linux' }, architecture: { enum: ['x64', 'arm64'] }, version: { type: 'string', minLength: 1, maxLength: 32 } }),
    source: { const: SOURCE },
    result: strict({
      class: { const: 'cdc-1m' },
      logicalBytes: { const: String(LOGICAL_BYTES) },
      chunkCount: integer(1, 1_048_576),
      totalChunkBytes: { const: String(LOGICAL_BYTES) },
      minimumChunkBytes: integer(1, 2_097_152),
      maximumChunkBytes: integer(1, 2_097_152),
      wholeFileSha256: sha256,
      manifestObjectId: { type: 'string', pattern: '^ogvcs:v1:content-manifest:sha256:[0-9a-f]{64}$' },
      manifestSha256: sha256,
      manifestBytes: integer(1, BOUNDS.manifestBytesMaximum),
      boundaryTranscriptSha256: sha256,
    }),
    resources: strict({
      wallTimeMilliseconds: integer(1, BOUNDS.wallTimeMillisecondsMaximum),
      cpuMicroseconds: integer(1, BOUNDS.cpuTimeMicrosecondsMaximum),
      cpuSource: { enum: ['node:process.cpuUsage:user+system-microseconds', 'linux:/proc/self/schedstat:runtime-nanoseconds'] },
      diskReadBytes: integer(), diskWriteBytes: integer(),
      ioSource: { const: 'linux:/proc/self/io:read_bytes+write_bytes' },
      processWriteBytes: integer(0, BOUNDS.processWriteBytesMaximum),
      processWriteSource: { const: 'linux:/proc/self/io:wchar' },
      measurementScope: { const: 'source-pattern-generation-through-scratch-cleanup-before-report-publication' },
      throughputBytesPerSecond: integer(1),
      peakRssBytes: integer(1, BOUNDS.peakRssBytesMaximum),
      maxRssSource: { enum: ['node:process.resourceUsage().maxRSS-kib', 'linux:/proc/self/status:VmHWM-kib'] },
      patternBufferBytes: { const: SOURCE.patternBytes }, scalarWorkingMemoryBytes: { const: 4_259_840 },
      ledgerRecords: integer(1, 1_048_576), ledgerPeakMemoryBytes: integer(1, BOUNDS.ledgerMemoryBytesMaximum),
      ledgerPeakScratchBytes: integer(1, BOUNDS.ledgerScratchBytesMaximum), ledgerSpilled: { const: true },
      scratchArtifactsAfter: { const: 0 },
    }),
    bounds: { const: BOUNDS },
    overallStatus: { const: 'passed' },
  }),
});

const retainedArtifact = (path) => strict({
  path: { const: path },
  mediaType: { const: 'application/json' },
  bytes: integer(2, 262_144),
  sha256,
  content: { type: 'string', minLength: 2, maxLength: 262_144 },
});

export const RETAINED_PUBLICATION_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://schemas.opengamevcs.dev/chunking-scale-evidence/v1/retained-publication.schema.json',
  title: 'OGVCS-007 retained exact-scale publication',
  ...strict({
    schemaVersion: { const: 'ogvcs.chunking-manifest/exact-scale-retained-publication/v1' },
    implementation: { enum: ['javascript', 'rust'] },
    bundleDigest: sha256,
    artifacts: {
      type: 'array',
      minItems: 3,
      maxItems: 3,
      prefixItems: [retainedArtifact('manifest.json'), retainedArtifact('projection.json'), retainedArtifact('report.json')],
      items: false,
    },
    publicationSha256: sha256,
  }),
});
