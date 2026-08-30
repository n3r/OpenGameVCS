export const PROFILE_TEXT = 'chunking.opengamevcs/gear-fastcdc-1m@1';

// Single source for the language-neutral public error authority. The JS and
// Rust packages have static parity tests against the generated registry.
export const ERRORS = Object.freeze([
  'CHUNK_BOUNDARY_MISMATCH',
  'CHUNK_COUNT_EXCEEDED',
  'CHUNK_DECLARED_LENGTH_INVALID',
  'CHUNK_DIGEST_MISMATCH',
  'CHUNK_FINGERPRINT_INPUT_INVALID',
  'CHUNK_FRAGMENT_INVALID',
  'CHUNK_MANIFEST_MISMATCH',
  'CHUNK_METADATA_CONFLICT',
  'CHUNK_PROFILE_UNSUPPORTED',
  'CHUNK_PUBLICATION_FAILED',
  'CHUNK_RESOURCE_EXHAUSTED',
  'CHUNK_RESOURCE_INVALID',
  'CHUNK_RESOURCE_UNSUPPORTED',
  'CHUNK_SCRATCH_EXHAUSTED',
  'CHUNK_SESSION_FAILED',
  'CHUNK_SESSION_FINISHED',
  'CHUNK_SINK_FAILED',
  'CHUNK_SINK_INVALID',
  'CHUNK_SOURCE_INVALID',
  'CHUNK_SOURCE_MISSING',
  'CHUNK_SOURCE_TOO_LONG',
  'CHUNK_SOURCE_TOO_SHORT',
]);

export const GOLDEN_INPUTS = Object.freeze([
  { caseId: 'empty', recipe: { kind: 'literal', hex: '' } },
  { caseId: 'tiny-ascii', recipe: { kind: 'literal', hex: '4f70656e47616d655643530a' } },
  { caseId: 'small-maximum', recipe: { kind: 'repeat', byte: 165, length: 262144 } },
  { caseId: 'counter-a-six-mib', recipe: { kind: 'sha256-counter', seed: 'counter-a', length: 6291456 } },
  { caseId: 'counter-b-four-mib', recipe: { kind: 'sha256-counter', seed: 'counter-b', length: 4194304 } },
  { caseId: 'zero-five-mib', recipe: { kind: 'repeat', byte: 0, length: 5242880 } },
  { caseId: 'ff-five-mib', recipe: { kind: 'repeat', byte: 255, length: 5242880 } },
  { caseId: 'insertion-base', recipe: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 } },
  { caseId: 'insertion-plus-17', recipe: { kind: 'insert', base: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 }, offset: 1048593, hex: '00112233445566778899aabbccddeeff42' } },
]);

export const MALFORMED = Object.freeze([
  { caseId: 'declared-negative', operation: 'chunk', parameters: { declaredLength: -1 }, expectedError: 'CHUNK_DECLARED_LENGTH_INVALID' },
  { caseId: 'declared-over-limit', operation: 'chunk', parameters: { declaredLength: 1099511627777 }, expectedError: 'CHUNK_DECLARED_LENGTH_INVALID' },
  { caseId: 'source-short', operation: 'chunk', parameters: { declaredLength: 4, sourceHex: '000102' }, expectedError: 'CHUNK_SOURCE_TOO_SHORT' },
  { caseId: 'source-long', operation: 'chunk', parameters: { declaredLength: 2, sourceHex: '000102' }, expectedError: 'CHUNK_SOURCE_TOO_LONG' },
  { caseId: 'unknown-profile', operation: 'chunk', parameters: { declaredLength: 0, profile: 'chunking.opengamevcs/unknown@1' }, expectedError: 'CHUNK_PROFILE_UNSUPPORTED' },
  { caseId: 'wrong-profile-major', operation: 'chunk', parameters: { declaredLength: 0, profile: 'chunking.opengamevcs/gear-fastcdc-1m@2' }, expectedError: 'CHUNK_PROFILE_UNSUPPORTED' },
  { caseId: 'boundary-shift', operation: 'verify', parameters: { vector: 'counter-a-six-mib', boundaryDelta: 1 }, expectedError: 'CHUNK_BOUNDARY_MISMATCH' },
  { caseId: 'chunk-bit-flip', operation: 'verify', parameters: { vector: 'counter-a-six-mib', chunkIndex: 0, xor: 1 }, expectedError: 'CHUNK_DIGEST_MISMATCH' },
  { caseId: 'manifest-bit-flip', operation: 'verify', parameters: { vector: 'counter-a-six-mib', manifestByte: 0, xor: 1 }, expectedError: 'CHUNK_MANIFEST_MISMATCH' },
  { caseId: 'fragment-over-limit', operation: 'chunk', parameters: { declaredLength: 67108865, fragmentLength: 67108865 }, expectedError: 'CHUNK_FRAGMENT_INVALID' },
  { caseId: 'resource-below-scalar-minimum', operation: 'chunk', parameters: { declaredLength: 6291456, maxWorkingMemoryBytes: 4259839 }, expectedError: 'CHUNK_RESOURCE_EXHAUSTED' },
]);

export const SELECTION_BENCHMARK_WORKLOADS = Object.freeze([
  {
    workloadId: 'source-like',
    class: 'source-like',
    mutationKind: 'replacement',
    description: 'Fixed-width source-like text with a bounded edited line window that preserves an exact suffix.',
    baseRecipe: { kind: 'source-like-text', lines: 220000, salt: 0, editStartLine: 0, editLineCount: 0 },
    candidateRecipe: { kind: 'source-like-text', lines: 220000, salt: 11, editStartLine: 90000, editLineCount: 3000 },
  },
  {
    workloadId: 'structured',
    class: 'structured',
    mutationKind: 'replacement',
    description: 'Fixed-width structured records with a bounded edited record window that keeps chunk boundaries stable.',
    baseRecipe: { kind: 'structured-records', records: 220000, salt: 0, editStartRecord: 0, editRecordCount: 0 },
    candidateRecipe: { kind: 'structured-records', records: 220000, salt: 19, editStartRecord: 58000, editRecordCount: 2200 },
  },
  {
    workloadId: 'already-compressed',
    class: 'already-compressed',
    mutationKind: 'replacement',
    description: 'Deterministic gzip of the source-like corpus to show that small logical edits can still yield poor chunk reuse after compression.',
    baseRecipe: {
      kind: 'gzip',
      source: { kind: 'source-like-text', lines: 220000, salt: 0, editStartLine: 0, editLineCount: 0 },
    },
    candidateRecipe: {
      kind: 'gzip',
      source: { kind: 'source-like-text', lines: 220000, salt: 11, editStartLine: 90000, editLineCount: 3000 },
    },
  },
  {
    workloadId: 'encrypted-random',
    class: 'encrypted/random',
    mutationKind: 'replacement',
    description: 'Two equal-length pseudorandom byte streams with independent seeds and no expected reuse.',
    baseRecipe: { kind: 'sha256-counter', seed: 'random-base-a', length: 6291456 },
    candidateRecipe: { kind: 'sha256-counter', seed: 'random-base-b', length: 6291456 },
  },
  {
    workloadId: 'insertion',
    class: 'insertion',
    mutationKind: 'insertion',
    description: 'The bounded golden insertion pair exercises boundary re-synchronization after a 17-byte insert near the 1 MiB target.',
    baseRecipe: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 },
    candidateRecipe: {
      kind: 'insert',
      base: { kind: 'sha256-counter', seed: 'insertion-base', length: 5242880 },
      offset: 1048593,
      hex: '00112233445566778899aabbccddeeff42',
    },
  },
  {
    workloadId: 'replacement',
    class: 'replacement',
    mutationKind: 'replacement',
    description: 'A fixed-length replacement window near the 1 MiB target measures reuse after an in-place rewrite.',
    baseRecipe: { kind: 'sha256-counter', seed: 'replacement-base', length: 5242880 },
    candidateRecipe: {
      kind: 'replace-window',
      base: { kind: 'sha256-counter', seed: 'replacement-base', length: 5242880 },
      offset: 1048593,
      replacement: { kind: 'sha256-counter', seed: 'replacement-window', length: 524288 },
    },
  },
  {
    workloadId: 'append',
    class: 'append',
    mutationKind: 'append',
    description: 'A deterministic suffix append isolates reused prefix chunks from newly required tail bytes.',
    baseRecipe: { kind: 'sha256-counter', seed: 'append-base', length: 4194304 },
    candidateRecipe: {
      kind: 'append',
      base: { kind: 'sha256-counter', seed: 'append-base', length: 4194304 },
      suffix: { kind: 'sha256-counter', seed: 'append-suffix', length: 786432 },
    },
  },
]);

export const SELECTION_BENCHMARK_THRESHOLDS = Object.freeze({
  schemaVersion: 'ogvcs.chunking/selection-benchmark-thresholds/v1',
  version: 1,
  owner: 'ogvcs-007',
  entries: [
    { id: 'all-seven-workloads-present', requirementId: 'OGVCS-007-FR-08', workloadId: '*', metric: 'workloadCount', operator: 'minimum', value: 7, severity: 'gate' },
    { id: 'all-seven-workloads-succeed', requirementId: 'OGVCS-005-FR-02', workloadId: '*', metric: 'successCount', operator: 'minimum', value: 7, severity: 'gate' },
    { id: 'all-byte-accounting-balances', requirementId: 'OGVCS-007-NFR-03', workloadId: '*', metric: 'accountingMismatchCount', operator: 'maximum', value: 0, severity: 'gate' },
    { id: 'source-like-retains-material-reuse', requirementId: 'OGVCS-007-FR-08', workloadId: 'source-like', metric: 'reusedBytes', operator: 'minimum', value: 4000000, severity: 'warning' },
    { id: 'structured-retains-material-reuse', requirementId: 'OGVCS-007-FR-08', workloadId: 'structured', metric: 'reusedBytes', operator: 'minimum', value: 14000000, severity: 'warning' },
    { id: 'compressed-observes-poor-reuse', requirementId: 'OGVCS-007-AC-04', workloadId: 'already-compressed', metric: 'reusedBytes', operator: 'maximum', value: 262144, severity: 'warning' },
    { id: 'random-observes-no-reuse', requirementId: 'OGVCS-007-AC-04', workloadId: 'encrypted-random', metric: 'reusedBytes', operator: 'maximum', value: 0, severity: 'warning' },
    { id: 'insertion-resynchronizes-boundedly', requirementId: 'OGVCS-007-AC-04', workloadId: 'insertion', metric: 'resynchronizationDistanceBytes', operator: 'maximum', value: 1048576, severity: 'warning' },
    { id: 'replacement-resynchronizes-boundedly', requirementId: 'OGVCS-007-AC-04', workloadId: 'replacement', metric: 'resynchronizationDistanceBytes', operator: 'maximum', value: 1572864, severity: 'warning' },
    { id: 'append-limits-new-tail-bytes', requirementId: 'OGVCS-007-FR-08', workloadId: 'append', metric: 'newlyRequiredBytes', operator: 'maximum', value: 2097152, severity: 'warning' },
  ],
});
