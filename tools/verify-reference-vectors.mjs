#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const FORMAT = join('spec', 'repository-format', 'v1');
const VECTOR_RELATIVE = join(FORMAT, 'vectors');
const MAX_JSON_BYTES = 16_777_216;
const EXPECTED = Object.freeze({ artifacts: 2815, obligations: 486, scenarios: 573, stableErrors: 81 });
const UNICODE_SOURCE_SHA256 = '7570877e0fa197c45338f7c41a02636da4e14c8dba6a3611a01cd30bf329d5ca';
const VALIDATION_STAGES = Object.freeze([
  'configured-resource-preflight', 'canonical-framing', 'sequence-shape-and-order',
  'declared-identity', 'transcript-authentication', 'known-schema',
  'closure-and-reference-resolution', 'declared-accounting', 'registry-semantics',
  'repository-semantics'
]);
const REGISTRY_FILES = Object.freeze([
  'object-kinds.json', 'hash-algorithms.json', 'common-fields.json', 'kind-fields.json',
  'entry-kinds.json', 'entry-modes.json', 'required-features.json', 'extensions.json',
  'profiles.json', 'logical-record-types.json', 'semantic-enums.json', 'limits.json'
]);
const REQUIREMENT_IDS = Object.freeze([
  'OGVCS-002-FR-04', 'OGVCS-002-FR-06', 'OGVCS-002-FR-09', 'OGVCS-002-FR-11',
  'OGVCS-002-FR-13', 'OGVCS-002-NFR-01', 'OGVCS-002-NFR-04', 'OGVCS-002-AC-03',
  'OGVCS-002-AC-04', 'OGVCS-002-AC-06', 'OGVCS-002-AC-07', 'OGVCS-002-AC-08',
  'OGVCS-002-AC-09', 'OGVCS-002-AC-10', 'OGVCS-002-AC-11'
]);
const REGISTRY_RECIPE_SCENARIOS = Object.freeze([
  'registry-conformance-mode', 'registry-conformance-production', 'registry-deprecated-read',
  'registry-deprecated-write', 'registry-duplicate', 'registry-invalid-entry',
  'registry-ratified-read-write', 'registry-reassigned', 'registry-reserved',
  'registry-unknown-profile'
]);
const CONFIGURED_RESOURCE_RECIPES = Object.freeze({
  'bundle-transcript-max-bytes-budget': {
    api: 'create-bundle-transcript-hash-writer',
    limits: { maxBytes: 1 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'bundle-visitor-max-item-budget': {
    api: 'visit-logical-bundle',
    limits: { maxItemBytes: 1 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'bundle-visitor-max-items-budget': {
    api: 'visit-logical-bundle',
    limits: { maxItems: 1 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'bundle-visitor-nested-map-key-capture-memory': {
    api: 'visit-logical-bundle',
    captureWorkspace: {
      depth: 8,
      derivation: 'one-byte-below-active-and-retained-canonical-key-capacity-v1',
      eachKeyAloneFits: true,
      growth: 'initial-64-double-to-required-v1'
    },
    limits: { maxCaptureBytes: 511, maxNesting: 10, maxValueBytes: 64 },
    source: 'logical-bundles/nested-map-key-capture-memory.cborseq'
  },
  'error-limit-memory': {
    api: 'verify-logical-bundle-stream',
    limits: { maxMemoryBytes: 1 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'error-limit-scratch': {
    api: 'verify-logical-bundle-stream',
    limits: { maxMemoryBytes: 67_108_864, maxScratchBytes: 0 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'error-limit-time': {
    api: 'verify-logical-bundle-stream',
    limits: { maxTimeMs: 0 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  }
});
const MANIFEST_WRITER_PART = Object.freeze({
  chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5',
  length: '12'
});
const MANIFEST_WRITER_LENGTH_FAULT_PART = Object.freeze({ ...MANIFEST_WRITER_PART, length: '11' });
const MANIFEST_WRITER_WRONG_KIND_PART = Object.freeze({
  chunk: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12',
  length: '12'
});
const MANIFEST_WRITER_PROVIDER_SHORT_PART = Object.freeze({
  chunk: 'ogvcs:v1:chunk:sha256:8cc81fc73a142566ef13224cd6669c89f252c4123db1d70d9912176ed26909e5',
  length: '12'
});
const MANIFEST_WRITER_PROVIDER_WRONG_PART = Object.freeze({
  chunk: 'ogvcs:v1:chunk:sha256:332477a223ae2defb717a8b1c7f4b9ed0b904d3a139c29277da9e89fc2e5da5d',
  length: '12'
});
const manifestWriterKnownSchemaBeforeChunkLength = parts => ({
  api: 'write-content-manifest',
  chunkArtifact: 'objects/01-chunk.bin',
  chunkProfile: 'chunking.test/external-boundaries@1',
  declaredParts: '2',
  logicalLength: '23',
  maxItems: 2,
  operation: 'conformance',
  outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
  parts,
  registry: 'bundled',
  schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
  wholeFileSha256: 'cb4f2424fd3588eb17773169678f8a2bc61546e0605e6f58ef64e4c67fdc49f8'
});
const manifestWriterCountBeforeKind = (parts, declaredParts, maxItems) => ({
  api: 'write-content-manifest',
  chunkArtifact: 'objects/01-chunk.bin',
  chunkProfile: 'chunking.test/external-boundaries@1',
  declaredParts,
  logicalLength: '24',
  maxItems,
  operation: 'conformance',
  outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
  parts,
  registry: 'bundled',
  schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
  wholeFileSha256: 'cb4f2424fd3588eb17773169678f8a2bc61546e0605e6f58ef64e4c67fdc49f8'
});
const manifestWriterContentObjectIdBeforeLength = order => ({
  api: 'write-content-manifest',
  chunkProfile: 'chunking.test/external-boundaries@1',
  declaredParts: '2',
  logicalLength: '24',
  maxItems: 2,
  operation: 'conformance',
  outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
  parts: order === 'forward'
    ? [MANIFEST_WRITER_PROVIDER_SHORT_PART, MANIFEST_WRITER_PROVIDER_WRONG_PART]
    : [MANIFEST_WRITER_PROVIDER_WRONG_PART, MANIFEST_WRITER_PROVIDER_SHORT_PART],
  chunkArtifacts: order === 'forward'
    ? ['writer-inputs/manifest-provider-short.bin', 'writer-inputs/manifest-provider-wrong.bin']
    : ['writer-inputs/manifest-provider-wrong.bin', 'writer-inputs/manifest-provider-short.bin'],
  registry: 'bundled',
  schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
  wholeFileSha256: order === 'forward'
    ? '17b36fa597cf366425ce6b0fd68e12713b442b2506d9d6e5e5188e03f5e741e4'
    : '8c39ce2ea3781d9febf8bd986d679aa19fc7b107a9ca9af3e3d76cd883573de6'
});
const MANIFEST_WRITER_RECIPES = Object.freeze({
  'manifest-writer-too-few-parts': {
    api: 'write-content-manifest',
    chunkArtifact: 'objects/01-chunk.bin',
    chunkProfile: 'chunking.test/external-boundaries@1',
    declaredParts: '2',
    logicalLength: '12',
    maxItems: 2,
    operation: 'conformance',
    parts: [{ chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' }],
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
    wholeFileSha256: '36fcc2e9442be1071c275604af6e41bd93875c743dc2fdaa6037662df74c5894'
  },
  'manifest-writer-too-many-parts': {
    api: 'write-content-manifest',
    chunkArtifact: 'objects/01-chunk.bin',
    chunkProfile: 'chunking.test/external-boundaries@1',
    declaredParts: '1',
    logicalLength: '24',
    maxItems: 2,
    operation: 'conformance',
    parts: [
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' },
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' }
    ],
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
    wholeFileSha256: 'cb4f2424fd3588eb17773169678f8a2bc61546e0605e6f58ef64e4c67fdc49f8'
  },
  'manifest-writer-count-before-profile-lifecycle': {
    api: 'write-content-manifest',
    chunkArtifact: 'objects/01-chunk.bin',
    chunkProfile: 'profile-state.test/chunking-conformance@1',
    declaredParts: '1',
    logicalLength: '24',
    maxItems: 2,
    operation: 'production-write',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    parts: [
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' },
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' }
    ],
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
    wholeFileSha256: 'cb4f2424fd3588eb17773169678f8a2bc61546e0605e6f58ef64e4c67fdc49f8'
  },
  'manifest-writer-limit-before-count-and-profile-lifecycle': {
    api: 'write-content-manifest',
    chunkArtifact: 'objects/01-chunk.bin',
    chunkProfile: 'profile-state.test/chunking-conformance@1',
    declaredParts: '1',
    logicalLength: '24',
    maxItems: 1,
    operation: 'production-write',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    parts: [
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' },
      { chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' }
    ],
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
    wholeFileSha256: 'cb4f2424fd3588eb17773169678f8a2bc61546e0605e6f58ef64e4c67fdc49f8'
  },
  'manifest-writer-object-id-before-profile-lifecycle': {
    api: 'write-content-manifest',
    chunkArtifact: 'lifecycle/chunk-object-id-mismatch.bin',
    chunkProfile: 'profile-state.test/chunking-conformance@1',
    declaredParts: '1',
    logicalLength: '12',
    maxItems: 1,
    operation: 'production-write',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    parts: [{ chunk: 'ogvcs:v1:chunk:sha256:944c987f358da73dedecbaa0599a5fcc606c407992708f0c0f6c5f7df6aac5c5', length: '12' }],
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    schema: 'ogvcs.repository-format.v1.manifest-writer-input.v1',
    wholeFileSha256: '9033b2344e924d278334018b2b9d51a3357f827016320f41a0ca294973474d9e'
  },
  'manifest-writer-known-schema-before-chunk-length-forward':
    manifestWriterKnownSchemaBeforeChunkLength([
      MANIFEST_WRITER_LENGTH_FAULT_PART, MANIFEST_WRITER_WRONG_KIND_PART
    ]),
  'manifest-writer-known-schema-before-chunk-length-reverse':
    manifestWriterKnownSchemaBeforeChunkLength([
      MANIFEST_WRITER_WRONG_KIND_PART, MANIFEST_WRITER_LENGTH_FAULT_PART
    ]),
  'manifest-writer-content-object-id-before-chunk-length-forward':
    manifestWriterContentObjectIdBeforeLength('forward'),
  'manifest-writer-content-object-id-before-chunk-length-reverse':
    manifestWriterContentObjectIdBeforeLength('reverse'),
  'manifest-writer-limit-before-kind': manifestWriterCountBeforeKind([
    MANIFEST_WRITER_WRONG_KIND_PART, MANIFEST_WRITER_PART
  ], '2', 1),
  'manifest-writer-count-before-kind-forward': manifestWriterCountBeforeKind([
    MANIFEST_WRITER_PART, MANIFEST_WRITER_WRONG_KIND_PART
  ], '1', 2),
  'manifest-writer-count-before-kind-reverse': manifestWriterCountBeforeKind([
    MANIFEST_WRITER_WRONG_KIND_PART, MANIFEST_WRITER_PART
  ], '1', 2)
});
const TREE_WRITER_ENTRIES = Object.freeze([0x21, 0x22].map((fill, index) => ({
  contentPolicy: 'content-policy.test/opaque@1',
  fileId: Buffer.alloc(16, fill).toString('hex'),
  kind: 2,
  logicalSize: '24',
  mode: 2,
  name: index === 0 ? 'a' : 'b',
  target: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12'
})));
const withFirstEntryContentConformance = entries => entries.map((entry, index) =>
  index === 0 ? { ...entry, contentPolicy: 'profile-state.test/content-conformance@1' } : entry);
const treeWriterPrecedenceEntry = (name, fill, target =
  'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12') => ({
  contentPolicy: 'content-policy.test/opaque@1',
  fileId: fill.repeat(16),
  kind: 2,
  logicalSize: '24',
  mode: 2,
  name,
  target
});
const treeWriterKnownSchemaBeforeOrder = entries => ({
  api: 'write-tree',
  descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
  entries,
  entryCount: '3',
  maxItems: 3,
  operation: 'conformance',
  ordering: 'ordered',
  outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
  registry: 'bundled',
  schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
});
const treeWriterSortedFamilyBeforeKind = order => {
  const familyFault = {
    ...TREE_WRITER_ENTRIES[0],
    contentPolicy: 'path.test/opaque@1',
    name: order === 'forward' ? 'a' : 'b'
  };
  const kindFault = {
    ...TREE_WRITER_ENTRIES[1],
    name: order === 'forward' ? 'b' : 'a',
    target: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19'
  };
  return {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: order === 'forward' ? [familyFault, kindFault] : [kindFault, familyFault],
    entryCount: '2',
    maxItems: 2,
    operation: 'conformance',
    ordering: 'sorted',
    outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  };
};
const TREE_WRITER_RECIPES = Object.freeze({
  'tree-writer-ordered-too-many-entries': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: TREE_WRITER_ENTRIES,
    entryCount: '1',
    maxItems: 2,
    operation: 'conformance',
    ordering: 'ordered',
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-sorted-too-many-entries': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: [...TREE_WRITER_ENTRIES].reverse(),
    entryCount: '1',
    maxItems: 2,
    operation: 'conformance',
    ordering: 'sorted',
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-count-before-feature-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: TREE_WRITER_ENTRIES,
    entryCount: '1',
    maxItems: 2,
    operation: 'production-write',
    ordering: 'ordered',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    requiredFeatures: [1],
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-sorted-count-before-feature-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: [...TREE_WRITER_ENTRIES].reverse(),
    entryCount: '1',
    maxItems: 2,
    operation: 'production-write',
    ordering: 'sorted',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    requiredFeatures: [1],
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-count-before-entry-profile-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: withFirstEntryContentConformance(TREE_WRITER_ENTRIES),
    entryCount: '1',
    maxItems: 2,
    operation: 'production-write',
    ordering: 'ordered',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-sorted-count-before-entry-profile-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: withFirstEntryContentConformance([...TREE_WRITER_ENTRIES].reverse()),
    entryCount: '1',
    maxItems: 2,
    operation: 'production-write',
    ordering: 'sorted',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-count-before-duplicate-fileid': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: TREE_WRITER_ENTRIES.map(entry => ({ ...entry, fileId: '21'.repeat(16) })),
    entryCount: '1',
    maxItems: 2,
    operation: 'conformance',
    ordering: 'ordered',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-sorted-count-before-duplicate-fileid': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: [...TREE_WRITER_ENTRIES].reverse().map(entry => ({ ...entry, fileId: '21'.repeat(16) })),
    entryCount: '1',
    maxItems: 2,
    operation: 'conformance',
    ordering: 'sorted',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-limit-before-count-and-feature-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: TREE_WRITER_ENTRIES,
    entryCount: '1',
    maxItems: 1,
    operation: 'production-write',
    ordering: 'ordered',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    requiredFeatures: [1],
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-sorted-limit-before-count-and-feature-lifecycle': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: [...TREE_WRITER_ENTRIES].reverse(),
    entryCount: '1',
    maxItems: 1,
    operation: 'production-write',
    ordering: 'sorted',
    outputDisposition: {
      orderedStagingSink: 'aborted-discard',
      successCommit: false
    },
    registry: 'bundled',
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    },
    requiredFeatures: [1],
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-limit-before-kind': {
    api: 'write-tree',
    descriptor: 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545',
    entries: [
      { ...TREE_WRITER_ENTRIES[0], target: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19' },
      TREE_WRITER_ENTRIES[1]
    ],
    entryCount: '2',
    maxItems: 1,
    operation: 'conformance',
    ordering: 'ordered',
    outputDisposition: { orderedStagingSink: 'aborted-discard', successCommit: false },
    registry: 'bundled',
    schema: 'ogvcs.repository-format.v1.tree-writer-input.v1'
  },
  'tree-writer-ordered-kind-before-order-forward': treeWriterKnownSchemaBeforeOrder([
    treeWriterPrecedenceEntry('b', '31'),
    treeWriterPrecedenceEntry('a', '32'),
    treeWriterPrecedenceEntry('c', '33',
      'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19')
  ]),
  'tree-writer-ordered-kind-before-order-reverse': treeWriterKnownSchemaBeforeOrder([
    treeWriterPrecedenceEntry('a', '31',
      'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19'),
    treeWriterPrecedenceEntry('c', '32'),
    treeWriterPrecedenceEntry('b', '33')
  ]),
  'tree-writer-sorted-family-before-kind-forward':
    treeWriterSortedFamilyBeforeKind('forward'),
  'tree-writer-sorted-family-before-kind-reverse':
    treeWriterSortedFamilyBeforeKind('reverse')
});
const BUNDLE_WRITER_COMMON = Object.freeze({
  api: 'write-logical-bundle',
  maxMemoryBytes: 67_108_864,
  operation: 'conformance',
  outputDisposition: {
    inMemoryResult: 'absent',
    orderedStagingSink: 'aborted-discard',
    successCommit: false
  },
  plan: {
    budget: {
      indexEntries: 2,
      largestItemBytes: 10_000,
      sequenceBytes: 100_000,
      traversalEdges: 100
    },
    logicalRecordCount: 0,
    objectCount: 2,
    rootCount: 0
  },
  registry: 'bundled',
  schema: 'ogvcs.repository-format.v1.logical-bundle-writer-input.v1',
  source: 'logical-bundles/valid-all-families.cborseq',
  writerSurfaces: ['bundle-memory-encoder', 'bundle-ordered']
});
const bundleWriterRecipes = {
  'bundle-writer-sequence-before-object-id': {
    ...BUNDLE_WRITER_COMMON,
    objectMutations: [
      { outputOrdinal: 0, sourceOrdinal: 2 },
      { outputOrdinal: 1, replaceDeclaredDigest: '00'.repeat(32), sourceOrdinal: 1 }
    ]
  },
  'bundle-writer-object-id-before-unknown-kind': {
    ...BUNDLE_WRITER_COMMON,
    objectMutations: [{
      allowUnknownKind: true,
      outputOrdinal: 0,
      replaceDeclaredDigest: '00'.repeat(32),
      replaceKind: 65_535,
      sourceOrdinal: 1
    }],
    plan: {
      ...BUNDLE_WRITER_COMMON.plan,
      budget: { ...BUNDLE_WRITER_COMMON.plan.budget, indexEntries: 1 },
      objectCount: 1
    }
  },
  'bundle-writer-object-id-before-feature-lifecycle': {
    ...BUNDLE_WRITER_COMMON,
    objectMutations: [{
      kind: 3,
      outputOrdinal: 0,
      replaceDeclaredDigest: '00'.repeat(32),
      sourceArtifact: 'lifecycle/tree-feature-conformance.cbor'
    }],
    operation: 'production-write',
    plan: {
      ...BUNDLE_WRITER_COMMON.plan,
      budget: { ...BUNDLE_WRITER_COMMON.plan.budget, indexEntries: 1 },
      objectCount: 1
    },
    registryFixture: {
      path: 'registries/index.json',
      scenarioId: 'registry-conformance-production'
    }
  }
};
const BUNDLE_WRITER_PRODUCTION = Object.freeze({
  operation: 'production-write',
  registryFixture: {
    path: 'registries/index.json',
    scenarioId: 'registry-conformance-production'
  }
});
for (const order of ['forward', 'reverse']) {
  const featureObject = {
    kind: 3,
    outputOrdinal: order === 'forward' ? 0 : 1,
    sourceArtifact: 'lifecycle/tree-feature-conformance.cbor'
  };
  const identityFault = order === 'forward' ? {
    kind: 4,
    outputOrdinal: 1,
    replaceDeclaredDigest: '00'.repeat(32),
    sourceArtifact: 'objects/04-change-set.cbor'
  } : {
    kind: 2,
    outputOrdinal: 0,
    replaceDeclaredDigest: '00'.repeat(32),
    sourceArtifact: 'objects/02-content-manifest.cbor'
  };
  bundleWriterRecipes[`bundle-writer-section-object-id-before-feature-lifecycle-${order}`] = {
    ...BUNDLE_WRITER_COMMON,
    ...BUNDLE_WRITER_PRODUCTION,
    objectMutations: order === 'forward'
      ? [featureObject, identityFault]
      : [identityFault, featureObject]
  };
  const conformanceRoot = order === 'forward' ? {
    identity: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19',
    kind: 1,
    roleProfile: 'bundle-role.test/root@1'
  } : {
    identity: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12',
    kind: 1,
    roleProfile: 'bundle-role.test/root@1'
  };
  const ratifiedRoot = order === 'forward' ? {
    identity: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12',
    kind: 1,
    roleProfile: 'profile-state.test/bundle-root-ratified@1'
  } : {
    identity: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19',
    kind: 1,
    roleProfile: 'profile-state.test/bundle-root-ratified@1'
  };
  bundleWriterRecipes[`bundle-writer-section-root-order-before-role-lifecycle-${order}`] = {
    ...BUNDLE_WRITER_COMMON,
    ...BUNDLE_WRITER_PRODUCTION,
    objectMutations: [
      { outputOrdinal: 0, sourceOrdinal: 1 },
      { outputOrdinal: 1, sourceOrdinal: 2 }
    ],
    plan: { ...BUNDLE_WRITER_COMMON.plan, rootCount: 2 },
    rootInputs: order === 'forward'
      ? [conformanceRoot, ratifiedRoot]
      : [ratifiedRoot, conformanceRoot]
  };
  const logicalRecordInputs = (order === 'forward' ? [
    'writer-inputs/logical-record-annotation-unknown-field.cbor',
    'logical-records/09-fixture-event.cbor',
    'logical-records/07-lock-reference.cbor'
  ] : [
    'logical-records/09-fixture-event.cbor',
    'logical-records/07-lock-reference.cbor',
    'writer-inputs/logical-record-annotation-unknown-field.cbor'
  ]).map((sourceArtifact, outputOrdinal) => ({ outputOrdinal, sourceArtifact }));
  bundleWriterRecipes[`bundle-writer-section-sequence-before-logical-schema-${order}`] = {
    ...BUNDLE_WRITER_COMMON,
    logicalRecordInputs,
    objectMutations: [],
    plan: {
      ...BUNDLE_WRITER_COMMON.plan,
      budget: { ...BUNDLE_WRITER_COMMON.plan.budget, indexEntries: 3 },
      logicalRecordCount: 3,
      objectCount: 0
    }
  };
}
const BUNDLE_WRITER_RECIPES = Object.freeze(bundleWriterRecipes);
const PATH_PROFILE_VALIDATOR_RECIPES = Object.freeze({
  'tree-ratified-path-profile-accept': {
    caseMode: 'case-sensitive',
    invocations: [{ decision: { accepted: true, platformKey: 'safe', repositoryKey: 'safe' }, segments: ['safe'] }],
    profile: 'path.opengamevcs/portable@1'
  },
  'tree-ratified-path-profile-case-folded-collision': {
    caseMode: 'case-folded',
    invocations: [
      { decision: { accepted: true, platformKey: 'A', repositoryKey: 'a' }, segments: ['A'] },
      { decision: { accepted: true, platformKey: 'a', repositoryKey: 'a' }, segments: ['a'] }
    ],
    profile: 'path.opengamevcs/portable@1'
  },
  'tree-ratified-path-profile-case-sensitive-distinct': {
    caseMode: 'case-sensitive',
    invocations: [
      { decision: { accepted: true, platformKey: 'A', repositoryKey: 'A' }, segments: ['A'] },
      { decision: { accepted: true, platformKey: 'a', repositoryKey: 'a' }, segments: ['a'] }
    ],
    profile: 'path.opengamevcs/portable@1'
  },
  'tree-ratified-path-profile-empty-accept': {
    caseMode: 'case-sensitive', invocations: [], profile: 'path.opengamevcs/portable@1'
  },
  'tree-ratified-path-profile-empty-missing-validator': null,
  'tree-ratified-path-profile-missing-manifest-before-wrong-validator': {
    caseMode: 'case-sensitive', invocations: [], profile: 'path.opengamevcs/windows@1'
  },
  'tree-ratified-path-profile-opaque-keys': {
    caseMode: 'case-sensitive',
    invocations: [
      { decision: { accepted: true, platformKey: '日本語', repositoryKey: 'e\u0301' }, segments: ['a'] },
      { decision: { accepted: true, platformKey: '日本語-2', repositoryKey: 'é' }, segments: ['b'] }
    ],
    profile: 'path.opengamevcs/portable@1'
  },
  'tree-ratified-path-profile-reject': {
    caseMode: 'case-sensitive',
    invocations: [{ decision: { accepted: false }, segments: ['blocked'] }],
    profile: 'path.opengamevcs/portable@1'
  }
});
const PATH_PROFILE_DECISION_RECIPES = Object.freeze({
  'tree-ratified-path-profile-missing-platform-key': {
    adapter: {
      caseMode: 'case-sensitive', decision: { accepted: true, repositoryKey: 'safe' },
      profile: 'path.opengamevcs/portable@1'
    },
    api: 'validate-path-profile-decision', caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/portable@1', schema: 'ogvcs.repository-format.v1.path-profile-decision-input.v1', segments: ['safe']
  },
  'tree-ratified-path-profile-missing-repository-key': {
    adapter: {
      caseMode: 'case-sensitive', decision: { accepted: true, platformKey: 'safe' },
      profile: 'path.opengamevcs/portable@1'
    },
    api: 'validate-path-profile-decision', caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/portable@1', schema: 'ogvcs.repository-format.v1.path-profile-decision-input.v1', segments: ['safe']
  },
  'tree-ratified-path-profile-missing-case-mode': {
    adapter: {
      decision: { accepted: true, platformKey: 'safe', repositoryKey: 'safe' },
      profile: 'path.opengamevcs/portable@1'
    },
    api: 'validate-path-profile-decision', caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/portable@1', schema: 'ogvcs.repository-format.v1.path-profile-decision-input.v1', segments: ['safe']
  },
  'tree-ratified-path-profile-wrong-case-mode': {
    adapter: {
      caseMode: 'case-sensitive', decision: { accepted: true, platformKey: 'safe', repositoryKey: 'safe' },
      profile: 'path.opengamevcs/portable@1'
    },
    api: 'validate-path-profile-decision', caseMode: 'case-folded',
    profile: 'path.opengamevcs/portable@1', schema: 'ogvcs.repository-format.v1.path-profile-decision-input.v1', segments: ['safe']
  }
});
const TREE_GROUPS_MEMORY_RECIPES = Object.freeze({
  'tree-groups-combined-memory': {
    api: 'validate-tree-groups-memory',
    assertNoPartialState: true,
    evidenceRequired: {
      eachComponentAloneFit: true,
      noPartialState: true,
      routeEvidence: [{
        noPartialState: true,
        recoveryKind: 'same-authority-instance',
        route: 'validate-tree-groups-memory',
        succeeded: true
      }]
    },
    memoryCeiling: {
      derivation: 'one-byte-below-simultaneous-retained-tree-group-membership-and-collision-index',
      requireEachComponentAloneToFit: true
    },
    routes: ['validate-tree-groups-memory'],
    schema: 'ogvcs.repository-format.v1.tree-groups-memory-input.v1'
  }
});
const RECOVERY_KIND_BY_ROUTE = Object.freeze({
  'expand-tree-edge-budget': 'same-authority-instance',
  'expand-tree-scratch-budget': 'same-authority-instance',
  'replay-change-set': 'same-authority-instance',
  'repository-object-lookup-validate-all': 'stateless-reinvoke',
  'validate-asset-groups': 'stateless-reinvoke',
  'validate-conflict-set': 'same-authority-instance',
  'validate-import-request': 'fresh-operation-after-deadline',
  'validate-known-schema': 'stateless-reinvoke',
  'validate-lifetime-and-imports': 'same-authority-instance',
  'validate-snapshot-graph': 'same-authority-instance',
  'verify-tree-file-stream': 'same-authority-instance',
  'validate-tree-groups-memory': 'same-authority-instance'
});
const routeEvidence = routes => routes.map(route => ({
  noPartialState: true,
  recoveryKind: RECOVERY_KIND_BY_ROUTE[route],
  route,
  succeeded: true
}));
const expectedEvidenceForRecipe = recipe => ({
  noPartialState: true,
  routeEvidence: routeEvidence(recipe.routes).map(observation => {
    if (observation.route === 'verify-tree-file-stream') return {
      compositeMemoryBounded: true,
      indexInstanceReused: true,
      ...observation,
      scratchIndexReusableAfterAbort: true,
      targetUnchanged: true
    };
    return recipe.assertCounterBaselineAfterFailure === true && recipe.assertCounterBaselineAfterRecovery === true
      ? { counterBaselineRestored: true, ...observation }
      : observation;
  })
});
const resourceReservationRecipes = Object.fromEntries([
  ['resource-replay-base-memory', ['replay-base', ['replay-change-set']]],
  ['resource-fileid-lifetime-import-indexes-memory', ['fileid-lifetime-import-indexes', ['validate-lifetime-and-imports']]],
  ['resource-graph-workspace-indexes-memory', ['graph-workspace-indexes', ['validate-snapshot-graph']]],
  ['resource-conflict-group-indexes-memory', ['conflict-group-indexes', ['validate-conflict-set', 'validate-asset-groups']]],
  ['resource-many-invalid-error-selection-memory', ['many-invalid-error-selection', ['repository-object-lookup-validate-all', 'validate-known-schema']]]
].map(([id, [cluster, routes]]) => [id, {
  api: 'validate-resource-reservation',
  assertNoPartialState: true,
  evidenceRequired: { noPartialState: true, routeEvidence: routeEvidence(routes) },
  cluster,
  fixture: 'bounded-reduced-retention-v1',
  memoryCeiling: { derivation: 'one-byte-below-conservative-retained-cost-v1' },
  routes,
  schema: 'ogvcs.repository-format.v1.resource-reservation-input.v1'
}]));
resourceReservationRecipes['resource-replay-base-memory'] = {
  ...resourceReservationRecipes['resource-replay-base-memory'],
  baseState: {
    groups: 'empty',
    tree: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19'
  },
  changeSet: 'ogvcs:v1:change-set:sha256:82cc41e5e86d1397579a8ebfc7ea6c7d9102552130f4da86ca592fc3c10a424c'
};
resourceReservationRecipes['resource-many-invalid-error-selection-memory'] = {
  ...resourceReservationRecipes['resource-many-invalid-error-selection-memory'],
  diagnosticWorkspace: {
    assertInputUnchanged: true,
    derivation: 'one-byte-below-conservative-retained-cost-v1',
    recoveryExpected: {
      code: 'SCHEMA_FIELD_UNKNOWN',
      layer: 2,
      stage: 'known-schema'
    },
    unknownFieldCount: 64
  }
};
resourceReservationRecipes['resource-conflict-group-indexes-memory'] = {
  ...resourceReservationRecipes['resource-conflict-group-indexes-memory'],
  conflictFixture: {
    reference: 'ogvcs:v1:conflict-set:sha256:562aa353fa3bfcf681e7e4a218f66c9f3c1157c490508cb81f4320f271be25cf',
    scenario: 'conflict-choice-base'
  }
};
resourceReservationRecipes['resource-lookup-edge-counter-rollback'] = {
  api: 'validate-resource-reservation',
  assertCounterBaselineAfterFailure: true,
  assertCounterBaselineAfterRecovery: true,
  assertNoPartialState: true,
  cluster: 'lookup-edge-counter-rollback',
  configuredLimit: { field: 'maxEdges', value: 1 },
  evidenceRequired: {
    noPartialState: true,
    routeEvidence: [{
      counterBaselineRestored: true,
      noPartialState: true,
      recoveryKind: 'same-authority-instance',
      route: 'expand-tree-edge-budget',
      succeeded: true
    }]
  },
  failureTree: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19',
  recovery: {
    api: 'verify-manifest',
    reference: 'ogvcs:v1:content-manifest:sha256:771d07afb8bb70aeacfb964f98d8a01670e79989406f2a5519f21ff57dec2c89'
  },
  routes: ['expand-tree-edge-budget'],
  schema: 'ogvcs.repository-format.v1.resource-reservation-input.v1'
};
resourceReservationRecipes['resource-lookup-scratch-counter-rollback'] = {
  api: 'validate-resource-reservation',
  assertCounterBaselineAfterFailure: true,
  assertCounterBaselineAfterRecovery: true,
  assertNoPartialState: true,
  cluster: 'lookup-scratch-counter-rollback',
  configuredLimit: { field: 'maxScratchBytes', value: 64 },
  evidenceRequired: {
    noPartialState: true,
    routeEvidence: [{
      counterBaselineRestored: true,
      noPartialState: true,
      recoveryKind: 'same-authority-instance',
      route: 'expand-tree-scratch-budget',
      succeeded: true
    }]
  },
  failureTree: 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19',
  recovery: {
    api: 'expand-tree',
    recoveryTree: 'ogvcs:v1:tree:sha256:79c0b6bc8cd423fd80f877a23fdc4502bc3a4d6a7d2afd42f82a507d72fffbdc'
  },
  routes: ['expand-tree-scratch-budget'],
  schema: 'ogvcs.repository-format.v1.resource-reservation-input.v1'
};
resourceReservationRecipes['resource-import-request-many-mappings-deadline'] = {
  api: 'validate-resource-reservation',
  assertNoPartialState: true,
  evidenceRequired: {
    noPartialState: true,
    routeEvidence: routeEvidence(['validate-import-request'])
  },
  cluster: 'fileid-import-many-mappings-deadline',
  fixture: 'bounded-many-import-mappings-v1',
  routes: ['validate-import-request'],
  schema: 'ogvcs.repository-format.v1.resource-reservation-input.v1',
  timeCeiling: { derivation: 'one-checkpoint-before-final-bounded-mapping-v1' }
};
resourceReservationRecipes['resource-tree-stream-transaction-composite-memory'] = {
  api: 'validate-resource-reservation',
  assertNoPartialState: true,
  cluster: 'tree-stream-transaction-composite-memory',
  evidenceRequired: {
    noPartialState: true,
    routeEvidence: [{
      compositeMemoryBounded: true,
      indexInstanceReused: true,
      noPartialState: true,
      recoveryKind: 'same-authority-instance',
      route: 'verify-tree-file-stream',
      scratchIndexReusableAfterAbort: true,
      succeeded: true,
      targetUnchanged: true
    }]
  },
  failure: {
    api: 'verify-tree-file',
    failurePoint: 'after-at-least-one-fileid-index-insertion',
    source: 'objects/03-tree.cbor'
  },
  memoryCeiling: {
    derivation: 'one-byte-below-reader-current-entry-and-fileid-index-composite-v1',
    indexCapacity: 'remaining-composite-budget-not-full-operation-ceiling'
  },
  operation: 'conformance',
  recovery: {
    api: 'verify-tree-file',
    reuseTreeFileIdIndex: true,
    source: 'scenarios/objects/resource-lookup-scratch-counter-rollback/recovery-tree.cbor'
  },
  registryFixture: {
    path: 'registries/index.json',
    scenarioId: 'registry-conformance-production'
  },
  routes: ['verify-tree-file-stream'],
  schema: 'ogvcs.repository-format.v1.resource-reservation-input.v1',
  transaction: {
    scratchIndexReusableAfterAbortDrop: true,
    targetBytesUnchanged: true
  }
};
const RESOURCE_RESERVATION_RECIPES = Object.freeze(resourceReservationRecipes);
const TYPED_REFERENCE_AUTHORITY_RECIPES = Object.freeze({
  'typed-reference-arbitrary-kind-map-relabel': {
    case: 'arbitrary-kind-map-relabel',
    kindCode: 3,
    kindMap: [[3, 'evil']],
    text: 'ogvcs:v1:evil:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19'
  },
  'typed-reference-duplicate-kind-token': {
    case: 'duplicate-kind-token',
    registryMutation: {
      action: 'replace-entry-field',
      field: 'textToken',
      file: 'object-kinds.json',
      selector: { code: 3 },
      value: 'content-manifest'
    }
  },
  'typed-reference-durable-overlength-colon-dense': {
    case: 'durable-text-overlength-colon-dense',
    maximumBytes: 144,
    text: `ogvcs:v1:${'tree:'.repeat(30)}sha256:${'0'.repeat(64)}`
  }
});
const GENERIC_CANONICAL_SCAN_RECIPES = Object.freeze(Object.fromEntries([
  ['unicode-age-15-assigned', 'unicode/cases/age-15-assigned.cbor'],
  ['unicode-age-frozen-unassigned', 'malformed/unicode-age-frozen-unassigned.cbor'],
  ['unicode-age-newer-canonical', 'malformed/unicode-age-newer-canonical.cbor'],
  ['unicode-age-newer-composition-pair', 'malformed/unicode-age-newer-composition-pair.cbor'],
  ['unicode-age-newer-decomposed', 'malformed/unicode-age-newer-decomposed.cbor']
].map(([id, source]) => [id, {
  api: 'canonical-scan',
  schema: 'ogvcs.repository-format.v1.canonical-scan-input.v1',
  source,
  surface: 'generic-cbor-item'
}])));
const CLOSURE_ACCUMULATOR_ROUTES = Object.freeze(Object.fromEntries([
  ['manifest', 'verify-manifest', 'chunk', 'objects/01-chunk.bin', 'manifest.cbor'],
  ['tree', 'expand-tree', 'content-manifest', 'objects/02-content-manifest.cbor', 'tree.cbor'],
  ['replay', 'replay-change-set', 'content-manifest', 'objects/02-content-manifest.cbor', 'change-set.cbor'],
  ['conflict', 'validate-conflict-set', 'content-manifest', 'objects/02-content-manifest.cbor', 'conflict-set.cbor'],
  ['snapshot', 'validate-snapshot-graph', 'snapshot', 'objects/07-snapshot.cbor', 'snapshot.cbor'],
  ['provenance', 'validate-provenance-graph', 'provenance', 'objects/09-provenance.cbor', null],
  ['shelf', 'validate-shelf-revision', 'provenance', 'objects/09-provenance.cbor', 'shelf-revision.cbor']
].flatMap(([route, api, kind, sourceArtifact, primaryName]) =>
  ['forward', 'reverse'].map(order => [`closure-${route}-identity-before-missing-${order}`, {
    api, kind, order, primaryName, route, sourceArtifact
  }]))));
const REPOSITORY_ROUTE_APIS = Object.freeze(Object.fromEntries([
  ...Object.entries(CLOSURE_ACCUMULATOR_ROUTES).map(([id, value]) => [id, value.api]),
  ...[
    'conflict-entry-target-missing',
    'conflict-entry-target-missing-before-profile-lifecycle',
    'conflict-entry-target-wrong-kind'
  ].map(id => [id, 'validate-conflict-set']),
  ...[
    'fileid-lifetime-first-change-bad-schema',
    'fileid-lifetime-first-change-missing',
    'fileid-lifetime-first-change-object-id-mismatch',
    'fileid-lifetime-first-change-profile-lifecycle',
    'fileid-lifetime-first-change-wrong-kind',
    ...['conformance', 'foreign-repository', 'production-conformance-only', 'wrong-family']
      .map(variant => `fileid-prior-import-mapping-lifetime-${variant}`)
  ].map(id => [id, 'validate-lifetime-and-imports']),
  ...['conformance', 'foreign-repository', 'production-conformance-only', 'wrong-family']
    .map(variant => [`fileid-prior-import-mapping-request-${variant}`, 'validate-import-request']),
  ...[
    'fileid-prior-import-mapping-candidate-conformance',
    'fileid-prior-import-mapping-candidate-foreign-repository',
    'fileid-prior-import-mapping-candidate-production-conformance-only',
    'fileid-prior-import-mapping-candidate-wrong-family',
    'repository-candidate-content-missing',
    'repository-candidate-missing-change-base',
    'repository-candidate-missing-change-before-profile-lifecycle',
    'repository-candidate-missing-tree-before-second-root',
    'repository-candidate-verify-content-false'
  ].map(id => [id, 'validate-repository-candidate']),
  ...[
    'provenance-cycle-branch-before-missing-input-forward',
    'provenance-cycle-branch-before-missing-input-reverse',
    'provenance-missing-reference-before-profile-lifecycle'
  ].map(id => [id, 'validate-provenance-graph']),
  ...['replay-entry-target-wrong-kind', 'replay-missing-reference-before-profile-lifecycle',
    'replay-restore-missing-source-tree-before-profile-lifecycle',
    'replay-restore-missing-proof-descriptor-before-cross-repository']
    .map(id => [id, 'replay-change-set']),
  ...['shelf-content-missing', 'shelf-missing-previous-before-chain-invalid', 'shelf-verify-content-false',
    'shelf-unrelated-known-schema-object-ignored', 'shelf-unrelated-profile-object-ignored']
    .map(id => [id, 'validate-shelf-revision']),
  ...[
    'snapshot-graph-missing-change-before-profile-lifecycle',
    'snapshot-graph-missing-descriptor-before-descriptor-mismatch',
    'snapshot-graph-second-root-before-missing-parent-forward',
    'snapshot-graph-second-root-before-missing-parent-reverse'
  ].map(id => [id, 'validate-snapshot-graph']),
  ...[
    'tree-missing-child-before-duplicate-fileid',
    'tree-missing-manifest-before-descriptor-mismatch',
    'tree-missing-reference-before-profile-lifecycle',
    'tree-missing-target-before-path-profile-lifecycle',
    'tree-ratified-path-profile-missing-child-before-missing-validator',
    'tree-ratified-path-profile-missing-chunk-before-missing-validator',
    'tree-ratified-path-profile-missing-manifest-before-wrong-validator'
  ].map(id => [id, 'expand-tree'])
]));
const SHELF_SCOPE_CONTROL_SOURCES = Object.freeze({
  'shelf-unrelated-known-schema-object-ignored': {
    path: 'scenarios/objects/shelf-unrelated-known-schema-object-ignored/unrelated-known-schema.cbor',
    sha256: '26c47404cce7bb16698556a814079180f02d80eddcd521ffe0143f4c38f5e6cb'
  },
  'shelf-unrelated-profile-object-ignored': {
    path: 'scenarios/objects/shelf-unrelated-profile-object-ignored/unrelated-profile.cbor',
    sha256: '0792bdf86ca6b788ca3dd3bbfaa6012b45f9c074a4c38ba58e1c721787e612a7'
  }
});
const operationModeRecipes = {};
const operationModeSchema = 'ogvcs.repository-format.v1.operation-mode-input.v1';
const bundleSource = 'logical-bundles/valid-supplied-closure.cborseq';
const operationModeDescriptor = 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545';
const operationModeSnapshot = 'ogvcs:v1:snapshot:sha256:cc4d4a4a7be098bc74f5bb97cfe1eb37d870832dd44c56f0ceac12d65f871290';
const operationModeTree = 'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19';
const operationModeManifest = 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12';
const baseRootWorkingLifetimeAdditions = [0x11, 0x12, 0x13, 0x14].map((fill, firstOperation) => ({
  fileId: fill.toString(16).padStart(2, '0').repeat(16),
  firstChangeSet: 'ogvcs:v1:change-set:sha256:9cda477b4303c876fc79feb4cbd0a5deda70011261bd81fc758b588872040720',
  firstOperation,
  origin: 'native-create'
}));
const sourceForSurface = surface => {
  if (surface.startsWith('bundle-')) return bundleSource;
  if (['manifest-verify', 'content-manifest'].includes(surface)) return 'objects/02-content-manifest.cbor';
  if (['tree-expand', 'tree-ordered', 'tree-sorted', 'tree-file', 'tree-schema-decoder', 'metadata-encoder', 'metadata-decoder'].includes(surface)) return 'objects/03-tree.cbor';
  if (['repository-candidate', 'import-request', 'repository-lookup-layer2'].includes(surface)) return 'objects/07-snapshot.cbor';
  return undefined;
};
const repositoryRouteCarrier = surface => {
  const shared = {
    objectLookup: 'scenario.context.objectLookup',
    repositoryDescriptor: operationModeDescriptor
  };
  if (surface === 'repository-candidate') return {
    ...shared,
    candidateSnapshot: operationModeSnapshot,
    designatedRoot: operationModeSnapshot,
    lifetimeContext: {
      importMappings: [],
      lifetimeRecords: [],
      workingLifetimeAdditions: baseRootWorkingLifetimeAdditions
    }
  };
  if (surface === 'import-request') return {
    ...shared,
    importContext: { importMappings: [], lifetimeRecords: [], workingLifetimeAdditions: [] },
    importRequest: {
      importerProfile: 'importer.test/fixture-adapter@1',
      requestedFileId: '77'.repeat(16),
      sourceIdentityDigest: '72'.repeat(32),
      sourceNamespaceDigest: '71'.repeat(32)
    }
  };
  if (surface === 'tree-expand') return { ...shared, tree: operationModeTree };
  if (surface === 'manifest-verify') return { ...shared, manifest: operationModeManifest };
  if (surface === 'tree-file') return shared;
  if (surface === 'asset-groups') return shared;
  return {};
};
const baseModeRecipe = (surface, extra = {}) => ({
  api: 'validate-operation-mode', registry: 'bundled', schema: operationModeSchema,
  ...(sourceForSurface(surface) ? { source: sourceForSurface(surface) } : {}), surface,
  ...repositoryRouteCarrier(surface),
  ...(surface === 'tree-expand' ? { caseMode: 'case-sensitive' } : {}), ...extra
});
const authorityOmittedRecipe = surface => {
  const request = baseModeRecipe(surface, { source: 'malformed/nonminimal-unsigned.cbor' });
  delete request.registry;
  return request;
};
const lifecycleDescriptors = Object.freeze({
  'content-policy.test/opaque@1': {
    bundleSource: 'lifecycle/bundle-content-policy-test-opaque-1.cborseq',
    descriptorSource: 'lifecycle/descriptor-content-policy-test-opaque-1.cbor',
    objectRef: 'ogvcs:v1:repository-descriptor:sha256:c3d080e1d63ab4ba8e2f81615a647292d799931e363aa2437f61239665ce1093'
  },
  'profile-state.test/conformance@1': {
    bundleSource: 'lifecycle/bundle-profile-state-test-conformance-1.cborseq',
    descriptorSource: 'lifecycle/descriptor-profile-state-test-conformance-1.cbor',
    objectRef: 'ogvcs:v1:repository-descriptor:sha256:709c49efb55c6d4f2fcc6c4ef89beba50efcefce4f03dd26f6cbe4d200fce108'
  },
  'profile-state.test/deprecated@1': {
    bundleSource: 'lifecycle/bundle-profile-state-test-deprecated-1.cborseq',
    descriptorSource: 'lifecycle/descriptor-profile-state-test-deprecated-1.cbor',
    objectRef: 'ogvcs:v1:repository-descriptor:sha256:4bc81671782f76026966209832fb2ac3153173a688df75524ee0226ea4a3551c'
  },
  'unknown.example/path@1': {
    bundleSource: 'lifecycle/bundle-unknown-example-path-1.cborseq',
    descriptorSource: 'lifecycle/descriptor-unknown-example-path-1.cbor',
    objectRef: 'ogvcs:v1:repository-descriptor:sha256:cbfffaead88a872ae2c1ea08b26d8dde669f9e3aa63d90e755260a8c45f1935c'
  }
});
const lifecycleTrees = Object.freeze({
  1: { requiredFeatures: [1], source: 'lifecycle/tree-feature-conformance.cbor' },
  2: { requiredFeatures: [2], source: 'lifecycle/tree-feature-deprecated.cbor' },
  3: { requiredFeatures: [3], source: 'lifecycle/tree-feature-unknown.cbor' }
});
const lifecycleProfileCarrier = (surface, profile) => {
  const artifact = lifecycleDescriptors[profile];
  return {
    expectedProfileFamily: 'path', objectRef: artifact.objectRef, profile,
    source: surface.startsWith('bundle-') ? artifact.bundleSource : artifact.descriptorSource
  };
};
const lifecycleFeatureCarrier = feature => lifecycleTrees[feature];
const emitterProductionConformanceId = surface =>
  `mode-${surface}-production-conformance-${surface.startsWith('tree-') ? 'feature' : 'profile'}`;
const codecLifecycleId = (surface, suffix) =>
  `mode-${surface}-${surface === 'tree-file' ? 'feature-' : ''}${suffix}`;
const emitterLifecycleCarrier = surface => {
  if (surface === 'metadata-encoder') return lifecycleProfileCarrier(surface, 'profile-state.test/conformance@1');
  if (surface === 'tree-ordered' || surface === 'tree-sorted') return lifecycleFeatureCarrier(1);
  if (surface === 'content-manifest') return {
    expectedProfileFamily: 'chunking', profile: 'profile-state.test/chunking-conformance@1',
    source: 'lifecycle/manifest-chunking-conformance.cbor'
  };
  return lifecycleProfileCarrier(surface, 'profile-state.test/conformance@1');
};
const invalidRegistryVariant = variant => variant === 'partial' ? {
  registry: 'partial', registryMutation: { action: 'drop-document', path: 'registries/profiles.json' }
} : {
  registry: 'forged', registryMutation: { action: 'replace-registry-set-sha256', value: '0'.repeat(64) }
};
const semanticSurfaces = ['repository-candidate', 'import-request', 'tree-expand', 'manifest-verify', 'asset-groups'];
for (const surface of semanticSurfaces) {
  operationModeRecipes[`mode-${surface}-conformance-accept`] = baseModeRecipe(surface,
    { mode: 'conformance', requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-read`] = baseModeRecipe(surface,
    { mode: 'read', requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-invalid`] = baseModeRecipe(surface,
    { mode: 'invalid', requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-omitted`] = baseModeRecipe(surface,
    { requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-production-conformance-profile`] = baseModeRecipe(surface,
    { mode: 'production', requestedLayer: 3, semanticProfiles: true });
  for (const variant of ['partial', 'forged']) {
    operationModeRecipes[`mode-${surface}-${variant}-registry`] = baseModeRecipe(surface, {
      ...invalidRegistryVariant(variant), mode: 'conformance', requestedLayer: 3,
      semanticProfiles: true, ...(sourceForSurface(surface) ? { source: 'malformed/nonminimal-unsigned.cbor' } : {})
    });
  }
}
for (const surface of ['repository-candidate', 'import-request', 'tree-expand', 'manifest-verify', 'asset-groups']) {
  operationModeRecipes[`mode-${surface}-missing-registry`] = baseModeRecipe(surface,
    { mode: 'conformance', registry: 'absent', requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-semantic-disabled`] = baseModeRecipe(surface,
    { mode: 'conformance', requestedLayer: 3, semanticProfiles: false });
}
const treeExpandMissingCaseMode = baseModeRecipe('tree-expand',
  { mode: 'conformance', requestedLayer: 3, semanticProfiles: true });
delete treeExpandMissingCaseMode.caseMode;
operationModeRecipes['mode-tree-expand-case-mode-missing'] = treeExpandMissingCaseMode;
operationModeRecipes['mode-tree-expand-case-mode-invalid'] = baseModeRecipe('tree-expand',
  { caseMode: 'invalid', mode: 'conformance', requestedLayer: 3, semanticProfiles: true });
operationModeRecipes['mode-repository-lookup-layer2-registry-free'] = baseModeRecipe('repository-lookup-layer2',
  { registry: 'absent', requestedLayer: 2, semanticProfiles: false });
operationModeRecipes['mode-repository-lookup-layer2-authority-omitted'] =
  authorityOmittedRecipe('repository-lookup-layer2');
for (const [suffix, mode] of [['read', 'read'], ['invalid', 'invalid']]) {
  operationModeRecipes[`mode-bundle-visitor-${suffix}`] = baseModeRecipe('bundle-visitor',
    { mode, registry: 'absent', requestedLayer: 2, semanticProfiles: false });
}
operationModeRecipes['mode-bundle-visitor-omitted'] = baseModeRecipe('bundle-visitor',
  { registry: 'absent', requestedLayer: 2, semanticProfiles: false });
operationModeRecipes['bundle-semantic-callback-does-not-promote'] = baseModeRecipe('bundle-memory-verifier', {
  registry: 'absent', requestedLayer: 2,
  semanticCallback: { behavior: 'no-op' }, semanticProfiles: false
});
for (const surface of ['metadata-encoder', 'tree-ordered', 'tree-sorted', 'content-manifest', 'bundle-ordered', 'bundle-memory-encoder']) {
  operationModeRecipes[`mode-${surface}-selector-missing`] = baseModeRecipe(surface);
  operationModeRecipes[`mode-${surface}-selector-read`] = baseModeRecipe(surface, { operation: 'read' });
  operationModeRecipes[`mode-${surface}-selector-invalid`] = baseModeRecipe(surface, { operation: 'invalid' });
  operationModeRecipes[`mode-${surface}-missing-registry`] = baseModeRecipe(surface,
    { operation: 'conformance', registry: 'absent' });
  operationModeRecipes[emitterProductionConformanceId(surface)] = baseModeRecipe(surface, {
    ...emitterLifecycleCarrier(surface), operation: 'production-write',
    registryFixture: { path: 'registries/index.json', scenarioId: 'registry-conformance-production' }
  });
  for (const variant of ['partial', 'forged']) {
    operationModeRecipes[`mode-${surface}-${variant}-registry`] = baseModeRecipe(surface, {
      ...invalidRegistryVariant(variant), operation: 'conformance',
      ...(sourceForSurface(surface) ? { source: 'malformed/nonminimal-unsigned.cbor' } : {})
    });
  }
}
const lifecycleFixtures = [
  ['deprecated-read-accept', 'read', 'profile-state.test/deprecated@1', 2, 'registry-deprecated-read'],
  ['conformance-read-rejected', 'read', 'profile-state.test/conformance@1', 1, 'registry-conformance-mode'],
  ['conformance-accept', 'conformance', 'profile-state.test/conformance@1', 1, 'registry-conformance-mode'],
  ['deprecated-production-write-rejected', 'production-write', 'profile-state.test/deprecated@1', 2, 'registry-deprecated-write'],
  ['conformance-production-write-rejected', 'production-write', 'profile-state.test/conformance@1', 1, 'registry-conformance-production']
];
for (const surface of ['tree-file', 'metadata-decoder', 'bundle-memory-verifier', 'bundle-stream-verifier']) {
  for (const [suffix, operation, profile, requiredFeature, scenarioId] of lifecycleFixtures) {
    operationModeRecipes[codecLifecycleId(surface, suffix)] = baseModeRecipe(surface, {
      ...(surface === 'tree-file'
        ? lifecycleFeatureCarrier(requiredFeature)
        : lifecycleProfileCarrier(surface, profile)),
      operation,
      registryFixture: { path: 'registries/index.json', scenarioId },
      requestedLayer: 3, semanticProfiles: true
    });
  }
  operationModeRecipes[`mode-${surface}-registry-operation-omitted`] = baseModeRecipe(surface,
    { requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-registry-operation-invalid`] = baseModeRecipe(surface,
    { operation: 'invalid', requestedLayer: 3, semanticProfiles: true });
  operationModeRecipes[`mode-${surface}-missing-registry`] = baseModeRecipe(surface, {
    operation: 'conformance', registry: 'absent', requestedLayer: 3,
    semanticProfiles: true, source: 'malformed/nonminimal-unsigned.cbor'
  });
  operationModeRecipes[`mode-${surface}-semantic-disabled`] = baseModeRecipe(surface,
    { operation: 'conformance', requestedLayer: 3, semanticProfiles: false });
  if (surface !== 'tree-file') {
    operationModeRecipes[`mode-${surface}-registry-free-layer2`] = baseModeRecipe(surface,
      { registry: 'absent', requestedLayer: 2, semanticProfiles: false });
    operationModeRecipes[`mode-${surface}-registry-free-wrong-family`] = baseModeRecipe(surface, {
      ...lifecycleProfileCarrier(surface, 'content-policy.test/opaque@1'),
      registry: 'absent', requestedLayer: 2, semanticProfiles: false
    });
  }
  const unknownId = surface === 'tree-file'
    ? `mode-${surface}-unknown-feature`
    : `mode-${surface}-unknown-profile`;
  operationModeRecipes[unknownId] = baseModeRecipe(surface, {
    ...(surface === 'tree-file'
      ? lifecycleFeatureCarrier(3)
      : lifecycleProfileCarrier(surface, 'unknown.example/path@1')),
    operation: 'read', requestedLayer: 3, semanticProfiles: true
  });
  for (const variant of ['partial', 'forged']) {
    operationModeRecipes[`mode-${surface}-${variant}-registry`] = baseModeRecipe(surface, {
      ...invalidRegistryVariant(variant), operation: 'conformance', requestedLayer: 3,
      semanticProfiles: true, source: 'malformed/nonminimal-unsigned.cbor'
    });
  }
}
operationModeRecipes['mode-tree-schema-decoder-registry-free-layer2'] = baseModeRecipe('tree-schema-decoder',
  { registry: 'absent', requestedLayer: 2, semanticProfiles: false });
operationModeRecipes['mode-tree-file-order-before-feature-lifecycle'] = baseModeRecipe('tree-file', {
  operation: 'production-write',
  registryFixture: { path: 'registries/index.json', scenarioId: 'registry-conformance-production' },
  requestedLayer: 3,
  semanticProfiles: true,
  source: 'lifecycle/tree-order-before-feature-lifecycle.cbor'
});
operationModeRecipes['mode-tree-file-order-before-descriptor-mismatch'] = baseModeRecipe('tree-file', {
  operation: 'conformance',
  repositoryDescriptor: 'ogvcs:v1:repository-descriptor:sha256:709c49efb55c6d4f2fcc6c4ef89beba50efcefce4f03dd26f6cbe4d200fce108',
  requestedLayer: 3,
  semanticProfiles: true,
  source: 'lifecycle/tree-order-before-descriptor-mismatch.cbor'
});
operationModeRecipes['mode-tree-file-target-before-duplicate-fileid'] = baseModeRecipe('tree-file', {
  operation: 'conformance',
  requestedLayer: 3,
  semanticProfiles: true,
  source: 'lifecycle/tree-target-before-duplicate-fileid.cbor'
});
operationModeRecipes['mode-tree-file-feature-before-duplicate-fileid'] = baseModeRecipe('tree-file', {
  operation: 'production-write',
  registryFixture: { path: 'registries/index.json', scenarioId: 'registry-conformance-production' },
  requestedLayer: 3,
  semanticProfiles: true,
  source: 'lifecycle/tree-feature-before-duplicate-fileid.cbor'
});
for (const order of ['forward', 'reverse']) {
  operationModeRecipes[`mode-tree-file-known-schema-before-order-${order}`] =
    baseModeRecipe('tree-file', {
      operation: 'conformance',
      requestedLayer: 3,
      semanticProfiles: true,
      source: `lifecycle/tree-known-schema-before-order-${order}.cbor`
    });
}
operationModeRecipes['mode-manifest-verify-missing-reference-before-profile-lifecycle'] =
  baseModeRecipe('manifest-verify', {
    manifest: 'ogvcs:v1:content-manifest:sha256:d140d3719b89622383790bf5a8c30d4e0072ab8470696aa03729de6d978c9fce',
    mode: 'production',
    registryFixture: { path: 'registries/index.json', scenarioId: 'registry-conformance-production' },
    requestedLayer: 3,
    semanticProfiles: true,
    source: 'lifecycle/manifest-missing-reference-before-profile-lifecycle.cbor'
  });
for (const order of ['forward', 'reverse']) {
  const profile = [
    'ogvcs:v1:tree:sha256:e3b10ed23408b39a1b8c8320ffbc3de0d1d0ca69bbdef1c27c7e37a383243ed4',
    'lifecycle/tree-feature-conformance.cbor'
  ];
  const malformed = [
    'ogvcs:v1:tree:sha256:8d0a6315bc3770fcd6f8572036ac00328ba0d56459e144866a32e3b55a846dfa',
    'lifecycle/tree-known-schema-before-profile-lifecycle.cbor'
  ];
  const ordered = order === 'forward' ? [profile, malformed] : [malformed, profile];
  operationModeRecipes[`lookup-validate-all-known-schema-before-profile-lifecycle-${order}`] =
    baseModeRecipe('repository-lookup-validate-all', {
      lookupOrder: ordered.map(([reference]) => reference),
      mode: 'production',
      registryFixture: {
        path: 'registries/index.json',
        scenarioId: 'registry-conformance-production'
      },
      requestedLayer: 3,
      semanticProfiles: true,
      sources: ordered.map(([, source]) => source)
    });
}
const rawImportBaseEntries = [
  ['schema', 'ogvcs.repository-format.v1.fileid-operation-input.v1'],
  ['operation', 'import-file-id'],
  ['importerProfile', 'importer.test/fixture-adapter@1'],
  ['sourceNamespaceDigest', '71'.repeat(32)],
  ['sourceIdentityDigest', '72'.repeat(32)],
  ['requestedFileId', '77'.repeat(16)]
];
for (const [field, malformedValue] of [
  ['sourceNamespaceDigest', '00'],
  ['sourceIdentityDigest', '00'],
  ['requestedFileId', '00']
]) {
  const malformed = rawImportBaseEntries.map(([key, value]) =>
    [key, key === field ? malformedValue : value]);
  const importerIndex = malformed.findIndex(([key]) => key === 'importerProfile');
  const malformedIndex = malformed.findIndex(([key]) => key === field);
  const lifecycleFirst = [...malformed];
  const schemaFirst = [...malformed];
  [schemaFirst[importerIndex], schemaFirst[malformedIndex]] =
    [schemaFirst[malformedIndex], schemaFirst[importerIndex]];
  const id = `import-request-raw-${field.replaceAll(/[A-Z]/g,
    match => `-${match.toLowerCase()}`)}-schema-before-profile-lifecycle`;
  operationModeRecipes[id] = baseModeRecipe('import-request-raw', {
    lifetimeContext: { importMappings: [], lifetimeRecords: [], workingLifetimeAdditions: [] },
    mode: 'production', objectLookup: 'scenario.context.objectLookup',
    rawImportRequestOrders: [lifecycleFirst, schemaFirst],
    repositoryDescriptor: operationModeDescriptor,
    requestedLayer: 3, semanticProfiles: true
  });
}
const rawLifetimeFirstChangeSet =
  'ogvcs:v1:change-set:sha256:9cda477b4303c876fc79feb4cbd0a5deda70011261bd81fc758b588872040720';
const rawLifetimeRecord = {
  descriptor: operationModeDescriptor,
  fileId: '11'.repeat(16),
  firstChangeSet: rawLifetimeFirstChangeSet,
  firstOperation: 0,
  origin: 'native-create'
};
const rawLifetimeRecordMalformed = { ...rawLifetimeRecord };
delete rawLifetimeRecordMalformed.fileId;
const rawImportMapping = {
  descriptor: operationModeDescriptor,
  fileId: '73'.repeat(16),
  importerProfile: 'importer.test/fixture-adapter@1',
  mappingKey: 'bfc8dc1a980e10425ed9fa86e6730157f9f87c02d93bcfb7faa40de1e5e6035c',
  sourceIdentityDigest: '72'.repeat(32),
  sourceNamespaceDigest: '71'.repeat(32),
  state: 'materialized'
};
const rawImportMappingMalformed = { ...rawImportMapping };
delete rawImportMappingMalformed.descriptor;
const rawWorkingAddition = { ...rawLifetimeRecord };
const rawWorkingAdditionMalformed = { ...rawWorkingAddition };
delete rawWorkingAdditionMalformed.firstOperation;
for (const [id, field, valid, malformed] of [
  ['lifetime-raw-lifetime-record-schema-before-duplicate', 'lifetimeRecords',
    rawLifetimeRecord, rawLifetimeRecordMalformed],
  ['lifetime-raw-import-mapping-schema-before-conflict', 'importMappings',
    rawImportMapping, rawImportMappingMalformed],
  ['lifetime-raw-working-addition-schema-before-duplicate', 'workingLifetimeAdditions',
    rawWorkingAddition, rawWorkingAdditionMalformed]
]) {
  const context = order => ({
    importMappings: field === 'importMappings' ? order : [],
    lifetimeRecords: field === 'lifetimeRecords' ? order : [],
    workingLifetimeAdditions: field === 'workingLifetimeAdditions' ? order : []
  });
  operationModeRecipes[id] = baseModeRecipe('lifetime-and-imports-raw', {
    mode: 'conformance',
    objectLookup: 'scenario.context.objectLookup',
    rawLifetimeContextOrders: [
      context([valid, valid, malformed]),
      context([malformed, valid, valid])
    ],
    repositoryDescriptor: operationModeDescriptor,
    requestedLayer: 3,
    semanticProfiles: true
  });
}
for (const [suffix, field, valid, malformed] of [
  ['lifetime-record', 'lifetimeRecords', rawLifetimeRecord, rawLifetimeRecordMalformed],
  ['import-mapping', 'importMappings', rawImportMapping, rawImportMappingMalformed]
]) {
  const context = order => ({
    importMappings: field === 'importMappings' ? order : [],
    lifetimeRecords: field === 'lifetimeRecords' ? order : [],
    workingLifetimeAdditions: []
  });
  operationModeRecipes[`import-request-raw-context-${suffix}-schema-before-profile-lifecycle`] =
    baseModeRecipe('import-request-context-raw', {
      importRequest: Object.fromEntries(rawImportBaseEntries),
      mode: 'production',
      objectLookup: 'scenario.context.objectLookup',
      rawLifetimeContextOrders: [
        context([valid, malformed]),
        context([malformed, valid])
      ],
      repositoryDescriptor: operationModeDescriptor,
      requestedLayer: 3,
      semanticProfiles: true
    });
}
for (const [label, sourceName] of [['lifetime', 'file-id-lifetime'], ['import-mapping', 'import-mapping']]) {
  for (const suffix of [
    'version-selector-invalid', 'type-selector-invalid', 'extra-field-22', 'extra-field-999'
  ]) {
    operationModeRecipes[`logical-record-${label}-${suffix}`] =
      baseModeRecipe('logical-record-map-raw', {
        registry: 'absent',
        requestedLayer: 2,
        semanticProfiles: false,
        source: `schema/logical-record-${sourceName}-${suffix}.cbor`
      });
  }
}
operationModeRecipes['mode-tree-schema-decoder-registry-free-wrong-family'] = baseModeRecipe('tree-schema-decoder', {
  expectedProfileFamily: 'content-policy', profile: 'path.test/opaque@1',
  registry: 'absent', requestedLayer: 2, semanticProfiles: false,
  source: 'lifecycle/tree-wrong-content-profile-family.cbor'
});
for (const surface of ['tree-schema-decoder', 'metadata-decoder', 'bundle-memory-verifier', 'bundle-stream-verifier']) {
  operationModeRecipes[`mode-${surface}-authority-omitted`] = authorityOmittedRecipe(surface);
  operationModeRecipes[`mode-${surface}-semantic-false-with-registry`] = baseModeRecipe(surface,
    { requestedLayer: 2, semanticProfiles: false });
  operationModeRecipes[`mode-${surface}-semantic-false-with-operation`] = baseModeRecipe(surface,
    { operation: 'read', registry: 'absent', requestedLayer: 2, semanticProfiles: false });
}
const groupInput = Object.freeze({
  externalKeyProfile: 'external-key.test/opaque@1', externalKeyValueHex: '01',
  fileIds: ['21212121212121212121212121212121'], groupId: '51515151515151515151515151515151',
  groupProfile: 'group.test/opaque@1', roleProfile: 'group-role.test/member@1'
});
for (const id of Object.keys(operationModeRecipes).filter(value => value.startsWith('mode-asset-groups-'))) {
  operationModeRecipes[id] = { ...operationModeRecipes[id], groupInput };
}
for (const [suffix, profileField, profileValue] of [
  ['unknown-group-profile', 'groupProfile', 'unknown.example/group@1'],
  ['unknown-role-profile', 'roleProfile', 'unknown.example/role@1'],
  ['unknown-external-key-profile', 'externalKeyProfile', 'unknown.example/external-key@1'],
  ['wrong-family-group-profile', 'groupProfile', 'content-policy.test/opaque@1'],
  ['wrong-family-role-profile', 'roleProfile', 'group.test/opaque@1'],
  ['wrong-family-external-key-profile', 'externalKeyProfile', 'group-role.test/member@1']
]) {
  operationModeRecipes[`group-standalone-${suffix}`] = baseModeRecipe('asset-groups', {
    groupInput: { ...groupInput, [profileField]: profileValue },
    mode: 'conformance', requestedLayer: 3, semanticProfiles: true
  });
}
const groupInputWrongFamily = {
  ...groupInput,
  fileIds: ['22'.repeat(16)],
  groupId: '52'.repeat(16),
  groupProfile: 'content-policy.test/opaque@1'
};
for (const order of ['forward', 'reverse']) {
  operationModeRecipes[`group-standalone-known-schema-before-profile-lifecycle-${order}`] =
    baseModeRecipe('asset-groups', {
      groupInputs: order === 'forward'
        ? [groupInput, groupInputWrongFamily]
        : [groupInputWrongFamily, groupInput],
      mode: 'production', requestedLayer: 3, semanticProfiles: true
    });
}
for (const [suffix, malformedCarrier] of [
  ['later-group-non-map', { kind: 'non-map-group', value: null }],
  ['later-member-non-map', { kind: 'non-map-member', value: null }],
  ['later-external-key-non-map', { kind: 'non-map-external-key', value: null }],
  ['later-proxy', {
    assertCallerCodeNotInvoked: true,
    kind: 'map-proxy-with-throwing-get-prototype-of',
    marker: 'OGVCS_CALLER_TRAP_MUST_NOT_RUN'
  }],
  ['groups-container-proxy', {
    assertCallerCodeNotInvoked: true,
    kind: 'groups-map-proxy-with-throwing-get-prototype-of',
    marker: 'OGVCS_CALLER_TRAP_MUST_NOT_RUN'
  }],
  ['members-array-proxy', {
    assertCallerCodeNotInvoked: true,
    kind: 'members-array-proxy-with-throwing-get-own-property-descriptor',
    marker: 'OGVCS_CALLER_TRAP_MUST_NOT_RUN'
  }],
  ['external-keys-array-proxy', {
    assertCallerCodeNotInvoked: true,
    kind: 'external-keys-array-proxy-with-throwing-get-own-property-descriptor',
    marker: 'OGVCS_CALLER_TRAP_MUST_NOT_RUN'
  }]
]) {
  operationModeRecipes[`group-standalone-raw-${suffix}-before-profile-lifecycle`] =
    baseModeRecipe('asset-groups-raw', {
      firstGroupInput: groupInput,
      laterGroupInput: {
        ...groupInput,
        fileIds: ['22'.repeat(16)],
        groupId: '52'.repeat(16)
      },
      malformedCarrier,
      mode: 'production', requestedLayer: 3, semanticProfiles: true
    });
}
operationModeRecipes['asset-groups-config-proxy-no-caller-code'] =
  baseModeRecipe('asset-groups-raw', {
    firstGroupInput: groupInput,
    laterGroupInput: {
      ...groupInput,
      fileIds: ['22'.repeat(16)],
      groupId: '52'.repeat(16)
    },
    malformedCarrier: {
      assertCallerCodeNotInvoked: true,
      kind: 'options-proxy-with-throwing-get-own-property-descriptor',
      marker: 'OGVCS_CALLER_TRAP_MUST_NOT_RUN'
    },
    mode: 'conformance', requestedLayer: 3, semanticProfiles: true
  });
operationModeRecipes['repository-lookup-zero-time'] = baseModeRecipe('repository-lookup-layer2', {
  limits: { maxTimeMs: 0 }, registry: 'absent', requestedLayer: 2, semanticProfiles: false
});
const OPERATION_MODE_RECIPES = Object.freeze(operationModeRecipes);
const OPERATION_MODE_SOURCE_SHA256 = Object.freeze({
  'logical-record-import-mapping-extra-field-22': 'ecdcb80f584a0be149fe1836d2768db3aef478472aed4bf9f76267b498a38c76',
  'logical-record-import-mapping-extra-field-999': '2724dc8e94da0a1c08572ff7be68292a2f8dff5c2506372e1eca696158a9e2d2',
  'logical-record-import-mapping-type-selector-invalid': '409959468dc0bfe4855ba301226a1a5993d1382cee2c3ebee9d0d3d4ecb0306c',
  'logical-record-import-mapping-version-selector-invalid': 'fc89801425ea144064173e9de240d51f577b83043de669ac929cc16e0f630c79',
  'logical-record-lifetime-extra-field-22': 'eaf53c7c838cdeef533be058743623b12d0919f8c88ee125761611be326efc48',
  'logical-record-lifetime-extra-field-999': 'bc24f598cc2f642148f9281afb2421328e23095243f3d67572e303520cb79292',
  'logical-record-lifetime-type-selector-invalid': 'ce0b0f2cffe8adfb6b953efe6ce03fed9b28689933fdb60f87c0f5abdba7eea6',
  'logical-record-lifetime-version-selector-invalid': '19f8dc2c96d9604020b7882f25598c9595bc7c90e6eeb8183834b517e72cc48e',
  'mode-manifest-verify-missing-reference-before-profile-lifecycle': '6e6e474af9210e456219075b2ef8cb5f2d2cdbeb18fced06d72d101400eb4e87',
  'mode-tree-file-feature-before-duplicate-fileid': '14a9db60d0fc6db8f23d1512c4c7e2e893c40f36959ca873385e6a43b111a437',
  'mode-tree-file-known-schema-before-order-forward': 'baaaa03e39ae7e8492f1490ee6abcc2a0fa3ff455f399df110dd27c3cadf2837',
  'mode-tree-file-known-schema-before-order-reverse': '61d5a5ce4247d09377aeea719ff980dbd0b9141d0ca29462c72f2b6b0324a21f',
  'mode-tree-file-order-before-descriptor-mismatch': '14a6a96fc32ae0f4878ca4b9ed4734667df06495eece0e37d19613f8e55c6d82',
  'mode-tree-file-order-before-feature-lifecycle': 'e8f8b2d29f504897be7720aa0e38f04ab0ab9bd969beb14d30cad40bc3048a1d',
  'mode-tree-file-target-before-duplicate-fileid': '9d43ddcb9cb7de73909b512e2c4f65db18671bc22a55fb45bc2a97ee14e9fbc2'
});
const ISOLATED_STABLE_ERROR_RECIPES = Object.freeze({
  'error-schema-field-unknown': {
    source: 'schema/invalid-unknown-field.cbor',
    sourceSha256: '6d0c0f61de3229b4b416414bc5a287c73cfab4d44de8693c21703174c779238d'
  }
});
const CLOSURE_LIFECYCLE_CARRIERS = Object.freeze({
  'conflict-missing-reference-before-profile-lifecycle': {
    absentRef: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12',
    operation: 'validate-repository',
    primaryPath: 'scenarios/objects/conflict-missing-reference-before-profile-lifecycle/published-snapshot.cbor',
    primarySha256: '31f4ec103b706075f64be1ba587754b80ec4c740b87bea911785dd88fb41deda'
  },
  'mode-manifest-verify-missing-reference-before-profile-lifecycle': {
    absentRef: `ogvcs:v1:chunk:sha256:${'e1'.repeat(32)}`,
    operation: 'validate-operation-mode',
    primaryPath: 'lifecycle/manifest-missing-reference-before-profile-lifecycle.cbor',
    primarySha256: '6e6e474af9210e456219075b2ef8cb5f2d2cdbeb18fced06d72d101400eb4e87'
  },
  'provenance-missing-reference-before-profile-lifecycle': {
    absentRef: `ogvcs:v1:content-manifest:sha256:${'e3'.repeat(32)}`,
    operation: 'validate-repository-route',
    primaryPath: 'scenarios/objects/provenance-missing-reference-before-profile-lifecycle/candidate-snapshot.cbor',
    primarySha256: '7c73c96fdbecb9b87da61e22b843565840d95e0310796ff7b432811ed111f794'
  },
  'replay-missing-reference-before-profile-lifecycle': {
    absentRef: 'ogvcs:v1:content-manifest:sha256:82fb14ee539371d23ddeb6da89c7a23423ef733874882a8f75e57460f6cb8a12',
    operation: 'validate-repository-route',
    primaryPath: 'scenarios/objects/replay-missing-reference-before-profile-lifecycle/candidate-snapshot.cbor',
    primarySha256: 'a3b97bdc9e1fa2227801d0edf65b9f043db1e356c791d63f92cb73aad828fead'
  },
  'repository-candidate-missing-change-base': {
    absentRef: `ogvcs:v1:snapshot:sha256:${'e9'.repeat(32)}`,
    mode: 'conformance',
    operation: 'validate-repository-route',
    primaryPath: 'scenarios/objects/repository-candidate-missing-change-base/candidate-change.cbor',
    primarySha256: 'f507f49d8483106fbb3e36fe5f112becd92f4cc29176cd725389299d967d3663'
  },
  'tree-missing-reference-before-profile-lifecycle': {
    absentRef: `ogvcs:v1:content-manifest:sha256:${'e2'.repeat(32)}`,
    operation: 'validate-repository-route',
    primaryPath: 'scenarios/objects/tree-missing-reference-before-profile-lifecycle/tree.cbor',
    primarySha256: '5d25ab81d8c41255fb04425c290cb81bf62c052eaa9c698743a68f8364a67d14'
  }
});
function fixtureAdapterRecipe(id, expectedCode, adapter, materialization = 'full') {
  return {
    adapter: {
      allocation: 'incrementing-nonzero-128-bit',
      persistLedger: 'memory',
      targetConsumption: 'always-available',
      ...adapter
    },
    expectedCode,
    generatorRequest: {
      destination: `fixture-adapter/${id}`,
      extensions: {
        'generation.large-file-mode': 'virtual',
        'generation.materialization': materialization
      },
      profile: { id: 'code-heavy', version: '2.0.0' },
      scale: { historyOperationCount: 8, largeFileBytes: 0, maxDepth: 5, pathCount: 6 },
      seed: `ogvcs-002-${id}`
    },
    schema: 'ogvcs.repository-format.v1.fixture-adapter-invocation.v1'
  };
}
const FIXTURE_ADAPTER_RECIPES = Object.freeze({
  'error-fixture-content-unavailable': fixtureAdapterRecipe('error-fixture-content-unavailable',
    'FIXTURE_CONTENT_UNAVAILABLE', {}, 'index-only'),
  'error-fixture-mapping-missing': fixtureAdapterRecipe('error-fixture-mapping-missing',
    'FIXTURE_MAPPING_MISSING', { persistLedger: 'omit' }),
  'error-fixture-native-binding-missing': fixtureAdapterRecipe('error-fixture-native-binding-missing',
    'FIXTURE_NATIVE_BINDING_MISSING', { requireNativeHistoryBindings: true }),
  'error-fixture-schema-unsupported': fixtureAdapterRecipe('error-fixture-schema-unsupported',
    'FIXTURE_SCHEMA_UNSUPPORTED', { postGenerationMutation: { type: 'request-profile-version', value: '1.0.0' } }),
  'error-fixture-semantic-invalid': fixtureAdapterRecipe('error-fixture-semantic-invalid',
    'FIXTURE_SEMANTIC_INVALID', { verifierResult: 'semantic-invalid' })
});
const REQUIRED_OBLIGATIONS = Object.freeze([
  ...['create', 'modify', 'copy', 'move', 'rename', 'delete', 'restore', 'group-create',
    'group-update', 'group-delete', 'merge-resolution'].map(name => `transition:${name}`),
  'transition:exact-replay', 'transition:result-mismatch',
  'history:parents-0', 'history:parents-1', 'history:parents-2', 'history:parents-8',
  'history:second-root', 'history:missing-parent', 'history:duplicate-parent', 'history:cycle',
  'history:cross-repository', 'history:parents-9',
  'fileid:zero', 'fileid:duplicate', 'fileid:create-reuse', 'fileid:copy-reuse',
  'fileid:source-forgery', 'fileid:move-rename', 'fileid:copy', 'fileid:delete-recreate',
  'fileid:restore-ancestry', 'fileid:restore-invalid-ancestry', 'fileid:restore-forgery',
  'fileid:cross-repository', 'fileid:import-retry', 'fileid:import-conflict',
  'fileid:import-native-collision', 'fileid:concurrent-loser-state',
  ...['missing', 'wrong-kind', 'object-id-mismatch', 'bad-schema', 'profile-lifecycle']
    .map(suffix => `fileid:lifetime-first-change-${suffix}`),
  ...['lifetime', 'request', 'candidate'].flatMap(surface =>
    ['conformance', 'wrong-family', 'production-conformance-only', 'foreign-repository']
      .map(variant => `fileid:prior-import-mapping-${surface}-${variant}`)),
  ...['lifetime', 'import-mapping'].flatMap(label => [
    'version-selector-invalid', 'type-selector-invalid', 'extra-field-22', 'extra-field-999'
  ].map(suffix => `fileid:serialized-${label}-${suffix}`)),
  'tree:empty', 'tree:unicode', 'tree:all-entry-kinds', 'tree:all-modes', 'tree:million-entries',
  'unicode:age-15-assigned', 'unicode:newer-composition-pair', 'unicode:newer-decomposed',
  'unicode:newer-canonical', 'unicode:frozen-unassigned',
  'tree:ratified-path-profile-accept', 'tree:ratified-path-profile-reject',
  'tree:ratified-path-profile-empty-accept', 'tree:ratified-path-profile-empty-missing-validator',
  'tree:ratified-path-profile-opaque-keys', 'tree:ratified-path-profile-missing-repository-key',
  'tree:ratified-path-profile-missing-platform-key',
  'tree:ratified-path-profile-case-sensitive-distinct', 'tree:ratified-path-profile-case-folded-collision',
  'tree:ratified-path-profile-missing-case-mode', 'tree:ratified-path-profile-wrong-case-mode',
  'tree:missing-child-before-missing-path-adapter',
  'tree:missing-manifest-before-wrong-path-adapter',
  'tree:missing-chunk-before-missing-path-adapter',
  'tree:missing-target-before-path-profile-lifecycle',
  'tree:missing-manifest-before-descriptor-mismatch',
  'tree:missing-child-before-duplicate-fileid',
  ...['repository-candidate', 'import-request', 'tree-expand', 'manifest-verify', 'asset-groups'].flatMap(surface => [
    `mode:${surface}-conformance-accept`,
    `mode:${surface}-read-rejected`, `mode:${surface}-invalid-rejected`,
    `mode:${surface}-omitted-rejected`, `mode:${surface}-production-conformance-rejected`,
    `mode:${surface}-partial-registry-rejected`, `mode:${surface}-forged-registry-rejected`
  ]),
  ...['repository-candidate', 'import-request', 'tree-expand', 'manifest-verify', 'asset-groups'].flatMap(surface => [
    `mode:${surface}-registry-required`, `mode:${surface}-semantic-disabled-rejected`
  ]),
  'mode:tree-expand-case-mode-missing-rejected', 'mode:tree-expand-case-mode-invalid-rejected',
  'mode:repository-lookup-layer2-registry-free',
  'mode:repository-lookup-layer2-authority-omitted-rejected',
  'mode:bundle-visitor-read-rejected', 'mode:bundle-visitor-invalid-rejected', 'mode:bundle-visitor-omitted',
  'bundle:semantic-callback-does-not-promote',
  ...['metadata-encoder', 'tree-ordered', 'tree-sorted', 'content-manifest',
    'bundle-ordered', 'bundle-memory-encoder'].flatMap(surface => [
    `mode:${surface}-selector-missing-rejected`, `mode:${surface}-selector-read-rejected`,
    `mode:${surface}-selector-invalid-rejected`, `mode:${surface}-registry-required`,
    `mode:${surface}-production-conformance-rejected`,
    `mode:${surface}-partial-registry-rejected`, `mode:${surface}-forged-registry-rejected`
  ]),
  ...['tree-file', 'metadata-decoder', 'bundle-memory-verifier', 'bundle-stream-verifier'].flatMap(surface => {
    const authority = suffix => `mode:${surface}-${surface === 'tree-file' ? 'feature-' : ''}${suffix}`;
    return [
    authority('deprecated-read-accept'), authority('conformance-read-rejected'),
    authority('conformance-accept'), authority('deprecated-production-write-rejected'),
    authority('conformance-production-write-rejected'),
    `mode:${surface}-registry-operation-required`, `mode:${surface}-registry-operation-invalid-rejected`,
    `mode:${surface}-registry-required`, `mode:${surface}-semantic-disabled-rejected`,
    `mode:${surface}-unknown-${surface === 'tree-file' ? 'feature' : 'profile'}-rejected`, `mode:${surface}-partial-registry-rejected`,
    `mode:${surface}-forged-registry-rejected`
  ];
  }),
  ...['tree-schema-decoder', 'metadata-decoder', 'bundle-memory-verifier', 'bundle-stream-verifier'].flatMap(surface => [
    `mode:${surface}-registry-free-layer2`, `mode:${surface}-registry-free-wrong-family-rejected`,
    `mode:${surface}-authority-omitted-rejected`,
    `mode:${surface}-semantic-false-with-registry-rejected`,
    `mode:${surface}-semantic-false-with-operation-rejected`
  ]),
  ...['unknown-group-profile', 'unknown-role-profile', 'unknown-external-key-profile',
    'wrong-family-group-profile', 'wrong-family-role-profile', 'wrong-family-external-key-profile']
    .map(suffix => `group:standalone-${suffix}`),
  'group:standalone-known-schema-before-profile-lifecycle-forward',
  'group:standalone-known-schema-before-profile-lifecycle-reverse',
  ...['later-group-non-map', 'later-member-non-map', 'later-external-key-non-map', 'later-proxy',
    'groups-container-proxy', 'members-array-proxy', 'external-keys-array-proxy']
    .map(suffix => `group:standalone-raw-${suffix}-before-profile-lifecycle`),
  'group:asset-groups-config-proxy-no-caller-code',
  'import-request:raw-context-lifetime-record-schema-before-profile-lifecycle',
  'import-request:raw-context-import-mapping-schema-before-profile-lifecycle',
  'limits:repository-lookup-zero-time', 'limits:tree-groups-combined-memory',
  'limits:replay-base-memory', 'limits:fileid-lifetime-import-indexes-memory',
  'limits:import-request-many-mappings-deadline',
  'limits:graph-workspace-indexes-memory', 'limits:conflict-group-indexes-memory',
  'limits:many-invalid-error-selection-memory', 'limits:lookup-edge-counter-rollback',
  'limits:lookup-scratch-counter-rollback',
  'limits:tree-stream-transaction-composite-memory',
  'typed-reference:arbitrary-kind-map-relabel', 'typed-reference:duplicate-kind-token',
  'typed-reference:durable-overlength-colon-dense',
  'group:create', 'group:update', 'group:delete', 'group:cardinality', 'group:external-key',
  ...['content', 'divergent-move', 'delete-modify', 'type', 'policy', 'group',
    'path-collision'].map(kind => `conflict:kind-${kind}`),
  'conflict:tombstoned-kind-mode-rejected',
  ...['base', 'left', 'right', 'delete', 'custom'].map(choice => `conflict:choice-${choice}`),
  'conflict:resolved', 'conflict:unresolved', 'conflict:custom-driver',
  'shelf:revision-chain', 'provenance:acyclic', 'provenance:cycle',
  'provenance:snapshot-cycle', 'attestation:unsigned', 'attestation:signed',
  'attestation:signature-shape',
  'manifest:empty', 'manifest:repeated-chunk', 'manifest:multi-chunk',
  'manifest:corrupt-chunk', 'manifest:chunk-length', 'manifest:length-sum-mismatch',
  'manifest:logical-ceiling', 'manifest:unknown-profile', 'manifest:one-tib',
  'manifest:annotation-invariance', 'manifest:writer-too-few-parts', 'manifest:writer-too-many-parts',
  'manifest:writer-count-before-profile-lifecycle',
  'manifest:writer-object-id-before-profile-lifecycle',
  'manifest:writer-known-schema-before-chunk-length-forward',
  'manifest:writer-known-schema-before-chunk-length-reverse',
  'manifest:writer-content-object-id-before-chunk-length-forward',
  'manifest:writer-content-object-id-before-chunk-length-reverse',
  'manifest:writer-limit-before-kind',
  'manifest:writer-count-before-kind-forward', 'manifest:writer-count-before-kind-reverse',
  'manifest:writer-limit-before-count-and-profile-lifecycle',
  'tree:writer-ordered-too-many-entries', 'tree:writer-sorted-too-many-entries',
  'tree:writer-ordered-count-before-feature-lifecycle', 'tree:writer-sorted-count-before-feature-lifecycle',
  'tree:writer-ordered-count-before-entry-profile-lifecycle',
  'tree:writer-sorted-count-before-entry-profile-lifecycle',
  'tree:writer-ordered-count-before-duplicate-fileid',
  'tree:writer-sorted-count-before-duplicate-fileid',
  'tree:writer-ordered-limit-before-count-and-feature-lifecycle',
  'tree:writer-sorted-limit-before-count-and-feature-lifecycle',
  'tree:writer-ordered-kind-before-order-forward',
  'tree:writer-ordered-kind-before-order-reverse',
  'tree:writer-ordered-limit-before-kind',
  'tree:writer-sorted-family-before-kind-forward', 'tree:writer-sorted-family-before-kind-reverse',
  ...['header', 'object', 'logical-record', 'root', 'trailer'].map(kind => `bundle:item-${kind}`),
  'bundle:zero-sections', 'bundle:logical-preservation', 'bundle:multi-root-sort',
  'bundle:sort', 'bundle:count', 'bundle:ordinal', 'bundle:mode', 'bundle:budget',
    'bundle:declared-accounting', 'bundle:visitor-item-budget', 'bundle:visitor-count-budget',
    'bundle:visitor-nested-key-capture-memory',
  'bundle:transcript-budget', 'bundle:writer-sequence-before-object-id',
  'bundle:writer-object-id-before-unknown-kind',
  'bundle:writer-object-id-before-feature-lifecycle',
  ...['forward', 'reverse'].flatMap(order => [
    `bundle:writer-section-object-id-before-feature-lifecycle-${order}`,
    `bundle:writer-section-root-order-before-role-lifecycle-${order}`,
    `bundle:writer-section-sequence-before-logical-schema-${order}`
  ]),
  'mode:tree-file-order-before-feature-lifecycle',
  'mode:tree-file-order-before-descriptor-mismatch',
  'mode:tree-file-target-before-duplicate-fileid',
  'mode:tree-file-feature-before-duplicate-fileid',
  'mode:tree-file-known-schema-before-order-forward',
  'mode:tree-file-known-schema-before-order-reverse',
  'mode:manifest-verify-missing-reference-before-profile-lifecycle',
  'lookup:validate-all-known-schema-before-profile-lifecycle-forward',
  'lookup:validate-all-known-schema-before-profile-lifecycle-reverse',
  'import-request:raw-sourceNamespaceDigest-schema-before-profile-lifecycle',
  'import-request:raw-sourceIdentityDigest-schema-before-profile-lifecycle',
  'import-request:raw-requestedFileId-schema-before-profile-lifecycle',
  'fileid:raw-lifetime-record-schema-before-duplicate',
  'fileid:raw-import-mapping-schema-before-conflict',
  'fileid:raw-working-addition-schema-before-duplicate',
  'tree:missing-reference-before-profile-lifecycle',
  'transition:missing-reference-before-profile-lifecycle',
  'transition:entry-target-wrong-kind',
  'conflict:missing-reference-before-profile-lifecycle',
  'conflict:entry-target-missing', 'conflict:entry-target-wrong-kind',
  'conflict:entry-target-missing-before-profile-lifecycle',
  'provenance:missing-reference-before-profile-lifecycle',
  ...['manifest', 'tree', 'replay', 'conflict', 'snapshot', 'provenance', 'shelf']
    .flatMap(route => ['forward', 'reverse']
      .map(order => `closure:${route}-identity-before-missing-${order}`)),
  'provenance:cycle-branch-before-missing-input-forward',
  'provenance:cycle-branch-before-missing-input-reverse',
  'snapshot-graph:missing-change-before-profile-lifecycle',
  'snapshot-graph:missing-descriptor-before-descriptor-mismatch',
  'snapshot-graph:second-root-before-missing-parent-forward',
  'snapshot-graph:second-root-before-missing-parent-reverse',
  'repository:candidate-verify-content-false-rejected',
  'repository:candidate-content-complete-missing-chunk',
  'repository:candidate-missing-change-base',
  'repository:candidate-missing-tree-before-second-root',
  'repository:candidate-missing-change-before-profile-lifecycle',
  'shelf:verify-content-false-rejected', 'shelf:content-complete-missing-chunk',
  'shelf:missing-previous-before-chain-invalid',
  'shelf:unrelated-known-schema-object-ignored', 'shelf:unrelated-profile-object-ignored',
  'transition:restore-missing-source-tree-before-profile-lifecycle',
  'transition:restore-missing-proof-descriptor-before-cross-repository',
  'tree:path-core-deep-chain',
  'bundle:object-id', 'bundle:record-id', 'bundle:root-invalid', 'bundle:trailer',
  'bundle:eof', 'bundle:duplicate', 'bundle:closure-missing', 'bundle:closure-extra',
  'bundle:wrong-kind', 'bundle:forbidden-claim', 'bundle:every-edge-family',
  'bundle:every-root-family',
  ...Array.from({ length: 11 }, (_, index) => `bundle:edge-object-kind-${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `bundle:logical-type-${index + 1}`),
  'bundle:root-kind-object', 'bundle:root-kind-logical-record',
  'mutation:single-bit', 'hash:tamper', 'truncation:every-prefix', 'malformed:complete',
  'limits:all', 'registry:duplicate', 'registry:reassigned', 'registry:invalid-entry',
  'registry:reserved', 'registry:ratified', 'registry:deprecated-read',
  'registry:deprecated-write', 'registry:conformance', 'registry:conformance-production',
  'registry:unknown-profile', 'registry:unknown-feature', 'registry:unknown-feature-forward',
  'registry:unknown-extension-preserve'
].sort());
const OPERATIONS = new Set([
  'adapt-fixture', 'allocate-file-id', 'canonical-scan', 'import-file-id', 'replay-change-set',
  'validate-abstract-reference-graph', 'validate-bundle', 'validate-bundle-claim',
  'validate-object', 'validate-operation-mode', 'validate-path-profile-decision',
  'validate-repository', 'validate-repository-route', 'validate-resource-reservation', 'validate-tree-groups-memory',
  'validate-typed-reference-authority', 'write-content-manifest', 'write-logical-bundle', 'write-tree'
]);
const RESOURCE_DOMAIN = Buffer.from('OpenGameVCS resource summary\0', 'ascii');
const REGISTRY_DOMAIN = Buffer.from('OpenGameVCS registry set\0', 'ascii');

function fail(message) { throw new Error(`reference-vector audit failed: ${message}`); }
function same(left, right) { return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right)); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function u16(value) { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; }
function u32(value) { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]));
  }
  return value;
}

function stableJson(value) { return `${JSON.stringify(stableValue(value), null, 2)}\n`; }

function safePath(value) {
  return typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes('\0') &&
    !value.startsWith('/') && value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

function expectedMediaType(path) {
  if (path.startsWith('scenarios/graphs/') && path.endsWith('.json')) {
    return 'application/vnd.opengamevcs.abstract-reference-graph+json';
  }
  if (path.endsWith('.cbor')) return 'application/cbor';
  if (path.endsWith('.cborseq')) return 'application/cbor-seq';
  if (path.endsWith('.bin')) return 'application/octet-stream';
  if (path.endsWith('.md')) return 'text/markdown';
  if (path.endsWith('.txt')) return 'text/plain; charset=utf-8';
  if (path.endsWith('.json')) return 'application/json';
  fail(`unrouted media type for ${path}`);
}

async function boundedJson(path, requireCanonical = false) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_JSON_BYTES) {
    fail(`unsafe or oversized JSON file ${path}`);
  }
  const bytes = await readFile(path);
  if (bytes.includes(0x0d) || bytes[0] === 0xef) fail(`noncanonical JSON bytes in ${path}`);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`invalid JSON in ${path}`); }
  if (requireCanonical && stableJson(value) !== bytes.toString('utf8')) {
    fail(`noncanonical JSON serialization in ${path}`);
  }
  return value;
}

async function canonicalJson(path) { return boundedJson(path, true); }

async function filesBelow(root, prefix = '') {
  const directory = prefix === '' ? root : join(root, ...prefix.split('/'));
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const files = [];
  for (const entry of entries) {
    const child = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (!safePath(child) || entry.isSymbolicLink()) fail(`unsafe vector filesystem entry ${child}`);
    if (entry.isDirectory()) files.push(...await filesBelow(root, child));
    else if (entry.isFile()) files.push(child);
    else fail(`unsupported vector filesystem entry ${child}`);
  }
  return files;
}

function recordMap(records, label, orderKey = 'path') {
  if (!Array.isArray(records)) fail(`${label} is not an array`);
  const map = new Map();
  let previous;
  for (const record of records) {
    const orderValue = record?.[orderKey];
    if (!safePath(record?.path) ||
        typeof orderValue !== 'string' ||
        (previous !== undefined && orderValue.localeCompare(previous, 'en') <= 0) ||
        map.has(record.path)) {
      fail(`${label} paths are not sorted and unique`);
    }
    previous = orderValue;
    map.set(record.path, record);
  }
  return map;
}

async function verifyArtifact(vectorRoot, inventory, record, label) {
  if (!record || !safePath(record.path)) fail(`${label} has an unsafe artifact path`);
  const expected = inventory.get(record.path);
  if (!expected || !same(expected, record)) fail(`${label} does not match the top-level inventory`);
  const bytes = await readFile(join(vectorRoot, ...record.path.split('/')));
  if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256 ||
      record.mediaType !== expectedMediaType(record.path)) fail(`${label} bytes or media type differ`);
  return bytes;
}

async function verifySeedAndPreimages(vectorRoot, inventory) {
  const objectDomain = Buffer.from('OpenGameVCS object\0', 'ascii');
  const logicalDomain = Buffer.from('OpenGameVCS logical record\0', 'ascii');
  const conflictDomain = Buffer.from('OpenGameVCS conflict\0', 'ascii');
  const objectIndex = await canonicalJson(join(vectorRoot, 'objects', 'index.json'));
  const logicalIndex = await canonicalJson(join(vectorRoot, 'logical-records', 'index.json'));
  const conflictIndex = await canonicalJson(join(vectorRoot, 'conflicts', 'index.json'));
  if (objectIndex.schema !== 'ogvcs.repository-format.v1.object-vectors.v1' ||
      !Array.isArray(objectIndex.objects) || objectIndex.objects.length !== 11 ||
      logicalIndex.schema !== 'ogvcs.repository-format.v1.logical-record-vectors.v1' ||
      !Array.isArray(logicalIndex.records) || logicalIndex.records.length !== 9 ||
      conflictIndex.schema !== 'ogvcs.repository-format.v1.conflict-preimages.v1' ||
      !Array.isArray(conflictIndex.combinations) || conflictIndex.combinations.length !== 8) {
    fail('identity preimage index shape changed');
  }
  for (const row of objectIndex.objects) {
    const payloadRecord = inventory.get(row.payloadPath);
    const payload = await verifyArtifact(vectorRoot, inventory, payloadRecord, `object preimage ${row.name}`);
    const preimage = Buffer.concat([objectDomain, u16(1), u16(row.kind), payload]);
    if (row.objectDomainHex !== objectDomain.toString('hex') || row.formatVersionUint16beHex !== '0001' ||
        row.kindUint16beHex !== u16(row.kind).toString('hex') || row.objectId !== sha256(preimage) ||
        row.preimageRecipe !== 'objectDomainHex || formatVersionUint16beHex || kindUint16beHex || exact payloadPath bytes' ||
        row.preimageHex !== (payload.length <= 256 ? preimage.toString('hex') : null)) {
      fail(`object preimage or identity differs for ${row.name}`);
    }
  }
  for (const row of logicalIndex.records) {
    const payload = await verifyArtifact(vectorRoot, inventory, inventory.get(row.payloadPath),
      `logical-record preimage ${row.type}`);
    const preimage = Buffer.concat([logicalDomain, u16(1), u16(row.type), payload]);
    if (row.logicalDomainHex !== logicalDomain.toString('hex') || row.formatVersionUint16beHex !== '0001' ||
        row.typeUint16beHex !== u16(row.type).toString('hex') || row.identity !== sha256(preimage) ||
        row.preimageHex !== preimage.toString('hex')) {
      fail(`logical-record preimage or identity differs for type ${row.type}`);
    }
  }
  for (let mask = 0; mask < conflictIndex.combinations.length; mask += 1) {
    const row = conflictIndex.combinations[mask];
    const bits = mask.toString(2).padStart(3, '0');
    const payload = await verifyArtifact(vectorRoot, inventory, inventory.get(row.keyedPayloadPath),
      `conflict preimage ${bits}`);
    const preimage = Buffer.concat([conflictDomain, u16(1), payload]);
    if (row.keyedPayloadPath !== `conflicts/${bits}-keyed-preimage.cbor` ||
        row.basePresent !== Boolean(mask & 4) || row.leftPresent !== Boolean(mask & 2) ||
        row.rightPresent !== Boolean(mask & 1) || row.domainHex !== conflictDomain.toString('hex') ||
        row.formatVersionUint16beHex !== '0001' || row.conflictId !== sha256(preimage)) {
      fail(`conflict preimage or identity differs for ${bits}`);
    }
  }
  if (conflictIndex.conflictIdRecipe !== 'SHA-256(domainHex || 0001 || exact keyedPayloadPath bytes)') {
    fail('conflict identity recipe changed');
  }

  const seed = await canonicalJson(join(vectorRoot, 'seed.json'));
  const first = objectIndex.objects[0];
  const payload = await readFile(join(vectorRoot, ...first.payloadPath.split('/')));
  const seedPreimage = Buffer.concat([objectDomain, u16(1), u16(1), payload]);
  if (seed.schema !== 'ogvcs.repository-format.v1.hand-auditable-seed.v1' ||
      !same(seed.independentlyReproducible, {
        formatVersionUint16beHex: '0001',
        formula: 'SHA-256(objectDomainHex || formatVersionUint16beHex || kindUint16beHex || payloadHex)',
        kindUint16beHex: '0001',
        objectDomainAscii: 'OpenGameVCS object\\0',
        objectDomainHex: objectDomain.toString('hex'),
        objectId: sha256(seedPreimage),
        payloadAsciiEscaped: 'OpenGameVCS\\n',
        payloadHex: payload.toString('hex'),
        preimageHex: seedPreimage.toString('hex')
      }) || first.kind !== 1 || first.objectId !== seed.independentlyReproducible.objectId) {
    fail('hand-auditable seed or preimage invariant differs');
  }
}

function resourceDigest(summary) {
  const fields = ['bytes', 'items', 'traversalEdges', 'indexEntries', 'peakMemoryBytes', 'scratchBytes'];
  for (const field of fields) {
    if (!Number.isSafeInteger(summary[field]) || summary[field] < 0) fail(`invalid resource counter ${field}`);
  }
  return sha256(Buffer.concat([RESOURCE_DOMAIN, u16(1), ...fields.map(field => u64(summary[field]))]));
}

function deriveUnicodeIntervals(source) {
  if (!source.startsWith('# DerivedAge-15.0.0.txt\n')) fail('Unicode age source version header changed');
  const ranges = [];
  for (const line of source.split('\n')) {
    const match = /^([0-9A-F]{4,6})(?:\.\.([0-9A-F]{4,6}))?\s*;\s*([0-9]+)\.([0-9]+)\b/.exec(line);
    if (!match) continue;
    const major = Number(match[3]);
    const minor = Number(match[4]);
    if (!(major < 15 || (major === 15 && minor === 0))) fail('Unicode age source contains a post-15.0 assignment');
    const from = Number.parseInt(match[1], 16);
    const to = Number.parseInt(match[2] ?? match[1], 16);
    if (from > to || to > 0x10ffff) fail('Unicode age source contains an invalid range');
    if (to < 0xd800 || from > 0xdfff) ranges.push([from, to]);
    else {
      if (from < 0xd800) ranges.push([from, 0xd7ff]);
      if (to > 0xdfff) ranges.push([0xe000, to]);
    }
  }
  ranges.sort((left, right) => left[0] - right[0] || left[1] - right[1]);
  const merged = [];
  for (const range of ranges) {
    const previous = merged.at(-1);
    if (previous && range[0] <= previous[1]) fail('Unicode age ranges overlap');
    if (previous && range[0] === previous[1] + 1) previous[1] = range[1];
    else merged.push([...range]);
  }
  return merged;
}

async function verifyUnicodeAuthority(root, vectorRoot, inventory, scenarios) {
  const source = await readFile(join(root, FORMAT, 'unicode', 'DerivedAge-15.0.0.txt'));
  if (source.length !== 130720 || sha256(source) !== UNICODE_SOURCE_SHA256) {
    fail('official Unicode 15.0 DerivedAge authority differs');
  }
  const intervals = deriveUnicodeIntervals(source.toString('utf8'));
  const scalarCount = intervals.reduce((sum, [from, to]) => sum + to - from + 1, 0);
  if (intervals.length !== 715 || scalarCount !== 286785) fail('Unicode 15.0 repertoire cardinality differs');

  const sourceRecord = inventory.get('unicode/DerivedAge-15.0.0.txt');
  const sourceCopy = await verifyArtifact(vectorRoot, inventory, sourceRecord, 'Unicode age source');
  if (!sourceCopy.equals(source)) fail('manifested Unicode age source differs from normative source');
  for (const [relative, digest] of [
    ['unicode/UNICODE-LICENSE.txt', 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96'],
    ['unicode/NOTICE.md', 'e93902743ef67c6fe07c902c05d025bd04cbd696a0efa2c77657b13d338f25fe']
  ]) {
    const record = inventory.get(relative);
    const copied = await verifyArtifact(vectorRoot, inventory, record, relative);
    const normative = await readFile(join(root, FORMAT, ...relative.split('/')));
    if (!copied.equals(normative) || sha256(normative) !== digest) fail(`${relative} provenance differs`);
  }

  const compact = await canonicalJson(join(vectorRoot, 'unicode', 'age-15.0.0-intervals.json'));
  if (compact.schema !== 'ogvcs.repository-format.v1.unicode-age-intervals.v1' ||
      compact.unicodeVersion !== '15.0.0' || compact.intervalCount !== 715 ||
      compact.scalarCount !== 286785 || !same(compact.intervals, intervals) ||
      compact.sourceSha256 !== UNICODE_SOURCE_SHA256 ||
      inventory.get('unicode/age-15.0.0-intervals.json')?.sha256 !==
        'f720e60157290e8714986679b54f8f49ce2c863146873dc5bda491d2d44a38b2') {
    fail('compact Unicode repertoire differs from the independent DerivedAge derivation');
  }
  const index = await canonicalJson(join(vectorRoot, 'unicode', 'index.json'));
  const expectedCases = [
    ['unicode-age-15-assigned', 'unicode/cases/age-15-assigned.cbor', [0x1fae8], 'accept'],
    ['unicode-age-newer-composition-pair', 'malformed/unicode-age-newer-composition-pair.cbor', [0x16d63, 0x16d68], 'reject'],
    ['unicode-age-newer-decomposed', 'malformed/unicode-age-newer-decomposed.cbor', [0x16d63, 0x16d67, 0x16d67], 'reject'],
    ['unicode-age-newer-canonical', 'malformed/unicode-age-newer-canonical.cbor', [0x16d6a], 'reject'],
    ['unicode-age-frozen-unassigned', 'malformed/unicode-age-frozen-unassigned.cbor', [0x0378], 'reject']
  ];
  if (index.schema !== 'ogvcs.repository-format.v1.unicode-authority.v1' ||
      index.unicodeVersion !== '15.0.0' || index.source?.sha256 !== UNICODE_SOURCE_SHA256 ||
      !same(index.evaluationOrder, [
        'shortest-form UTF-8 and Unicode scalar decoding', 'Unicode 15.0 Age repertoire',
        'NFC under the host normalizer'
      ]) || index.cases?.length !== expectedCases.length) {
    fail('Unicode authority index shape or evaluation order differs');
  }
  const malformed = await canonicalJson(join(vectorRoot, 'malformed', 'index.json'));
  for (let indexNumber = 0; indexNumber < expectedCases.length; indexNumber += 1) {
    const [scenarioId, relative, codePoints, result] = expectedCases[indexNumber];
    const body = Buffer.from(String.fromCodePoint(...codePoints), 'utf8');
    const expectedBytes = Buffer.concat([Buffer.from([0x60 + body.length]), body]);
    const record = inventory.get(relative);
    const actual = await verifyArtifact(vectorRoot, inventory, record, `Unicode case ${scenarioId}`);
    const row = scenarios.get(scenarioId);
    const caseRow = index.cases[indexNumber];
    if (!actual.equals(expectedBytes) || caseRow.artifact !== relative ||
        !same(caseRow.codePoints, codePoints.map(value => `U+${value.toString(16).toUpperCase().padStart(4, '0')}`)) ||
        caseRow.expected?.result !== result || !row || row.materialization !== 'byte-materialized-operation-request' ||
        row.expected.result !== result) {
      fail(`Unicode case binding differs for ${scenarioId}`);
    }
    if (result === 'reject') {
      const malformedRow = malformed.explicitCases.find(item => item.artifact === relative);
      if (!malformedRow || malformedRow.expected?.code !== 'CBOR_NON_CANONICAL' ||
          malformedRow.failureOrder !== 'reject a scalar outside the frozen Unicode 15.0 Age repertoire before NFC comparison') {
        fail(`Unicode malformed-case failure order differs for ${scenarioId}`);
      }
    }
  }
}

function artifactBytes(inventory, path) {
  const record = inventory.get(path);
  if (!record) fail(`scenario references an uninventoried artifact ${path}`);
  return record.bytes;
}

async function registryDigest(root) {
  const hash = createHash('sha256');
  hash.update(REGISTRY_DOMAIN);
  hash.update(u16(1));
  const records = [];
  for (const file of REGISTRY_FILES) {
    const pathText = `registries/${file}`;
    const bytes = await readFile(join(root, FORMAT, 'registries', file));
    hash.update(u32(Buffer.byteLength(pathText)));
    hash.update(pathText, 'utf8');
    hash.update(u64(bytes.length));
    hash.update(bytes);
    records.push({ bytes: bytes.length, path: pathText, sha256: sha256(bytes) });
  }
  return { digest: hash.digest('hex'), records };
}

function permitsSite(error, stage, layer) {
  return error?.sites?.some(site => site.stage === stage && site.layers.includes(layer)) === true;
}

async function verifyScenarios(root, vectorRoot, inventory, manifest, registrySet, errors) {
  const index = await canonicalJson(join(vectorRoot, 'scenarios', 'index.json'));
  if (!Array.isArray(index.cases) || index.cases.length !== EXPECTED.scenarios) fail('scenario index count changed');
  const byId = new Map();
  for (const row of index.cases) {
    if (byId.has(row.scenarioId)) fail(`duplicate scenario ${row.scenarioId}`);
    byId.set(row.scenarioId, row);
  }
  const manifestScenarios = recordMap(manifest.scenarios, 'manifest scenarios', 'scenarioId');
  if (manifestScenarios.size !== index.cases.length) fail('manifest scenario count differs from index');
  const configuredResourceSeen = new Set();
  const fixtureAdapterSeen = new Set();
  const manifestWriterSeen = new Set();
  const treeWriterSeen = new Set();
  const bundleWriterSeen = new Set();
  const operationModeSeen = new Set();
  const repositoryRouteSeen = new Set();
  const closureAccumulatorSeen = new Set();
  const shelfScopeControlSeen = new Set();
  const pathProfileDecisionSeen = new Set();
  const pathProfileValidatorSeen = new Set();
  const treeGroupsMemorySeen = new Set();
  const resourceReservationSeen = new Set();
  const typedReferenceAuthoritySeen = new Set();
  const genericCanonicalScanSeen = new Set();
  const sharedRawLogicalRecordSeen = new Set();
  const rejectionStagesSeen = new Set();

  for (const row of index.cases) {
    const listed = manifestScenarios.get(row.artifact);
    if (!listed || listed.scenarioId !== row.scenarioId) fail(`scenario route missing for ${row.scenarioId}`);
    const bytes = await verifyArtifact(vectorRoot, inventory, inventory.get(row.artifact), `scenario ${row.scenarioId}`);
    if (sha256(bytes) !== listed.sha256) fail(`scenario manifest digest differs for ${row.scenarioId}`);
    const scenario = await canonicalJson(join(vectorRoot, ...row.artifact.split('/')));
    if (scenario.schemaVersion !== 'ogvcs.repository-format/validation-scenario/v1' ||
        scenario.scenarioId !== row.scenarioId || scenario.operation !== row.operation ||
        !OPERATIONS.has(scenario.operation) || scenario.failurePrecedence !== 'errors-v1-layer-stage-code-offset-subject') {
      fail(`scenario envelope mismatch for ${row.scenarioId}`);
    }
    const implementationScope = scenario.implementationScope ?? ['javascript', 'rust'];
    if (!Array.isArray(implementationScope) || implementationScope.length === 0 ||
        new Set(implementationScope).size !== implementationScope.length ||
        implementationScope.some(value => !['javascript', 'rust'].includes(value)) ||
        !same(scenario.implementationScope, row.implementationScope)) {
      fail(`scenario implementation scope mismatch for ${row.scenarioId}`);
    }
    if (!Array.isArray(scenario.requirementIds) || !same(scenario.requirementIds, row.requirementIds) ||
        new Set(scenario.requirementIds).size !== scenario.requirementIds.length) {
      fail(`scenario requirement routing mismatch for ${row.scenarioId}`);
    }
    if (['conflict-mode-resolved', 'conflict-mode-unresolved-shelf'].includes(row.scenarioId) &&
        !same(row.obligationTags, ['conflict:tombstoned-kind-mode-rejected'])) {
      fail(`tombstoned conflict-kind coverage is misclassified for ${row.scenarioId}`);
    }
    if (scenario.context?.registrySnapshot?.registrySetSha256 !== registrySet ||
        scenario.context?.asOf !== 'immediately-before-candidate-snapshot' ||
        !['conformance', 'production'].includes(scenario.context?.mode) ||
        !['case-sensitive', 'case-folded'].includes(scenario.context?.caseMode)) {
      fail(`scenario registry or temporal context mismatch for ${row.scenarioId}`);
    }
    for (const input of scenario.inputs ?? []) await verifyArtifact(vectorRoot, inventory, input, `${row.scenarioId} input`);
    for (const entry of scenario.context?.objectLookup ?? []) {
      await verifyArtifact(vectorRoot, inventory, entry.artifact, `${row.scenarioId} lookup`);
    }
    if (row.scenarioId === 'tree-path-core-deep-chain') {
      const deepTrees = scenario.context.objectLookup.filter(entry =>
        /^scenarios\/objects\/tree-path-core-deep-chain\/deep-path-[0-9]{3}\.cbor$/.test(
          entry.artifact.path));
      if (deepTrees.length !== 257 || scenario.expected.code !== 'PATH_CORE_INVALID' ||
          scenario.expected.layer !== 3 || scenario.expected.stage !== 'repository-semantics' ||
          !same(implementationScope, ['javascript', 'rust'])) {
        fail('bounded deep-tree typed-failure coverage differs');
      }
    }
    if (row.scenarioId === 'error-repository-descriptor-mismatch') {
      const foreign = scenario.context.objectLookup.find(entry =>
        entry.artifact.path.endsWith('/foreign-descriptor.cbor'));
      if (!foreign || foreign.ref === scenario.context.repositoryDescriptor ||
          scenario.expected.code !== 'REPOSITORY_DESCRIPTOR_MISMATCH' ||
          scenario.expected.layer !== 3 || scenario.expected.stage !== 'repository-semantics') {
        fail('repository descriptor mismatch carrier differs');
      }
    }
    if (row.scenarioId === 'snapshot-graph-missing-descriptor-before-descriptor-mismatch') {
      const missing = `ogvcs:v1:repository-descriptor:sha256:${'ed'.repeat(32)}`;
      const candidate = scenario.context.objectLookup.find(entry =>
        entry.artifact.path.endsWith('/candidate.cbor'));
      if (!candidate || candidate.artifact.sha256 !==
          'b9ad429789dd7c1a0d0c9e4c22392d8a91cc7089b30b938710347a4243f97f6c' ||
          scenario.context.objectLookup.some(entry => entry.ref === missing) ||
          scenario.expected.code !== 'OBJECT_REFERENCE_MISSING' || scenario.expected.layer !== 2) {
        fail('snapshot descriptor-closure carrier differs');
      }
    }
    if (row.scenarioId === 'replay-restore-missing-source-tree-before-profile-lifecycle') {
      const source = scenario.context.objectLookup.find(entry =>
        entry.artifact.path.endsWith('/source-snapshot.cbor'));
      if (!source || source.artifact.sha256 !==
          'ede1433f14be5c21eaa5f67c061cd5a41961229418e01f5739c74954e2d4312a' ||
          scenario.context.objectLookup.some(entry => entry.ref ===
            `ogvcs:v1:tree:sha256:${'ef'.repeat(32)}`) ||
          scenario.context.mode !== 'production' ||
          scenario.expected.code !== 'OBJECT_REFERENCE_MISSING' || scenario.expected.layer !== 2) {
        fail('restore proof-closure carrier differs');
      }
    }
    if (row.scenarioId === 'replay-restore-missing-proof-descriptor-before-cross-repository') {
      const source = scenario.context.objectLookup.find(entry =>
        entry.artifact.path.endsWith('/source-snapshot.cbor'));
      if (!source || source.artifact.sha256 !==
          '019884704cfda52132c8f5ed3d0e29bf2ecc6ed0887f0ebd20184d3232fa80e1' ||
          scenario.context.objectLookup.some(entry => entry.ref ===
            `ogvcs:v1:repository-descriptor:sha256:${'ee'.repeat(32)}`) ||
          scenario.context.mode !== 'production' ||
          scenario.expected.code !== 'OBJECT_REFERENCE_MISSING' || scenario.expected.layer !== 2) {
        fail('restore proof-descriptor closure carrier differs');
      }
    }

    const definitionPath = scenario.resources?.recipe?.parameters?.definition;
    const definitionHash = scenario.resources?.recipe?.parameters?.definitionSha256;
    if (!safePath(definitionPath) || inventory.get(definitionPath)?.sha256 !== definitionHash) {
      fail(`scenario definition binding mismatch for ${row.scenarioId}`);
    }
    const definition = await canonicalJson(join(vectorRoot, ...definitionPath.split('/')));
    if (definition.expectedRootState?.scenarioId !== row.scenarioId ||
        definition.registrySetSha256 !== registrySet || definition.failurePrecedence !== scenario.failurePrecedence ||
        definition.operation !== scenario.operation ||
        !same(definition.implementationScope, scenario.implementationScope)) fail(`scenario definition mismatch for ${row.scenarioId}`);

    const definitionInput = scenario.inputs.find(input => input.path === definitionPath);
    if (!definitionInput) fail(`scenario omits its definition input for ${row.scenarioId}`);
    const isolatedStableError = ISOLATED_STABLE_ERROR_RECIPES[row.scenarioId];
    if (isolatedStableError) {
      const source = scenario.inputs.find(item => item.path === isolatedStableError.source);
      if (scenario.operation !== 'validate-object' ||
          row.materialization !== 'byte-materialized-stable-error-artifact' ||
          !source || source.sha256 !== isolatedStableError.sourceSha256) {
        fail(`isolated stable-error artifact differs for ${row.scenarioId}`);
      }
    }
    const expectedResourceRecipe = CONFIGURED_RESOURCE_RECIPES[row.scenarioId];
    if (expectedResourceRecipe) {
      if (row.materialization !== 'executable-configured-resource-constructor' ||
          !same(definition.exactConstructorValues?.configuredResource, expectedResourceRecipe) ||
          !scenario.inputs.some(input => input.path === expectedResourceRecipe.source)) {
        fail(`configured resource recipe differs for ${row.scenarioId}`);
      }
      if (row.scenarioId === 'bundle-visitor-nested-map-key-capture-memory') {
        const depth = expectedResourceRecipe.captureWorkspace.depth;
        const initialCaptureBytes = 64;
        const derivedPeak = depth * initialCaptureBytes;
        const largestCompleteKeyBytes = 2 * (depth - 1) + 1;
        const sourceBytes = await readFile(join(vectorRoot, ...expectedResourceRecipe.source.split('/')));
        const nestedValue = Buffer.concat([
          Buffer.alloc(depth, 0xa1),
          Buffer.alloc(depth + 1, 0x00)
        ]);
        const nestedOffset = sourceBytes.indexOf(nestedValue);
        if (depth !== 8 || largestCompleteKeyBytes >= initialCaptureBytes ||
            expectedResourceRecipe.limits.maxCaptureBytes !== derivedPeak - 1 ||
            expectedResourceRecipe.limits.maxValueBytes !== initialCaptureBytes ||
            expectedResourceRecipe.limits.maxNesting !== depth + 2 ||
            nestedOffset < 0 || sourceBytes.indexOf(nestedValue, nestedOffset + 1) !== -1 ||
            scenario.expected.code !== 'LIMIT_MEMORY' || scenario.expected.layer !== 1 ||
            scenario.expected.stage !== 'configured-resource-preflight') {
          fail('nested canonical map-key capture workspace authority differs');
        }
      }
      configuredResourceSeen.add(row.scenarioId);
    } else if (row.materialization === 'executable-configured-resource-constructor') {
      fail(`unexpected configured resource constructor ${row.scenarioId}`);
    }
    const expectedFixtureAdapter = FIXTURE_ADAPTER_RECIPES[row.scenarioId];
    if (expectedFixtureAdapter) {
      if (scenario.operation !== 'adapt-fixture' ||
          row.materialization !== 'executable-fixture-adapter-constructor' ||
          !same(scenario.implementationScope, ['javascript']) ||
          !same(definition.exactConstructorValues?.fixtureAdapter, expectedFixtureAdapter)) {
        fail(`fixture adapter recipe differs for ${row.scenarioId}`);
      }
      fixtureAdapterSeen.add(row.scenarioId);
    } else if (scenario.operation === 'adapt-fixture' ||
        row.materialization === 'executable-fixture-adapter-constructor') {
      fail(`unexpected fixture adapter constructor ${row.scenarioId}`);
    }
    const expectedManifestWriter = MANIFEST_WRITER_RECIPES[row.scenarioId];
    if (expectedManifestWriter) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      const providerSources = expectedManifestWriter.chunkArtifacts ??
        [expectedManifestWriter.chunkArtifact];
      if (scenario.operation !== 'write-content-manifest' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.manifestWriter, expectedManifestWriter) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedManifestWriter) ||
          providerSources.some(source => !scenario.inputs.some(item => item.path === source)) ||
          (row.scenarioId === 'manifest-writer-object-id-before-profile-lifecycle' &&
            scenario.inputs.find(item => item.path === expectedManifestWriter.chunkArtifact)?.sha256 !==
              '9033b2344e924d278334018b2b9d51a3357f827016320f41a0ca294973474d9e') ||
          (expectedManifestWriter.registryFixture &&
            !scenario.inputs.some(item => item.path === expectedManifestWriter.registryFixture.path))) {
        fail(`manifest writer recipe differs for ${row.scenarioId}`);
      }
      if (row.scenarioId.startsWith('manifest-writer-content-object-id-before-chunk-length-')) {
        const short = scenario.inputs.find(item => item.path === 'writer-inputs/manifest-provider-short.bin');
        const wrong = scenario.inputs.find(item => item.path === 'writer-inputs/manifest-provider-wrong.bin');
        if (short?.bytes !== 11 || short.sha256 !==
              '2378216a7b104434475e25832d40c5f239611ecc3d9d26551bd97cd4d9174ca7' ||
            wrong?.bytes !== 12 || wrong.sha256 !==
              '8fbce5bea2a9bd00ab7f2d5e5ea3ae9c28c89a2ad59a8783148cf333c93e7c26' ||
            scenario.expected.code !== 'OBJECT_ID_MISMATCH' || scenario.expected.layer !== 1 ||
            scenario.expected.stage !== 'declared-identity') {
          fail(`manifest content-pass precedence carrier differs for ${row.scenarioId}`);
        }
      }
      manifestWriterSeen.add(row.scenarioId);
    } else if (scenario.operation === 'write-content-manifest' || definition.exactConstructorValues?.manifestWriter) {
      fail(`unexpected manifest writer constructor ${row.scenarioId}`);
    }
    const expectedTreeWriter = TREE_WRITER_RECIPES[row.scenarioId];
    if (expectedTreeWriter) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'write-tree' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.treeWriter, expectedTreeWriter) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedTreeWriter) ||
          (expectedTreeWriter.registryFixture &&
            !scenario.inputs.some(item => item.path === expectedTreeWriter.registryFixture.path))) {
        fail(`tree writer recipe differs for ${row.scenarioId}`);
      }
      treeWriterSeen.add(row.scenarioId);
    } else if (scenario.operation === 'write-tree' || definition.exactConstructorValues?.treeWriter) {
      fail(`unexpected tree writer constructor ${row.scenarioId}`);
    }
    const expectedBundleWriter = BUNDLE_WRITER_RECIPES[row.scenarioId];
    if (expectedBundleWriter) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      const expectedImplementationScope = row.scenarioId === 'bundle-writer-object-id-before-unknown-kind'
        ? ['javascript'] : undefined;
      if (scenario.operation !== 'write-logical-bundle' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(row.implementationScope, expectedImplementationScope) ||
          !same(scenario.implementationScope, expectedImplementationScope) ||
          !same(definition.implementationScope, expectedImplementationScope) ||
          !same(definition.exactConstructorValues?.bundleWriter, expectedBundleWriter) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedBundleWriter) ||
          !scenario.inputs.some(item => item.path === expectedBundleWriter.source) ||
          expectedBundleWriter.objectMutations.some(mutation => mutation.sourceArtifact &&
            !scenario.inputs.some(item => item.path === mutation.sourceArtifact)) ||
          (expectedBundleWriter.logicalRecordInputs ?? []).some(record =>
            !scenario.inputs.some(item => item.path === record.sourceArtifact)) ||
          (row.scenarioId === 'bundle-writer-object-id-before-feature-lifecycle' &&
            scenario.inputs.find(item => item.path === 'lifecycle/tree-feature-conformance.cbor')?.sha256 !==
              '740615ea266c868838c932b5c41c2ae5726290598a7b2202859a9f966fc804af') ||
          (expectedBundleWriter.registryFixture &&
            !scenario.inputs.some(item => item.path === expectedBundleWriter.registryFixture.path)) ||
          !same(expectedBundleWriter.outputDisposition, {
            inMemoryResult: 'absent',
            orderedStagingSink: 'aborted-discard',
            successCommit: false
          }) ||
          !same(expectedBundleWriter.writerSurfaces, ['bundle-memory-encoder', 'bundle-ordered'])) {
        fail(`logical-bundle writer recipe differs for ${row.scenarioId}`);
      }
      bundleWriterSeen.add(row.scenarioId);
    } else if (scenario.operation === 'write-logical-bundle' || definition.exactConstructorValues?.bundleWriter) {
      fail(`unexpected logical-bundle writer constructor ${row.scenarioId}`);
    }
    const expectedOperationMode = OPERATION_MODE_RECIPES[row.scenarioId];
    if (expectedOperationMode) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'validate-operation-mode' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.operationMode, expectedOperationMode) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedOperationMode) ||
          (expectedOperationMode.source && !scenario.inputs.some(item => item.path === expectedOperationMode.source)) ||
          (OPERATION_MODE_SOURCE_SHA256[row.scenarioId] !== undefined &&
            scenario.inputs.find(item => item.path === expectedOperationMode.source)?.sha256 !==
              OPERATION_MODE_SOURCE_SHA256[row.scenarioId]) ||
          (expectedOperationMode.registryFixture &&
            !scenario.inputs.some(item => item.path === expectedOperationMode.registryFixture.path))) {
        fail(`operation mode recipe differs for ${row.scenarioId}`);
      }
      if (expectedOperationMode.surface === 'logical-record-map-raw') {
        if (!same(implementationScope, ['javascript', 'rust']) ||
            row.implementationScope !== undefined || scenario.implementationScope !== undefined ||
            definition.implementationScope !== undefined) {
          fail(`raw logical-record byte carrier is not shared for ${row.scenarioId}`);
        }
        sharedRawLogicalRecordSeen.add(row.scenarioId);
      }
      if (expectedOperationMode.objectLookup === 'scenario.context.objectLookup') {
        const lookupRefs = new Set(scenario.context.objectLookup.map(entry => entry.ref));
        if (scenario.context.objectLookup.length === 0 ||
            ['repositoryDescriptor', 'candidateSnapshot', 'designatedRoot', 'tree', 'manifest']
              .some(field => expectedOperationMode[field] !== undefined && !lookupRefs.has(expectedOperationMode[field])) ||
            (expectedOperationMode.repositoryDescriptor !== undefined &&
              scenario.context.repositoryDescriptor !== expectedOperationMode.repositoryDescriptor) ||
            (expectedOperationMode.candidateSnapshot !== undefined &&
              scenario.context.candidateSnapshot !== expectedOperationMode.candidateSnapshot) ||
            (expectedOperationMode.designatedRoot !== undefined &&
              scenario.context.designatedRoot !== expectedOperationMode.designatedRoot) ||
            (expectedOperationMode.importContext !== undefined &&
              (!same(scenario.context.importMappings, expectedOperationMode.importContext.importMappings) ||
               !same(scenario.context.lifetimeRecords, expectedOperationMode.importContext.lifetimeRecords) ||
               !same(scenario.context.workingLifetimeAdditions, expectedOperationMode.importContext.workingLifetimeAdditions))) ||
            (expectedOperationMode.lifetimeContext !== undefined &&
              (!same(scenario.context.importMappings, expectedOperationMode.lifetimeContext.importMappings) ||
               !same(scenario.context.lifetimeRecords, expectedOperationMode.lifetimeContext.lifetimeRecords) ||
               !same(scenario.context.workingLifetimeAdditions, expectedOperationMode.lifetimeContext.workingLifetimeAdditions)))) {
          fail(`operation mode real public-route carrier differs for ${row.scenarioId}`);
        }
      }
      operationModeSeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-operation-mode' || definition.exactConstructorValues?.operationMode) {
      fail(`unexpected operation mode constructor ${row.scenarioId}`);
    }
    const expectedRepositoryRouteApi = REPOSITORY_ROUTE_APIS[row.scenarioId];
    if (expectedRepositoryRouteApi) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      const request = operationInput
        ? await canonicalJson(join(vectorRoot, ...operationInput.path.split('/')))
        : undefined;
      if (scenario.operation !== 'validate-repository-route' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !operationInput || request?.schema !== 'ogvcs.repository-format.v1.repository-route-input.v1' ||
          request?.authorityContext !== 'scenario.context' || request?.api !== expectedRepositoryRouteApi ||
          !same(definition.exactConstructorValues?.repositoryRoute, request)) {
        fail(`repository-route recipe differs for ${row.scenarioId}`);
      }
      const lookupRefs = new Set(scenario.context.objectLookup.map(entry => entry.ref));
      const closureAccumulator = CLOSURE_ACCUMULATOR_ROUTES[row.scenarioId];
      const mutationRefs = new Set((request.lookupMutations ?? []).map(item => item.reference));
      if ((request.lookupMutations ?? []).some(mutation =>
        mutation.action !== 'replace-payload-preserve-reference' ||
        !lookupRefs.has(mutation.reference) ||
        !scenario.inputs.some(input => input.path === mutation.sourceArtifact))) {
        fail(`repository-route lookup mutation authority differs for ${row.scenarioId}`);
      }
      const closureMissingFill = closureAccumulator?.order === 'forward' ? 'fc' : 'fd';
      const closureCorruptFill = closureAccumulator?.order === 'forward' ? 'fd' : 'fc';
      const closureMissingRef = closureAccumulator
        ? `ogvcs:v1:${closureAccumulator.kind}:sha256:${closureMissingFill.repeat(32)}`
        : undefined;
      const requiredLookupRefs = [
        request.manifest, request.tree, request.changeSet, request.conflictSet, request.candidateSnapshot,
        request.designatedRoot, request.shelfRevision, request.baseState?.tree,
        ...(request.roots ?? [])
      ].filter(Boolean);
      if (requiredLookupRefs.some(reference => !lookupRefs.has(reference) &&
            !mutationRefs.has(reference) && reference !== closureMissingRef) ||
          (request.repositoryDescriptor !== undefined &&
            request.repositoryDescriptor !== scenario.context.repositoryDescriptor) ||
          (request.candidateSnapshot !== undefined &&
            request.candidateSnapshot !== scenario.context.candidateSnapshot) ||
          (request.designatedRoot !== undefined &&
            request.designatedRoot !== scenario.context.designatedRoot) ||
          (request.caseMode !== undefined && request.caseMode !== scenario.context.caseMode)) {
        fail(`repository-route authority context differs for ${row.scenarioId}`);
      }
      if (closureAccumulator) {
        const corruptRef = `ogvcs:v1:${closureAccumulator.kind}:sha256:${closureCorruptFill.repeat(32)}`;
        const expectedMutation = [{
          action: 'replace-payload-preserve-reference',
          reference: corruptRef,
          sourceArtifact: closureAccumulator.sourceArtifact
        }];
        const sourceInput = scenario.inputs.find(item => item.path === closureAccumulator.sourceArtifact);
        if (scenario.expected.code !== 'OBJECT_ID_MISMATCH' || scenario.expected.layer !== 1 ||
            scenario.expected.stage !== 'declared-identity' ||
            !same(request.lookupMutations, expectedMutation) || !sourceInput ||
            !lookupRefs.has(corruptRef) || lookupRefs.has(closureMissingRef)) {
          fail(`closure accumulator mutation differs for ${row.scenarioId}`);
        }
        const expectedFaultOrder = closureAccumulator.order === 'forward'
          ? [closureMissingRef, corruptRef] : [corruptRef, closureMissingRef];
        if (closureAccumulator.route === 'provenance') {
          if (!same(request.roots, expectedFaultOrder)) {
            fail(`closure accumulator root order differs for ${row.scenarioId}`);
          }
        } else {
          const primaryPath = `scenarios/objects/${row.scenarioId}/${closureAccumulator.primaryName}`;
          const primary = scenario.context.objectLookup.find(entry => entry.artifact.path === primaryPath);
          if (!primary) fail(`closure accumulator primary differs for ${row.scenarioId}`);
          const payload = await readFile(join(vectorRoot, ...primaryPath.split('/')));
          const firstFaultOffset = payload.indexOf(Buffer.from(
            (closureAccumulator.order === 'forward' ? closureMissingFill : closureCorruptFill).repeat(32), 'hex'));
          const secondFaultOffset = payload.indexOf(Buffer.from(
            (closureAccumulator.order === 'forward' ? closureCorruptFill : closureMissingFill).repeat(32), 'hex'));
          if (firstFaultOffset < 0 || secondFaultOffset <= firstFaultOffset) {
            fail(`closure accumulator edge order differs for ${row.scenarioId}`);
          }
        }
        closureAccumulatorSeen.add(row.scenarioId);
      }
      if (expectedRepositoryRouteApi === 'validate-repository-candidate' ||
          expectedRepositoryRouteApi === 'validate-shelf-revision') {
        const falseSelector = row.scenarioId.endsWith('verify-content-false');
        if (request.forceContentComplete !== true || request.callerVerifyContent !== !falseSelector ||
            (falseSelector && (scenario.expected.code !== 'SCHEMA_FIELD_INVALID' ||
              scenario.expected.layer !== 1 || scenario.expected.stage !== 'configured-resource-preflight'))) {
          fail(`high-level content-completeness recipe differs for ${row.scenarioId}`);
        }
      }
      const shelfScopeControl = SHELF_SCOPE_CONTROL_SOURCES[row.scenarioId];
      if (shelfScopeControl) {
        const unrelated = scenario.context.objectLookup.filter(entry =>
          entry.artifact.path === shelfScopeControl.path);
        if (scenario.expected.result !== 'accept' || scenario.expected.highestLayer !== 3 ||
            request.api !== 'validate-shelf-revision' || request.callerVerifyContent !== true ||
            request.forceContentComplete !== true || unrelated.length !== 1 ||
            unrelated[0].artifact.sha256 !== shelfScopeControl.sha256 ||
            unrelated[0].ref === request.shelfRevision) {
          fail(`shelf exact-scope negative control differs for ${row.scenarioId}`);
        }
        shelfScopeControlSeen.add(row.scenarioId);
      }
      if (expectedRepositoryRouteApi === 'expand-tree' &&
          (request.verifyContent !== true || request.caseMode !== scenario.context.caseMode)) {
        fail(`tree expansion scope differs for ${row.scenarioId}`);
      }
      if (row.scenarioId.startsWith('fileid-prior-import-mapping-')) {
        const mappings = scenario.context.importMappings;
        const lifetimes = scenario.context.lifetimeRecords;
        const mapping = mappings?.[0];
        const expectedKeys = [
          'descriptor', 'fileId', 'importerProfile', 'mappingKey',
          'sourceIdentityDigest', 'sourceNamespaceDigest', 'state'
        ];
        if (mappings?.length !== 1 || lifetimes?.length !== 1 ||
            !same(Object.keys(mapping ?? {}).sort(), expectedKeys) ||
            !/^ogvcs:v1:repository-descriptor:sha256:[0-9a-f]{64}$/.test(mapping.descriptor) ||
            !/^[0-9a-f]{64}$/.test(mapping.mappingKey) ||
            lifetimes[0].origin !== 'import' || lifetimes[0].importMappingKey !== mapping.mappingKey ||
            lifetimes[0].fileId !== mapping.fileId) {
          fail(`prior import-mapping binding differs for ${row.scenarioId}`);
        }
        const foreign = row.scenarioId.endsWith('-foreign-repository');
        const wrongFamily = row.scenarioId.endsWith('-wrong-family');
        if ((mapping.descriptor !== scenario.context.repositoryDescriptor) !== foreign ||
            mapping.importerProfile !== (wrongFamily
              ? 'content-policy.test/opaque@1' : 'importer.test/fixture-adapter@1') ||
            scenario.context.mode !== (row.scenarioId.endsWith('-production-conformance-only')
              ? 'production' : 'conformance')) {
          fail(`prior import-mapping semantic carrier differs for ${row.scenarioId}`);
        }
        if (expectedRepositoryRouteApi === 'validate-import-request' &&
            (!same(request.importRequest, {
              importerProfile: mapping.importerProfile,
              requestedFileId: mapping.fileId,
              sourceIdentityDigest: mapping.sourceIdentityDigest,
              sourceNamespaceDigest: mapping.sourceNamespaceDigest
            }))) {
          fail(`prior import-request carrier differs for ${row.scenarioId}`);
        }
      }
      if (row.scenarioId.startsWith('fileid-lifetime-first-change-') &&
          (scenario.context.lifetimeRecords.length !== 1 || scenario.context.importMappings.length !== 0)) {
        fail(`firstChangeSet evidence carrier differs for ${row.scenarioId}`);
      }
      repositoryRouteSeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-repository-route' ||
        definition.exactConstructorValues?.repositoryRoute) {
      fail(`unexpected repository-route constructor ${row.scenarioId}`);
    }
    const closureCarrier = CLOSURE_LIFECYCLE_CARRIERS[row.scenarioId];
    if (closureCarrier) {
      const primary = scenario.inputs.find(item => item.path === closureCarrier.primaryPath) ??
        scenario.context.objectLookup.find(item =>
          item.artifact.path === closureCarrier.primaryPath)?.artifact;
      if (scenario.operation !== closureCarrier.operation ||
          scenario.context.mode !== (closureCarrier.mode ?? 'production') ||
          scenario.expected?.code !== 'OBJECT_REFERENCE_MISSING' || scenario.expected?.layer !== 2 ||
          scenario.expected?.stage !== 'closure-and-reference-resolution' ||
          !primary || primary.sha256 !== closureCarrier.primarySha256 ||
          scenario.context.objectLookup.some(entry => entry.ref === closureCarrier.absentRef)) {
        fail(`closure-before-lifecycle carrier differs for ${row.scenarioId}`);
      }
    }
    const expectedPathDecision = PATH_PROFILE_DECISION_RECIPES[row.scenarioId];
    if (expectedPathDecision) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'validate-path-profile-decision' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.pathProfileDecision, expectedPathDecision) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedPathDecision) ||
          scenario.context.pathProfileValidator !== undefined) {
        fail(`path-profile decision recipe differs for ${row.scenarioId}`);
      }
      pathProfileDecisionSeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-path-profile-decision' || definition.exactConstructorValues?.pathProfileDecision) {
      fail(`unexpected path-profile decision constructor ${row.scenarioId}`);
    }
    const expectedTreeGroupsMemory = TREE_GROUPS_MEMORY_RECIPES[row.scenarioId];
    if (expectedTreeGroupsMemory) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'validate-tree-groups-memory' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.treeGroupsMemory, expectedTreeGroupsMemory) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedTreeGroupsMemory) ||
          !scenario.context.candidateSnapshot || !scenario.context.repositoryDescriptor ||
          expectedTreeGroupsMemory.assertNoPartialState !== true ||
          !same(expectedTreeGroupsMemory.evidenceRequired, {
            eachComponentAloneFit: true,
            noPartialState: true,
            routeEvidence: routeEvidence(expectedTreeGroupsMemory.routes)
          }) || !same(scenario.expected.evidence, expectedTreeGroupsMemory.evidenceRequired)) {
        fail(`tree/groups memory recipe differs for ${row.scenarioId}`);
      }
      treeGroupsMemorySeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-tree-groups-memory' || definition.exactConstructorValues?.treeGroupsMemory) {
      fail(`unexpected tree/groups memory constructor ${row.scenarioId}`);
    }
    const expectedResourceReservation = RESOURCE_RESERVATION_RECIPES[row.scenarioId];
    if (expectedResourceReservation) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'validate-resource-reservation' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.resourceReservation, expectedResourceReservation) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedResourceReservation) ||
          expectedResourceReservation.assertNoPartialState !== true ||
          !Array.isArray(expectedResourceReservation.routes) || expectedResourceReservation.routes.length === 0 ||
          new Set(expectedResourceReservation.routes).size !== expectedResourceReservation.routes.length ||
          expectedResourceReservation.routes.some(route => RECOVERY_KIND_BY_ROUTE[route] === undefined) ||
          !same(expectedResourceReservation.evidenceRequired, expectedEvidenceForRecipe(expectedResourceReservation)) ||
          !same(scenario.expected.evidence, expectedResourceReservation.evidenceRequired) ||
          (expectedResourceReservation.conflictFixture &&
            (scenario.context.objectLookup.length !== 18 ||
             scenario.context.repositoryDescriptor !== 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545' ||
             !scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.conflictFixture.reference))) ||
          (expectedResourceReservation.cluster === 'lookup-edge-counter-rollback' && (() => {
            const recoveryEntry = scenario.context.objectLookup.find(entry =>
              entry.ref === expectedResourceReservation.recovery.reference);
            return !scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.failureTree) ||
              !recoveryEntry || !same(recoveryEntry.artifact, {
                bytes: 136,
                mediaType: 'application/cbor',
                path: 'scenarios/objects/resource-lookup-edge-counter-rollback/recovery-manifest.cbor',
                sha256: '9be1796b7beba06504f827399501441b9e608bcfbed560a394167e758f42516d'
              });
          })()) ||
          (expectedResourceReservation.cluster === 'lookup-scratch-counter-rollback' &&
            (!scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.failureTree) ||
             !scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.recovery.recoveryTree))) ||
          (expectedResourceReservation.cluster === 'replay-base' &&
            (!scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.changeSet) ||
             !scenario.context.objectLookup.some(entry => entry.ref === expectedResourceReservation.baseState.tree)))) {
        fail(`resource reservation recipe differs for ${row.scenarioId}`);
      }
      resourceReservationSeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-resource-reservation' || definition.exactConstructorValues?.resourceReservation) {
      fail(`unexpected resource reservation constructor ${row.scenarioId}`);
    }
    const expectedTypedReferenceAuthority = TYPED_REFERENCE_AUTHORITY_RECIPES[row.scenarioId];
    if (expectedTypedReferenceAuthority) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      const expectedImplementationScope = row.scenarioId === 'typed-reference-arbitrary-kind-map-relabel'
        ? ['javascript'] : undefined;
      if (scenario.operation !== 'validate-typed-reference-authority' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(row.implementationScope, expectedImplementationScope) ||
          !same(scenario.implementationScope, expectedImplementationScope) ||
          !same(definition.implementationScope, expectedImplementationScope) ||
          !same(definition.exactConstructorValues?.typedReferenceAuthority, expectedTypedReferenceAuthority) ||
          !operationInput || !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedTypedReferenceAuthority)) {
        fail(`typed-reference authority recipe differs for ${row.scenarioId}`);
      }
      typedReferenceAuthoritySeen.add(row.scenarioId);
    } else if (scenario.operation === 'validate-typed-reference-authority' || definition.exactConstructorValues?.typedReferenceAuthority) {
      fail(`unexpected typed-reference authority constructor ${row.scenarioId}`);
    }
    const expectedGenericCanonicalScan = GENERIC_CANONICAL_SCAN_RECIPES[row.scenarioId];
    if (expectedGenericCanonicalScan) {
      const operationInput = scenario.inputs.find(item => item.path === `scenarios/operations/${row.scenarioId}.json`);
      if (scenario.operation !== 'canonical-scan' ||
          row.materialization !== 'byte-materialized-operation-request' ||
          !same(definition.exactConstructorValues?.genericCanonicalScan, expectedGenericCanonicalScan) ||
          !operationInput ||
          !same(await canonicalJson(join(vectorRoot, ...operationInput.path.split('/'))), expectedGenericCanonicalScan) ||
          !scenario.inputs.some(item => item.path === expectedGenericCanonicalScan.source)) {
        fail(`generic canonical-scan recipe differs for ${row.scenarioId}`);
      }
      genericCanonicalScanSeen.add(row.scenarioId);
    } else if (definition.exactConstructorValues?.genericCanonicalScan) {
      fail(`unexpected generic canonical-scan constructor ${row.scenarioId}`);
    }
    if (Object.hasOwn(PATH_PROFILE_VALIDATOR_RECIPES, row.scenarioId)) {
      const expectedPathValidator = PATH_PROFILE_VALIDATOR_RECIPES[row.scenarioId];
      const pathRoutePrecedence =
        row.scenarioId === 'tree-ratified-path-profile-missing-manifest-before-wrong-validator';
      if (!same(scenario.context.pathProfileValidator ?? null, expectedPathValidator) ||
          !same(definition.normativeContext?.pathProfileValidator ?? null, expectedPathValidator) ||
          scenario.context.caseMode !== (expectedPathValidator?.caseMode ?? 'case-sensitive') ||
          scenario.context.mode !== 'conformance' ||
          row.materialization !== (pathRoutePrecedence
            ? 'byte-materialized-operation-request' : 'byte-materialized-object-graph')) {
        fail(`ratified path-profile validator recipe differs for ${row.scenarioId}`);
      }
      pathProfileValidatorSeen.add(row.scenarioId);
    } else if (scenario.context.pathProfileValidator !== undefined) {
      fail(`unexpected path-profile validator recipe ${row.scenarioId}`);
    }
    const logical = definition.suppliedResourceCatalogue?.logicalRecordArtifacts ?? [];
    const summary = scenario.resources.summary;
    const suppliedPaths = new Set([
      ...scenario.inputs.map(item => item.path),
      ...(scenario.context.objectLookup ?? []).map(item => item.artifact.path),
      ...logical
    ]);
    const expectedBytes = [...suppliedPaths].reduce((sum, path) => sum + artifactBytes(inventory, path), 0);
    if (summary.bytes !== expectedBytes || summary.items !== (scenario.context.objectLookup?.length ?? 0) + logical.length ||
        summary.traversalEdges !== 0 || summary.indexEntries !== 0 || summary.peakMemoryBytes !== 0 ||
        summary.scratchBytes !== 0 || summary.summarySha256 !== resourceDigest(summary)) {
      fail(`scenario resource summary mismatch for ${row.scenarioId}`);
    }

    if (row.expected.result === 'reject') {
      if (scenario.expected.result !== 'reject' || scenario.expected.code !== row.code ||
          scenario.expected.layer !== row.expected.layer || scenario.expected.stage !== row.expected.stage ||
          !permitsSite(errors.get(row.code), scenario.expected.stage, scenario.expected.layer)) {
        fail(`scenario rejection mismatch for ${row.scenarioId}`);
      }
      rejectionStagesSeen.add(scenario.expected.stage);
    } else {
      if (scenario.expected.result !== 'accept' || scenario.expected.highestLayer !== row.expected.highestLayer ||
          scenario.expected.output.summarySha256 !== summary.summarySha256) fail(`scenario acceptance mismatch for ${row.scenarioId}`);
      await verifyArtifact(vectorRoot, inventory, scenario.expected.output.artifact, `${row.scenarioId} output`);
      const output = await canonicalJson(join(vectorRoot, ...scenario.expected.output.artifact.path.split('/')));
      const { schema, ...rootState } = output;
      if (schema !== 'ogvcs.repository-format.v1.scenario-output.v1' ||
          !same(rootState, definition.expectedRootState)) {
        fail(`scenario output differs from its definition for ${row.scenarioId}`);
      }
    }
    const expectedLayer = scenario.expected.result === 'reject'
      ? scenario.expected.layer : scenario.expected.highestLayer;
    if (definition.validation?.requestedLayer !== expectedLayer) {
      fail(`scenario definition layer differs for ${row.scenarioId}`);
    }
  }

  if (!same([...shelfScopeControlSeen].sort(), Object.keys(SHELF_SCOPE_CONTROL_SOURCES).sort())) {
    fail('shelf exact-scope negative-control coverage differs');
  }
  if (!same([...configuredResourceSeen].sort(), Object.keys(CONFIGURED_RESOURCE_RECIPES).sort())) {
    fail('configured resource scenario set changed');
  }
  if (!same([...fixtureAdapterSeen].sort(), Object.keys(FIXTURE_ADAPTER_RECIPES).sort())) {
    fail('fixture adapter scenario set changed');
  }
  if (!same([...manifestWriterSeen].sort(), Object.keys(MANIFEST_WRITER_RECIPES).sort())) {
    fail('manifest writer scenario set changed');
  }
  if (!same([...treeWriterSeen].sort(), Object.keys(TREE_WRITER_RECIPES).sort())) {
    fail('tree writer scenario set changed');
  }
  if (!same([...bundleWriterSeen].sort(), Object.keys(BUNDLE_WRITER_RECIPES).sort())) {
    fail('logical-bundle writer scenario set changed');
  }
  if (!same([...operationModeSeen].sort(), Object.keys(OPERATION_MODE_RECIPES).sort())) {
    fail('operation mode scenario set changed');
  }
  const expectedSharedRawLogicalRecords = Object.entries(OPERATION_MODE_RECIPES)
    .filter(([, recipe]) => recipe.surface === 'logical-record-map-raw')
    .map(([scenarioId]) => scenarioId)
    .sort();
  if (expectedSharedRawLogicalRecords.length !== 8 ||
      !same([...sharedRawLogicalRecordSeen].sort(), expectedSharedRawLogicalRecords)) {
    fail('shared raw logical-record applicability coverage differs');
  }
  if (!same([...repositoryRouteSeen].sort(), Object.keys(REPOSITORY_ROUTE_APIS).sort())) {
    fail('repository-route scenario set changed');
  }
  if (!same([...closureAccumulatorSeen].sort(), Object.keys(CLOSURE_ACCUMULATOR_ROUTES).sort())) {
    fail('closure accumulator scenario set changed');
  }
  if (!same([...pathProfileDecisionSeen].sort(), Object.keys(PATH_PROFILE_DECISION_RECIPES).sort())) {
    fail('path-profile decision scenario set changed');
  }
  if (!same([...pathProfileValidatorSeen].sort(), Object.keys(PATH_PROFILE_VALIDATOR_RECIPES).sort())) {
    fail('path-profile validator scenario set changed');
  }
  if (!same([...treeGroupsMemorySeen].sort(), Object.keys(TREE_GROUPS_MEMORY_RECIPES).sort())) {
    fail('tree/groups memory scenario set changed');
  }
  if (!same([...resourceReservationSeen].sort(), Object.keys(RESOURCE_RESERVATION_RECIPES).sort())) {
    fail('resource reservation scenario set changed');
  }
  if (!same([...typedReferenceAuthoritySeen].sort(), Object.keys(TYPED_REFERENCE_AUTHORITY_RECIPES).sort())) {
    fail('typed-reference authority scenario set changed');
  }
  if (!same([...genericCanonicalScanSeen].sort(), Object.keys(GENERIC_CANONICAL_SCAN_RECIPES).sort())) {
    fail('generic canonical-scan scenario set changed');
  }
  if (!same([...rejectionStagesSeen].sort(), [...VALIDATION_STAGES].sort())) {
    fail('rejecting scenarios do not execute every frozen validation stage');
  }
  return { index, byId };
}

async function verifyCoverage(vectorRoot, scenarioIndex, errors) {
  const coverage = await canonicalJson(join(vectorRoot, 'coverage-matrix.json'));
  const rows = scenarioIndex.cases;
  if (REQUIRED_OBLIGATIONS.length !== EXPECTED.obligations) fail('independent obligation contract count differs');
  const expectedObligations = REQUIRED_OBLIGATIONS.map(obligation => ({
    obligation,
    scenarios: rows.filter(row => row.obligationTags.includes(obligation)).map(row => row.scenarioId)
  }));
  const expectedRequirements = REQUIREMENT_IDS.map(requirementId => ({
    requirementId,
    scenarios: rows.filter(row => row.requirementIds.includes(requirementId)).map(row => row.scenarioId)
  }));
  const expectedErrors = [...errors].map(code => ({
    code,
    scenarios: rows.filter(row => row.code === code).map(row => row.scenarioId)
  }));
  const materialization = Object.fromEntries([...new Set(rows.map(row => row.materialization))].sort().map(kind => [
    kind, rows.filter(row => row.materialization === kind).length
  ]));
  if (!same(coverage.obligations, expectedObligations) ||
      !same(coverage.requirementIds, expectedRequirements) || !same(coverage.stableErrors, expectedErrors) ||
      !same(coverage.totals, {
        materialization,
        obligations: EXPECTED.obligations,
        scenarios: EXPECTED.scenarios,
        stableErrors: EXPECTED.stableErrors
      })) fail('coverage matrix is not derivable from the scenario index and error catalogue');
  for (const row of coverage.stableErrors) if (row.scenarios.length === 0) fail(`stable error lacks a scenario: ${row.code}`);
}

async function verifyLimits(root, vectorRoot, scenarios) {
  const registry = await boundedJson(join(root, FORMAT, 'registries', 'limits.json'));
  const summary = await canonicalJson(join(vectorRoot, 'limits.json'));
  const constructors = await canonicalJson(join(vectorRoot, 'limits', 'virtual-constructors.json'));
  if (registry.entries.length !== 25 || summary.cases.length !== 25 || constructors.cases.length !== 50) {
    fail('hard-limit corpus cardinality changed');
  }
  const byName = new Map(summary.cases.map(row => [row.name, row]));
  const variants = new Map();
  for (const item of constructors.cases) {
    const key = `${item.case}/${item.variant}`;
    if (variants.has(key) || item.algorithm?.id !== 'ogvcs.virtual-boundary-constructor' ||
        item.algorithm.version !== 1 || typeof item.emitter !== 'string' || item.emitter.length === 0 ||
        item.summary?.digestHex !== sha256(stableJson(item.summary.input))) fail(`invalid virtual limit constructor ${key}`);
    variants.set(key, item);
  }
  for (const limit of registry.entries) {
    const row = byName.get(limit.name);
    if (!row || row.unit !== limit.unit || row.maximum.value !== limit.value ||
        row.maximumPlusOne.value !== limit.value + 1 || row.maximumPlusOne.expected.code !== limit.errorCode) {
      fail(`limit summary differs from registry for ${limit.name}`);
    }
    for (const [variant, value, expected] of [
      ['maximum', limit.value, row.maximum.expected],
      ['maximum-plus-one', limit.value + 1, row.maximumPlusOne.expected]
    ]) {
      const item = variants.get(`${limit.name}/${variant}`);
      if (!item || item.valueDecimal !== String(value) || !same(item.expected, expected) ||
          item.summary.input.valueDecimal !== String(value) || item.summary.input.variant !== variant) {
        fail(`limit constructor differs for ${limit.name}/${variant}`);
      }
      const suffix = variant === 'maximum' ? 'max' : 'max-plus-one';
      const scenarioId = `limit-${limit.name}-${suffix}`;
      const scenario = scenarios.get(scenarioId);
      const expectedMatches = scenario && scenario.expected.result === item.expected.result &&
        (item.expected.result === 'accept'
          ? scenario.expected.highestLayer === item.expected.highestLayer
          : scenario.expected.code === item.expected.code && scenario.expected.layer === item.expected.layer &&
            scenario.expected.stage === item.expected.stage);
      if (!expectedMatches ||
          scenario.materialization !== 'executable-virtual-limit-constructor') {
        fail(`limit scenario differs from executable constructor for ${limit.name}/${variant}`);
      }
      const definition = await canonicalJson(join(
        vectorRoot, 'scenarios', 'definitions', `${scenarioId}.json`
      ));
      if (!same(definition.exactConstructorValues?.virtualLimit, {
        case: limit.name,
        recipe: 'limits/virtual-constructors.json',
        variant
      })) {
        fail(`limit scenario omits executable constructor binding for ${limit.name}/${variant}`);
      }
    }
  }
}

async function verifyMutationRecipes(vectorRoot, inventory) {
  const mutation = await canonicalJson(join(vectorRoot, 'mutations', 'single-bit.json'));
  let cases = 0;
  for (const source of mutation.sources) {
    if (artifactBytes(inventory, source.source) !== source.byteLength) fail(`mutation source length differs for ${source.source}`);
    cases += source.byteLength * 8;
  }
  for (const item of mutation.bundleItemShapes) {
    if (item.byteOffset + item.byteLength > artifactBytes(inventory, item.source)) fail('bundle item mutation range exceeds source');
    cases += item.byteLength * 8;
  }
  if (mutation.wholeSequence.byteLength !== artifactBytes(inventory, mutation.wholeSequence.source)) {
    fail('whole bundle mutation length differs');
  }
  cases += mutation.wholeSequence.byteLength * 8;
  if (cases !== mutation.totalCases || cases !== 58_520) fail('single-bit mutation cardinality differs');

  const truncation = await canonicalJson(join(vectorRoot, 'mutations', 'truncation.json'));
  let prefixes = 0;
  for (const source of truncation.sources) {
    const byteOffset = source.byteOffset ?? 0;
    if (!Number.isSafeInteger(byteOffset) || byteOffset < 0 ||
        byteOffset + source.byteLength > artifactBytes(inventory, source.source) ||
        source.prefixes.fromInclusive !== 0 || source.prefixes.toInclusive !== source.byteLength - 1) {
      fail(`truncation source range differs for ${source.source}`);
    }
    prefixes += source.byteLength;
  }
  const whole = truncation.wholeSequence;
  if (whole.byteLength !== artifactBytes(inventory, whole.source)) fail('whole bundle truncation length differs');
  let cursor = 0;
  for (const range of whole.ranges) {
    if (range.fromInclusive !== cursor || range.toInclusive < range.fromInclusive) fail('bundle truncation ranges are not contiguous');
    prefixes += range.toInclusive - range.fromInclusive + 1;
    cursor = range.toInclusive + 1;
  }
  if (cursor !== whole.byteLength || prefixes !== 7_303) fail('truncation prefix cardinality differs');
  const malformed = await canonicalJson(join(vectorRoot, 'malformed', 'index.json'));
  for (const [scenarioId, path, totalCases] of [
    ['malformed-complete-corpus', 'malformed/index.json', malformed.explicitCases.length],
    ['mutation-systematic-single-bit', 'mutations/single-bit.json', cases],
    ['truncation-every-prefix', 'mutations/truncation.json', prefixes]
  ]) {
    const scenario = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', `${scenarioId}.json`));
    const definition = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', `${scenarioId}.json`));
    if (!scenario.inputs.some(input => input.path === path) ||
        !same(definition.exactConstructorValues?.enumeratedRecipe, { path, totalCases }) ||
        scenario.expected.result !== 'accept' || scenario.expected.highestLayer !== 1) {
      fail(`enumerated scenario is not bound to its executable recipe: ${scenarioId}`);
    }
  }
  return { mutationCases: cases, truncationPrefixes: prefixes };
}

async function verifyRegistryRecipes(vectorRoot, scenarios) {
  const index = await canonicalJson(join(vectorRoot, 'registries', 'index.json'));
  const oldSnapshot = await canonicalJson(join(vectorRoot, 'registries', 'old-snapshot.json'));
  const contentConformance = oldSnapshot.profiles?.entries?.filter(entry =>
    entry.namespace === 'profile-state.test' && entry.id === 'content-conformance' && entry.major === 1);
  if (!same(contentConformance, [{
    family: 'content-policy', id: 'content-conformance', major: 1,
    namespace: 'profile-state.test', productionWriteAllowed: false, state: 'conformance-only'
  }])) {
    fail('entry-level content-policy lifecycle authority differs');
  }
  const recipes = index.cases.filter(item => REGISTRY_RECIPE_SCENARIOS.includes(item.scenarioId));
  const ids = recipes.map(item => item.scenarioId).sort((left, right) => left.localeCompare(right, 'en'));
  if (!same(ids, [...REGISTRY_RECIPE_SCENARIOS].sort((left, right) => left.localeCompare(right, 'en'))) ||
      new Set(ids).size !== ids.length) fail('registry scenario recipe set differs');
  for (const recipe of recipes) {
    const row = scenarios.get(recipe.scenarioId);
    const outcomeMatches = row && row.expected.result === recipe.expected.result &&
      (recipe.expected.result === 'accept'
        ? row.expected.highestLayer === recipe.expected.highestLayer
        : row.expected.code === recipe.expected.code && row.expected.layer === recipe.expected.layer &&
          row.expected.stage === recipe.expected.stage);
    if (!row || row.materialization !== 'executable-enumerated-registry-recipe' ||
        !outcomeMatches) fail(`registry scenario outcome differs from recipe: ${recipe.scenarioId}`);
    const scenario = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', `${recipe.scenarioId}.json`));
    const definition = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', `${recipe.scenarioId}.json`));
    if (!scenario.inputs.some(input => input.path === 'registries/index.json') ||
        !same(definition.exactConstructorValues?.registryCase, {
          path: 'registries/index.json', scenarioId: recipe.scenarioId
        })) fail(`registry scenario omits executable recipe binding: ${recipe.scenarioId}`);
    if (recipe.operation === 'validate-registry-set') {
      if (recipe.sourceRegistryDirectory !== '../registries' ||
          !['append-copy', 'append-entry', 'replace-entry-field'].includes(recipe.mutation?.action) ||
          !REGISTRY_FILES.includes(recipe.mutation?.file)) {
        fail(`invalid registry-set mutation recipe: ${recipe.scenarioId}`);
      }
    } else if (recipe.snapshot !== 'old' || typeof recipe.profile !== 'string' ||
        !['conformance', 'production-write', 'read', 'read-or-production-write'].includes(recipe.operation)) {
      fail(`invalid registry lifecycle recipe: ${recipe.scenarioId}`);
    }
  }
}

async function verifyScaleDefinitions(vectorRoot) {
  const manifestCase = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', 'manifest-one-tib.json'));
  const manifest = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', 'manifest-one-tib.json'));
  const treeCase = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', 'tree-million-entries.json'));
  const tree = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', 'tree-million-entries.json'));
  if (!same(manifestCase.requirementIds, ['OGVCS-002-AC-09', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02']) ||
      !same(treeCase.requirementIds, ['OGVCS-002-AC-02', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02'])) {
    fail('scale cases do not route their acceptance requirements');
  }
  const manifestPlan = manifest.exactConstructorValues.scalePlan;
  const seed = Buffer.from(manifestPlan.recurrence.seed, 'hex');
  const block = createHash('sha256').update(seed).update(Buffer.from([0x43]))
    .update("repeated-chunk-v1", 'ascii').digest();
  const chunk = Buffer.alloc(1_048_576);
  for (let offset = 0; offset < chunk.length; offset += block.length) block.copy(chunk, offset);
  const objectDigest = createHash('sha256').update('OpenGameVCS object\0', 'ascii')
    .update(u16(1)).update(u16(1)).update(chunk).digest('hex');
  const fixed = manifestPlan.fixedFields;
  if (seed.length !== 32 || block.toString('hex') !== fixed.repeatedBlockSha256 ||
      sha256(chunk) !== fixed.rawChunkSha256 ||
      fixed.chunkObjectRef !== `ogvcs:v1:chunk:sha256:${objectDigest}` ||
      fixed.chunkBytes !== '1048576' || fixed.chunkCount !== '1048576' ||
      fixed.logicalBytes !== '1099511627776') fail('1 TiB manifest recurrence is not self-consistent');
  const treePlan = tree.exactConstructorValues.scalePlan;
  if (treePlan.streamCardinality !== '1000000' || treePlan.recurrence.seed !== tree.seedHex ||
      manifestPlan.recurrence.seed !== manifest.seedHex || tree.seedHex !== treeCase.resources.recipe.seed ||
      manifest.seedHex !== manifestCase.resources.recipe.seed) {
    fail('scale recurrence cardinality or seed differs');
  }
}

async function verifyExpectations(vectorRoot, inventory) {
  const expectations = await canonicalJson(join(vectorRoot, 'expectations.json'));
  const paths = expectations.artifacts.map(record => record.path);
  const expected = [...inventory.keys()].filter(path => path !== 'expectations.json');
  if (!same(paths, expected) || new Set(paths).size !== paths.length) fail('artifact expectations do not route the inventory exactly once');
}

function parseArguments(argv) {
  if (argv.length === 0) return DEFAULT_ROOT;
  if (argv.length === 2 && argv[0] === '--root') return resolve(argv[1]);
  fail('usage: node tools/verify-reference-vectors.mjs [--root REPOSITORY]');
}

async function main() {
  const root = parseArguments(process.argv.slice(2));
  const vectorRoot = join(root, VECTOR_RELATIVE);
  const manifest = await canonicalJson(join(vectorRoot, 'manifest.json'));
  if (manifest.manifestVersion !== 'ogvcs.repository-format/vector-manifest/v1' ||
      manifest.generator?.implementation !== 'node tools/reference-vector-generator/generate.mjs' ||
      manifest.generator.version !== '2.0.0') fail('vector manifest identity differs');
  const generatorBytes = await readFile(join(root, 'tools', 'reference-vector-generator', 'generate.mjs'));
  if (sha256(generatorBytes) !== manifest.generator.sourceSha256) fail('vector generator provenance digest differs');

  const inventory = recordMap(manifest.artifacts, 'artifact inventory');
  if (inventory.size !== EXPECTED.artifacts) fail('artifact inventory count changed');
  const actualFiles = (await filesBelow(vectorRoot))
    .filter(path => path !== 'manifest.json')
    .sort((left, right) => left.localeCompare(right, 'en'));
  if (!same(actualFiles, [...inventory.keys()])) fail('artifact inventory does not match the vector tree');
  for (const record of inventory.values()) await verifyArtifact(vectorRoot, inventory, record, `inventory ${record.path}`);

  const errorsDocument = await boundedJson(join(root, FORMAT, 'errors.json'));
  const errorCodes = errorsDocument.errors.map(item => item.code);
  if (errorCodes.length !== EXPECTED.stableErrors || new Set(errorCodes).size !== errorCodes.length) {
    fail('stable error catalogue count or uniqueness changed');
  }
  const errors = new Map();
  for (const error of errorsDocument.errors) {
    if (!Array.isArray(error.sites) || error.sites.length === 0) fail(`stable error lacks validation sites: ${error.code}`);
    const pairs = new Set();
    for (const site of error.sites) {
      if (!VALIDATION_STAGES.includes(site.stage) || !Array.isArray(site.layers) || site.layers.length === 0 ||
          site.layers.some(layer => !Number.isInteger(layer) || layer < 1 || layer > 3)) {
        fail(`stable error has invalid validation site: ${error.code}`);
      }
      for (const layer of site.layers) {
        const pair = `${site.stage}\0${layer}`;
        if (pairs.has(pair)) fail(`stable error repeats validation site: ${error.code}`);
        pairs.add(pair);
      }
    }
    errors.set(error.code, error);
  }
  const registry = await registryDigest(root);
  const snapshot = await canonicalJson(join(vectorRoot, 'registries', 'live-snapshot.json'));
  if (snapshot.registrySetSha256 !== registry.digest || !same(snapshot.registries, registry.records)) {
    fail('live registry snapshot does not match normative registry bytes');
  }
  await verifySeedAndPreimages(vectorRoot, inventory);
  const scenarios = await verifyScenarios(root, vectorRoot, inventory, manifest, registry.digest, errors);
  await verifyUnicodeAuthority(root, vectorRoot, inventory, scenarios.byId);
  await verifyCoverage(vectorRoot, scenarios.index, new Set(errorCodes));
  await verifyLimits(root, vectorRoot, scenarios.byId);
  const recipes = await verifyMutationRecipes(vectorRoot, inventory);
  await verifyRegistryRecipes(vectorRoot, scenarios.byId);
  await verifyScaleDefinitions(vectorRoot);
  await verifyExpectations(vectorRoot, inventory);
  process.stdout.write(`${JSON.stringify({
    artifacts: inventory.size,
    obligations: EXPECTED.obligations,
    registrySetSha256: registry.digest,
    scenarios: scenarios.byId.size,
    schema: 'ogvcs.repository-format.vector-audit/v1',
    stableErrors: errorCodes.length,
    validationStages: VALIDATION_STAGES.length,
    ...recipes
  })}\n`);
}

await main();
