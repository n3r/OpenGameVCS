export const LIMITS = Object.freeze({
  collisionKeyBytesMaximum: 32_768,
  collisionKeyBytesTotalMaximum: 67_108_864,
  compiledRuleBytesMaximum: 16_777_216,
  fullLogicalBytesMaximum: 9_007_199_254_740_991,
  inputRecordBytesMaximum: 4_185,
  logicalBytesMaximum: 1_099_511_627_776,
  metadataBytesMaximum: 67_108_864,
  metadataRecordsMaximum: 100_000,
  outputBytesMaximum: 75_497_472,
  outputRecordBytesMaximum: 4_154,
  ruleBytesMaximum: 4_114,
  rulesMaximum: 4_096,
  sinkFragmentBytesMaximum: 4_154,
});

export const CONTRACT = Object.freeze({
  schemaVersion: 'ogvcs.selective-sync/kernel-contract/v1',
  contractVersion: '0.1.0-rc.1',
  state: 'private-untrusted-selection-candidate',
  owner: 'OGVCS-013',
  predecessorPins: {
    path: {
      authority: 'ogvcs.path-filesystem@1',
      contractVersion: '1.0.0',
      manifestPath: 'spec/path-filesystem/v1/manifest.json',
      manifestSha256: '2f343e1dac238da527fbd36160419ec6fb53b780ac7e33c01e11acabbdd4782b',
      registrySetSha256: 'bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42',
      unicodeVersion: '16.0.0',
      unicodeCaseFoldingSha256: '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb',
    },
  },
  selection: {
    schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1',
    version: 1,
    materializationCodes: {
      full: 1,
      'metadata-only': 2,
      'absent-by-spec': 3,
    },
    matchCodes: { exact: 1, subtree: 2 },
    platformCodes: { linux: 1, macos: 2, windows: 3 },
    platformCompatibility: {
      'path.opengamevcs/linux@1': ['linux'],
      'path.opengamevcs/macos@1': ['macos'],
      'path.opengamevcs/portable@1': ['linux', 'macos', 'windows'],
      'path.opengamevcs/windows@1': ['windows'],
    },
    semantics: [
      'rules-are-evaluated-in-strict-ordinal-order',
      'the-greatest-matching-ordinal-wins',
      'subtree-matches-the-named-path-and-component-descendants',
      'exact-matches-only-the-named-path',
      'exact-and-subtree-have-no-priority-beyond-ordinal',
      'the-default-class-applies-when-no-rule-matches',
      'duplicate-rule-scope-and-repository-key-is-invalid',
      'distinct-spellings-that-collide-in-repository-or-platform-keys-are-invalid',
    ],
  },
  bindings: [
    'snapshot-digest',
    'settings-digest',
    'consistency-token-digest',
    'path-profile',
    'case-mode',
    'platform',
    'selection-spec-digest',
    'metadata-projection-digest',
    'metadata-record-count',
  ],
  errorRegistry: 'registries/errors.json',
  encodings: {
    digest: 'raw-32-byte-sha256',
    integer: 'unsigned-64-bit-big-endian',
    string: 'u64-byte-length-followed-by-utf8',
    optionalContent: 'one-byte-tag-0-or-1; tag-1-is-digest-then-u64-logical-bytes',
    domains: {
      selectionSpec: 'OpenGameVCS selective sync spec v1\\0',
      metadataProjection: 'OpenGameVCS selective sync metadata projection v1\\0',
      evaluationBindings: 'OpenGameVCS selective sync evaluation bindings v1\\0',
      outputProjection: 'OpenGameVCS selective sync output projection v1\\0',
    },
    selectionSpecPreimage: [
      'domain', 'schema-version-string', 'version-u64', 'default-materialization-u8',
      'rule-count-u64', 'for-each-rule:ordinal-u64,match-u8,path-string,materialization-u8',
    ],
    metadataProjectionPreimage: [
      'domain', 'declared-record-count-u64',
      'for-each-record:ordinal-u64,path-string,entry-digest,optional-content',
    ],
    evaluationBindingsPreimage: [
      'domain', 'snapshot-digest', 'settings-digest', 'consistency-token-digest',
      'path-profile-string', 'case-mode-u8', 'platform-u8', 'selection-spec-digest',
      'metadata-projection-digest', 'metadata-record-count-u64',
    ],
    outputStream: [
      'ascii-OGVCS-SELECT-V1\\0', 'metadata-record-count-u64', 'evaluation-bindings-digest',
      'for-each-record:ordinal-u64,path-string,materialization-u8,optional-content',
    ],
    outputProjectionPreimage: ['domain', 'exact-output-stream-bytes'],
  },
  limits: LIMITS,
  output: {
    ordering: 'strictly-increasing-repository-collision-key',
    ordinals: 'contiguous-zero-through-count-minus-one',
    metadataOnlyAndAbsentContentTag: 0,
    fullContentTag: 'caller-content-tag-preserved',
    entryDigest: 'input-only-opaque-metadata-record-commitment-never-emitted',
    headerTrust: 'caller-declared-bindings-discard-only-until-eof-count-order-collision-byte-digest-write-and-flush-checks-complete',
    result: 'plain-untrusted-summary-with-digests-counts-and-byte-ledgers-only',
    errorDisposition: 'discard-all-sink-bytes-no-summary',
    cancellationCheckpoints: ['before-header', 'before-source-poll', 'after-source-poll', 'before-flush'],
    sinkSemantics: 'synchronous-fragment-emission-has-no-application-value;-javascript-callback-write-and-flush-return-undefined;-rust-write-all-and-flush-complete-with-ok-unit;-each-javascript-call-receives-a-private-fragment-copy',
  },
  publicClaims: {
    authentication: false,
    authorizationFiltering: false,
    cache: false,
    filesystemMutation: false,
    materialization: false,
    networkRegistered: false,
    productionEntryBrand: false,
    publicCli: false,
    requestRootIntegration: false,
    syncPlanning: false,
  },
  networkRoutes: [],
});

export const ERROR_REGISTRY = Object.freeze({
  schemaVersion: 'ogvcs.selective-sync/error-registry/v1',
  entries: [
    'SELECT_ADAPTER_INVALID', 'SELECT_BINDING_INVALID', 'SELECT_CANCELLED',
    'SELECT_COLLISION_KEY_LIMIT', 'SELECT_COLLISION_KEY_TOTAL_LIMIT',
    'SELECT_COMPILED_RULE_LIMIT', 'SELECT_CONTRACT_INVALID', 'SELECT_INPUT_INVALID',
    'SELECT_INPUT_RECORD_LIMIT', 'SELECT_LEDGER_LIMIT', 'SELECT_LOGICAL_BYTES_LIMIT',
    'SELECT_METADATA_BYTES_LIMIT', 'SELECT_METADATA_COUNT_LIMIT',
    'SELECT_METADATA_COUNT_MISMATCH', 'SELECT_METADATA_DIGEST_MISMATCH',
    'SELECT_METADATA_ORDINAL_INVALID', 'SELECT_METADATA_ORDER_INVALID',
    'SELECT_OUTPUT_BYTES_LIMIT', 'SELECT_OUTPUT_RECORD_LIMIT', 'SELECT_PATH_COLLISION',
    'SELECT_PATH_INVALID', 'SELECT_PLATFORM_PROFILE_MISMATCH', 'SELECT_PROJECTION_INVALID',
    'SELECT_RULE_DUPLICATE', 'SELECT_RULE_LIMIT', 'SELECT_SINK_FAILED',
    'SELECT_SINK_FRAGMENT_LIMIT', 'SELECT_SINK_INVALID', 'SELECT_SOURCE_FAILED',
    'SELECT_SOURCE_INVALID', 'SELECT_SPEC_DIGEST_MISMATCH', 'SELECT_SPEC_INVALID',
  ].map((name, index) => ({ code: index + 1, name })),
});

const digest = (byte) => byte.repeat(64);
const content = (byte, logicalBytes) => ({ digest: digest(byte), logicalBytes });

export const GOLDEN_INPUTS = Object.freeze([
  {
    caseId: 'artist-subtree-sidecar-and-exclusion',
    spec: {
      schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1', version: 1,
      defaultMaterialization: 'absent-by-spec',
      rules: [
        { ordinal: 0, match: 'subtree', path: 'Game/Characters/Hero', materialization: 'full' },
        { ordinal: 1, match: 'subtree', path: 'Game/Characters/Hero/Derived', materialization: 'metadata-only' },
        { ordinal: 2, match: 'exact', path: 'Game/Characters/Hero/Derived/Preview.bin', materialization: 'absent-by-spec' },
      ],
    },
    bindings: { snapshotDigest: digest('1'), settingsDigest: digest('2'), consistencyTokenDigest: digest('3'), pathProfile: 'path.opengamevcs/portable@1', caseMode: 'case-sensitive', platform: 'macos' },
    metadata: [
      { ordinal: 0, path: 'Docs/Readme.txt', entryDigest: digest('a'), content: content('4', 20) },
      { ordinal: 1, path: 'Game/Characters/Hero', entryDigest: digest('b'), content: null },
      { ordinal: 2, path: 'Game/Characters/Hero/Derived/Preview.bin', entryDigest: digest('c'), content: content('5', 300) },
      { ordinal: 3, path: 'Game/Characters/Hero/Hero.uasset', entryDigest: digest('d'), content: content('6', 1_000) },
    ],
  },
  {
    caseId: 'developer-exact-after-subtree-tie-by-ordinal',
    spec: {
      schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1', version: 1,
      defaultMaterialization: 'metadata-only',
      rules: [
        { ordinal: 0, match: 'exact', path: 'Source', materialization: 'absent-by-spec' },
        { ordinal: 1, match: 'subtree', path: 'Source', materialization: 'full' },
        { ordinal: 2, match: 'exact', path: 'Source/Secrets.txt', materialization: 'absent-by-spec' },
      ],
    },
    bindings: { snapshotDigest: digest('7'), settingsDigest: digest('8'), consistencyTokenDigest: digest('9'), pathProfile: 'path.opengamevcs/linux@1', caseMode: 'case-sensitive', platform: 'linux' },
    metadata: [
      { ordinal: 0, path: 'Source', entryDigest: digest('2'), content: null },
      { ordinal: 1, path: 'Source/Main.cpp', entryDigest: digest('3'), content: content('b', 900) },
      { ordinal: 2, path: 'Source/Secrets.txt', entryDigest: digest('4'), content: content('c', 40) },
      { ordinal: 3, path: 'README.md', entryDigest: digest('1'), content: content('a', 90) },
    ],
  },
  {
    caseId: 'ci-unicode-folded-last-match',
    spec: {
      schemaVersion: 'ogvcs.selective-sync/workspace-selection-spec/v1', version: 1,
      defaultMaterialization: 'absent-by-spec',
      rules: [
        { ordinal: 0, match: 'subtree', path: 'Build/Straße', materialization: 'full' },
        { ordinal: 1, match: 'subtree', path: 'Build/STRASSE/Debug', materialization: 'absent-by-spec' },
        { ordinal: 2, match: 'exact', path: 'Build/strasse/config.json', materialization: 'metadata-only' },
      ],
    },
    bindings: { snapshotDigest: digest('d'), settingsDigest: digest('e'), consistencyTokenDigest: digest('f'), pathProfile: 'path.opengamevcs/linux@1', caseMode: 'case-folded', platform: 'linux' },
    metadata: [
      { ordinal: 0, path: 'Build/STRASSE', entryDigest: digest('5'), content: null },
      { ordinal: 1, path: 'Build/STRASSE/Debug/log.txt', entryDigest: digest('8'), content: content('3', 10) },
      { ordinal: 2, path: 'Build/STRASSE/App.bin', entryDigest: digest('6'), content: content('1', 5_000) },
      { ordinal: 3, path: 'Build/STRASSE/config.json', entryDigest: digest('7'), content: content('2', 50) },
    ],
  },
]);

export const SPEC_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://opengamevcs.dev/spec/selective-sync/v1/schemas/workspace-selection-spec.schema.json',
  title: 'Private selective-sync kernel workspace selection spec rc.1',
  type: 'object',
  additionalProperties: false,
  required: ['schemaVersion', 'version', 'defaultMaterialization', 'rules'],
  properties: {
    schemaVersion: { const: 'ogvcs.selective-sync/workspace-selection-spec/v1' },
    version: { const: 1 },
    defaultMaterialization: { enum: ['full', 'metadata-only', 'absent-by-spec'] },
    rules: {
      type: 'array', maxItems: LIMITS.rulesMaximum,
      items: {
        type: 'object', additionalProperties: false,
        required: ['ordinal', 'match', 'path', 'materialization'],
        properties: {
          ordinal: { type: 'integer', minimum: 0, maximum: LIMITS.rulesMaximum - 1 },
          match: { enum: ['exact', 'subtree'] },
          path: { type: 'string', minLength: 1, maxLength: 4_096 },
          materialization: { enum: ['full', 'metadata-only', 'absent-by-spec'] },
        },
      },
    },
  },
});
