export const TOOL_NAME = 'ogvcs-fixture';
export const GENERATOR_VERSION = '1.0.0';
export const REQUEST_SCHEMA = 'ogvcs.fixture/request/v1';
export const PROFILE_SCHEMA = 'ogvcs.fixture/workload-profile/v1';
export const SCENARIO_SCHEMA = 'ogvcs.fixture/operation-scenario/v2';
export const MANIFEST_SCHEMA = 'ogvcs.fixture/manifest/v1';
export const CHECKPOINT_SCHEMA = 'ogvcs.fixture/checkpoint/v1';
export const VERIFICATION_SCHEMA = 'ogvcs.fixture/verification-result/v1';
export const INVENTORY_RECORD_SCHEMA = 'ogvcs.fixture/inventory-record/v2';
export const GROUP_RELATIONSHIPS_SCHEMA = 'ogvcs.fixture/group-relationships/v2';
export const LARGE_FILE_DESCRIPTOR_SCHEMA = 'ogvcs.fixture/large-file-descriptor/v2';
export const CLI_RESULT_SCHEMA = 'ogvcs.fixture/cli-result/v1';
export const PRNG_ALGORITHM = 'ogvcs-counter-sha256-v1';
export const CANONICAL_ALGORITHM = 'ogvcs-canonical-json-v1';
export const PATH_ALGORITHM = 'ogvcs-logical-path-v1';
export const CONTENT_ALGORITHM = 'ogvcs.fixture/content-aes-256-ctr/v2';
export const TREE_ALGORITHM = 'ogvcs-fixture-tree-digest-v1';

export const SCHEMA_VERSIONS = Object.freeze({
  checkpoint: CHECKPOINT_SCHEMA,
  groupRelationships: GROUP_RELATIONSHIPS_SCHEMA,
  inventoryRecord: INVENTORY_RECORD_SCHEMA,
  largeFileDescriptor: LARGE_FILE_DESCRIPTOR_SCHEMA,
  manifest: MANIFEST_SCHEMA,
  profile: PROFILE_SCHEMA,
  request: REQUEST_SCHEMA,
  scenario: SCENARIO_SCHEMA,
  verification: VERIFICATION_SCHEMA,
});

export const MAX_SAFE_COUNT = 10_000_000;
export const MAX_CONTROL_DOCUMENT_BYTES = 2 * 1024 * 1024;
export const MAX_GROUP_RELATIONSHIP_BYTES = 128 * 1024 * 1024;
export const MAX_REQUEST_DOCUMENT_BYTES = 2 * 1024 * 1024;
export const MIN_DEPTH = 2;
export const MAX_DEPTH = 64;
export const MAX_LOGICAL_BYTES = 1n << 40n;
export const DEFAULT_CHECKPOINT_EVERY = 10_000;
export const DEFAULT_IO_CHUNK_BYTES = 1024 * 1024;
