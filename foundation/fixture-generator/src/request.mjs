import { canonicalDigest } from './canonical.mjs';
import {
  DEFAULT_CHECKPOINT_EVERY,
  GENERATOR_VERSION,
  MAX_DEPTH,
  MAX_LOGICAL_BYTES,
  MAX_SAFE_COUNT,
  MIN_DEPTH,
  REQUEST_SCHEMA,
  SCHEMA_VERSIONS,
  TOOL_NAME,
} from './constants.mjs';
import { invalidRequest } from './errors.mjs';
import { getProfile } from './profiles.mjs';
import {
  containsUnpairedSurrogate,
  portableRelativePathIssue,
  validateSchemaDocument,
} from './schema-validator.mjs';

const PROFILE_VERSION = '2.0.0';
const REQUEST_KEYS = new Set([
  'destination',
  'expectedSchemaVersions',
  'extensions',
  'featureFlags',
  'generator',
  'profile',
  'resourceLimits',
  'scale',
  'schemaVersion',
  'seed',
]);
const PROFILE_KEYS = new Set(['id', 'version']);
const SCALE_KEYS = new Set(['historyOperationCount', 'largeFileBytes', 'maxDepth', 'pathCount']);
const RESOURCE_KEYS = new Set(['maximumDurationSeconds', 'maximumMemoryBytes', 'maximumPhysicalBytes']);
const EXTENSION_KEYS = new Set([
  'generation.checkpoint-every',
  'generation.compression-class',
  'generation.duplication-permille',
  'generation.edit-locality-permille',
  'generation.large-file-mode',
  'generation.materialization',
  'generation.materialized-path-limit',
  'generation.mutable-versions',
]);

const OPERATIONAL_DEFAULTS = Object.freeze({
  'generation.checkpoint-every': DEFAULT_CHECKPOINT_EVERY,
  'generation.compression-class': 'mixed',
  'generation.duplication-permille': 100,
  'generation.edit-locality-permille': 800,
  'generation.large-file-mode': 'full',
  'generation.materialization': 'full',
  'generation.materialized-path-limit': 512,
  'generation.mutable-versions': 3,
});

function assertObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalidRequest(`${label} must be an object`);
  }
  return value;
}

function assertAllowedKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw invalidRequest(`${label} contains unknown field ${JSON.stringify(key)}`, {
        field: `${label}.${key}`,
      });
    }
  }
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalidRequest(`${label} must be an integer from ${minimum} through ${maximum}`, {
      field: label,
      value,
    });
  }
  return value;
}

function enumValue(value, label, allowed) {
  if (!allowed.includes(value)) {
    throw invalidRequest(`${label} must be one of: ${allowed.join(', ')}`, {
      field: label,
      value,
    });
  }
  return value;
}

function booleanValue(value, label) {
  if (typeof value !== 'boolean') throw invalidRequest(`${label} must be boolean`, { field: label });
  return value;
}

function portableDestination(value) {
  const portableIssue = portableRelativePathIssue(value);
  if (portableIssue !== null) {
    throw invalidRequest(`destination ${portableIssue}`, { reason: portableIssue, value });
  }
  return value;
}

function normalizedSeed(value) {
  if (typeof value !== 'string' || [...value].length < 1 || [...value].length > 1024) {
    throw invalidRequest('seed must be a string containing 1 through 1024 characters');
  }
  if (
    containsUnpairedSurrogate(value)
    || value !== value.normalize('NFC')
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw invalidRequest('seed must be NFC text without control characters');
  }
  return value;
}

function normalizeFeatureFlags(value, profile) {
  const input = value ?? {};
  assertObject(input, 'featureFlags');
  const allowed = new Set(profile.features);
  assertAllowedKeys(input, allowed, 'featureFlags');
  return Object.fromEntries(
    [...allowed]
      .sort()
      .map((name) => [name, booleanValue(input[name] ?? true, `featureFlags.${name}`)]),
  );
}

function normalizeExtensions(value = {}) {
  assertObject(value, 'extensions');
  assertAllowedKeys(value, EXTENSION_KEYS, 'extensions');
  const merged = { ...OPERATIONAL_DEFAULTS, ...value };
  return {
    'generation.checkpoint-every': integer(
      merged['generation.checkpoint-every'],
      'extensions.generation.checkpoint-every',
      1,
      1_000_000,
    ),
    'generation.compression-class': enumValue(
      merged['generation.compression-class'],
      'extensions.generation.compression-class',
      ['compressible', 'mixed', 'incompressible'],
    ),
    'generation.duplication-permille': integer(
      merged['generation.duplication-permille'],
      'extensions.generation.duplication-permille',
      0,
      1000,
    ),
    'generation.edit-locality-permille': integer(
      merged['generation.edit-locality-permille'],
      'extensions.generation.edit-locality-permille',
      0,
      1000,
    ),
    'generation.large-file-mode': enumValue(
      merged['generation.large-file-mode'],
      'extensions.generation.large-file-mode',
      ['full', 'sparse', 'stream-verified', 'virtual'],
    ),
    'generation.materialization': enumValue(
      merged['generation.materialization'],
      'extensions.generation.materialization',
      ['full', 'sampled', 'index-only'],
    ),
    'generation.materialized-path-limit': integer(
      merged['generation.materialized-path-limit'],
      'extensions.generation.materialized-path-limit',
      0,
      100_000,
    ),
    'generation.mutable-versions': integer(
      merged['generation.mutable-versions'],
      'extensions.generation.mutable-versions',
      1,
      64,
    ),
  };
}

export function createRequest(input = {}) {
  assertObject(input, 'request');
  assertAllowedKeys(input, REQUEST_KEYS, 'request');

  const profileInput = input.profile ?? { id: 'code-heavy', version: PROFILE_VERSION };
  assertObject(profileInput, 'profile');
  assertAllowedKeys(profileInput, PROFILE_KEYS, 'profile');
  if (typeof profileInput.id !== 'string' || profileInput.id.length === 0) {
    throw invalidRequest('profile.id must be a non-empty string');
  }
  let profile;
  try {
    profile = getProfile(profileInput.id, profileInput.version ?? PROFILE_VERSION);
  } catch (error) {
    throw invalidRequest(error.message);
  }

  const scaleInput = input.scale ?? {};
  assertObject(scaleInput, 'scale');
  assertAllowedKeys(scaleInput, SCALE_KEYS, 'scale');
  const scale = {
    historyOperationCount: integer(
      scaleInput.historyOperationCount ?? profile.defaults.historyOperationCount,
      'scale.historyOperationCount',
      0,
      MAX_SAFE_COUNT,
    ),
    largeFileBytes: integer(
      scaleInput.largeFileBytes ?? profile.defaults.largeFileBytes,
      'scale.largeFileBytes',
      0,
      Number(MAX_LOGICAL_BYTES),
    ),
    maxDepth: integer(
      scaleInput.maxDepth ?? profile.defaults.maxDepth,
      'scale.maxDepth',
      MIN_DEPTH,
      MAX_DEPTH,
    ),
    pathCount: integer(
      scaleInput.pathCount ?? profile.defaults.pathCount,
      'scale.pathCount',
      1,
      MAX_SAFE_COUNT,
    ),
  };

  if (input.schemaVersion !== undefined && input.schemaVersion !== REQUEST_SCHEMA) {
    throw invalidRequest(`schemaVersion must be ${REQUEST_SCHEMA}`);
  }
  if (input.generator !== undefined) {
    assertObject(input.generator, 'generator');
    assertAllowedKeys(input.generator, new Set(['name', 'version']), 'generator');
    if (input.generator.name !== TOOL_NAME || input.generator.version !== GENERATOR_VERSION) {
      throw invalidRequest(`generator must be ${TOOL_NAME}@${GENERATOR_VERSION}`);
    }
  }

  const expected = input.expectedSchemaVersions ?? SCHEMA_VERSIONS;
  assertObject(expected, 'expectedSchemaVersions');
  assertAllowedKeys(expected, new Set(Object.keys(SCHEMA_VERSIONS)), 'expectedSchemaVersions');
  for (const [name, version] of Object.entries(SCHEMA_VERSIONS)) {
    if (expected[name] !== version) {
      throw invalidRequest(`expectedSchemaVersions.${name} must be ${version}`);
    }
  }

  let resourceLimits;
  if (input.resourceLimits !== undefined) {
    assertObject(input.resourceLimits, 'resourceLimits');
    assertAllowedKeys(input.resourceLimits, RESOURCE_KEYS, 'resourceLimits');
    resourceLimits = {};
    if (input.resourceLimits.maximumDurationSeconds !== undefined) {
      resourceLimits.maximumDurationSeconds = integer(
        input.resourceLimits.maximumDurationSeconds,
        'resourceLimits.maximumDurationSeconds',
        1,
        604_800,
      );
    }
    if (input.resourceLimits.maximumMemoryBytes !== undefined) {
      resourceLimits.maximumMemoryBytes = integer(
        input.resourceLimits.maximumMemoryBytes,
        'resourceLimits.maximumMemoryBytes',
        1_048_576,
        1_099_511_627_776,
      );
    }
    if (input.resourceLimits.maximumPhysicalBytes !== undefined) {
      resourceLimits.maximumPhysicalBytes = integer(
        input.resourceLimits.maximumPhysicalBytes,
        'resourceLimits.maximumPhysicalBytes',
        0,
        Number.MAX_SAFE_INTEGER,
      );
    }
  }

  const request = {
    destination: portableDestination(
      input.destination === undefined ? `fixtures/${profile.id}` : input.destination,
    ),
    expectedSchemaVersions: { ...SCHEMA_VERSIONS },
    extensions: normalizeExtensions(input.extensions),
    featureFlags: normalizeFeatureFlags(input.featureFlags, profile),
    generator: { name: TOOL_NAME, version: GENERATOR_VERSION },
    profile: { id: profile.id, version: profile.version },
    scale,
    schemaVersion: REQUEST_SCHEMA,
    seed: normalizedSeed(input.seed ?? 'opengamevcs-v1'),
  };
  if (resourceLimits && Object.keys(resourceLimits).length > 0) request.resourceLimits = resourceLimits;

  const schemaIssues = validateSchemaDocument('FixtureRequest', request);
  if (schemaIssues.length > 0) {
    throw invalidRequest('canonical request does not satisfy FixtureRequest.schema.json', {
      issues: schemaIssues.slice(0, 16),
    });
  }
  return Object.freeze(request);
}

export function resolveRequest(input = {}) {
  const request = createRequest(input);
  return {
    profile: getProfile(request.profile.id, request.profile.version),
    request,
    requestDigest: canonicalDigest(request, 'ogvcs.fixture/request/v1'),
  };
}

export function requestSettings(request) {
  return {
    checkpointEvery: request.extensions['generation.checkpoint-every'],
    compressionClass: request.extensions['generation.compression-class'],
    duplicationPermille: request.extensions['generation.duplication-permille'],
    editLocalityPermille: request.extensions['generation.edit-locality-permille'],
    largeFileMode: request.extensions['generation.large-file-mode'],
    materialization: request.extensions['generation.materialization'],
    materializedPathLimit: request.extensions['generation.materialized-path-limit'],
    mutableVersions: request.extensions['generation.mutable-versions'],
    negativeCases: request.featureFlags['negative-cases'] ?? false,
  };
}

export function referenceScaleRequest(destination = 'fixtures/reference-scale') {
  return createRequest({
    destination,
    extensions: {
      'generation.checkpoint-every': 50_000,
      'generation.large-file-mode': 'stream-verified',
      'generation.materialization': 'index-only',
      'generation.materialized-path-limit': 0,
    },
    profile: { id: 'large-binary', version: PROFILE_VERSION },
    scale: {
      historyOperationCount: 10_000,
      largeFileBytes: 100 * 1024 ** 3,
      maxDepth: 12,
      pathCount: 1_000_000,
    },
    seed: 'opengamevcs-reference-scale-v1',
  });
}
