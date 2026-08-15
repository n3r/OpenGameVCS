import { canonicalClone, canonicalDigest } from './canonical.mjs';

export const PROFILE_SCHEMA_VERSION = 'ogvcs.fixture/workload-profile/v1';
export const PROFILE_VERSION = '2.0.0';

const COMMON_LIMITS = Object.freeze({
  pathCount: Object.freeze({ minimum: 1, maximum: 10_000_000 }),
  historyOperationCount: Object.freeze({ minimum: 0, maximum: 10_000_000 }),
  largeFileBytes: Object.freeze({ minimum: 0, maximum: 1_099_511_627_776 }),
  maxDepth: Object.freeze({ minimum: 2, maximum: 64 }),
});

const PROFILES = new Map([
  profile({
    id: 'code-heavy',
    displayName: 'Code-heavy repository',
    description: 'Deep and wide source trees with executable bits and text-oriented history.',
    defaults: { pathCount: 1_000, historyOperationCount: 250, largeFileBytes: 0, maxDepth: 12 },
    features: ['branches', 'copies', 'deletes', 'executables', 'merges', 'renames', 'text-edits'],
    contentClasses: ['source-text', 'configuration', 'script'],
    operationKinds: ['create', 'edit', 'branch', 'merge', 'rename', 'copy', 'delete'],
    groupKinds: [],
    exclusions: ['build', 'dist', 'node_modules'],
  }),
  profile({
    id: 'unreal-like',
    displayName: 'Unreal-like repository',
    description: 'Wholly synthetic packages, maps, sidecars, source/configuration and lock contention.',
    defaults: { pathCount: 800, historyOperationCount: 160, largeFileBytes: 268_435_456, maxDepth: 14 },
    features: ['external-actors', 'large-file-churn', 'lock-conflicts', 'maps', 'sidecars'],
    contentClasses: ['synthetic-package', 'synthetic-map', 'source-text', 'configuration'],
    operationKinds: ['create', 'edit', 'rename', 'lock-acquire', 'lock-conflict', 'submit'],
    groupKinds: ['map-external-actors', 'package-sidecars'],
    exclusions: ['Binaries', 'DerivedDataCache', 'Intermediate', 'Saved'],
  }),
  profile({
    id: 'unity-like',
    displayName: 'Unity-like repository',
    description: 'Synthetic asset/sidecar pairs, stable GUID relations and negative sidecar cases.',
    defaults: { pathCount: 900, historyOperationCount: 180, largeFileBytes: 134_217_728, maxDepth: 12 },
    features: [
      'asset-meta-pairs',
      'binary-imports',
      'duplicate-sidecar-negative',
      'missing-sidecar-negative',
      'moves',
      'negative-cases',
    ],
    contentClasses: ['asset', 'meta', 'scene-text', 'prefab-text', 'binary-import'],
    operationKinds: ['create', 'edit', 'move', 'delete', 'submit'],
    groupKinds: ['asset-meta'],
    exclusions: ['Library', 'Logs', 'Temp', 'obj'],
  }),
  profile({
    id: 'large-binary',
    displayName: 'Large binary repository',
    description: 'Streaming binary versions with locality, duplication and cross-version reuse controls.',
    defaults: { pathCount: 100, historyOperationCount: 40, largeFileBytes: 10_737_418_240, maxDepth: 8 },
    features: ['cross-version-reuse', 'duplication', 'edit-locality'],
    contentClasses: ['incompressible', 'mixed', 'compressible'],
    operationKinds: ['create', 'edit', 'copy', 'submit'],
    groupKinds: ['binary-version-family'],
    exclusions: [],
  }),
  profile({
    id: 'global-studio',
    displayName: 'Global studio operation scenario',
    description: 'Neutral ordered multi-site operations and configured network conditions.',
    defaults: { pathCount: 2_000, historyOperationCount: 500, largeFileBytes: 1_073_741_824, maxDepth: 16 },
    features: ['branch-update', 'ci-materialization', 'interruptions', 'lock-lifecycle', 'network-conditions', 'review', 'selective-sync'],
    contentClasses: ['source-text', 'synthetic-asset', 'synthetic-package'],
    operationKinds: [
      'selective-sync', 'lock-acquire', 'lock-conflict', 'lock-loss', 'submit',
      'branch-update', 'review', 'ci-materialize', 'interrupt', 'network-condition',
    ],
    groupKinds: ['site', 'team', 'asset'],
    exclusions: ['generated-cache'],
  }),
].map((entry) => [entry.id, entry]));

/** Return stable summaries for every built-in profile, sorted by identifier. */
export function listProfiles() {
  return [...PROFILES.values()]
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0))
    .map((entry) => canonicalClone({
      id: entry.id,
      version: entry.version,
      schemaVersion: entry.schemaVersion,
      displayName: entry.displayName,
      description: entry.description,
      digest: entry.digest,
    }));
}

/** Return a defensive copy of a built-in current profile. */
export function getProfile(id, version = PROFILE_VERSION) {
  if (typeof id !== 'string') throw new TypeError('profile id must be a string');
  const entry = PROFILES.get(id);
  if (!entry || entry.version !== version) {
    throw new RangeError(`Unknown fixture profile: ${id}@${version}`);
  }
  return canonicalClone(entry);
}

/**
 * Resolve request scale and feature overrides against a built-in profile.
 * The returned object is canonical JSON data and includes a digest over the
 * exact resolved profile instance.
 */
export function resolveProfile(id, overrides = {}) {
  if (!isPlainObject(overrides)) throw new TypeError('profile overrides must be a plain object');
  const version = overrides.version ?? PROFILE_VERSION;
  const base = getProfile(id, version);
  const scaleOverrides = overrides.scale ?? overrides.parameters ?? {};
  if (!isPlainObject(scaleOverrides)) throw new TypeError('scale overrides must be a plain object');
  rejectUnknownKeys(scaleOverrides, Object.keys(base.defaults), 'scale');

  const scale = { ...base.defaults, ...scaleOverrides };
  for (const [name, bounds] of Object.entries(base.limits)) {
    const value = scale[name];
    if (!Number.isSafeInteger(value) || value < bounds.minimum || value > bounds.maximum) {
      throw new RangeError(`${name} must be an integer from ${bounds.minimum} through ${bounds.maximum}`);
    }
  }

  const featureFlags = overrides.featureFlags ?? {};
  if (!isPlainObject(featureFlags)) throw new TypeError('featureFlags must be a plain object');
  rejectUnknownKeys(featureFlags, base.features, 'featureFlags');
  for (const [name, enabled] of Object.entries(featureFlags)) {
    if (typeof enabled !== 'boolean') throw new TypeError(`featureFlags.${name} must be boolean`);
  }

  const resolved = {
    ...base,
    scale,
    featureFlags: Object.fromEntries(base.features.map((name) => [name, featureFlags[name] ?? true])),
  };
  delete resolved.digest;
  resolved.resolvedDigest = canonicalDigest(resolved, 'ogvcs.fixture/resolved-profile/v1');
  return canonicalClone(resolved);
}

function profile(definition) {
  const entry = {
    schemaVersion: PROFILE_SCHEMA_VERSION,
    id: definition.id,
    name: definition.id,
    version: PROFILE_VERSION,
    displayName: definition.displayName,
    description: definition.description,
    defaults: definition.defaults,
    limits: COMMON_LIMITS,
    features: [...definition.features].sort(),
    contentClasses: [...definition.contentClasses].sort(),
    operationKinds: [...definition.operationKinds],
    operationTypes: [...definition.operationKinds],
    groupKinds: [...definition.groupKinds].sort(),
    pathModel: {
      algorithm: 'synthetic-posix-tree-v1',
      normalization: 'NFC',
      maximumDepthParameter: 'maxDepth',
    },
    groupModel: {
      types: [...definition.groupKinds].sort(),
      atomicByDefault: definition.groupKinds.length > 0,
    },
    exclusions: [...definition.exclusions].sort(),
    license: 'NOASSERTION',
    provenance: {
      classification: 'fully-synthetic',
      externalSourceIdentifiersAllowed: false,
      license: 'NOASSERTION',
    },
  };
  entry.digest = canonicalDigest(entry, 'ogvcs.fixture/workload-profile/v1');
  return deepFreeze(entry);
}

function rejectUnknownKeys(object, allowed, name) {
  const permitted = new Set(allowed);
  const unknown = Object.keys(object).filter((key) => !permitted.has(key));
  if (unknown.length > 0) throw new RangeError(`Unknown ${name} field(s): ${unknown.sort().join(', ')}`);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function deepFreeze(value) {
  Object.freeze(value);
  for (const nested of Object.values(value)) {
    if (nested !== null && typeof nested === 'object' && !Object.isFrozen(nested)) deepFreeze(nested);
  }
  return value;
}
