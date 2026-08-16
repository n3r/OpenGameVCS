import { OgvcsError, fail } from './errors.js';

const DEFINITIONS = Object.freeze({
  'asset-group-members': [64, 'LIMIT_COUNT', 2, 2],
  'asset-groups': [10_000, 'LIMIT_COUNT', 2, 2],
  'bundle-index-entries': [20_000_000, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-largest-item-bytes': [536_871_424, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-logical-records': [10_000_000, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-objects': [10_000_000, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-roots': [20_000_000, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-sequence-bytes': [2_199_023_255_552, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-total-items': [40_000_002, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'bundle-traversal-edges': [100_000_000, 'BUNDLE_BUDGET_EXCEEDED', 1, 1],
  'cbor-nesting-depth': [32, 'LIMIT_NESTING', 2, 1],
  'change-set-operations': [1_000_000, 'LIMIT_COUNT', 2, 2],
  'chunk-payload-bytes': [67_108_864, 'LIMIT_CHUNK_BYTES', 2, 1],
  'extension-aggregate-bytes-per-object': [16_777_216, 'LIMIT_EXTENSION_BYTES', 2, 1],
  'extensions-per-object': [128, 'LIMIT_COUNT', 2, 1],
  'generic-text-or-byte-value-bytes': [16_777_216, 'LIMIT_VALUE_BYTES', 2, 1],
  'logical-file-bytes': [1_099_511_627_776, 'LIMIT_LOGICAL_BYTES', 2, 2],
  'manifest-chunks': [1_048_576, 'LIMIT_COUNT', 2, 2],
  'metadata-payload-bytes': [536_870_912, 'LIMIT_METADATA_BYTES', 2, 1],
  'path-bytes': [4_096, 'PATH_CORE_INVALID', 2, 2],
  'path-segment-bytes': [255, 'PATH_CORE_INVALID', 2, 2],
  'path-segments': [256, 'PATH_CORE_INVALID', 2, 2],
  'snapshot-message-bytes': [1_048_576, 'LIMIT_VALUE_BYTES', 2, 2],
  'snapshot-parents': [8, 'SNAPSHOT_PARENT_COUNT_INVALID', 2, 2],
  'tree-entries': [1_000_000, 'LIMIT_COUNT', 2, 2]
});

const LIMIT_CODES = new Set([
  'BUNDLE_BUDGET_EXCEEDED', 'LIMIT_CHUNK_BYTES', 'LIMIT_COUNT',
  'LIMIT_EXTENSION_BYTES', 'LIMIT_LOGICAL_BYTES', 'LIMIT_METADATA_BYTES',
  'LIMIT_NESTING', 'LIMIT_VALUE_BYTES', 'PATH_CORE_INVALID',
  'SNAPSHOT_PARENT_COUNT_INVALID'
]);
const CONFIGURED_PREFLIGHT_LIMITS = new Set([
  'bundle-index-entries', 'bundle-largest-item-bytes', 'bundle-logical-records',
  'bundle-objects', 'bundle-roots', 'bundle-sequence-bytes', 'bundle-total-items',
  'bundle-traversal-edges', 'chunk-payload-bytes', 'metadata-payload-bytes'
]);

function decimal(value) {
  if (typeof value === 'bigint' && value >= 0n) return value;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}

function definition(registry, name) {
  if (typeof name !== 'string' || !Object.hasOwn(DEFINITIONS, name)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  }
  const [frozenMaximum, frozenCode, acceptLayer, rejectLayer] = DEFINITIONS[name];
  const entry = registry?.limits?.get(name);
  if (registry !== undefined && (!entry || !LIMIT_CODES.has(entry.errorCode) || !Number.isSafeInteger(entry.value) ||
      entry.value !== frozenMaximum || entry.errorCode !== frozenCode)) {
    fail('REGISTRY_INVALID', { layer: 3 });
  }
  return { acceptLayer, frozenCode, frozenMaximum, rejectLayer };
}

/** Returns the frozen maximum as a safe JavaScript integer. */
export function hardLimitMaximum(name, registry) {
  return definition(registry, name).frozenMaximum;
}

/**
 * Returns a configured ceiling constrained by the frozen hard maximum.
 * Every format-v1 maximum is below Number.MAX_SAFE_INTEGER; comparison and
 * clamping still happen as BigInt so callers cannot lose precision first.
 */
export function configuredHardLimit(name, configured, registry) {
  const { frozenMaximum } = definition(registry, name);
  const hard = BigInt(frozenMaximum);
  const requested = configured === undefined ? hard : decimal(configured);
  return Number(requested < hard ? requested : hard);
}

/**
 * Execute one isolated hard-limit preflight without allocating from `value`.
 * This is the implementation boundary used by the normative virtual
 * max/max+1 constructors. It does not claim that a maximum-sized object was
 * materialized; it proves exact unsigned comparison, error code, and layer.
 */
export function evaluateHardLimit(registry, name, value) {
  const { frozenMaximum, frozenCode, acceptLayer, rejectLayer } = definition(registry, name);
  const observed = decimal(value);
  const maximum = BigInt(frozenMaximum);
  const accepted = observed <= maximum;
  let stage = null;
  if (!accepted) {
    const explicit = rejectLayer === 2 ? 'known-schema'
      : CONFIGURED_PREFLIGHT_LIMITS.has(name) ? 'configured-resource-preflight'
        : 'canonical-framing';
    stage = new OgvcsError(frozenCode, { layer: rejectLayer, stage: explicit }).stage;
  }
  return Object.freeze({
    accepted,
    code: accepted ? null : frozenCode,
    layer: accepted ? acceptLayer : rejectLayer,
    stage,
    maximumDecimal: maximum.toString(),
    name,
    valueDecimal: observed.toString()
  });
}

export function enforceHardLimit(registry, name, value, options = {}) {
  const decision = evaluateHardLimit(registry, name, value);
  if (!decision.accepted) fail(options.code ?? decision.code, {
    layer: options.layer ?? decision.layer,
    stage: options.stage ?? (options.code === undefined && options.layer === undefined ? decision.stage : undefined)
  });
  const configured = configuredHardLimit(name, options.maximum, registry);
  if (BigInt(decision.valueDecimal) > BigInt(configured)) {
    const { frozenCode, rejectLayer } = definition(registry, name);
    fail(options.code ?? frozenCode, { layer: options.layer ?? rejectLayer, stage: options.stage });
  }
  return Object.freeze({ ...decision, effectiveMaximumDecimal: configured.toString() });
}

export const HARD_LIMIT_NAMES = Object.freeze(Object.keys(DEFINITIONS));
