import { fail } from './errors.js';
import { RegistrySnapshot, isCompleteRegistrySnapshot } from './registry.js';

const OPERATIONS = Object.freeze({
  conformance: 'conformance',
  production: 'production-write'
});
const WRITER_OPERATIONS = new Set(['conformance', 'production-write']);
const REGISTRY_OPERATIONS = new Set(['read', 'conformance', 'production-write']);

/** Parses the closed repository/bundle API mode before any payload work. */
export function validationMode(value, { required = false } = {}) {
  if (value === undefined && required) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const mode = value ?? 'conformance';
  if (typeof mode !== 'string' || !Object.hasOwn(OPERATIONS, mode)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return mode;
}

export function validationOperation(value, options) {
  return OPERATIONS[validationMode(value, options)];
}

/** Parses the closed tree/manifest writer operation before any input work. */
export function writerOperation(value) {
  const operation = value;
  if (typeof operation !== 'string' || !WRITER_OPERATIONS.has(operation)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return operation;
}

/** Parses a registry lifecycle operation for semantic decoding/validation. */
export function registryOperation(value, { required = false } = {}) {
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'string' || !REGISTRY_OPERATIONS.has(value)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return value;
}

/** Validates the immutable registry authority used by semantic operations. */
export function registrySnapshot(value, { required = false, complete = false } = {}) {
  if (value === undefined && !required) return undefined;
  if (!(value instanceof RegistrySnapshot)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (complete && !isCompleteRegistrySnapshot(value)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return value;
}

/** Returns one closed, operation-aware semantic API context. */
export function semanticValidationContext(
  modeValue,
  registryValue,
  { requireRegistry = false, requireMode = requireRegistry || registryValue !== undefined } = {}
) {
  const mode = validationMode(modeValue, { required: requireMode });
  const registry = registrySnapshot(registryValue, {
    required: requireRegistry || mode === 'production', complete: true
  });
  return Object.freeze({ mode, operation: OPERATIONS[mode], registry });
}

/** Returns the mandatory authority context for a public tree/manifest emitter. */
export function writerValidationContext(operationValue, registryValue) {
  const operation = writerOperation(operationValue);
  const registry = registrySnapshot(registryValue, { required: true, complete: true });
  return Object.freeze({ operation, registry });
}

/** Authority context for a decoder/verifier that may stop honestly at L2. */
export function registryValidationContext(operationValue, registryValue) {
  const registry = registrySnapshot(registryValue, { complete: registryValue !== undefined });
  if (registry === undefined && operationValue !== undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  const operation = registryOperation(operationValue, { required: registry !== undefined });
  return Object.freeze({ operation, registry });
}

/** Closed authority pair for a codec/verifier with an explicit layer-two mode. */
export function codecValidationContext({ operation, registry, semantic } = {}) {
  if (semantic === false) {
    if (registry !== undefined || operation !== undefined) {
      fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
    }
    return Object.freeze({ operation: undefined, registry: undefined, semantic: false });
  }
  if (semantic === true && registry === undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  if (semantic === undefined && registry === undefined && operation === undefined) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return Object.freeze({ ...registryValidationContext(operation, registry), semantic });
}
