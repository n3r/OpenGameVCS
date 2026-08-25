import { canonicalJson, cloneJson, deepFreeze, inspectJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, ProtocolBaselineError, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';

const IGNORED_KEYWORDS = new Set([
  '$comment', '$defs', '$id', '$schema', 'default', 'deprecated', 'description',
  'examples', 'readOnly', 'title', 'writeOnly',
]);

const SUPPORTED_KEYWORDS = new Set([
  '$ref', 'additionalProperties', 'allOf', 'anyOf', 'const', 'contains',
  'dependentRequired', 'else', 'enum', 'exclusiveMaximum', 'exclusiveMinimum',
  'format', 'if', 'items', 'maxContains', 'maximum', 'maxItems', 'maxLength',
  'maxProperties', 'minContains', 'minimum', 'minItems', 'minLength',
  'minProperties', 'multipleOf', 'not', 'oneOf', 'pattern', 'prefixItems',
  'properties', 'propertyNames', 'required', 'then', 'type', 'unevaluatedProperties',
  'uniqueItems',
]);

const AUTHENTICATED_SCHEMA_INVENTORY = Symbol('authenticated protocol schema inventory');

class SchemaMismatch extends Error {
  constructor(path, reason) {
    super(reason);
    this.path = path;
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function pointerValue(root, fragment) {
  if (fragment === '' || fragment === '#') return root;
  if (!fragment.startsWith('#/')) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema reference fragment is unsupported');
  let current = root;
  for (const raw of fragment.slice(2).split('/')) {
    const part = raw.replaceAll('~1', '/').replaceAll('~0', '~');
    if (!isObject(current) || !Object.hasOwn(current, part)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema reference fragment is unresolved');
    current = current[part];
  }
  return current;
}

function typeMatches(value, type) {
  switch (type) {
    case 'null': return value === null;
    case 'boolean': return typeof value === 'boolean';
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'integer': return typeof value === 'number' && Number.isSafeInteger(value);
    case 'string': return typeof value === 'string';
    case 'array': return Array.isArray(value);
    case 'object': return isObject(value);
    default: return false;
  }
}

function displayPath(path) {
  const result = path.length > 240 ? `${path.slice(0, 237)}...` : path;
  return result || '$';
}

export class ProtocolSchemaValidator {
  #byId = new Map();
  #byName = new Map();
  #byVersion = new Map();
  #patterns = new Map();

  constructor(schemas, inventoryAuthority) {
    const suppliedEntries = schemas instanceof Map ? [...schemas.entries()] : Object.entries(schemas ?? {});
    const entries = inventoryAuthority === AUTHENTICATED_SCHEMA_INVENTORY
      ? suppliedEntries
      : suppliedEntries.map(([name, schema]) => [name, deepFreeze(cloneJson(schema, {
        maxBytes: HARD_LIMITS.jsonBytes,
        maxDepth: HARD_LIMITS.jsonDepth,
        maxNodes: HARD_LIMITS.jsonNodes,
        maxCollectionItems: HARD_LIMITS.collectionItems,
      }))]);
    if (entries.length === 0 || entries.length > 1024) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schema inventory is invalid');
    for (const [name, schema] of entries) {
      if (typeof name !== 'string' || name.length === 0 || !isObject(schema)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schema entry is invalid');
      if (inventoryAuthority === AUTHENTICATED_SCHEMA_INVENTORY && !Object.isFrozen(schema)) {
        protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'authenticated protocol schema inventory must be immutable');
      }
      inspectJson(schema);
      if (typeof schema.$id !== 'string' || schema.$id.length === 0 || this.#byId.has(schema.$id)) {
        protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schema identifier is missing or duplicated');
      }
      this.#byId.set(schema.$id, schema);
      this.#byName.set(name, schema);
      if (isObject(schema.properties) && isObject(schema.properties.schemaVersion) && typeof schema.properties.schemaVersion.const === 'string') {
        const version = schema.properties.schemaVersion.const;
        if (this.#byVersion.has(version)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol schemaVersion is duplicated');
        this.#byVersion.set(version, schema);
      }
      this.#auditSchema(schema, new Set());
    }
    for (const schema of this.#byName.values()) this.#auditReferences(schema, schema, new Set());
  }

  #auditReferences(schema, root, seen) {
    if (schema === true || schema === false || !isObject(schema) || seen.has(schema)) return;
    seen.add(schema);
    if (schema.$ref !== undefined) {
      const resolved = this.#resolveReference(schema.$ref, root);
      this.#auditReferences(resolved.schema, resolved.root, seen);
    }
    for (const key of ['additionalProperties', 'contains', 'else', 'if', 'items', 'not', 'propertyNames', 'then', 'unevaluatedProperties']) {
      if (Object.hasOwn(schema, key)) this.#auditReferences(schema[key], root, seen);
    }
    for (const key of ['allOf', 'anyOf', 'oneOf', 'prefixItems']) for (const child of schema[key] ?? []) this.#auditReferences(child, root, seen);
    for (const key of ['$defs', 'properties']) for (const child of Object.values(schema[key] ?? {})) this.#auditReferences(child, root, seen);
  }

  #auditSchema(schema, seen, retainPatterns = true) {
    if (schema === true || schema === false) return;
    if (!isObject(schema)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema node must be an object or boolean');
    if (seen.has(schema)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema graph contains an in-memory cycle');
    seen.add(schema);
    for (const [key, value] of Object.entries(schema)) {
      if (!(IGNORED_KEYWORDS.has(key) || SUPPORTED_KEYWORDS.has(key) || key.startsWith('x-'))) {
        protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `unsupported JSON Schema keyword: ${key}`);
      }
      if (key === 'pattern') {
        if (typeof value !== 'string' || value.length > 512 || /\\[1-9]/u.test(value)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema pattern is outside the supported subset');
        try {
          const pattern = new RegExp(value, 'u');
          if (retainPatterns) this.#patterns.set(value, pattern);
        } catch (error) {
          protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema pattern is invalid', { cause: error });
        }
      }
    }
    const direct = ['additionalProperties', 'contains', 'else', 'if', 'items', 'not', 'propertyNames', 'then', 'unevaluatedProperties'];
    for (const key of direct) if (Object.hasOwn(schema, key) && (isObject(schema[key]) || typeof schema[key] === 'boolean')) this.#auditSchema(schema[key], seen, retainPatterns);
    for (const key of ['allOf', 'anyOf', 'oneOf', 'prefixItems']) {
      if (schema[key] !== undefined) {
        if (!Array.isArray(schema[key])) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${key} must be an array`);
        for (const child of schema[key]) this.#auditSchema(child, seen, retainPatterns);
      }
    }
    for (const key of ['$defs', 'properties']) {
      if (schema[key] !== undefined) {
        if (!isObject(schema[key])) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `${key} must be an object`);
        for (const child of Object.values(schema[key])) this.#auditSchema(child, seen, retainPatterns);
      }
    }
    seen.delete(schema);
  }

  schema(selector, options = {}) {
    if (isObject(selector)) {
      const schema = deepFreeze(cloneJson(selector, {
        ...options,
        maxBytes: HARD_LIMITS.jsonBytes,
        maxDepth: HARD_LIMITS.jsonDepth,
        maxNodes: HARD_LIMITS.jsonNodes,
        maxCollectionItems: HARD_LIMITS.collectionItems,
      }));
      this.#auditSchema(schema, new Set(), false);
      this.#auditReferences(schema, schema, new Set());
      return schema;
    }
    if (typeof selector !== 'string' || selector.length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'schema selector is invalid');
    const schema = this.#byName.get(selector) ?? this.#byId.get(selector) ?? this.#byVersion.get(selector);
    if (!schema) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `protocol schema is unavailable: ${selector}`);
    return schema;
  }

  #resolveReference(reference, currentRoot) {
    if (typeof reference !== 'string' || reference.length === 0 || reference.length > 2048) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema reference is invalid');
    if (reference.startsWith('#')) return { schema: pointerValue(currentRoot, reference), root: currentRoot };
    const hash = reference.indexOf('#');
    const id = hash === -1 ? reference : reference.slice(0, hash);
    let root = this.#byId.get(id) ?? this.#byName.get(id);
    if (!root && typeof currentRoot.$id === 'string') {
      try { root = this.#byId.get(new URL(id, currentRoot.$id).href); } catch { /* handled below */ }
    }
    if (!root) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `external schema reference is unresolved: ${id}`);
    return { schema: pointerValue(root, hash === -1 ? '' : reference.slice(hash)), root };
  }

  #step(state) {
    state.steps += 1;
    if ((state.steps & 1023) === 0) state.deadline.checkpoint();
    if (state.steps > state.maxSteps) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'schema validation step ceiling exceeded');
  }

  #branch(value, schema, root, path, state, evaluationDepth) {
    try {
      this.#validate(value, schema, root, path, state, evaluationDepth + 1);
      return true;
    } catch (error) {
      if (error instanceof SchemaMismatch) return false;
      throw error;
    }
  }

  #validate(value, schema, root, path, state, evaluationDepth = 0) {
    this.#step(state);
    if (evaluationDepth > 128) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'schema evaluation recursion ceiling exceeded');
    if (schema === true) return;
    if (schema === false) throw new SchemaMismatch(path, 'is forbidden');
    if (schema['x-ogvcs-maxDepth'] !== undefined || schema['x-ogvcs-maxNodes'] !== undefined) {
      inspectJson(value, {
        maxDepth: schema['x-ogvcs-maxDepth'] ?? HARD_LIMITS.jsonDepth,
        maxNodes: schema['x-ogvcs-maxNodes'] ?? HARD_LIMITS.jsonNodes,
        deadline: state.deadline,
      });
    }
    if (schema.$ref !== undefined) {
      const resolved = this.#resolveReference(schema.$ref, root);
      this.#validate(value, resolved.schema, resolved.root, path, state, evaluationDepth + 1);
    }
    if (schema.type !== undefined) {
      const types = Array.isArray(schema.type) ? schema.type : [schema.type];
      if (types.length === 0 || !types.every((type) => typeof type === 'string') || !types.some((type) => typeMatches(value, type))) {
        throw new SchemaMismatch(path, 'has the wrong type');
      }
    }
    if (schema.const !== undefined && canonicalJson(value) !== canonicalJson(schema.const)) throw new SchemaMismatch(path, 'does not equal its constant');
    if (schema.enum !== undefined) {
      if (!Array.isArray(schema.enum) || !schema.enum.some((candidate) => canonicalJson(candidate) === canonicalJson(value))) throw new SchemaMismatch(path, 'is outside its enum');
    }
    if (schema.allOf !== undefined && !schema.allOf.every((child) => this.#branch(value, child, root, path, state, evaluationDepth))) throw new SchemaMismatch(path, 'does not satisfy allOf');
    // No annotation produced by this supported subset depends on evaluating
    // every successful anyOf branch. Short-circuiting is deterministic and
    // makes the frozen schema-step ceiling reflect actual work performed.
    if (schema.anyOf !== undefined && !schema.anyOf.some((child) => this.#branch(value, child, root, path, state, evaluationDepth))) throw new SchemaMismatch(path, 'does not satisfy anyOf');
    if (schema.oneOf !== undefined) {
      const matches = schema.oneOf.filter((child) => this.#branch(value, child, root, path, state, evaluationDepth)).length;
      if (matches !== 1) throw new SchemaMismatch(path, 'does not satisfy oneOf');
    }
    if (schema.not !== undefined && this.#branch(value, schema.not, root, path, state, evaluationDepth)) throw new SchemaMismatch(path, 'matches a forbidden schema');
    if (schema.if !== undefined) {
      const branch = this.#branch(value, schema.if, root, path, state, evaluationDepth) ? schema.then : schema.else;
      if (branch !== undefined) this.#validate(value, branch, root, path, state, evaluationDepth + 1);
    }

    if (typeof value === 'string') {
      const length = [...value].length;
      if (schema.minLength !== undefined && length < schema.minLength) throw new SchemaMismatch(path, 'is too short');
      if (schema.maxLength !== undefined && length > schema.maxLength) throw new SchemaMismatch(path, 'is too long');
      if (schema['x-ogvcs-maxUtf8Bytes'] !== undefined && Buffer.byteLength(value, 'utf8') > schema['x-ogvcs-maxUtf8Bytes']) throw new SchemaMismatch(path, 'exceeds its UTF-8 byte ceiling');
      if (schema.pattern !== undefined) {
        const pattern = this.#patterns.get(schema.pattern) ?? new RegExp(schema.pattern, 'u');
        if (!pattern.test(value)) throw new SchemaMismatch(path, 'does not match its pattern');
      }
      if (schema.format !== undefined) {
        if (schema.format === 'uri') {
          try { new URL(value); } catch { throw new SchemaMismatch(path, 'is not a URI'); }
        } else if (schema.format === 'uuid') {
          if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) throw new SchemaMismatch(path, 'is not a UUID');
        } else if (schema.format === 'date-time') {
          if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) || Number.isNaN(Date.parse(value))) throw new SchemaMismatch(path, 'is not a UTC date-time');
        } else protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, `unsupported schema format: ${schema.format}`);
      }
    }
    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum) throw new SchemaMismatch(path, 'is below its minimum');
      if (schema.maximum !== undefined && value > schema.maximum) throw new SchemaMismatch(path, 'is above its maximum');
      if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) throw new SchemaMismatch(path, 'is below its exclusive minimum');
      if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) throw new SchemaMismatch(path, 'is above its exclusive maximum');
      if (schema.multipleOf !== undefined && Math.abs(value / schema.multipleOf - Math.round(value / schema.multipleOf)) > Number.EPSILON * 8) throw new SchemaMismatch(path, 'is not a required multiple');
    }
    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems) throw new SchemaMismatch(path, 'has too few items');
      if (schema.maxItems !== undefined && value.length > schema.maxItems) throw new SchemaMismatch(path, 'has too many items');
      if (schema.uniqueItems === true) {
        const seen = new Set();
        for (const item of value) {
          const key = canonicalJson(item);
          if (seen.has(key)) throw new SchemaMismatch(path, 'contains duplicate items');
          seen.add(key);
        }
      }
      for (let index = 0; index < (schema.prefixItems?.length ?? 0) && index < value.length; index += 1) this.#validate(value[index], schema.prefixItems[index], root, `${path}/${index}`, state, evaluationDepth + 1);
      if (schema.items !== undefined) {
        const start = schema.prefixItems?.length ?? 0;
        for (let index = start; index < value.length; index += 1) this.#validate(value[index], schema.items, root, `${path}/${index}`, state, evaluationDepth + 1);
      }
      if (schema.contains !== undefined) {
        const matches = value.filter((item, index) => this.#branch(item, schema.contains, root, `${path}/${index}`, state, evaluationDepth)).length;
        const minimum = schema.minContains ?? 1;
        const maximum = schema.maxContains ?? Number.MAX_SAFE_INTEGER;
        if (matches < minimum || matches > maximum) throw new SchemaMismatch(path, 'does not satisfy contains');
      }
    }
    if (isObject(value)) {
      const keys = Object.keys(value);
      if (schema.minProperties !== undefined && keys.length < schema.minProperties) throw new SchemaMismatch(path, 'has too few properties');
      if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) throw new SchemaMismatch(path, 'has too many properties');
      for (const required of schema.required ?? []) if (!Object.hasOwn(value, required)) throw new SchemaMismatch(`${path}/${required}`, 'is required');
      for (const [key, child] of Object.entries(schema.properties ?? {})) if (Object.hasOwn(value, key)) this.#validate(value[key], child, root, `${path}/${key}`, state, evaluationDepth + 1);
      const known = new Set(Object.keys(schema.properties ?? {}));
      for (const key of keys) {
        if (schema.propertyNames !== undefined) this.#validate(key, schema.propertyNames, root, `${path}/<property>`, state, evaluationDepth + 1);
        if (known.has(key)) continue;
        const additional = schema.additionalProperties ?? schema.unevaluatedProperties;
        if (additional === false) throw new SchemaMismatch(`${path}/${key}`, 'is not a registered property');
        if (isObject(additional) || typeof additional === 'boolean') this.#validate(value[key], additional, root, `${path}/${key}`, state, evaluationDepth + 1);
      }
      for (const [key, dependents] of Object.entries(schema.dependentRequired ?? {})) {
        if (Object.hasOwn(value, key)) for (const dependent of dependents) if (!Object.hasOwn(value, dependent)) throw new SchemaMismatch(`${path}/${dependent}`, `is required by ${key}`);
      }
    }
  }

  validate(value, selector, options = {}) {
    inspectJson(value, options);
    const schema = this.schema(selector, options);
    const state = {
      steps: 0,
      maxSteps: boundedInteger(options.maxSteps, HARD_LIMITS.schemaSteps, HARD_LIMITS.schemaSteps, 'maxSteps'),
      deadline: deadlineFrom(options),
    };
    try {
      this.#validate(value, schema, schema, '$', state);
    } catch (error) {
      if (error instanceof SchemaMismatch) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `protocol value ${error.reason ?? error.message}`, { details: { path: displayPath(error.path) } });
      }
      throw error;
    }
    state.deadline.checkpoint();
    return cloneJson(value, options);
  }
}

// Contract loaders call this only after canonical bytes and manifest digests
// have authenticated and deep-frozen every schema. Reusing those immutable
// graphs avoids retaining a second full schema inventory outside the loader's
// declared working-memory reservation. This helper is intentionally omitted
// from the package entry-point exports.
export function protocolSchemaValidatorFromAuthenticatedInventory(schemas) {
  return new ProtocolSchemaValidator(schemas, AUTHENTICATED_SCHEMA_INVENTORY);
}

export function validateProtocolValue(contract, selector, value, options = {}) {
  if (!(contract?.validator instanceof ProtocolSchemaValidator)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol contract has no schema validator');
  try {
    return contract.validator.validate(value, selector, options);
  } catch (error) {
    if (error instanceof ProtocolBaselineError) throw error;
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol schema validation failed', { cause: error });
  }
}
