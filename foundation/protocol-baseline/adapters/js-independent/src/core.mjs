import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { basename, resolve, sep } from 'node:path';

export const FROZEN_LIMITS = Object.freeze({
  maxControlMessageBytes: 1_048_576,
  maxCanonicalInputBytes: 1_048_576,
  maxJsonDepth: 64,
  maxJsonNodes: 100_000,
  maxObjectMembers: 256,
  maxArrayItems: 4_096,
  maxStringUtf8Bytes: 65_536,
  maxExtensionEntries: 32,
  maxCapabilityItems: 128,
  maxErrorParameters: 16,
  maxPageItems: 1_000,
  maxJsonlFrameBytes: 1_048_576,
  maxJsonlFrames: 100_000,
  maxCursorBytes: 1_024,
  maxIdempotencyKeyBytes: 256,
  maxReceiptBytes: 16_384,
  maxGrantBytes: 16_384,
  maxTransferRangeBytes: 1_073_741_824,
  maxHeaderBytes: 32_768,
  maxCorrelationIdBytes: 128,
  maxOperationBytes: 256,
  maxRunnerCases: 1_024,
  maxSafeParameterBytes: 1_024,
  maxDeadlineHorizonMs: 86_400_000,
  maxReceiptLifetimeMs: 300_000,
  maxCursorLifetimeMs: 86_400_000,
  maxRegistryEntries: 4_096,
  maxJsonKeyUtf8Bytes: 256,
  maxJsonCollectionItems: 100_000,
  maxJsonlStreamBytes: 67_108_864,
  maxWorkingMemoryBytes: 67_108_864,
  maxOperationTimeMs: 120_000,
  maxSchemaEvaluationSteps: 1_000_000,
  maxContractArtifacts: 4_096,
  maxContractBytes: 67_108_864,
});

const MANIFEST_MAX_BYTES = 1_048_576;
const REQUIRED_REGISTRIES = Object.freeze([
  'authorization-contracts', 'capabilities', 'compatibility', 'error-codes', 'event-versions',
  'extensions', 'field-assignments', 'limits', 'path-contracts', 'path-profiles',
  'protocol-versions', 'release-assignments', 'repository-formats', 'schema-versions', 'schemas', 'transfer-profiles',
]);
const SAFE_PATH = /^(?:profiles\/[a-z0-9][a-z0-9-]*\.json|registries\/[a-z0-9][a-z0-9-]*\.json|schemas\/[A-Za-z][A-Za-z0-9]*\.schema\.json)$/u;

export class AdapterFault extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'AdapterFault';
    this.kind = kind;
  }
}

export function fail(kind, message) { throw new AdapterFault(kind, message); }
export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
export function base64url(bytes) { return Buffer.from(bytes).toString('base64url'); }

function unicodeOkay(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return false;
  }
  return true;
}

function boundedLimits(overrides = {}) {
  const output = { ...FROZEN_LIMITS };
  for (const [name, value] of Object.entries(overrides)) {
    const minimum = name === 'maxErrorParameters' ? 0 : 1;
    if (!Object.hasOwn(FROZEN_LIMITS, name) || !Number.isSafeInteger(value) || value < minimum || value > FROZEN_LIMITS[name]) fail('invalid', 'configured limit is invalid');
    output[name] = value;
  }
  return output;
}

export function inspectJson(value, overrides = {}) {
  const limits = boundedLimits(overrides);
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  let collectionItems = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > limits.maxJsonNodes || current.depth > limits.maxJsonDepth) fail('limit', 'JSON structural ceiling exceeded');
    const item = current.value;
    if (item === null || typeof item === 'boolean') continue;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || Number.isInteger(item) && !Number.isSafeInteger(item)) fail('invalid', 'number is outside I-JSON');
      continue;
    }
    if (typeof item === 'string') {
      if (!unicodeOkay(item)) fail('invalid', 'string is not Unicode');
      if (Buffer.byteLength(item, 'utf8') > limits.maxStringUtf8Bytes) fail('limit', 'string ceiling exceeded');
      continue;
    }
    if (Array.isArray(item)) {
      if (item.length > limits.maxArrayItems) fail('limit', 'array ceiling exceeded');
      collectionItems += item.length;
      for (let index = item.length - 1; index >= 0; index -= 1) {
        if (!Object.hasOwn(item, index)) fail('invalid', 'array is sparse');
        stack.push({ value: item[index], depth: current.depth + 1 });
      }
    } else if (item && typeof item === 'object' && (Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null)) {
      const keys = Object.keys(item);
      if (keys.length > limits.maxObjectMembers) fail('limit', 'object-member ceiling exceeded');
      collectionItems += keys.length;
      for (const key of keys) {
        if (!unicodeOkay(key)) fail('invalid', 'object key is not Unicode');
        if (Buffer.byteLength(key, 'utf8') > limits.maxJsonKeyUtf8Bytes) fail('limit', 'object-key ceiling exceeded');
        stack.push({ value: item[key], depth: current.depth + 1 });
      }
    } else fail('invalid', 'value is outside I-JSON');
    if (collectionItems > limits.maxJsonCollectionItems) fail('limit', 'JSON collection ceiling exceeded');
  }
  return { nodes, collectionItems };
}

function encodeJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(encodeJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${encodeJson(value[key])}`).join(',')}}`;
}

export function canonicalJson(value, overrides = {}) {
  const limits = boundedLimits(overrides);
  inspectJson(value, limits);
  const text = encodeJson(value);
  if (Buffer.byteLength(text, 'utf8') > limits.maxCanonicalInputBytes) fail('limit', 'canonical JSON byte ceiling exceeded');
  return text;
}

class JsonReader {
  constructor(text, limits) {
    this.text = text;
    this.limits = limits;
    this.offset = 0;
    this.nodes = 0;
    this.collectionItems = 0;
  }

  whitespace() {
    while (' \t\r\n'.includes(this.text[this.offset] ?? '\0')) this.offset += 1;
  }

  value(depth) {
    this.whitespace();
    this.nodes += 1;
    if (this.nodes > this.limits.maxJsonNodes || depth > this.limits.maxJsonDepth) fail('limit', 'JSON structural ceiling exceeded');
    const token = this.text[this.offset];
    if (token === '"') return this.string(false);
    if (token === '{') return this.object(depth);
    if (token === '[') return this.array(depth);
    if (this.text.startsWith('true', this.offset)) { this.offset += 4; return true; }
    if (this.text.startsWith('false', this.offset)) { this.offset += 5; return false; }
    if (this.text.startsWith('null', this.offset)) { this.offset += 4; return null; }
    if (token === '-' || token >= '0' && token <= '9') return this.number();
    fail('invalid', 'invalid JSON token');
  }

  string(key) {
    const start = this.offset++;
    let escaped = false;
    while (this.offset < this.text.length) {
      const code = this.text.charCodeAt(this.offset);
      if (!escaped && code === 0x22) { this.offset += 1; break; }
      if (!escaped && code === 0x5c) escaped = true;
      else escaped = false;
      if (code < 0x20) fail('invalid', 'control character in JSON string');
      this.offset += 1;
    }
    if (this.text.charCodeAt(this.offset - 1) !== 0x22) fail('invalid', 'unterminated JSON string');
    let value;
    try { value = JSON.parse(this.text.slice(start, this.offset)); } catch { fail('invalid', 'invalid JSON string'); }
    if (!unicodeOkay(value)) fail('invalid', 'JSON string is not Unicode');
    const maximum = key ? this.limits.maxJsonKeyUtf8Bytes : this.limits.maxStringUtf8Bytes;
    if (Buffer.byteLength(value, 'utf8') > maximum) fail('limit', 'JSON string ceiling exceeded');
    return value;
  }

  number() {
    const rest = this.text.slice(this.offset);
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(rest);
    if (!match) fail('invalid', 'invalid JSON number');
    this.offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value) || Number.isInteger(value) && !Number.isSafeInteger(value)) fail('invalid', 'number is outside I-JSON');
    return value;
  }

  array(depth) {
    this.offset += 1;
    const output = [];
    this.whitespace();
    if (this.text[this.offset] === ']') { this.offset += 1; return output; }
    while (true) {
      output.push(this.value(depth + 1));
      this.collectionItems += 1;
      if (output.length > this.limits.maxArrayItems || this.collectionItems > this.limits.maxJsonCollectionItems) fail('limit', 'JSON collection ceiling exceeded');
      this.whitespace();
      if (this.text[this.offset] === ']') { this.offset += 1; return output; }
      if (this.text[this.offset] !== ',') fail('invalid', 'invalid JSON array');
      this.offset += 1;
    }
  }

  object(depth) {
    this.offset += 1;
    const output = Object.create(null);
    const names = new Set();
    this.whitespace();
    if (this.text[this.offset] === '}') { this.offset += 1; return output; }
    while (true) {
      this.whitespace();
      if (this.text[this.offset] !== '"') fail('invalid', 'invalid JSON object name');
      const name = this.string(true);
      if (names.has(name)) fail('invalid', 'duplicate JSON object name');
      names.add(name);
      this.whitespace();
      if (this.text[this.offset] !== ':') fail('invalid', 'invalid JSON object separator');
      this.offset += 1;
      Object.defineProperty(output, name, { value: this.value(depth + 1), enumerable: true, configurable: true, writable: true });
      this.collectionItems += 1;
      if (names.size > this.limits.maxObjectMembers || this.collectionItems > this.limits.maxJsonCollectionItems) fail('limit', 'JSON collection ceiling exceeded');
      this.whitespace();
      if (this.text[this.offset] === '}') { this.offset += 1; return output; }
      if (this.text[this.offset] !== ',') fail('invalid', 'invalid JSON object');
      this.offset += 1;
    }
  }

  parse() {
    const value = this.value(0);
    this.whitespace();
    if (this.offset !== this.text.length) fail('invalid', 'trailing JSON data');
    return value;
  }
}

export function parseJson(input, overrides = {}) {
  const limits = boundedLimits(overrides);
  if (!(typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array)) fail('invalid', 'JSON input must be text or bytes');
  if (typeof input === 'string' && (!unicodeOkay(input) || input.length > limits.maxControlMessageBytes || Buffer.byteLength(input, 'utf8') > limits.maxControlMessageBytes)) fail('invalid', 'JSON text is not well-formed Unicode');
  const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array ? Buffer.from(input) : Buffer.from(input, 'utf8');
  if (bytes.length === 0) fail('invalid', 'JSON input is empty');
  if (bytes.length > limits.maxControlMessageBytes) fail('limit', 'JSON input byte ceiling exceeded');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail('invalid', 'JSON is not UTF-8'); }
  return new JsonReader(text, limits).parse();
}

export function parseCanonical(input, overrides = {}) {
  if (!(typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array)) fail('invalid', 'canonical JSON input must be text or bytes');
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  const value = parseJson(bytes, overrides);
  const text = new TextDecoder().decode(bytes);
  if (canonicalJson(value, overrides) !== text) fail('invalid', 'JSON is not canonical');
  return value;
}

async function readBounded(path, maximum, tooLargeKind = 'contract') {
  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const before = await handle.stat();
    if (!before.isFile() || before.size <= 0) fail('contract', 'contract asset is not a bounded regular file');
    if (before.size > maximum) fail(tooLargeKind, 'contract asset exceeds its receiver ceiling');
    const buffer = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, Math.min(65_536, buffer.length - offset), null);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) fail('contract', 'contract asset changed while reading');
    return buffer.subarray(0, offset);
  } catch (error) {
    if (error instanceof AdapterFault) throw error;
    fail('contract', 'contract asset cannot be read');
  } finally { await handle?.close().catch(() => {}); }
}

function mediaType(path) {
  if (path === 'LICENSE') return 'text/plain; charset=utf-8';
  if (path === 'README.md' || path.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (path.endsWith('.jsonl')) return 'application/jsonl';
  return 'application/json';
}

function pointer(root, fragment) {
  let current = root;
  for (const encoded of fragment.split('/').slice(1)) {
    const name = encoded.replaceAll('~1', '/').replaceAll('~0', '~');
    if (!current || typeof current !== 'object' || !Object.hasOwn(current, name)) fail('contract', 'schema reference is unresolved');
    current = current[name];
  }
  return current;
}

function sameValue(left, right) { return canonicalJson(left) === canonicalJson(right); }

export class IndependentSchemaSet {
  #byId = new Map();
  #byName = new Map();

  constructor(schemas) {
    const versions = new Set();
    for (const [name, schema] of Object.entries(schemas)) {
      if (!schema || typeof schema !== 'object' || Array.isArray(schema) || typeof schema.$id !== 'string' || this.#byName.has(name) || this.#byId.has(schema.$id)) fail('contract', 'schema identity is duplicated');
      const version = schema.properties?.schemaVersion?.const;
      if (typeof version === 'string') {
        if (versions.has(version)) fail('contract', 'schemaVersion selector is duplicated');
        versions.add(version);
      }
      this.#byName.set(name, schema);
      this.#byId.set(schema.$id, schema);
    }
    for (const schema of this.#byName.values()) this.#audit(schema, schema, new Set());
  }

  #resolve(reference, root) {
    if (reference.startsWith('#')) return { schema: pointer(root, reference.slice(1)), root };
    const [resource, fragment] = reference.split('#', 2);
    const name = basename(resource);
    const target = this.#byName.get(name) ?? this.#byId.get(resource);
    if (!target) fail('contract', 'schema reference is unavailable');
    return { schema: fragment === undefined ? target : pointer(target, fragment), root: target };
  }

  #audit(schema, root, seen) {
    if (!schema || typeof schema !== 'object' || Array.isArray(schema) || seen.has(schema)) return;
    seen.add(schema);
    if (schema.$ref !== undefined) this.#resolve(schema.$ref, root);
    for (const value of Object.values(schema)) {
      if (Array.isArray(value)) for (const child of value) this.#audit(child, root, seen);
      else this.#audit(value, root, seen);
    }
  }

  #matches(value, schema, root, state, depth) {
    state.steps += 1;
    if (state.steps > state.limit) fail('limit', 'schema evaluation ceiling exceeded');
    if (schema['x-ogvcs-maxDepth'] !== undefined || schema['x-ogvcs-maxNodes'] !== undefined) {
      inspectJson(value, {
        maxJsonDepth: Math.min(state.configured.maxJsonDepth, schema['x-ogvcs-maxDepth'] ?? FROZEN_LIMITS.maxJsonDepth),
        maxJsonNodes: Math.min(state.configured.maxJsonNodes, schema['x-ogvcs-maxNodes'] ?? FROZEN_LIMITS.maxJsonNodes),
      });
    }
    if (schema.$ref !== undefined) {
      const resolved = this.#resolve(schema.$ref, root);
      if (!this.#matches(value, resolved.schema, resolved.root, state, depth + 1)) return false;
    }
    if (schema.const !== undefined && !sameValue(value, schema.const)) return false;
    if (schema.enum !== undefined && !schema.enum.some((item) => sameValue(value, item))) return false;
    if (schema.type !== undefined) {
      const valid = schema.type === 'null' ? value === null
        : schema.type === 'boolean' ? typeof value === 'boolean'
          : schema.type === 'integer' ? Number.isSafeInteger(value)
            : schema.type === 'number' ? typeof value === 'number' && Number.isFinite(value)
              : schema.type === 'string' ? typeof value === 'string'
                : schema.type === 'array' ? Array.isArray(value)
                  : schema.type === 'object' ? value !== null && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
                    : false;
      if (!valid) return false;
    }
    if (typeof value === 'number') {
      if (schema.minimum !== undefined && value < schema.minimum || schema.maximum !== undefined && value > schema.maximum) return false;
    }
    if (typeof value === 'string') {
      const length = [...value].length;
      if (schema.minLength !== undefined && length < schema.minLength || schema.maxLength !== undefined && length > schema.maxLength) return false;
      if (schema['x-ogvcs-maxUtf8Bytes'] !== undefined && Buffer.byteLength(value, 'utf8') > schema['x-ogvcs-maxUtf8Bytes']) return false;
      if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) return false;
    }
    if (Array.isArray(value)) {
      if (schema.minItems !== undefined && value.length < schema.minItems || schema.maxItems !== undefined && value.length > schema.maxItems) return false;
      if (schema.uniqueItems === true && new Set(value.map((item) => canonicalJson(item))).size !== value.length) return false;
      if (schema.items !== undefined && value.some((item) => !this.#matches(item, schema.items, root, state, depth + 1))) return false;
    }
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      const keys = Object.keys(value);
      if (schema.minProperties !== undefined && keys.length < schema.minProperties || schema.maxProperties !== undefined && keys.length > schema.maxProperties) return false;
      if (schema.required !== undefined && schema.required.some((name) => !Object.hasOwn(value, name))) return false;
      for (const name of keys) {
        if (schema.propertyNames !== undefined && !this.#matches(name, schema.propertyNames, root, state, depth + 1)) return false;
        if (schema.properties && Object.hasOwn(schema.properties, name)) {
          if (!this.#matches(value[name], schema.properties[name], root, state, depth + 1)) return false;
        } else if (schema.additionalProperties === false) return false;
        else if (schema.additionalProperties && typeof schema.additionalProperties === 'object' && !this.#matches(value[name], schema.additionalProperties, root, state, depth + 1)) return false;
      }
    }
    if (schema.allOf !== undefined && schema.allOf.some((child) => !this.#matches(value, child, root, state, depth + 1))) return false;
    if (schema.anyOf !== undefined && !schema.anyOf.some((child) => this.#matches(value, child, root, state, depth + 1))) return false;
    if (schema.oneOf !== undefined && schema.oneOf.filter((child) => this.#matches(value, child, root, state, depth + 1)).length !== 1) return false;
    if (schema.not !== undefined && this.#matches(value, schema.not, root, state, depth + 1)) return false;
    if (schema.if !== undefined) {
      const condition = this.#matches(value, schema.if, root, state, depth + 1);
      if (condition && schema.then !== undefined && !this.#matches(value, schema.then, root, state, depth + 1)) return false;
      if (!condition && schema.else !== undefined && !this.#matches(value, schema.else, root, state, depth + 1)) return false;
    }
    return true;
  }

  validate(value, selector, options = {}) {
    const schema = typeof selector === 'string' ? this.#byName.get(basename(selector)) ?? this.#byId.get(selector) : selector;
    if (!schema) fail('contract', 'requested public schema is unavailable');
    inspectJson(value, options.configuredLimits ?? {});
    const limit = options.configuredLimits?.maxSchemaEvaluationSteps ?? FROZEN_LIMITS.maxSchemaEvaluationSteps;
    if (!this.#matches(value, schema, schema, { steps: 0, limit, configured: boundedLimits(options.configuredLimits ?? {}) }, 0)) fail('invalid', 'value does not satisfy its public schema');
    return value;
  }
}

function genericRegistry(name, value, limits) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.version !== 1 || value.license !== 'MIT') fail('contract', 'registry envelope is invalid');
  if (name === 'field-assignments') {
    if (value.schemaVersion !== 'ogvcs.protocol/field-assignments/v1' || !Array.isArray(value.messages) || value.messages.length > limits.maxRegistryEntries) fail('contract', 'field assignment registry is invalid');
    return;
  }
  if (value.schemaVersion !== 'ogvcs.protocol/registry/v1' || value.registry !== name) fail('contract', 'registry identity is invalid');
  if (!Array.isArray(value.entries) || value.entries.length > limits.maxRegistryEntries) fail('contract', 'registry entry ceiling exceeded');
}

function validateAuthority(manifest, assets, limits) {
  if (manifest.schemaVersion !== 'ogvcs.protocol/contract-manifest/v1' || manifest.packageName !== '@opengamevcs/protocol-contract-v1' || manifest.contractVersion !== '1.0.0-rc.1' || manifest.license !== 'MIT' || !manifest.predecessorPins || !manifest.counts) fail('contract', 'contract manifest identity is invalid');
  const registries = {};
  const schemas = {};
  for (const name of REQUIRED_REGISTRIES) {
    const value = assets[`registries/${name}.json`];
    genericRegistry(name, value, limits);
    registries[name] = value;
  }
  for (const [path, value] of Object.entries(assets)) if (path.startsWith('schemas/')) schemas[path.slice(8)] = value;
  if (Object.keys(schemas).length !== manifest.counts.schemas || Object.keys(registries).length !== manifest.counts.registries) fail('contract', 'contract schema or registry inventory count is invalid');
  const schemaRows = registries.schemas.entries;
  if (!Array.isArray(schemaRows) || schemaRows.length !== Object.keys(schemas).length) fail('contract', 'schema registry is invalid');
  for (const row of schemaRows) {
    const schema = schemas[basename(row.path ?? '')];
    if (!schema || row.sha256 !== sha256(Buffer.from(canonicalJson(schema))) || schema.$id !== row.id) fail('contract', 'schema registry assignment is invalid');
  }
  const limitRows = registries.limits.entries;
  if (!Array.isArray(limitRows) || limitRows.length !== Object.keys(FROZEN_LIMITS).length) fail('contract', 'limit registry count is invalid');
  for (const row of limitRows) if (!Object.hasOwn(FROZEN_LIMITS, row.name) || FROZEN_LIMITS[row.name] !== row.value) fail('contract', 'limit registry assignment is invalid');
  if (registries.compatibility.predecessorPins === undefined || canonicalJson(registries.compatibility.predecessorPins) !== canonicalJson(manifest.predecessorPins)) fail('contract', 'compatibility predecessor pins are invalid');
  return { registries, schemas, validator: new IndependentSchemaSet(schemas) };
}

export async function loadAuthority(rootInput, options = {}) {
  if (typeof rootInput !== 'string' || rootInput.length === 0 || rootInput.length > 16_384 || rootInput.includes('\0')) fail('invalid', 'contract root is invalid');
  const maxContractArtifacts = options.maxContractArtifacts ?? FROZEN_LIMITS.maxContractArtifacts;
  const maxContractBytes = options.maxContractBytes ?? FROZEN_LIMITS.maxContractBytes;
  const maxWorkingMemoryBytes = options.maxWorkingMemoryBytes ?? FROZEN_LIMITS.maxWorkingMemoryBytes;
  for (const [name, value] of Object.entries({ maxContractArtifacts, maxContractBytes, maxWorkingMemoryBytes })) {
    if (!Number.isSafeInteger(value) || value < 1 || value > FROZEN_LIMITS[name]) fail('invalid', 'contract receiver ceiling is invalid');
  }
  const root = `${resolve(rootInput)}${sep}`;
  let manifestBytes = await readBounded(resolve(root, 'manifest.json'), Math.min(MANIFEST_MAX_BYTES, Math.max(0, Math.floor((maxWorkingMemoryBytes - 128) / 4))), 'limit');
  const manifest = parseCanonical(manifestBytes);
  const manifestSha256 = sha256(manifestBytes);
  let workingMemoryBytes = manifestBytes.length * 4 + 128;
  manifestBytes = undefined;
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length < 1) fail('contract', 'contract artifact inventory is invalid');
  if (manifest.artifacts.length > maxContractArtifacts) fail('limit', 'contract artifact inventory exceeds its receiver ceiling');
  let totalBytes = Buffer.byteLength(canonicalJson(manifest));
  if (totalBytes > maxContractBytes) fail('limit', 'contract byte ceiling exceeded');
  const executionViewBytes = await readBounded(resolve(root, 'adapter-execution-view.json'), MANIFEST_MAX_BYTES);
  const executionViewBinding = manifest.adapterExecutionView;
  if (executionViewBinding !== undefined && (executionViewBinding?.path !== 'adapter-execution-view.json'
      || executionViewBinding.bytes !== executionViewBytes.length
      || executionViewBinding.sha256 !== sha256(executionViewBytes))) fail('contract', 'adapter execution view manifest binding is invalid');
  if (totalBytes + executionViewBytes.length > maxContractBytes) fail('limit', 'contract byte ceiling exceeded');
  const viewReservation = executionViewBytes.length * 4 + 128;
  if (workingMemoryBytes + viewReservation > maxWorkingMemoryBytes) fail('limit', 'adapter execution view exceeds working-memory ceiling');
  const executionView = parseCanonical(executionViewBytes);
  if (executionView.schemaVersion !== 'ogvcs.protocol/adapter-execution-view/v1'
      || executionView.contractManifestPath !== 'manifest.json'
      || executionView.contractVersion !== manifest.contractVersion
      || executionView.license !== 'MIT'
      || !Array.isArray(executionView.authorityArtifacts)
      || canonicalJson(executionView.predecessorPins) !== canonicalJson(manifest.predecessorPins)
      || executionView.authoritySetSha256 !== executionViewBinding?.authoritySetSha256
      || canonicalJson(executionView.excludedNamespaces) !== '["docs/","vectors/"]') fail('contract', 'adapter execution view is invalid');
  const expectedAuthority = manifest.artifacts
    .filter((entry) => /^(?:profiles|registries|schemas)\//u.test(entry.path))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const suppliedAuthority = [...executionView.authorityArtifacts]
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  if (canonicalJson(suppliedAuthority) !== canonicalJson(expectedAuthority)) fail('contract', 'adapter execution view authority inventory is not exact');
  const paths = new Set();
  totalBytes += executionViewBytes.length;
  workingMemoryBytes += viewReservation;
  const assets = Object.create(null);
  const manifestByPath = new Map(manifest.artifacts.map((entry) => [entry.path, entry]));
  for (const entry of executionView.authorityArtifacts) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.path !== 'string' || !SAFE_PATH.test(entry.path) || paths.has(entry.path) || entry.mediaType !== mediaType(entry.path) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || entry.bytes > FROZEN_LIMITS.maxContractBytes || !/^[0-9a-f]{64}$/u.test(entry.sha256 ?? '')) fail('contract', 'contract artifact descriptor is invalid');
    const manifested = manifestByPath.get(entry.path);
    if (!manifested || canonicalJson(manifested) !== canonicalJson(entry)) fail('contract', 'execution authority is not bound by the contract manifest');
    paths.add(entry.path);
    totalBytes += entry.bytes;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > maxContractBytes) fail('limit', 'contract byte ceiling exceeded');
    const parsed = entry.mediaType === 'application/json';
    const reservation = parsed ? entry.bytes * 4 + 128 : 0;
    if (!Number.isSafeInteger(reservation) || workingMemoryBytes + reservation > maxWorkingMemoryBytes) fail('limit', 'contract retained graph exceeds working-memory ceiling');
    const maxLiveBytes = parsed ? Math.max(0, Math.floor((maxWorkingMemoryBytes - workingMemoryBytes - 128) / 4)) : maxWorkingMemoryBytes - workingMemoryBytes;
    const bytes = await readBounded(resolve(root, entry.path), Math.min(entry.bytes, maxLiveBytes), 'limit');
    if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) fail('contract', 'contract artifact digest is invalid');
    if (parsed) {
      assets[entry.path] = parseCanonical(bytes);
      workingMemoryBytes += reservation;
    }
  }
  const authorityRecords = [...paths].map((path) => ({ path, sha256: manifestByPath.get(path).sha256 })).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  if (sha256(Buffer.from(canonicalJson(authorityRecords))) !== executionView.authoritySetSha256) fail('contract', 'adapter execution authority digest is invalid');
  const limits = Object.fromEntries(assets['registries/limits.json'].entries.map((row) => [row.name, row.value]));
  if (Object.keys(limits).length !== Object.keys(FROZEN_LIMITS).length) fail('contract', 'contract limit authority is invalid');
  const validated = validateAuthority(manifest, assets, limits);
  return Object.freeze({ root, manifest, manifestSha256, executionView, assets, limits: Object.freeze(limits), totalBytes, workingMemoryBytes, ...validated });
}

export function configuredLimits(value) {
  if (value === undefined) return Object.freeze({});
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid', 'configuredLimits is invalid');
  boundedLimits(value);
  return Object.freeze(Object.fromEntries(Object.entries(value)));
}
