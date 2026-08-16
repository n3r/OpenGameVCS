#!/usr/bin/env node
// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
// Independent validator: deliberately does not import the protocol generator/model.

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPOSITORY_ROOT = path.resolve(HERE, "../../..");
const DEFAULT_SPEC_ROOT = HERE;
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";
const VECTOR_CATEGORIES = ["cursors", "envelopes", "idempotency", "malformed", "negotiation", "release", "resources", "security", "streams", "transfer"];
const OPERATIONS = new Set(["negotiate", "validate-envelope", "fingerprint", "validate-cursor", "validate-stream", "transfer-probe", "contract-load", "runner-batch", "release-preflight"]);
const INPUT_KINDS = new Set(["semantic-value", "raw-json", "raw-bytes", "jsonl"]);
const UNSAFE_ERROR_MEMBERS = new Set(["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "currentGeneration"]);
const ALLOWED_SCENARIO_KEYS = new Set(["schemaVersion", "id", "category", "operation", "inputKind", "input", "control", "configuredLimits", "expected", "requirementIds", "forbiddenResponseFields", "resourceWitness", "hiddenMarkerValues", "hiddenServerInputs", "predecessorCase"]);
const ALLOWED_EXPECTED_KEYS = new Set(["result", "code", "preMutation", "mutationCount", "semanticDigest", "traceDigest"]);
const RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN = "ogvcs.protocol/release-assignment-semantics/v1";
const RELEASE_COMPATIBILITY_POLICY = "immutable-code-name-scope-semantics-no-removal-unique-registered-optional-candidate-additions";
const DERIVED_REQUEST_ROOT_CONTEXT_FIELDS = Object.freeze({
  "wrong-audience": ["audience"],
  expired: ["now"],
  "stale-epoch": ["authorityEpoch"],
  "stale-key-generation": ["keyGeneration"],
  "stale-key-id": ["keyId"],
  "wrong-repository": ["repository"],
  "altered-claims": [],
  "wrong-subject": ["subject"],
  "wrong-issuer": ["issuer"],
  "wrong-operation": ["operation", "permission"],
  replayed: [],
});

function fail(message) {
  throw new Error(`protocol contract invalid: ${message}`);
}

function check(condition, message) {
  if (!condition) fail(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function checkUnicode(value, location) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      check(next >= 0xdc00 && next <= 0xdfff, `${location} contains an unpaired high surrogate`);
      index += 1;
    } else check(!(unit >= 0xdc00 && unit <= 0xdfff), `${location} contains an unpaired low surrogate`);
  }
}

function canonical(value, location = "$", active = new Set()) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") { checkUnicode(value, location); return JSON.stringify(value); }
  if (typeof value === "number") {
    check(Number.isFinite(value) && Number.isSafeInteger(value), `${location} is not a finite safe integer`);
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  check(typeof value === "object", `${location} contains unsupported ${typeof value}`);
  check(!active.has(value), `${location} is cyclic`);
  active.add(value);
  if (Array.isArray(value)) {
    const result = `[${value.map((entry, index) => canonical(entry, `${location}[${index}]`, active)).join(",")}]`;
    active.delete(value);
    return result;
  }
  check(Object.getPrototypeOf(value) === Object.prototype, `${location} is not a plain object`);
  const result = `{${Object.keys(value).sort().map((key) => {
    checkUnicode(key, `${location} key`);
    check(value[key] !== undefined, `${location}.${key} is undefined`);
    return `${JSON.stringify(key)}:${canonical(value[key], `${location}.${key}`, active)}`;
  }).join(",")}}`;
  active.delete(value);
  return result;
}

function canonicalDigest(value) {
  return sha256(Buffer.from(canonical(value), "utf8"));
}

function semanticFingerprint(domain, value) {
  return sha256(Buffer.concat([Buffer.from(`${domain}\0`, "utf8"), Buffer.from(canonical(value), "utf8")]));
}

function withoutKeys(value, excluded) {
  return Object.fromEntries(Object.entries(value).filter(([name]) => !excluded.includes(name)));
}

function releaseAssignment(identity, policy) {
  return {
    ...identity,
    semanticSha256: semanticFingerprint(RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN, { ...identity, policy }),
  };
}

function declarativeTypeFromSchema(schema, location) {
  if (schema?.$ref === "#/$defs/JsonValue") return {
    kind: "json",
    maxDepth: schema["x-ogvcs-maxDepth"],
    maxNodes: schema["x-ogvcs-maxNodes"],
  };
  if (typeof schema?.$ref === "string") return { kind: "reference", name: schema.$ref.replace(/\.schema\.json$/u, "") };
  if (schema?.type === "boolean") return schema.const === undefined ? { kind: "boolean" } : { kind: "boolean", const: schema.const };
  if (Object.hasOwn(schema ?? {}, "const")) return { kind: "enum", values: [schema.const] };
  if (Array.isArray(schema?.enum)) return { kind: "enum", values: schema.enum };
  if (schema?.type === "string") {
    const output = { kind: "string", minLength: schema.minLength, maxLength: schema.maxLength };
    if (schema.pattern !== undefined) output.pattern = schema.pattern;
    if (schema.format !== undefined) output.format = schema.format;
    if (schema["x-ogvcs-maxUtf8Bytes"] !== undefined) output.maxUtf8Bytes = schema["x-ogvcs-maxUtf8Bytes"];
    return output;
  }
  if (schema?.type === "integer") return { kind: "integer", minimum: schema.minimum, maximum: schema.maximum };
  if (schema?.type === "array") {
    const output = {
      kind: "array",
      items: declarativeTypeFromSchema(schema.items, `${location}[]`),
      minItems: schema.minItems,
      maxItems: schema.maxItems,
    };
    if (schema.uniqueItems !== undefined) output.uniqueItems = schema.uniqueItems;
    return output;
  }
  if (schema?.type === "object" && schema.additionalProperties && typeof schema.additionalProperties === "object") return {
    kind: "map",
    values: declarativeTypeFromSchema(schema.additionalProperties, `${location}{}`),
    minProperties: schema.minProperties,
    maxProperties: schema.maxProperties,
    keyPattern: schema.propertyNames?.pattern,
    maxKeyUtf8Bytes: schema.propertyNames?.["x-ogvcs-maxUtf8Bytes"],
  };
  fail(`${location} cannot be normalized into release semantics`);
}

function expectedReleaseAssignments(schemaSummary, limits, errors, capabilities, extensions) {
  const output = [];
  for (const message of schemaSummary.assignmentDoc.messages) {
    const schema = schemaSummary.schemaDocuments.get(`${message.name}.schema.json`);
    const messageConstraints = schema["x-ogvcs-semantic-constraints"] ?? [];
    output.push(releaseAssignment(
      { kind: "message", scope: "protocol", name: message.name, code: message.code },
      { closed: true, constraints: messageConstraints, reservedFields: message.reservedFields ?? [] },
    ));
    for (const field of message.fields) output.push(releaseAssignment(
      { kind: "field", scope: message.name, name: field.name, code: field.id },
      {
        type: declarativeTypeFromSchema(schema.properties[field.name], `${message.name}.${field.name}`),
        required: field.required,
        presence: field.presence,
        fingerprint: field.fingerprint,
        sensitive: field.sensitive,
        messageConstraints,
      },
    ));
  }
  for (const entry of limits.entries) output.push(releaseAssignment(
    { kind: "limit", scope: "protocol", name: entry.name, code: entry.code },
    withoutKeys(entry, ["code", "name"]),
  ));
  for (const entry of errors.entries) output.push(releaseAssignment(
    { kind: "error", scope: "protocol", name: entry.name, code: entry.code },
    {
      ...withoutKeys(entry, ["code", "name"]),
      parameterDomains: Object.fromEntries(entry.safeParameters.map((name) => [name, errors.parameterDomains[name]])),
    },
  ));
  for (const entry of capabilities.entries) output.push(releaseAssignment(
    { kind: "capability", scope: entry.axis, name: entry.id, code: entry.code },
    withoutKeys(entry, ["code", "id"]),
  ));
  for (const entry of extensions.entries) output.push(releaseAssignment(
    { kind: "extension", scope: "extension-registry", name: entry.id, code: entry.code },
    withoutKeys(entry, ["code", "id"]),
  ));
  return new Map(output.map((entry) => [`${entry.kind}\0${entry.scope}\0${entry.name}`, entry]));
}

async function readCanonicalJson(filePath, label = filePath) {
  const bytes = await fs.readFile(filePath);
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (error) { fail(`${label} is not JSON: ${error.message}`); }
  const expected = Buffer.from(canonical(value), "utf8");
  check(bytes.equals(expected), `${label} is not RFC 8785 canonical JSON`);
  return { bytes, value };
}

function relativeIsSafe(relativePath) {
  return typeof relativePath === "string" && relativePath.length > 0 && !path.isAbsolute(relativePath) && !relativePath.split("/").includes("..") && relativePath === relativePath.replaceAll("\\", "/");
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function artifactSetDigest(artifacts) {
  return canonicalDigest(artifacts.map(({ path: artifactPath, sha256: digest }) => ({ path: artifactPath, sha256: digest })));
}

async function listFiles(root, relativeRoot = "") {
  const start = path.join(root, relativeRoot);
  let entries;
  try { entries = await fs.readdir(start, { withFileTypes: true }); } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const result = [];
  for (const entry of entries.sort((left, right) => compareText(left.name, right.name))) {
    if (["target", "build", "bin", "obj", "node_modules"].includes(entry.name)) continue;
    const relativePath = path.posix.join(relativeRoot.replaceAll("\\", "/"), entry.name);
    if (entry.isDirectory()) result.push(...await listFiles(root, relativePath));
    else if (entry.isFile()) result.push(relativePath);
    else fail(`${relativePath} is not a regular file`);
  }
  return result;
}

async function validateArtifactInventory(root, artifacts, actualPaths, label) {
  check(Array.isArray(artifacts) && artifacts.length > 0, `${label} artifact inventory is empty`);
  const seen = new Set();
  let prior = "";
  for (const artifact of artifacts) {
    check(relativeIsSafe(artifact.path), `${label} has unsafe artifact path ${String(artifact.path)}`);
    check(!seen.has(artifact.path), `${label} repeats artifact ${artifact.path}`);
    check(compareText(prior, artifact.path) <= 0, `${label} artifact order is not canonical`);
    check(Number.isSafeInteger(artifact.bytes) && artifact.bytes >= 0, `${artifact.path} byte count is invalid`);
    check(/^[0-9a-f]{64}$/.test(artifact.sha256), `${artifact.path} digest is invalid`);
    check(typeof artifact.mediaType === "string" && artifact.mediaType.length > 0, `${artifact.path} media type is missing`);
    const bytes = await fs.readFile(path.join(root, artifact.path));
    check(bytes.length === artifact.bytes, `${artifact.path} byte count differs`);
    check(sha256(bytes) === artifact.sha256, `${artifact.path} digest differs`);
    if (artifact.path.endsWith(".json")) await readCanonicalJson(path.join(root, artifact.path), artifact.path);
    seen.add(artifact.path);
    prior = artifact.path;
  }
  check([...actualPaths].sort().join("\0") === [...seen].sort().join("\0"), `${label} inventory differs from distributed files`);
}

function localPointerExists(root, reference) {
  if (reference === "#") return true;
  if (!reference.startsWith("#/")) return false;
  let current = root;
  for (const raw of reference.slice(2).split("/")) {
    const part = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!current || typeof current !== "object" || !Object.hasOwn(current, part)) return false;
    current = current[part];
  }
  return true;
}

function walkSchema(node, location, schemaNames, depth = 0, root = node) {
  check(depth <= 128, `${location} schema nesting is excessive`);
  if (typeof node === "boolean") return;
  check(node && typeof node === "object" && !Array.isArray(node), `${location} schema node is not an object`);
  if (node.$ref !== undefined) {
    check(typeof node.$ref === "string", `${location} has non-string $ref`);
    if (node.$ref.startsWith("#")) check(localPointerExists(root, node.$ref), `${location} references missing local schema ${node.$ref}`);
    else check(schemaNames.has(node.$ref), `${location} references missing schema ${node.$ref}`);
  }
  if (node.type === "string") check(Number.isSafeInteger(node.maxLength) && node.maxLength >= 0, `${location} string is unbounded`);
  if (node.type === "array") check(Number.isSafeInteger(node.maxItems) && node.maxItems >= 0 && node.items !== undefined, `${location} array is unbounded`);
  if (node.type === "object") {
    check(node.additionalProperties === false || (node.additionalProperties && typeof node.additionalProperties === "object" && Number.isSafeInteger(node.maxProperties)), `${location} object is open or unbounded`);
  }
  if (node.type === "integer") check(Number.isSafeInteger(node.minimum) && Number.isSafeInteger(node.maximum) && node.minimum >= -MAX_SAFE && node.maximum <= MAX_SAFE, `${location} integer bounds are unsafe`);
  for (const [key, value] of Object.entries(node)) {
    if (["description", "title", "$id", "$schema", "$ref", "pattern", "format"].includes(key) || key.startsWith("x-ogvcs-")) continue;
    if (Array.isArray(value)) value.forEach((entry, index) => {
      if (entry && typeof entry === "object") walkSchema(entry, `${location}.${key}[${index}]`, schemaNames, depth + 1, root);
    });
    else if (value && typeof value === "object") {
      if (["properties", "$defs"].includes(key)) for (const [name, entry] of Object.entries(value)) walkSchema(entry, `${location}.${key}.${name}`, schemaNames, depth + 1, root);
      else if (["items", "additionalProperties", "propertyNames", "if", "then", "else", "not"].includes(key)) walkSchema(value, `${location}.${key}`, schemaNames, depth + 1, root);
    }
  }
}

function jsonEqual(left, right) {
  if (Object.is(left, right)) return true;
  if (typeof left !== typeof right || left === null || right === null || typeof left !== "object") return false;
  if (Array.isArray(left) !== Array.isArray(right)) return false;
  if (Array.isArray(left)) return left.length === right.length && left.every((entry, index) => jsonEqual(entry, right[index]));
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && jsonEqual(left[key], right[key]));
}

function jsonShapeWithin(value, maxDepth, maxNodes) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > maxNodes || current.depth > maxDepth) return false;
    if (typeof current.value === "string") {
      try { checkUnicode(current.value, "schema instance"); } catch { return false; }
    } else if (typeof current.value === "number" && (!Number.isSafeInteger(current.value) || !Number.isFinite(current.value))) return false;
    else if (current.value !== null && typeof current.value === "object") {
      if (Array.isArray(current.value)) {
        for (let index = current.value.length - 1; index >= 0; index -= 1) stack.push({ value: current.value[index], depth: current.depth + 1 });
      } else {
        if (Object.getPrototypeOf(current.value) !== Object.prototype) return false;
        for (const key of Object.keys(current.value)) {
          try { checkUnicode(key, "schema instance key"); } catch { return false; }
          stack.push({ value: current.value[key], depth: current.depth + 1 });
        }
      }
    } else if (!["boolean", "string", "number"].includes(typeof current.value) && current.value !== null) return false;
  }
  return true;
}

function resolveSchemaReference(reference, rootSchema, schemas) {
  let document = rootSchema;
  let fragment = reference;
  if (!reference.startsWith("#")) {
    const separator = reference.indexOf("#");
    const fileName = separator === -1 ? reference : reference.slice(0, separator);
    document = schemas.get(fileName);
    fragment = separator === -1 ? "#" : reference.slice(separator);
  }
  if (!document) return undefined;
  if (fragment === "#" || fragment === "") return { schema: document, root: document };
  if (!fragment.startsWith("#/")) return undefined;
  let target = document;
  for (const raw of fragment.slice(2).split("/")) {
    const part = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    if (!target || typeof target !== "object" || !Object.hasOwn(target, part)) return undefined;
    target = target[part];
  }
  return { schema: target, root: document };
}

function schemaMatches(value, schema, schemas, rootSchema = schema, budget = { steps: 0 }) {
  budget.steps += 1;
  if (budget.steps > 1_000_000) return false;
  if (typeof schema === "boolean") return schema;
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return false;
  if (schema.$ref !== undefined) {
    const resolved = resolveSchemaReference(schema.$ref, rootSchema, schemas);
    if (!resolved || !schemaMatches(value, resolved.schema, schemas, resolved.root, budget)) return false;
  }
  if (schema.const !== undefined && !jsonEqual(value, schema.const)) return false;
  if (schema.enum !== undefined && !schema.enum.some((entry) => jsonEqual(value, entry))) return false;
  if (schema.allOf !== undefined && !schema.allOf.every((branch) => schemaMatches(value, branch, schemas, rootSchema, budget))) return false;
  if (schema.anyOf !== undefined && !schema.anyOf.some((branch) => schemaMatches(value, branch, schemas, rootSchema, budget))) return false;
  if (schema.oneOf !== undefined && schema.oneOf.filter((branch) => schemaMatches(value, branch, schemas, rootSchema, budget)).length !== 1) return false;
  if (schema.not !== undefined && schemaMatches(value, schema.not, schemas, rootSchema, budget)) return false;
  if (schema.if !== undefined) {
    const condition = schemaMatches(value, schema.if, schemas, rootSchema, budget);
    if (condition && schema.then !== undefined && !schemaMatches(value, schema.then, schemas, rootSchema, budget)) return false;
    if (!condition && schema.else !== undefined && !schemaMatches(value, schema.else, schemas, rootSchema, budget)) return false;
  }
  if (schema["x-ogvcs-maxDepth"] !== undefined || schema["x-ogvcs-maxNodes"] !== undefined) {
    if (!jsonShapeWithin(value, schema["x-ogvcs-maxDepth"] ?? MAX_SAFE, schema["x-ogvcs-maxNodes"] ?? MAX_SAFE)) return false;
  }
  if (schema.type !== undefined) {
    const validType = schema.type === "null" ? value === null
      : schema.type === "boolean" ? typeof value === "boolean"
      : schema.type === "integer" ? Number.isSafeInteger(value)
      : schema.type === "string" ? typeof value === "string"
      : schema.type === "array" ? Array.isArray(value)
      : schema.type === "object" ? value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype
      : false;
    if (!validType) return false;
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) return false;
    if (schema.maximum !== undefined && value > schema.maximum) return false;
  }
  if (typeof value === "string") {
    const scalarLength = [...value].length;
    if (schema.minLength !== undefined && scalarLength < schema.minLength) return false;
    if (schema.maxLength !== undefined && scalarLength > schema.maxLength) return false;
    if (schema["x-ogvcs-maxUtf8Bytes"] !== undefined && Buffer.byteLength(value, "utf8") > schema["x-ogvcs-maxUtf8Bytes"]) return false;
    if (schema.pattern !== undefined && !(new RegExp(schema.pattern, "u")).test(value)) return false;
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) return false;
    if (schema.maxItems !== undefined && value.length > schema.maxItems) return false;
    if (schema.uniqueItems === true && value.some((entry, index) => value.slice(0, index).some((prior) => jsonEqual(entry, prior)))) return false;
    if (schema.items !== undefined && !value.every((entry) => schemaMatches(entry, schema.items, schemas, rootSchema, budget))) return false;
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) return false;
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) return false;
    if (schema.required !== undefined && !schema.required.every((name) => Object.hasOwn(value, name))) return false;
    if (schema.propertyNames !== undefined && !keys.every((name) => schemaMatches(name, schema.propertyNames, schemas, rootSchema, budget))) return false;
    if (schema.properties !== undefined) {
      for (const [name, propertySchema] of Object.entries(schema.properties)) if (Object.hasOwn(value, name) && !schemaMatches(value[name], propertySchema, schemas, rootSchema, budget)) return false;
    }
    const extras = keys.filter((name) => !Object.hasOwn(schema.properties ?? {}, name));
    if (schema.additionalProperties === false && extras.length > 0) return false;
    if (schema.additionalProperties && typeof schema.additionalProperties === "object" && !extras.every((name) => schemaMatches(value[name], schema.additionalProperties, schemas, rootSchema, budget))) return false;
  }
  return true;
}

function normalizedSchemaFieldType(schema) {
  if (typeof schema?.$ref === "string") return schema.$ref === "#/$defs/JsonValue" ? "json" : "reference";
  if (schema?.type === "array") return `array<${normalizedSchemaFieldType(schema.items)}>`;
  if (schema?.type === "object" && schema.additionalProperties && typeof schema.additionalProperties === "object") return `map<${normalizedSchemaFieldType(schema.additionalProperties)}>`;
  if (["string", "integer", "boolean"].includes(schema?.type)) return schema.type;
  const values = schema?.enum ?? (Object.hasOwn(schema ?? {}, "const") ? [schema.const] : undefined);
  if (Array.isArray(values) && values.length > 0) return `enum<${typeof values[0] === "number" ? "integer" : "string"}>`;
  fail("field schema has no normalized protocol type");
}

function schemaFieldReference(schema) {
  if (typeof schema?.$ref === "string") return schema.$ref === "#/$defs/JsonValue" ? null : schema.$ref.replace(/\.schema\.json$/u, "");
  if (schema?.type === "array") return schemaFieldReference(schema.items);
  if (schema?.type === "object" && schema.additionalProperties && typeof schema.additionalProperties === "object") return schemaFieldReference(schema.additionalProperties);
  return null;
}

async function validateSchemasAndAssignments(specRoot) {
  const assignmentDoc = (await readCanonicalJson(path.join(specRoot, "registries/field-assignments.json"))).value;
  check(assignmentDoc.schemaVersion === "ogvcs.protocol/field-assignments/v1" && assignmentDoc.version === 1 && assignmentDoc.license === "MIT", "field assignment header is invalid");
  check(Array.isArray(assignmentDoc.messages) && assignmentDoc.messages.length > 0, "field assignments have no messages");
  const messageCodes = new Set();
  const messageNames = new Set();
  const schemaDocuments = new Map();
  const schemaNames = new Set(assignmentDoc.messages.map((message) => `${message.name}.schema.json`));
  const schemaVersionSelectors = new Map();
  const descriptors = { messages: [], fields: [] };
  let fieldCount = 0;
  for (const message of assignmentDoc.messages) {
    check(Number.isInteger(message.code) && message.code > 0 && !messageCodes.has(message.code), `message code ${message.code} is invalid or reused`);
    check(/^[A-Za-z][A-Za-z0-9]*$/.test(message.name) && !messageNames.has(message.name), `message name ${message.name} is invalid or reused`);
    const schemaPath = path.join(specRoot, `schemas/${message.name}.schema.json`);
    const schema = (await readCanonicalJson(schemaPath)).value;
    schemaDocuments.set(`${message.name}.schema.json`, schema);
    check(schema.$schema === JSON_SCHEMA_DIALECT, `${message.name} uses the wrong JSON Schema dialect`);
    check(schema.$id === `https://schemas.opengamevcs.dev/protocol/v1/${message.name}.schema.json`, `${message.name} $id is invalid`);
    check(schema.type === "object" && schema.additionalProperties === false, `${message.name} root is not closed`);
    check(schema["x-ogvcs-message-code"] === message.code, `${message.name} message assignment differs`);
    check(schema["x-ogvcs-license"] === "MIT", `${message.name} license marker differs`);
    const selector = schema.required.includes("schemaVersion") ? schema.properties?.schemaVersion?.const : undefined;
    if (typeof selector === "string") {
      check(!schemaVersionSelectors.has(selector), `${message.name} reuses schemaVersion selector ${selector} from ${schemaVersionSelectors.get(selector)}`);
      schemaVersionSelectors.set(selector, message.name);
    }
    const fields = new Set();
    const ids = new Set();
    descriptors.messages.push({ code: message.code, name: message.name, fieldCount: message.fields.length });
    for (const field of message.fields) {
      check(Number.isInteger(field.id) && field.id > 0 && !ids.has(field.id), `${message.name} field id ${field.id} is invalid or reused`);
      check(/^[A-Za-z][A-Za-z0-9]*$/.test(field.name) && !fields.has(field.name), `${message.name}.${field.name} is invalid or reused`);
      const property = schema.properties?.[field.name];
      check(property && property["x-ogvcs-field-id"] === field.id, `${message.name}.${field.name} schema assignment differs`);
      check(property["x-ogvcs-sensitive"] === field.sensitive && property["x-ogvcs-fingerprint"] === field.fingerprint, `${message.name}.${field.name} policy differs`);
      check(schema.required.includes(field.name) === field.required, `${message.name}.${field.name} required policy differs`);
      const normalizedType = normalizedSchemaFieldType(property);
      const reference = schemaFieldReference(property);
      check(field.presence === (field.required ? "required" : "optional"), `${message.name}.${field.name} presence differs`);
      check(field.normalizedType === normalizedType && field.reference === reference, `${message.name}.${field.name} normalized type/reference differs`);
      descriptors.fields.push({
        messageCode: message.code,
        messageName: message.name,
        wireName: field.name,
        number: field.id,
        normalizedType,
        reference,
        required: field.required,
        presence: field.presence,
        fingerprint: field.fingerprint,
        sensitive: field.sensitive,
      });
      fields.add(field.name); ids.add(field.id); fieldCount += 1;
    }
    for (const reserved of message.reservedFields ?? []) {
      check(Number.isInteger(reserved.id) && reserved.id > 0 && !ids.has(reserved.id), `${message.name} reserved field id ${reserved.id} is invalid or active`);
      check(typeof reserved.name === "string" && reserved.name.length > 0 && !fields.has(reserved.name), `${message.name} reserved field name ${reserved.name} is invalid or active`);
      check(typeof reserved.reason === "string" && reserved.reason.length > 0, `${message.name} reserved field ${reserved.name} lacks a reason`);
      check(!Object.hasOwn(schema.properties, reserved.name), `${message.name} reserved field ${reserved.name} remains in the schema`);
      ids.add(reserved.id); fields.add(reserved.name);
    }
    const activeFields = new Set(message.fields.map((field) => field.name));
    check(Object.keys(schema.properties).sort().join("\0") === [...activeFields].sort().join("\0"), `${message.name} schema fields differ from assignments`);
    walkSchema(schema, message.name, schemaNames);
    messageCodes.add(message.code); messageNames.add(message.name);
  }
  const request = assignmentDoc.messages.find((message) => message.name === "RequestEnvelope");
  const requestFingerprintFields = request.fields.filter((field) => field.fingerprint).map((field) => field.name).sort();
  return { messageCount: messageNames.size, fieldCount, names: messageNames, requestFingerprintFields, schemaDocuments, assignmentDoc, descriptors };
}

async function validateRegistries(specRoot, manifest, schemaSummary) {
  const registryPaths = manifest.artifacts.filter((artifact) => artifact.path.startsWith("registries/")).map((artifact) => artifact.path);
  const codes = new Set();
  const registryRecords = [];
  for (const registryPath of registryPaths) {
    const { bytes, value } = await readCanonicalJson(path.join(specRoot, registryPath));
    check(value.license === "MIT", `${registryPath} is not MIT`);
    if (registryPath !== "registries/field-assignments.json") {
      check(value.schemaVersion === "ogvcs.protocol/registry/v1" && value.version === 1 && Array.isArray(value.entries), `${registryPath} header is invalid`);
    }
    registryRecords.push({ path: registryPath, sha256: sha256(bytes) });
  }
  check(artifactSetDigest(registryRecords) === manifest.registrySetSha256, "registry set digest differs");
  const errors = (await readCanonicalJson(path.join(specRoot, "registries/error-codes.json"))).value;
  check(errors.rfc9457Subset === "closed-safe" && errors.forbiddenMembers.sort().join("\0") === ["detail", "instance"].sort().join("\0"), "RFC 9457 safe subset declaration differs");
  check(canonical(errors.parameterDomains) === canonical({
    conflictClass: { type: "string", values: ["idempotency-input-mismatch"] },
    gapClass: { type: "string", values: ["generation-changed", "retention-gap"] },
    retryAfterMs: { type: "canonical-decimal", minimum: 0, maximum: 86_400_000 },
  }), "safe parameter domains differ");
  check(Array.isArray(errors.excludedParameters) && errors.excludedParameters.some((entry) => entry.name === "currentGeneration"), "currentGeneration is not explicitly excluded from R0");
  const names = new Set();
  for (const entry of errors.entries) {
    check(Number.isInteger(entry.code) && entry.code > 0 && !codes.has(entry.code), `error code ${entry.code} is invalid or reused`);
    check(/^[A-Z][A-Z0-9_]+$/.test(entry.name) && !names.has(entry.name), `error name ${entry.name} is invalid or reused`);
    check(entry.status >= 400 && entry.status <= 599 && typeof entry.retryable === "boolean", `error ${entry.name} status/retry policy is invalid`);
    check(Array.isArray(entry.safeParameters) && !entry.safeParameters.some((name) => UNSAFE_ERROR_MEMBERS.has(name)), `error ${entry.name} exposes unsafe parameters`);
    check(entry.safeParameters.every((name) => Object.hasOwn(errors.parameterDomains, name)), `error ${entry.name} uses an unregistered safe parameter domain`);
    check(entry.type.startsWith("https://errors.opengamevcs.dev/protocol/v1/"), `error ${entry.name} type URI is unsafe`);
    codes.add(entry.code); names.add(entry.name);
  }
  const limits = (await readCanonicalJson(path.join(specRoot, "registries/limits.json"))).value;
  const limitNames = new Set();
  const limitCodes = new Set();
  for (const entry of limits.entries) {
    check(Number.isInteger(entry.code) && entry.code > 0 && !limitCodes.has(entry.code), `limit code ${entry.code} is invalid or reused`);
    check(typeof entry.name === "string" && !limitNames.has(entry.name), `limit name ${entry.name} is reused`);
    check(Number.isSafeInteger(entry.value) && entry.value >= 0 && typeof entry.enforcement === "string", `limit ${entry.name} is invalid`);
    check(entry.configuredMinimum === undefined || (entry.name === "maxErrorParameters" && entry.configuredMinimum === 0), `limit ${entry.name} has an unsupported configured minimum`);
    limitCodes.add(entry.code); limitNames.add(entry.name);
  }
  const runnerLimit = limits.entries.find((entry) => entry.name === "maxRunnerCases");
  const controlLimit = limits.entries.find((entry) => entry.name === "maxControlMessageBytes");
  check(runnerLimit?.value === 1_024, "runner case ceiling is not the frozen report-safe value");
  const worstRow = {
    schemaVersion: "ogvcs.protocol/runner-result/v1",
    id: "x".repeat(256),
    result: "reject",
    code: [...names].sort((left, right) => right.length - left.length)[0],
    preMutation: false,
    mutationCount: MAX_SAFE,
    semanticDigest: "f".repeat(64),
    traceDigest: "f".repeat(64),
  };
  const worstReport = {
    schemaVersion: "ogvcs.protocol/runner-report/v1",
    adapterId: "a".repeat(256),
    contractManifestSha256: "f".repeat(64),
    results: Array.from({ length: runnerLimit.value }, () => worstRow),
    passed: runnerLimit.value,
    failed: runnerLimit.value,
    reportDigest: "f".repeat(64),
  };
  check(Buffer.byteLength(canonical(worstReport), "utf8") <= controlLimit.value, "maxRunnerCases can exceed maxControlMessageBytes at worst-case RunnerResult size");
  const schemas = (await readCanonicalJson(path.join(specRoot, "registries/schemas.json"))).value;
  check(schemas.entries.length === schemaSummary.messageCount, "schema registry count differs");
  for (const entry of schemas.entries) {
    const bytes = await fs.readFile(path.join(specRoot, entry.path));
    check(sha256(bytes) === entry.sha256 && schemaSummary.names.has(entry.message), `schema registry entry ${entry.message} differs`);
  }
  const capabilities = (await readCanonicalJson(path.join(specRoot, "registries/capabilities.json"))).value;
  const requiredAxes = ["protocol", "schema", "repository-format", "authorization-contract", "path-contract", "path-profile", "event", "transfer", "extension"];
  for (const axis of requiredAxes) check(capabilities.entries.some((entry) => entry.axis === axis), `capability axis ${axis} is missing`);
  const extensions = (await readCanonicalJson(path.join(specRoot, "registries/extensions.json"))).value;
  check(["candidate", "deprecated", "reserved"].every((state) => extensions.entries.some((entry) => entry.state === state)), "extension lifecycle coverage is incomplete");
  const extensionsById = new Map(extensions.entries.map((entry) => [entry.id, entry]));
  const release = (await readCanonicalJson(path.join(specRoot, "registries/release-assignments.json"))).value;
  check(release.compatibilityPolicy === RELEASE_COMPATIBILITY_POLICY && release.entries.length > 0, "release assignment authority is missing");
  check(canonical(release.semanticHash) === canonical({ algorithm: "SHA-256", canonicalization: "RFC8785", domain: RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN, projection: "{kind,scope,name,code,policy}" }), "release semantic hash authority differs");
  check(canonicalDigest(release.entries) === release.snapshotSha256, "release assignment snapshot digest differs");
  const expectedAssignments = expectedReleaseAssignments(schemaSummary, limits, errors, capabilities, extensions);
  const releaseNames = new Set();
  const releaseCodes = new Set();
  for (const entry of release.entries) {
    const nameKey = `${entry.kind}\0${entry.scope}\0${entry.name}`;
    const codeKey = `${entry.kind}\0${entry.scope}\0${entry.code}`;
    check(Object.keys(entry).sort().join("\0") === ["code", "kind", "name", "scope", "semanticSha256"].sort().join("\0"), `release assignment ${entry.kind}/${entry.scope}/${entry.name} is not closed`);
    check(/^[0-9a-f]{64}$/u.test(entry.semanticSha256), `release assignment ${entry.kind}/${entry.scope}/${entry.name} semantic SHA-256 is invalid`);
    check(canonical(entry) === canonical(expectedAssignments.get(nameKey)), `release assignment ${entry.kind}/${entry.scope}/${entry.name} semantics differ`);
    check(!releaseNames.has(nameKey) && !releaseCodes.has(codeKey), `release assignment ${entry.kind}/${entry.scope}/${entry.name} is reused`);
    releaseNames.add(nameKey); releaseCodes.add(codeKey);
  }
  check(Array.isArray(release.allowedAdditions) && release.allowedAdditions.length > 0, "release authority has no compatible addition registry");
  const additionNames = new Set();
  const additionCodes = new Set();
  for (const addition of release.allowedAdditions) {
    const assignment = addition.assignment;
    const registration = extensionsById.get(assignment?.name);
    const nameKey = `${assignment?.kind}\0${assignment?.scope}\0${assignment?.name}`;
    const codeKey = `${assignment?.kind}\0${assignment?.scope}\0${assignment?.code}`;
    check(addition.registry === "extensions" && addition.state === "candidate" && addition.requirement === "optional" && addition.major === 1, "release addition policy is not optional candidate v1");
    check(assignment?.kind === "extension" && assignment.scope === "extension-registry" && registration?.code === assignment.code && registration.state === addition.state && registration.requirement === addition.requirement && assignment.name.endsWith("@1"), "release addition is not bound to a registered optional candidate");
    check(canonical(assignment) === canonical(expectedAssignments.get(nameKey)), "release addition semantic SHA-256 differs from its registered policy");
    check(!releaseNames.has(nameKey) && !releaseCodes.has(codeKey) && !additionNames.has(nameKey) && !additionCodes.has(codeKey), "release addition collides with a prior or sibling assignment");
    additionNames.add(nameKey); additionCodes.add(codeKey);
  }
  check(release.entries.length + release.allowedAdditions.length === expectedAssignments.size, "release semantic assignment inventory is incomplete");
  return { errorNames: names, errors: errors.entries, limits: limits.entries };
}

async function validateProfiles(specRoot) {
  const control = (await readCanonicalJson(path.join(specRoot, "profiles/control-https-json-v1.json"))).value;
  check(control.transport.tls === "1.3" && control.transport.http === "1.1", "control transport is not TLS 1.3 HTTP/1.1");
  check(control.transport.cleartext === "forbidden-for-negotiation-and-mutations" && control.transport.loopbackCleartext === "envelope-conformance-harness-only", "cleartext/loopback transport boundary differs");
  check(control.control.producerCanonicalization === "RFC8785" && control.control.contentCoding === "identity", "control canonicalization/coding differs");
  check(control.control.mutationRedirects === "forbidden" && control.stream.explicitTerminalRequired === true && control.stream.eofIsSuccess === false, "redirect or terminal policy differs");
  check(control.retryAfter?.header === "retry-after" && control.retryAfter.fieldNameComparison === "ASCII-case-insensitive" && control.retryAfter.producerFieldName === "retry-after" && control.retryAfter.syntax === "RFC9110-delta-seconds" && control.retryAfter.httpDate === "forbidden", "Retry-After field syntax differs");
  check(control.retryAfter.presence === "iff-safe-retryAfterMs" && control.retryAfter.conversion === "ceil-milliseconds-divided-by-1000" && control.retryAfter.maximumSeconds === 86_400 && control.retryAfter.duplicates === "reject-after-lowercase-normalization", "Retry-After semantic mapping differs");
  check(control.idempotency?.keySyntax === "ik1.<issuedAtUnixMs>.<expiresAtUnixMs>.<base64url-entropy>" && control.idempotency.maxKeyLifetimeMs === 86_400_000 && control.idempotency.maxFutureIssueSkewMs === 0, "self-dating idempotency key authority differs");
  check(control.idempotency.expiryOutcome === "IDEMPOTENCY_KEY_REQUIRED" && control.idempotency.postExpiryReuse === "new-key-required-even-after-tombstone-retirement" && control.idempotency.minimumRetention === "committed-outcome-and-tombstone-through-embedded-expiry" && control.idempotency.retryWithoutRecord === "first-execution-exactly-once", "idempotency execution/expiry outcome differs");
  const transfer = (await readCanonicalJson(path.join(specRoot, "profiles/transfer-probe-v1.json"))).value;
  check(transfer.scope === "application-neutral-conformance-probe" && transfer.representation.contentCoding === "identity", "transfer probe scope/coding differs");
  check(transfer.grant.representation === "request-root" && transfer.grant.explicitObjectCount === 0 && transfer.grant.queryString === "forbidden", "transfer grant is not compact request-root-only");
  check(transfer.httpFieldMapping?.validator?.syntax === "RFC9110-quoted-strong" && transfer.httpFieldMapping?.digest?.syntax === "RFC9530-sha-256-byte-sequence", "transfer HTTP semantic/header mapping differs");
  check(canonical(transfer.httpRangeCarrier?.response?.allowedStatuses) === canonical([200, 206, 416]) && transfer.httpRangeCarrier.response.unsupportedStatusOutcome === "PROTOCOL_MALFORMED-before-validator-or-range-semantics", "HTTP Range response-status authority differs");
  check(transfer.httpRangeCarrier?.response?.successfulValidators?.etag === "exactly-one-canonical-RFC9110-quoted-strong" && transfer.httpRangeCarrier.response.successfulValidators.contentDigest === "exactly-one-canonical-RFC9530-sha-256", "successful HTTP Range validator authority differs");
  check(transfer.httpRangeCarrier.response.bodyCarrier === "bounded-lowercase-even-length-responseBodyHex" && transfer.httpRangeCarrier.response.digestAuthority === "SHA-256(decoded-responseBodyHex)", "HTTP Range response-body digest authority differs");
  check(transfer.httpRangeCarrier.response.unsatisfiedBody === "empty" && transfer.httpRangeCarrier.response.unsatisfiedValidators === "content-digest-and-etag-absent", "HTTP 416 body/validator policy differs");
  check(transfer.preflight?.projectionSchema === "TransferProbeNonGrantInput" && transfer.preflight.beforeGrant === true && canonical(transfer.preflight.failureOrder) === canonical(["non-grant-shape", "range", "resume-validator", "grant-shape", "grant-verification"]), "transfer non-grant/grant preflight order differs");
  for (const excluded of ["production-routes", "upload-sessions", "pack-layout", "compression", "placement", "availability"]) check(transfer.excluded.includes(excluded), `transfer exclusion ${excluded} is missing`);
}

const RESOURCE_ROUTES = Object.freeze({
  maxControlMessageBytes: ["validate-envelope", "control-parser-bytes"],
  maxCanonicalInputBytes: ["fingerprint", "semantic-fingerprint-canonical-input"],
  maxJsonDepth: ["validate-envelope", "bounded-json-depth"],
  maxJsonNodes: ["validate-envelope", "bounded-json-node-count"],
  maxObjectMembers: ["validate-envelope", "bounded-json-object-members"],
  maxArrayItems: ["validate-envelope", "bounded-json-array-items"],
  maxStringUtf8Bytes: ["validate-envelope", "bounded-json-string-bytes"],
  maxExtensionEntries: ["validate-envelope", "request-extension-dispatch"],
  maxCapabilityItems: ["negotiate", "negotiation-axis-count"],
  maxErrorParameters: ["validate-envelope", "problem-parameter-count"],
  maxPageItems: ["validate-envelope", "page-item-count"],
  maxJsonlFrameBytes: ["validate-stream", "canonical-jsonl-frame-parser"],
  maxJsonlFrames: ["validate-stream", "canonical-jsonl-frame-count"],
  maxCursorBytes: ["validate-cursor", "opaque-cursor-byte-count"],
  maxIdempotencyKeyBytes: ["fingerprint", "idempotency-key-byte-count"],
  maxReceiptBytes: ["negotiate", "negotiation-receipt-byte-count"],
  maxGrantBytes: ["transfer-probe", "authorization-grant-byte-count"],
  maxTransferRangeBytes: ["transfer-probe", "transfer-range-preflight"],
  maxHeaderBytes: ["validate-envelope", "http-header-block"],
  maxCorrelationIdBytes: ["validate-envelope", "request-correlation-id"],
  maxOperationBytes: ["validate-envelope", "request-operation-id"],
  maxRunnerCases: ["runner-batch", "runner-case-collection"],
  maxSafeParameterBytes: ["validate-envelope", "safe-problem-parameter-bytes"],
  maxDeadlineHorizonMs: ["validate-envelope", "request-deadline-horizon"],
  maxReceiptLifetimeMs: ["negotiate", "negotiation-receipt-lifetime"],
  maxCursorLifetimeMs: ["validate-cursor", "cursor-issue-lifetime"],
  maxRegistryEntries: ["contract-load", "contract-registry-entry-count"],
  maxJsonKeyUtf8Bytes: ["validate-envelope", "bounded-json-key-bytes"],
  maxJsonCollectionItems: ["validate-envelope", "bounded-json-aggregate-items"],
  maxJsonlStreamBytes: ["validate-stream", "canonical-jsonl-stream-bytes"],
  maxWorkingMemoryBytes: ["validate-envelope", "bounded-json-working-reservation"],
  maxOperationTimeMs: ["validate-envelope", "shared-operation-deadline"],
  maxSchemaEvaluationSteps: ["validate-envelope", "json-schema-evaluation-steps"],
  maxContractArtifacts: ["contract-load", "contract-inventory-count"],
  maxContractBytes: ["contract-load", "contract-asset-stream-bytes"],
});

function jsonStatistics(value) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  let maxDepth = 0;
  let collectionItems = 0;
  let maxObjectMembers = 0;
  let maxArrayItems = 0;
  let maxStringBytes = 0;
  let maxKeyBytes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    maxDepth = Math.max(maxDepth, current.depth);
    if (typeof current.value === "string") maxStringBytes = Math.max(maxStringBytes, Buffer.byteLength(current.value, "utf8"));
    else if (Array.isArray(current.value)) {
      maxArrayItems = Math.max(maxArrayItems, current.value.length);
      collectionItems += current.value.length;
      for (const entry of current.value) stack.push({ value: entry, depth: current.depth + 1 });
    } else if (current.value !== null && typeof current.value === "object") {
      const keys = Object.keys(current.value);
      maxObjectMembers = Math.max(maxObjectMembers, keys.length);
      collectionItems += keys.length;
      for (const key of keys) {
        maxKeyBytes = Math.max(maxKeyBytes, Buffer.byteLength(key, "utf8"));
        stack.push({ value: current.value[key], depth: current.depth + 1 });
      }
    }
  }
  return { nodes, maxDepth, collectionItems, maxObjectMembers, maxArrayItems, maxStringBytes, maxKeyBytes };
}

function decodedBase64urlBytes(value) {
  check(typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value), "resource grant carrier is not base64url");
  return Buffer.from(value, "base64url").length;
}

function parseSelfDatingIdempotencyKey(value) {
  const match = /^ik1\.(0|[1-9][0-9]{0,15})\.(0|[1-9][0-9]{0,15})\.([A-Za-z0-9_-]{22,218})$/u.exec(value);
  if (!match) return undefined;
  const issuedAtUnixMs = Number(match[1]);
  const expiresAtUnixMs = Number(match[2]);
  if (!Number.isSafeInteger(issuedAtUnixMs) || !Number.isSafeInteger(expiresAtUnixMs)) return undefined;
  return { issuedAtUnixMs, expiresAtUnixMs };
}

function canonicalBase64url(value, minimumDecodedBytes, maximumDecodedBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length >= minimumDecodedBytes && decoded.length <= maximumDecodedBytes && decoded.toString("base64url") === value;
}

function retryAfterRelationshipValid(input) {
  const document = input.document;
  const problem = document?.code === undefined ? document?.problem : document;
  const parameters = problem?.parameters?.filter((entry) => entry.name === "retryAfterMs") ?? [];
  const headers = input.headers.filter((entry) => entry.name.toLowerCase() === "retry-after");
  if (parameters.length === 0) return headers.length === 0;
  if (parameters.length !== 1 || headers.length !== 1) return false;
  const milliseconds = parameters[0].value;
  if (!/^(?:0|[1-9][0-9]{0,6}|[1-7][0-9]{7}|8[0-5][0-9]{6}|86[0-3][0-9]{5}|86400000)$/u.test(milliseconds)) return false;
  const expectedSeconds = String(Math.min(86_400, Math.ceil(Number(milliseconds) / 1_000)));
  return /^(?:0|[1-9][0-9]{0,4})$/u.test(headers[0].value) && headers[0].value === expectedSeconds;
}

function transferResultStateValid(result, schemas) {
  if (!schemaMatches(result, schemas.get("TransferProbeResult.schema.json"), schemas)) return false;
  const { acceptedStart: start, acceptedEndExclusive: end, totalBytes: total } = result;
  if (!(start <= end && end <= total)) return false;
  switch (result.status) {
    case "complete": return result.terminal === true && end === total && result.problem === undefined;
    case "partial": return result.terminal === false && start < end && end < total && result.problem === undefined;
    case "interrupted": return result.terminal === false && start <= end && end < total && result.problem === undefined;
    case "rejected": return result.terminal === false && start === end && result.problem !== undefined;
    default: return false;
  }
}

function transferHeaderMap(headers) {
  const result = new Map();
  for (const header of headers) {
    const name = header.name.toLowerCase();
    const values = result.get(name) ?? [];
    values.push(header.value);
    result.set(name, values);
  }
  return result;
}

function transferProbePreflightOutcome(input, schemas) {
  const probe = input.probe;
  if (!probe || typeof probe !== "object" || Array.isArray(probe)) return "PROTOCOL_MALFORMED";
  const sourceSchemaVersion = schemas.get("TransferProbe.schema.json").properties.schemaVersion.const;
  const projectionSchema = schemas.get("TransferProbeNonGrantInput.schema.json");
  if (probe.schemaVersion !== sourceSchemaVersion) return "PROTOCOL_MALFORMED";
  const { grant, ...nonGrant } = probe;
  const projection = { ...nonGrant, schemaVersion: projectionSchema.properties.schemaVersion.const };
  if (!schemaMatches(projection, projectionSchema, schemas)) {
    if (probe.contentEncoding !== "identity") return "COMPRESSION_FORBIDDEN";
    if (probe.followRedirects !== false) return "REDIRECT_FORBIDDEN";
    return "PROTOCOL_MALFORMED";
  }
  if (probe.endOffsetExclusive !== undefined && probe.endOffsetExclusive <= probe.startOffset) return "TRANSFER_RANGE_INVALID";
  if (probe.startOffset > 0 && probe.validatorTag === undefined) return "TRANSFER_VALIDATOR_MISMATCH";
  if (!schemaMatches(grant, schemas.get("CompactTransferGrant.schema.json"), schemas)) return "TRANSFER_GRANT_INVALID";
  return "NONE";
}

function transferHttpRangeOutcome(input, schemas) {
  if (!schemaMatches(input.probe, schemas.get("TransferProbe.schema.json"), schemas)) return "PROTOCOL_MALFORMED";
  if (![200, 206, 416].includes(input.responseStatus)) return "PROTOCOL_MALFORMED";
  const request = transferHeaderMap(input.requestHeaders);
  const response = transferHeaderMap(input.responseHeaders);
  const singletonNames = ["range", "if-range", "content-range", "content-length", "content-digest", "etag", "content-encoding"];
  if (singletonNames.some((name) => (request.get(name)?.length ?? 0) > 1 || (response.get(name)?.length ?? 0) > 1)) return "PROTOCOL_MALFORMED";
  const only = (map, name) => map.get(name)?.[0];
  const contentEncoding = only(response, "content-encoding");
  if (contentEncoding !== undefined && contentEncoding !== "identity") return "COMPRESSION_FORBIDDEN";
  if (typeof input.responseBodyHex !== "string" || !/^(?:[0-9a-f]{2})*$/u.test(input.responseBodyHex)) return "PROTOCOL_MALFORMED";
  const responseBody = Buffer.from(input.responseBodyHex, "hex");
  const contentLengthText = only(response, "content-length");
  if (contentLengthText === undefined || !/^(?:0|[1-9][0-9]{0,9})$/u.test(contentLengthText)) return "PROTOCOL_MALFORMED";
  if (Number(contentLengthText) !== responseBody.length) return "TRANSFER_RANGE_INVALID";
  const total = input.transportResponse.totalBytes;
  if (!Number.isSafeInteger(total) || total < 0) return "PROTOCOL_MALFORMED";
  const etagText = only(response, "etag");
  const contentDigestText = only(response, "content-digest");
  let responseValidatorTag;
  if (input.responseStatus === 200 || input.responseStatus === 206) {
    const etag = /^"([A-Za-z0-9._~-]{16,256})"$/u.exec(etagText ?? "");
    if (!etag) return "PROTOCOL_MALFORMED";
    responseValidatorTag = etag[1];
    const digest = /^sha-256=:([A-Za-z0-9+/]{43}=):$/u.exec(contentDigestText ?? "");
    if (!digest) return "PROTOCOL_MALFORMED";
    const digestBytes = Buffer.from(digest[1], "base64");
    if (digestBytes.length !== 32 || digestBytes.toString("base64") !== digest[1]) return "PROTOCOL_MALFORMED";
    const bodySha256 = sha256(responseBody);
    if (digestBytes.toString("hex") !== bodySha256 || (input.probe.expectedSha256 !== undefined && input.probe.expectedSha256 !== bodySha256)) return "TRANSFER_VALIDATOR_MISMATCH";
  }
  const rangeText = only(request, "range");
  const contentRangeText = only(response, "content-range");
  if (rangeText === undefined) {
    if (only(request, "if-range") !== undefined) return "TRANSFER_VALIDATOR_MISMATCH";
    if (input.responseStatus !== 200 || contentRangeText !== undefined || input.probe.startOffset !== 0 || (input.probe.endOffsetExclusive !== undefined && input.probe.endOffsetExclusive !== total) || responseBody.length !== total) return "TRANSFER_RANGE_INVALID";
    return "NONE";
  }
  const range = /^bytes=(0|[1-9][0-9]*)-(?:(0|[1-9][0-9]*))?$/u.exec(rangeText);
  if (!range) return "PROTOCOL_MALFORMED";
  const requestedStart = Number(range[1]);
  const requestedInclusiveEnd = range[2] === undefined ? undefined : Number(range[2]);
  if (!Number.isSafeInteger(requestedStart) || requestedStart !== input.probe.startOffset) return "TRANSFER_RANGE_INVALID";
  if (requestedInclusiveEnd === undefined) {
    if (input.probe.endOffsetExclusive !== undefined) return "TRANSFER_RANGE_INVALID";
  } else if (!Number.isSafeInteger(requestedInclusiveEnd) || requestedInclusiveEnd < requestedStart || input.probe.endOffsetExclusive !== requestedInclusiveEnd + 1) return "TRANSFER_RANGE_INVALID";
  const ifRange = only(request, "if-range");
  if (input.probe.validatorTag !== undefined) {
    const expected = `"${input.probe.validatorTag}"`;
    if (ifRange !== expected || responseValidatorTag !== input.probe.validatorTag) return "TRANSFER_VALIDATOR_MISMATCH";
  } else if (ifRange !== undefined) return "TRANSFER_VALIDATOR_MISMATCH";
  if (input.responseStatus === 416) {
    if (contentDigestText !== undefined || etagText !== undefined) return "PROTOCOL_MALFORMED";
    const unsatisfied = /^bytes \*\/(0|[1-9][0-9]*)$/u.exec(contentRangeText ?? "");
    if (!unsatisfied) return "PROTOCOL_MALFORMED";
    if (Number(unsatisfied[1]) !== total || requestedStart < total || responseBody.length !== 0) return "TRANSFER_RANGE_INVALID";
    return "TRANSFER_RANGE_INVALID";
  }
  if (input.responseStatus !== 206) return "TRANSFER_RANGE_INVALID";
  const satisfied = /^bytes (0|[1-9][0-9]*)-(0|[1-9][0-9]*)\/(0|[1-9][0-9]*)$/u.exec(contentRangeText ?? "");
  if (!satisfied) return "PROTOCOL_MALFORMED";
  const responseStart = Number(satisfied[1]);
  const responseInclusiveEnd = Number(satisfied[2]);
  const responseTotal = Number(satisfied[3]);
  const expectedInclusiveEnd = (requestedInclusiveEnd ?? (total - 1));
  if (responseStart !== requestedStart || responseInclusiveEnd !== expectedInclusiveEnd || responseTotal !== total || responseInclusiveEnd >= total || responseBody.length !== responseInclusiveEnd - responseStart + 1) return "TRANSFER_RANGE_INVALID";
  return "NONE";
}

function measureResourceCase(limitName, scenario, schemas) {
  const input = scenario.input;
  const documentStats = input.document === undefined ? undefined : jsonStatistics(input.document);
  switch (limitName) {
    case "maxControlMessageBytes": return Buffer.byteLength(input.rawInput, "utf8");
    case "maxCanonicalInputBytes": return Buffer.byteLength(input.rawInputs[0], "utf8");
    case "maxJsonDepth": return documentStats.maxDepth;
    case "maxJsonNodes": return documentStats.nodes;
    case "maxObjectMembers": return documentStats.maxObjectMembers;
    case "maxArrayItems": return documentStats.maxArrayItems;
    case "maxStringUtf8Bytes": return documentStats.maxStringBytes;
    case "maxExtensionEntries": return Object.keys(input.document.extensions).length;
    case "maxCapabilityItems": return Math.max(...Object.values(input.offer.capabilities).filter(Array.isArray).map((entries) => entries.length));
    case "maxErrorParameters": return input.document.parameters?.length ?? 0;
    case "maxPageItems": return input.document.items.length;
    case "maxJsonlFrameBytes": return Math.max(...input.jsonl.trimEnd().split("\n").map((line) => Buffer.byteLength(line, "utf8")));
    case "maxJsonlFrames": return input.frames.length;
    case "maxCursorBytes": return Buffer.byteLength(input.suppliedToken, "utf8");
    case "maxIdempotencyKeyBytes": return Buffer.byteLength(input.idempotencyKey, "utf8");
    case "maxReceiptBytes": {
      const receipt = {
        algorithm: "HMAC-SHA-256",
        keyId: input.receiptKeyId,
        claims: {
          schemaVersion: "ogvcs.protocol/negotiation-receipt-claims/v1",
          selection: input.serverSelection,
          ...input.principal,
          clientNonce: input.offer.clientNonce,
          serverNonce: input.serverNonce,
          issuedAtUnixMs: input.issueAtUnixMs,
          expiresAtUnixMs: input.issueAtUnixMs + input.receiptLifetimeMs,
        },
        mac: "A".repeat(43),
      };
      return Buffer.byteLength(canonical(receipt), "utf8");
    }
    case "maxGrantBytes": return decodedBase64urlBytes(input.probe.grant.envelope);
    case "maxTransferRangeBytes": return scenario.resourceWitness.dimension === "response" ? input.transportResponse.rangeBytes : input.probe.endOffsetExclusive - input.probe.startOffset;
    case "maxHeaderBytes": return input.headers.reduce((total, header) => total + Buffer.byteLength(header.name, "utf8") + 2 + Buffer.byteLength(header.value, "utf8") + 2, 0);
    case "maxCorrelationIdBytes": return Buffer.byteLength(input.document.correlationId, "utf8");
    case "maxOperationBytes": return Buffer.byteLength(input.document.operation, "utf8");
    case "maxRunnerCases": return input.cases.length;
    case "maxSafeParameterBytes": return Math.max(...input.document.parameters.map((parameter) => Buffer.byteLength(parameter.value, "utf8")));
    case "maxDeadlineHorizonMs": return input.document.deadlineUnixMs - input.atUnixMs;
    case "maxReceiptLifetimeMs": return input.receiptLifetimeMs;
    case "maxCursorLifetimeMs": return input.ttlMs;
    case "maxRegistryEntries": return input.registryEntries.length;
    case "maxJsonKeyUtf8Bytes": return documentStats.maxKeyBytes;
    case "maxJsonCollectionItems": return documentStats.collectionItems;
    case "maxJsonlStreamBytes": return Buffer.byteLength(input.jsonl, "utf8");
    case "maxWorkingMemoryBytes": return 128 + (4 * Buffer.byteLength(input.rawInput, "utf8"));
    case "maxOperationTimeMs": return scenario.control.clockSamplesUnixMs.at(-1) - scenario.control.clockSamplesUnixMs[0];
    case "maxSchemaEvaluationSteps": {
      const schema = schemas.get("EnvelopeCaseInput.schema.json");
      const budget = { steps: 0 };
      check(schemaMatches(input.document, schema.$defs.JsonValue, schemas, schema, budget), `${scenario.id} schema-evaluation input is invalid`);
      return budget.steps;
    }
    case "maxContractArtifacts": return input.artifacts.length;
    case "maxContractBytes": return input.artifacts.reduce((total, artifact) => total + Buffer.from(artifact.bytesHex, "hex").length, 0);
    default: fail(`resource route for ${limitName} is not independently executable`);
  }
}

function evaluateReleasePreflight(input, authority) {
  if (input.requiredCapabilities.some((identifier) => !authority.capabilityIds.has(identifier))) return "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN";
  const selection = { ...input.proposedSelection, extensions: [...input.proposedSelection.extensions].sort(), schemaVersion: "ogvcs.protocol/negotiation-selection/v1" };
  const required = [...input.requiredCapabilities].sort();
  const tuplePresent = authority.compatibilityEntries.some((entry) => canonical({ ...entry.selection, extensions: [...entry.selection.extensions].sort() }) === canonical(selection) && canonical([...entry.requiredCapabilities].sort()) === canonical(required));
  if (!tuplePresent) return "PROTOCOL_UNSUPPORTED";
  if (input.authorizationManifestSha256 !== authority.predecessorPins.authorization.manifestSha256 || input.pathManifestSha256 !== authority.predecessorPins.path.manifestSha256 || input.repositoryManifestSha256 !== authority.predecessorPins.repository.manifestSha256) return "PROTOCOL_UNSUPPORTED";
  if (input.priorAssignmentSnapshotSha256 !== authority.releaseSnapshotSha256) return "PROTOCOL_UNSUPPORTED";
  const names = new Set();
  const codes = new Set();
  for (const entry of input.proposedAssignments) {
    const nameKey = `${entry.kind}\0${entry.scope}\0${entry.name}`;
    const codeKey = `${entry.kind}\0${entry.scope}\0${entry.code}`;
    if (names.has(nameKey) || codes.has(codeKey)) return "PROTOCOL_UNSUPPORTED";
    names.add(nameKey); codes.add(codeKey);
  }
  const proposed = new Map(input.proposedAssignments.map((entry) => [`${entry.kind}\0${entry.scope}\0${entry.name}`, entry]));
  for (const prior of authority.releaseAssignments) {
    const current = proposed.get(`${prior.kind}\0${prior.scope}\0${prior.name}`);
    if (!current || canonical(current) !== canonical(prior)) return "PROTOCOL_UNSUPPORTED";
  }
  const priorNames = new Set(authority.releaseAssignments.map((entry) => `${entry.kind}\0${entry.scope}\0${entry.name}`));
  const allowedAdditions = new Set(authority.allowedAdditions.map((entry) => canonical(entry.assignment)));
  for (const entry of input.proposedAssignments) if (!priorNames.has(`${entry.kind}\0${entry.scope}\0${entry.name}`) && !allowedAdditions.has(canonical(entry))) return "PROTOCOL_UNSUPPORTED";
  return "NONE";
}

async function validateVectors(specRoot, errorNames, limits, manifest, schemaSummary) {
  const vectorManifest = (await readCanonicalJson(path.join(specRoot, "vectors/manifest.json"))).value;
  check(vectorManifest.schemaVersion === "ogvcs.protocol/vector-manifest/v1" && vectorManifest.contractVersion === manifest.contractVersion && vectorManifest.license === "MIT", "vector manifest header differs");
  const artifactRecords = [];
  let total = 0;
  let accepts = 0;
  let rejects = 0;
  const caseIds = new Set();
  const expectedTraceDigests = new Map();
  const predecessorCaseIds = new Set();
  const resourcePairs = new Map();
  const capabilityAxisResourceCoverage = new Set();
  const transferRangeResourceCoverage = new Set();
  let executedResourceCases = 0;
  const hostileMemberDigests = [];
  let releaseCoverage = 0;
  let replayAuthorizationCoverage = 0;
  const ac04Operations = new Set();
  const scenariosById = new Map();
  const positiveExtensionSelectionCoverage = new Set();
  let goldenStreamScenario;
  const releaseRegistry = (await readCanonicalJson(path.join(specRoot, "registries/release-assignments.json"))).value;
  const compatibilityRegistry = (await readCanonicalJson(path.join(specRoot, "registries/compatibility.json"))).value;
  const capabilityRegistry = (await readCanonicalJson(path.join(specRoot, "registries/capabilities.json"))).value;
  const extensionRegistry = (await readCanonicalJson(path.join(specRoot, "registries/extensions.json"))).value;
  const extensionsById = new Map(extensionRegistry.entries.map((entry) => [entry.id, entry]));
  const releaseAuthority = {
    releaseAssignments: releaseRegistry.entries,
    allowedAdditions: releaseRegistry.allowedAdditions,
    releaseSnapshotSha256: releaseRegistry.snapshotSha256,
    compatibilityEntries: compatibilityRegistry.entries,
    capabilityIds: new Set(capabilityRegistry.entries.map((entry) => entry.id)),
    predecessorPins: manifest.predecessorPins,
  };
  const expectedVectorFiles = ["vectors/manifest.json", ...vectorManifest.artifacts.map((entry) => entry.path)].sort(compareText);
  const actualVectorFiles = (await fs.readdir(path.join(specRoot, "vectors"), { withFileTypes: true }))
    .map((entry) => {
      check(entry.isFile(), `vectors/${entry.name} is not a regular file`);
      return `vectors/${entry.name}`;
    })
    .sort(compareText);
  check(canonical(actualVectorFiles) === canonical(expectedVectorFiles), "vector directory inventory differs from its authenticated manifest");
  const scenarioArtifacts = vectorManifest.artifacts.filter((entry) => Number.isSafeInteger(entry.cases));
  const categoryCounts = new Map(VECTOR_CATEGORIES.map((category) => [category, 0]));
  const vectorArtifactByteLimit = Math.min(
    limits.find((entry) => entry.name === "maxCanonicalInputBytes").value,
    limits.find((entry) => entry.name === "maxControlMessageBytes").value,
  );
  const hardOperationTimeMs = limits.find((entry) => entry.name === "maxOperationTimeMs").value;
  let idempotencyGoldenDocuments = 0;
  for (const artifact of scenarioArtifacts) {
    const relativePath = artifact.path;
    check(relativeIsSafe(relativePath) && /^vectors\/[a-z0-9][a-z0-9-]*\.json$/u.test(relativePath) && relativePath !== "vectors/manifest.json", `scenario artifact path ${String(relativePath)} is invalid`);
    const { bytes, value } = await readCanonicalJson(path.join(specRoot, relativePath));
    const category = value.category;
    check(VECTOR_CATEGORIES.includes(category), `${relativePath} has unknown category ${String(category)}`);
    check(value.schemaVersion === "ogvcs.protocol/scenario-set/v1" && value.category === category && value.license === "MIT", `${category} vector header differs`);
    check(Array.isArray(value.cases) && value.cases.length > 0, `${category} vector set is empty`);
    check(bytes.length <= vectorArtifactByteLimit, `${relativePath} exceeds the configured canonical/control input byte limit`);
    check(artifact.cases === value.cases.length && artifact.bytes === bytes.length, `${relativePath} manifest counts differ`);
    categoryCounts.set(category, categoryCounts.get(category) + value.cases.length);
    for (const scenario of value.cases) {
      check(Object.keys(scenario).every((key) => ALLOWED_SCENARIO_KEYS.has(key)), `${scenario.id} has an unknown scenario field`);
      check(scenario.schemaVersion === "ogvcs.protocol/scenario/v1" && scenario.category === category, `${scenario.id} scenario header differs`);
      check(/^[a-z0-9][a-z0-9-]{0,127}$/.test(scenario.id) && !caseIds.has(scenario.id), `scenario id ${scenario.id} is invalid or reused`);
      scenariosById.set(scenario.id, scenario);
      check(OPERATIONS.has(scenario.operation) && INPUT_KINDS.has(scenario.inputKind), `${scenario.id} operation/input kind is invalid`);
      check(scenario.control && ["none", "before-operation", "after-first-stream-frame"].includes(scenario.control.cancellation), `${scenario.id} cancellation control is invalid`);
      check(Array.isArray(scenario.control.clockSamplesUnixMs) && scenario.control.clockSamplesUnixMs.length >= 1 && scenario.control.clockSamplesUnixMs.length <= 16 && scenario.control.clockSamplesUnixMs.every((value) => Number.isSafeInteger(value) && value >= 0), `${scenario.id} clock controls are invalid`);
      check(Object.keys(scenario.expected).every((key) => ALLOWED_EXPECTED_KEYS.has(key)), `${scenario.id} has an unknown expected field`);
      check(["accept", "reject"].includes(scenario.expected.result), `${scenario.id} result is invalid`);
      check(typeof scenario.expected.preMutation === "boolean" && Number.isSafeInteger(scenario.expected.mutationCount) && scenario.expected.mutationCount >= 0, `${scenario.id} mutation witness is invalid`);
      check(scenario.expected.preMutation === (scenario.expected.mutationCount === 0), `${scenario.id} mutation witness is inconsistent`);
      check(/^[0-9a-f]{64}$/.test(scenario.expected.traceDigest), `${scenario.id} trace digest oracle is missing or invalid`);
      expectedTraceDigests.set(scenario.id, scenario.expected.traceDigest);
      if (scenario.expected.semanticDigest !== undefined) check(scenario.expected.result === "accept" && /^[0-9a-f]{64}$/.test(scenario.expected.semanticDigest), `${scenario.id} semantic digest oracle is invalid`);
      if (scenario.expected.mutationCount > 0) check(category === "idempotency" && scenario.expected.mutationCount === 1, `${scenario.id} has an unsupported post-mutation outcome`);
      if (scenario.expected.result === "accept") { check(scenario.expected.code === "NONE", `${scenario.id} accept has an error code`); accepts += 1; }
      else { check(errorNames.has(scenario.expected.code), `${scenario.id} uses unregistered error ${scenario.expected.code}`); rejects += 1; }
      const clockSamples = scenario.control.clockSamplesUnixMs;
      const clockNondecreasing = clockSamples.every((sample, index) => index === 0 || sample >= clockSamples[index - 1]);
      if (!clockNondecreasing) {
        check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} decreasing clock samples do not fail preflight as malformed`);
      } else {
        const elapsed = clockSamples.at(-1) - clockSamples[0];
        check(Number.isSafeInteger(elapsed) && elapsed >= 0, `${scenario.id} clock elapsed computation is not safe`);
        if (scenario.configuredLimits?.maxOperationTimeMs === undefined && elapsed >= hardOperationTimeMs) check(scenario.expected.result === "reject" && scenario.expected.code === "DEADLINE_EXCEEDED" && scenario.expected.mutationCount === 0, `${scenario.id} does not enforce the hard/default operation deadline`);
      }
      check(Array.isArray(scenario.requirementIds) && scenario.requirementIds.length > 0, `${scenario.id} lacks requirements`);
      if (scenario.requirementIds.includes("OGVCS-041-AC-05")) releaseCoverage += 1;
      if (scenario.category === "release") check(scenario.requirementIds.includes("OGVCS-041-AC-05"), `${scenario.id} lacks AC-05 release coverage`);
      if (scenario.requirementIds.includes("OGVCS-041-AC-04")) ac04Operations.add(scenario.operation);
      check(Array.isArray(scenario.forbiddenResponseFields) && [...UNSAFE_ERROR_MEMBERS].slice(0, 6).every((field) => scenario.forbiddenResponseFields.includes(field)), `${scenario.id} lacks safe-output assertions`);
      check(scenario.resourceRecipe === undefined && !Object.hasOwn(scenario.input, "logicalSize"), `${scenario.id} retains a virtual or label-only resource recipe`);
      const executableCase = {
        schemaVersion: "ogvcs.protocol/runner-case/v1",
        id: scenario.id,
        operation: scenario.operation,
        input: scenario.input,
        inputKind: scenario.inputKind,
        control: scenario.control,
        ...(scenario.configuredLimits === undefined ? {} : { configuredLimits: scenario.configuredLimits }),
        ...(scenario.hiddenServerInputs === undefined ? {} : { serverContext: scenario.hiddenServerInputs }),
      };
      check(schemaMatches(executableCase, schemaSummary.schemaDocuments.get("RunnerCase.schema.json"), schemaSummary.schemaDocuments), `${scenario.id} is not a valid public executable RunnerCase`);
      if (scenario.operation === "negotiate") {
        const secureTransport = scenario.input.transportScheme === "https" && scenario.input.tlsVersion === "1.3";
        if (!secureTransport) check(scenario.expected.result === "reject" && scenario.expected.code === "NEGOTIATION_DOWNGRADE_REJECTED" && scenario.expected.mutationCount === 0, `${scenario.id} insecure negotiation transport does not fail before selection or receipt issuance`);
        const nonceIsCanonical = canonicalBase64url(scenario.input.serverNonce, 16, 64);
        if (!nonceIsCanonical) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} noncanonical server nonce does not fail before negotiation`);
        if (scenario.expected.result === "accept" && scenario.input.route === "negotiate") {
          const axes = [
            ["protocolVersions", "protocolVersion"], ["schemaVersions", "messageSchemaVersion"],
            ["repositoryFormats", "repositoryFormat"], ["authorizationContracts", "authorizationContract"],
            ["pathContracts", "pathContract"], ["pathProfiles", "pathProfile"],
            ["eventVersions", "eventVersion"], ["transferProfiles", "transferProfile"],
          ];
          const offered = new Set(scenario.input.offer.capabilities.extensions);
          const matchingRows = compatibilityRegistry.entries.filter((row) => ["candidate", "ratified"].includes(row.state)
            && axes.every(([offerField, selectionField]) => scenario.input.offer.capabilities[offerField].includes(row.selection[selectionField])));
          const row = matchingRows.find((candidate) => {
            const selectedExtensions = candidate.selection.extensions.filter((id) => offered.has(id));
            const expectedSelection = { ...candidate.selection, extensions: selectedExtensions, protocolRegistrySetSha256: scenario.input.serverSelection.protocolRegistrySetSha256 };
            return canonical(expectedSelection) === canonical(scenario.input.serverSelection);
          });
          check(row !== undefined, `${scenario.id} positive negotiation selection is not derived from a selectable compatibility row`);
          for (const extensionId of row.selection.extensions.filter((id) => offered.has(id))) positiveExtensionSelectionCoverage.add(`${row.code}\0${extensionId}`);
        }
      }
      if (scenario.operation === "fingerprint") {
        const projectionFields = schemaSummary.requestFingerprintFields.join("\0");
        const projectionSchema = schemaSummary.schemaDocuments.get("IdempotencyProjectionInput.schema.json");
        const projectionsValid = scenario.input.projections.every((projection) => schemaMatches(projection, projectionSchema, schemaSummary.schemaDocuments));
        if (!projectionsValid) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} invalid idempotency projection does not fail structurally`);
        else for (const [index, projection] of scenario.input.projections.entries()) check(Object.keys(projection).sort().join("\0") === projectionFields, `${scenario.id} projection ${index} differs from RequestEnvelope fingerprint=true fields`);
        check(scenario.input.attemptAuthorizationDecisions.length === scenario.input.attemptProjectionIndexes.length, `${scenario.id} does not carry one authorization decision per attempt`);
        const projectionIndexesValid = scenario.input.attemptProjectionIndexes.every((index) => index < scenario.input.projections.length);
        if (!projectionIndexesValid) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} out-of-range projection index does not fail structurally`);
        const executionShapeValid = scenario.input.route !== "idempotency" || (scenario.input.retryableMutation === true && scenario.input.idempotencyKey.length > 0);
        if (!executionShapeValid) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} invalid idempotency execution route does not fail structurally`);
        if (scenario.input.idempotencyKey === "") check(scenario.expected.code === "PROTOCOL_MALFORMED", `${scenario.id} empty execution key is not malformed`);
        else {
          const keyTime = parseSelfDatingIdempotencyKey(scenario.input.idempotencyKey);
          check(keyTime, `${scenario.id} self-dating key syntax is invalid`);
          check(Number.isSafeInteger(scenario.input.atUnixMs) && Number.isSafeInteger(scenario.input.tombstoneRetentionMs), `${scenario.id} idempotency evaluation time is not explicit`);
          const embeddedFieldsMatch = keyTime.issuedAtUnixMs === scenario.input.idempotencyIssuedAtUnixMs && keyTime.expiresAtUnixMs === scenario.input.idempotencyExpiresAtUnixMs;
          if (!embeddedFieldsMatch) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} key/field mismatch does not fail structurally before mutation`);
          else {
            const lifetime = keyTime.expiresAtUnixMs - keyTime.issuedAtUnixMs;
            const hasPriorCommit = scenario.input.attemptSchedule.includes("commit");
            if (lifetime <= 0 || lifetime > 86_400_000) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} invalid key lifetime does not fail structurally before mutation`);
            else if (keyTime.issuedAtUnixMs > scenario.input.atUnixMs) check(scenario.expected.result === "reject" && scenario.expected.code === "IDEMPOTENCY_KEY_REQUIRED" && scenario.expected.mutationCount === 0, `${scenario.id} future-issued key does not require a new key before mutation`);
            else if (scenario.input.atUnixMs >= keyTime.expiresAtUnixMs) check(scenario.expected.result === "reject" && scenario.expected.code === "IDEMPOTENCY_KEY_REQUIRED" && scenario.expected.mutationCount === (hasPriorCommit ? 1 : 0), `${scenario.id} expired key outcome is not stable across retention`);
          }
        }
      }
      if (scenario.operation === "validate-envelope" && category !== "resources") {
        const problem = scenario.input.document?.code === undefined ? scenario.input.document?.problem : scenario.input.document;
        const hasRetryParameter = problem?.parameters?.some((entry) => entry.name === "retryAfterMs") === true;
        const hasRetryHeader = scenario.input.headers.some((entry) => entry.name.toLowerCase() === "retry-after");
        if (hasRetryParameter || hasRetryHeader) {
          const valid = retryAfterRelationshipValid(scenario.input);
          check(scenario.expected.result === (valid ? "accept" : "reject") && scenario.expected.code === (valid ? "NONE" : "PROTOCOL_MALFORMED"), `${scenario.id} Retry-After outcome is not derived from its safe parameter and received fields`);
        }
        if (["NegotiationCaseInput", "CursorCaseInput"].includes(scenario.input.targetSchema)) {
          const valid = schemaMatches(scenario.input.document, schemaSummary.schemaDocuments.get(`${scenario.input.targetSchema}.schema.json`), schemaSummary.schemaDocuments);
          check(scenario.expected.result === (valid ? "accept" : "reject") && scenario.expected.code === (valid ? "NONE" : "PROTOCOL_MALFORMED"), `${scenario.id} target-schema outcome is not derived from ${scenario.input.targetSchema}`);
        }
      }
      if (scenario.operation === "validate-cursor") {
        const scopeSchema = schemaSummary.schemaDocuments.get("CursorScopeInput.schema.json");
        const scopesValid = schemaMatches(scenario.input.issueScope, scopeSchema, schemaSummary.schemaDocuments) && schemaMatches(scenario.input.readScope, scopeSchema, schemaSummary.schemaDocuments);
        if (!scopesValid) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} malformed cursor scope does not fail before lifecycle semantics`);
        const expiresAtUnixMs = scenario.input.issuedAtUnixMs + scenario.input.ttlMs;
        if (!Number.isSafeInteger(expiresAtUnixMs)) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED" && scenario.expected.mutationCount === 0, `${scenario.id} overflowing cursor expiry does not fail before lifecycle semantics`);
        if (scenario.input.route === "validate-page") {
          const valid = schemaMatches(scenario.input.page, schemaSummary.schemaDocuments.get("PageEnvelope.schema.json"), schemaSummary.schemaDocuments);
          if (!valid) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED", `${scenario.id} invalid page state does not reject as malformed`);
        }
      }
      if (scenario.operation === "validate-stream") {
        const invalidFrame = scenario.input.frames.some((frame) => !schemaMatches(frame, schemaSummary.schemaDocuments.get("StreamFrame.schema.json"), schemaSummary.schemaDocuments));
        if (invalidFrame) check(scenario.expected.result === "reject" && scenario.expected.code === "PROTOCOL_MALFORMED", `${scenario.id} invalid stream frame does not reject as malformed`);
        if (scenario.input.encoding === "jsonl" && !scenario.input.jsonl.endsWith("\n")) check(scenario.expected.result === "reject" && scenario.expected.code === "STREAM_INCOMPLETE", `${scenario.id} empty or mid-frame EOF is not incomplete`);
      }
      if (scenario.id === "stream-golden-jsonl-byte-exact") goldenStreamScenario = scenario;
      if (scenario.operation === "transfer-probe" && scenario.input.route === "validate-result") {
        const valid = transferResultStateValid(scenario.input.probeResult, schemaSummary.schemaDocuments);
        check(scenario.expected.result === (valid ? "accept" : "reject") && scenario.expected.code === (valid ? "NONE" : "PROTOCOL_MALFORMED"), `${scenario.id} transfer result outcome is not derived from its state and range fields`);
      }
      if (scenario.operation === "transfer-probe" && scenario.input.route === "http-range") {
        const code = transferHttpRangeOutcome(scenario.input, schemaSummary.schemaDocuments);
        check(scenario.expected.code === code && scenario.expected.result === (code === "NONE" ? "accept" : "reject"), `${scenario.id} HTTP Range outcome is not derived from its public carrier fields`);
      }
      if (scenario.operation === "transfer-probe" && ["probe", "verify-grant"].includes(scenario.input.route)) {
        const code = transferProbePreflightOutcome(scenario.input, schemaSummary.schemaDocuments);
        if (code !== "NONE") check(scenario.expected.code === code && scenario.expected.result === "reject", `${scenario.id} transfer preflight outcome/order differs`);
      }
      if (scenario.id === "idempotency-after-retention-same-key-requires-new-key") {
        check(scenario.input.atUnixMs > scenario.input.idempotencyExpiresAtUnixMs + scenario.input.tombstoneRetentionMs, "post-retention idempotency witness has not crossed retention");
        check(canonical(scenario.input.attemptSchedule) === canonical(["begin-mutation", "commit", "expire-key", "retire-tombstone", "retry"]), "post-retention idempotency witness does not retire then retry the same key");
        check(scenario.expected.result === "reject" && scenario.expected.code === "IDEMPOTENCY_KEY_REQUIRED" && scenario.expected.preMutation === false && scenario.expected.mutationCount === 1, "post-retention idempotency outcome permits a second mutation");
      }
      if (scenario.id === "idempotency-response-loss-replay-authorization-revoked") {
        check(canonical(scenario.input.attemptAuthorizationDecisions) === canonical(["allow", "deny"]), "replay authorization witness does not revoke access on retry");
        check(canonical(scenario.input.attemptSchedule) === canonical(["begin-mutation", "commit", "lose-response", "retry"]), "replay authorization witness does not cover lost response after commit");
        check(scenario.expected.code === "AUTHORIZATION_DENIED" && scenario.expected.preMutation === false && scenario.expected.mutationCount === 1, "replay authorization denial mutation witness differs");
        check(scenario.hiddenMarkerValues?.every((marker) => canonical(scenario.hiddenServerInputs).includes(marker)), "replay authorization denial lacks a hidden stored outcome");
        replayAuthorizationCoverage += 1;
      }
      if (scenario.id === "idempotency-retention-before-expiry-replay") {
        check(scenario.input.atUnixMs < scenario.input.idempotencyExpiresAtUnixMs && scenario.input.atUnixMs > scenario.input.idempotencyIssuedAtUnixMs + scenario.input.tombstoneRetentionMs, "pre-expiry retention witness does not cross ordinary retention before embedded expiry");
        check(scenario.expected.result === "accept" && scenario.expected.preMutation === false && scenario.expected.mutationCount === 1, "pre-expiry retention witness permits store retirement or a second mutation");
      }
      if (scenario.id === "idempotency-retry-only-unused-key-first-execution") {
        check(canonical(scenario.input.attemptSchedule) === canonical(["retry"]) && canonical(scenario.input.attemptProjectionIndexes) === canonical([0]) && canonical(scenario.input.attemptAuthorizationDecisions) === canonical(["allow"]), "retry-only first-execution witness is not one authorized fresh attempt");
        check(scenario.input.idempotencyIssuedAtUnixMs === scenario.input.atUnixMs && scenario.input.atUnixMs < scenario.input.idempotencyExpiresAtUnixMs, "retry-only first-execution key is not valid at the explicit clock");
        check(scenario.expected.result === "accept" && scenario.expected.code === "NONE" && scenario.expected.preMutation === false && scenario.expected.mutationCount === 1, "retry-only unused key is not frozen as one first execution");
      }
      if (scenario.id === "idempotency-zero-tombstone-retention-first-execution") {
        check(scenario.input.tombstoneRetentionMs === 0 && canonical(scenario.input.attemptSchedule) === canonical(["retry"]), "zero-retention idempotency witness does not execute the fresh retry-only path");
        check(scenario.expected.result === "accept" && scenario.expected.code === "NONE" && scenario.expected.preMutation === false && scenario.expected.mutationCount === 1, "zero ordinary tombstone retention is not accepted for a valid fresh key");
      }
      if (scenario.id === "idempotency-initial-authorization-denied") {
        check(canonical(scenario.input.attemptSchedule) === canonical(["begin-mutation"]) && canonical(scenario.input.attemptAuthorizationDecisions) === canonical(["deny"]), "initial authorization denial is not the first attempt checkpoint");
        check(scenario.expected.code === "AUTHORIZATION_DENIED" && scenario.expected.preMutation === true && scenario.expected.mutationCount === 0, "initial authorization denial increments mutation state");
      }
      if (scenario.id === "negotiation-receipt-expired-invalid-mac") {
        check(scenario.input.receiptMacXor !== 0 && scenario.input.verifyAtUnixMs > scenario.input.issueAtUnixMs + scenario.input.receiptLifetimeMs, "combined receipt witness lacks both faults");
        check(scenario.expected.code === "NEGOTIATION_RECEIPT_INVALID", "receipt expiry is exposed before MAC authenticity");
      }
      if (scenario.id === "security-hidden-cardinality-error") {
        check(scenario.hiddenServerInputs?.protectedCardinality === 987654321 && scenario.hiddenServerInputs?.derivedCardinalityCanary === "1975308642", "hidden-cardinality server witness differs");
        check(["count", "cardinality", "totalCount", "protectedCardinality", "derivedCardinalityCanary"].every((field) => scenario.forbiddenResponseFields.includes(field)), "hidden-cardinality response field oracle is incomplete");
        check(["987654321", "1975308642"].every((marker) => scenario.hiddenMarkerValues.includes(marker)), "hidden-cardinality exact/derived value oracle is incomplete");
      }
      if (scenario.id.startsWith("envelope-hostile-json-member-names-")) {
        const parsed = JSON.parse(scenario.input.rawInput);
        check(["__proto__", "constructor", "prototype"].every((name) => Object.hasOwn(parsed, name)), `${scenario.id} loses a prototype-sensitive own member`);
        const digest = canonicalDigest(parsed);
        check(digest === scenario.expected.semanticDigest, `${scenario.id} hostile-member canonical digest differs`);
        hostileMemberDigests.push(digest);
      }
      if (scenario.id === "envelope-literal-unpaired-surrogate-code-unit") {
        check(scenario.input.rawInput === "" && canonical(scenario.input.rawInputUtf16CodeUnits) === "[55296]", "literal surrogate carrier is not the frozen UTF-16 code unit");
        const materialized = String.fromCharCode(...scenario.input.rawInputUtf16CodeUnits);
        check(materialized.length === 1 && materialized.charCodeAt(0) === 0xd800, "literal surrogate carrier does not materialize an unpaired high surrogate");
      }
      if (scenario.operation === "release-preflight") {
        const code = evaluateReleasePreflight(scenario.input, releaseAuthority);
        check(scenario.expected.code === code && scenario.expected.result === (code === "NONE" ? "accept" : "reject"), `${scenario.id} release-preflight outcome is not derived from frozen authorities`);
      }
      if (scenario.hiddenMarkerValues !== undefined || scenario.hiddenServerInputs !== undefined) {
        check(category === "security" || category === "transfer" || category === "negotiation" || (category === "idempotency" && scenario.requirementIds.includes("OGVCS-041-AC-04")), `${scenario.id} has hidden inputs outside a security surface`);
        check(Array.isArray(scenario.hiddenMarkerValues) && scenario.hiddenMarkerValues.length >= 1 && scenario.hiddenMarkerValues.length <= 16 && scenario.hiddenMarkerValues.every((marker) => typeof marker === "string" && marker.length >= 8 && Buffer.byteLength(marker, "utf8") <= 1_024), `${scenario.id} hidden marker oracle is invalid`);
        check(scenario.hiddenServerInputs && typeof scenario.hiddenServerInputs === "object" && !Array.isArray(scenario.hiddenServerInputs), `${scenario.id} hidden server input is invalid`);
        const hiddenText = canonical(scenario.hiddenServerInputs);
        const publicInputText = canonical({ input: scenario.input, inputKind: scenario.inputKind, control: scenario.control, configuredLimits: scenario.configuredLimits ?? null });
        for (const marker of scenario.hiddenMarkerValues) {
          check(hiddenText.includes(marker), `${scenario.id} hidden marker is not present in server input`);
          check(!publicInputText.includes(marker), `${scenario.id} leaks a hidden marker into public client input`);
        }
      }
      if (scenario.predecessorCase !== undefined) {
        check(scenario.predecessorCase.contract === "ogvcs.authorization@1" && scenario.predecessorCase.manifestSha256 === manifest.predecessorPins.authorization.manifestSha256, `${scenario.id} predecessor case does not bind authorization authority`);
        check(scenario.predecessorCase.vectorPath === "vectors/grants.json" && /^[0-9a-f]{64}$/.test(scenario.predecessorCase.vectorSha256) && /^[0-9a-f]{64}$/.test(scenario.predecessorCase.caseSha256), `${scenario.id} predecessor vector binding is invalid`);
        check(["native-request-root", "derived-request-root-context", "excluded-explicit-object-carrier"].includes(scenario.predecessorCase.applicability), `${scenario.id} predecessor applicability is invalid`);
        if (scenario.predecessorCase.applicability === "excluded-explicit-object-carrier") check(["valid-download", "wrong-object"].includes(scenario.predecessorCase.caseId) && scenario.expected.code === "TRANSFER_GRANT_INVALID", `${scenario.id} explicit carrier exclusion is invalid`);
        for (const forbidden of ["grantVerification", "authorizationVectorPath", "authorizationCaseId", "authorizationCaseSha256", "authorizationContextPatch"]) check(!Object.hasOwn(scenario.input, forbidden), `${scenario.id} exposes predecessor oracle field ${forbidden}`);
        check(typeof scenario.input.probe?.grant?.envelope === "string" && /^[A-Za-z0-9_-]+$/.test(scenario.input.probe.grant.envelope), `${scenario.id} does not carry an opaque authorization envelope`);
        check(scenario.input.authorizationContext && typeof scenario.input.authorizationContext === "object" && !Array.isArray(scenario.input.authorizationContext), `${scenario.id} lacks the carried authorization context`);
        check(scenario.input.authorizationPublicJwk && typeof scenario.input.authorizationPublicJwk === "object" && !Array.isArray(scenario.input.authorizationPublicJwk), `${scenario.id} lacks the carried public verification key`);
        predecessorCaseIds.add(scenario.predecessorCase.caseId);
      }
      if (category === "resources") {
        const witness = scenario.resourceWitness;
        check(witness && typeof witness.route === "string" && witness.route.length > 0 && ["max", "max-plus-one"].includes(witness.relation), `${scenario.id} lacks an executable resource witness`);
        const key = witness.limit;
        const authority = limits.find((limit) => limit.name === key);
        check(authority && scenario.configuredLimits && Object.keys(scenario.configuredLimits).length === 1 && scenario.configuredLimits[key] === witness.configuredMaximum, `${scenario.id} configured limit does not match its witness`);
        const configuredMinimum = authority.configuredMinimum ?? 1;
        check(Number.isSafeInteger(witness.configuredMaximum) && witness.configuredMaximum >= configuredMinimum && witness.configuredMaximum < authority.value, `${scenario.id} does not use a safe reduced ceiling`);
        const routeAuthority = RESOURCE_ROUTES[key];
        check(routeAuthority && scenario.operation === routeAuthority[0] && witness.route === routeAuthority[1], `${scenario.id} does not use the frozen ${key} production route`);
        const measured = measureResourceCase(key, scenario, schemaSummary.schemaDocuments);
        check(measured === witness.observed, `${scenario.id} witness ${witness.observed} differs from executed ${measured}`);
        const exceeds = key === "maxOperationTimeMs" ? measured >= witness.configuredMaximum : measured > witness.configuredMaximum;
        check(exceeds === (witness.relation === "max-plus-one"), `${scenario.id} executed boundary relation differs`);
        check(scenario.expected.result === (exceeds ? "reject" : "accept") && scenario.expected.code === (exceeds ? "PROTOCOL_LIMIT_EXCEEDED" : "NONE"), `${scenario.id} outcome does not follow executed configured limit`);
        if (key === "maxExtensionEntries") for (const extensionId of Object.keys(scenario.input.document.extensions)) {
          const registration = extensionsById.get(extensionId);
          check(registration?.state === "candidate" && registration.requirement === "optional" && registration.affectedSchemas.includes("RequestEnvelope") && scenario.input.selectedExtensions.includes(extensionId), `${scenario.id} extension ${extensionId} is not a valid registered and selected request payload`);
        }
        if (key === "maxCapabilityItems") {
          check(["protocolVersions", "schemaVersions", "repositoryFormats", "authorizationContracts", "pathContracts", "pathProfiles", "eventVersions", "transferProfiles", "extensions", "requiredCapabilities"].includes(witness.axis), `${scenario.id} capability-axis witness is invalid`);
          check(scenario.input.offer.capabilities[witness.axis].length === witness.observed, `${scenario.id} does not exercise its declared capability axis`);
          if (witness.relation === "max-plus-one") capabilityAxisResourceCoverage.add(witness.axis);
        }
        if (key === "maxTransferRangeBytes" && witness.dimension !== undefined) {
          check(["request", "response"].includes(witness.dimension), `${scenario.id} transfer range dimension is invalid`);
          const requestRange = scenario.input.probe.endOffsetExclusive - scenario.input.probe.startOffset;
          const responseRange = scenario.input.transportResponse.rangeBytes;
          check((witness.dimension === "request" ? requestRange : responseRange) > witness.configuredMaximum && (witness.dimension === "request" ? responseRange : requestRange) <= witness.configuredMaximum, `${scenario.id} is not an asymmetric transfer-range witness`);
          transferRangeResourceCoverage.add(witness.dimension);
        }
        if (!exceeds && scenario.operation === "validate-envelope" && scenario.input.encoding === "semantic-json" && scenario.input.targetSchema !== "JsonValue") {
          check(schemaMatches(scenario.input.document, schemaSummary.schemaDocuments.get(`${scenario.input.targetSchema}.schema.json`), schemaSummary.schemaDocuments), `${scenario.id} max input is invalid after its resource preflight`);
        }
        if (!exceeds && scenario.operation === "transfer-probe") check(schemaMatches(scenario.input.probe, schemaSummary.schemaDocuments.get("TransferProbe.schema.json"), schemaSummary.schemaDocuments), `${scenario.id} max transfer input is schema-invalid`);
        if (!exceeds && scenario.operation === "validate-stream") for (const [index, frame] of scenario.input.frames.entries()) check(schemaMatches(frame, schemaSummary.schemaDocuments.get("StreamFrame.schema.json"), schemaSummary.schemaDocuments), `${scenario.id} max stream frame ${index} is schema-invalid`);
        if (!exceeds && scenario.operation === "contract-load") for (const artifact of scenario.input.artifacts) {
          const decoded = Buffer.from(artifact.bytesHex, "hex");
          let parsed; try { parsed = JSON.parse(decoded.toString("utf8")); } catch { fail(`${scenario.id} max contract artifact is not JSON`); }
          check(Buffer.from(canonical(parsed), "utf8").equals(decoded), `${scenario.id} max contract artifact is not canonical JSON`);
        }
        check(witness.observed <= 65_536, `${scenario.id} attempts an exact-scale materialization`);
        const list = resourcePairs.get(key) ?? [];
        list.push(witness);
        resourcePairs.set(key, list);
        executedResourceCases += 1;
      }
      caseIds.add(scenario.id); total += 1;
    }
    if (category === "idempotency" && value.goldens !== undefined) {
      idempotencyGoldenDocuments += 1;
      check(Array.isArray(value.goldens) && value.goldens.length > 0, "idempotency semantic goldens are missing");
      for (const golden of value.goldens) {
        check(Object.keys(golden.left).sort().join("\0") === schemaSummary.requestFingerprintFields.join("\0"), `${golden.id} projection differs from field policy`);
        check(canonical(golden.left) === golden.leftCanonicalJcs && canonical(golden.right) === golden.rightCanonicalJcs, `${golden.id} JCS differs`);
        check(golden.leftCanonicalJcs === golden.rightCanonicalJcs && golden.equal === true, `${golden.id} reordered semantics differ`);
        check(semanticFingerprint(golden.domain, golden.left) === golden.fingerprint && golden.rawInputFingerprintForbidden === true, `${golden.id} fingerprint differs`);
      }
    } else check(value.goldens === undefined, `${relativePath} has unexpected semantic goldens`);
    artifactRecords.push({ path: relativePath, sha256: sha256(bytes) });
  }
  check(Object.keys(vectorManifest.categories).sort(compareText).join("\0") === [...VECTOR_CATEGORIES].sort(compareText).join("\0"), "vector manifest category inventory differs");
  for (const category of VECTOR_CATEGORIES) check(categoryCounts.get(category) === vectorManifest.categories[category] && categoryCounts.get(category) > 0, `${category} vector case count differs`);
  check(idempotencyGoldenDocuments === 1, "idempotency semantic goldens must occur in exactly one scenario artifact");
  const jsonlPath = path.join(specRoot, "vectors/golden-stream.jsonl");
  const jsonl = await fs.readFile(jsonlPath, "utf8");
  check(jsonl.endsWith("\n"), "golden JSONL lacks LF termination");
  const frames = jsonl.slice(0, -1).split("\n").map((line, index) => {
    let frame; try { frame = JSON.parse(line); } catch (error) { fail(`golden stream line ${index} is invalid: ${error.message}`); }
    check(canonical(frame) === line, `golden stream line ${index} is not RFC 8785 canonical`);
    check(frame.sequence === index, `golden stream line ${index} sequence differs`);
    return frame;
  });
  check(frames.length >= 1 && frames.at(-1).kind === "terminal" && !frames.slice(0, -1).some((frame) => ["terminal", "gap", "cancelled", "error"].includes(frame.kind)), "golden stream terminal semantics differ");
  const jsonlBytes = Buffer.from(jsonl, "utf8");
  check(goldenStreamScenario?.operation === "validate-stream" && goldenStreamScenario.inputKind === "jsonl" && goldenStreamScenario.input.encoding === "jsonl", "golden stream has no executable validate-stream case");
  check(Buffer.from(goldenStreamScenario.input.jsonl, "utf8").equals(jsonlBytes), "golden stream executable input is not byte-identical to golden-stream.jsonl");
  check(canonical(goldenStreamScenario.input.frames) === canonical(frames), "golden stream executable frame inventory differs");
  artifactRecords.push({ path: "vectors/golden-stream.jsonl", sha256: sha256(jsonlBytes) });
  const tracePath = path.join(specRoot, "vectors/golden-traces.jsonl");
  const traceText = await fs.readFile(tracePath, "utf8");
  check(traceText.endsWith("\n"), "golden trace JSONL lacks LF termination");
  const traceIds = new Set();
  let priorTraceId = "";
  for (const [index, line] of traceText.slice(0, -1).split("\n").entries()) {
    let record; try { record = JSON.parse(line); } catch (error) { fail(`golden trace line ${index} is invalid: ${error.message}`); }
    check(canonical(record) === line, `golden trace line ${index} is not RFC 8785 canonical`);
    check(Object.keys(record).sort().join("\0") === ["id", "trace", "traceDigest"].sort().join("\0"), `golden trace line ${index} is not closed`);
    check(typeof record.id === "string" && !traceIds.has(record.id) && compareText(priorTraceId, record.id) <= 0, `golden trace id ${String(record.id)} is invalid, duplicated, or unordered`);
    check(schemaMatches(record.trace, schemaSummary.schemaDocuments.get("AdapterTrace.schema.json"), schemaSummary.schemaDocuments), `${record.id} golden trace does not match AdapterTrace`);
    check(record.traceDigest === canonicalDigest(record.trace) && expectedTraceDigests.get(record.id) === record.traceDigest, `${record.id} golden trace digest differs from its independently canonicalized oracle`);
    traceIds.add(record.id); priorTraceId = record.id;
  }
  check(traceIds.size === total && traceIds.size === expectedTraceDigests.size && [...caseIds].every((id) => traceIds.has(id)), "golden trace coverage differs from the complete scenario inventory");
  const traceBytes = Buffer.from(traceText, "utf8");
  artifactRecords.push({ path: "vectors/golden-traces.jsonl", sha256: sha256(traceBytes) });
  check(total === vectorManifest.totalCases && accepts === vectorManifest.acceptCases && rejects === vectorManifest.rejectCases, "vector case totals differ");
  check(artifactSetDigest(vectorManifest.artifacts) === vectorManifest.vectorSetSha256, "vector manifest set digest differs");
  for (const artifact of vectorManifest.artifacts) {
    const found = artifactRecords.find((entry) => entry.path === artifact.path);
    check(found && found.sha256 === artifact.sha256, `vector manifest artifact ${artifact.path} differs`);
  }
  for (const limit of limits) {
    const witnesses = resourcePairs.get(limit.name) ?? [];
    const expectedWitnesses = limit.name === "maxCapabilityItems" ? 11 : limit.name === "maxTransferRangeBytes" ? 4 : 2;
    check(witnesses.length === expectedWitnesses, `resource vectors for ${limit.name} have ${witnesses.length}, expected ${expectedWitnesses}`);
    check(new Set(witnesses.map((entry) => entry.relation)).size === 2 && witnesses.some((entry) => entry.relation === "max") && witnesses.some((entry) => entry.relation === "max-plus-one"), `resource vectors for ${limit.name} do not cover reduced max/max+1`);
  }
  check(capabilityAxisResourceCoverage.size === 10, `maxCapabilityItems covers ${capabilityAxisResourceCoverage.size}, expected all 10 independent axes`);
  check(transferRangeResourceCoverage.size === 2, "maxTransferRangeBytes lacks asymmetric request/response coverage");
  check(executedResourceCases === limits.length * 2 + 11, `resource executor ran ${executedResourceCases}, expected ${limits.length * 2 + 11}`);
  check(caseIds.has("envelope-pre-cancelled") && caseIds.has("stream-cancelled-mid-flight"), "pre-aborted and mid-flight cancellation scenarios are missing");
  const decreasingClock = scenariosById.get("malformed-decreasing-clock-samples");
  const hardDefaultDeadline = scenariosById.get("envelope-hard-default-operation-time-expired");
  check(decreasingClock?.expected.code === "PROTOCOL_MALFORMED" && canonical(decreasingClock.control.clockSamplesUnixMs) === canonical([1_001, 1_000]) && decreasingClock.expected.mutationCount === 0, "decreasing runner clock preflight witness differs");
  check(hardDefaultDeadline?.expected.code === "DEADLINE_EXCEEDED" && hardDefaultDeadline.configuredLimits === undefined && canonical(hardDefaultDeadline.control.clockSamplesUnixMs) === canonical([0, hardOperationTimeMs]) && hardDefaultDeadline.expected.mutationCount === 0, "hard/default operation deadline witness differs");
  const codeUnitCase = caseIds.has("envelope-literal-unpaired-surrogate-code-unit");
  check(codeUnitCase, "literal unpaired-surrogate code-unit carrier is missing");
  check(caseIds.has("idempotency-timeout-late-commit-reconcile") && caseIds.has("idempotency-response-loss-replay"), "lost-response idempotency recovery scenarios are missing");
  check(caseIds.has("idempotency-after-retention-same-key-requires-new-key"), "post-retention idempotency key rejection scenario is missing");
  for (const row of compatibilityRegistry.entries.filter((entry) => ["candidate", "ratified"].includes(entry.state))) {
    for (const extensionId of row.selection.extensions) {
      const registration = extensionsById.get(extensionId);
      check(registration && registration.requirement === "optional" && ["candidate", "ratified"].includes(registration.state), `compatibility row ${row.code} selects an ineligible extension ${extensionId}`);
      check(positiveExtensionSelectionCoverage.has(`${row.code}\0${extensionId}`), `compatibility row ${row.code} extension ${extensionId} lacks positive selection coverage`);
    }
  }
  const safeRequiredPositive = scenariosById.get("negotiation-required-safe-extension-selected");
  const safeRequiredNegative = scenariosById.get("negotiation-required-safe-extension-not-offered");
  const deterministicExtensions = scenariosById.get("negotiation-extension-selection-deterministic");
  const cleartextLoopback = scenariosById.get("negotiation-cleartext-loopback-rejected");
  const safeExtension = "ogvcs.extension.safe-optional@1";
  const auditExtension = "ogvcs.extension.audit-optional@1";
  check(safeRequiredPositive?.expected.result === "accept" && canonical(safeRequiredPositive.input.offer.capabilities.extensions) === canonical([safeExtension]) && safeRequiredPositive.input.offer.capabilities.requiredCapabilities.includes(safeExtension) && canonical(safeRequiredPositive.input.serverSelection.extensions) === canonical([safeExtension]), "registered required extension positive selection witness differs");
  check(safeRequiredNegative?.expected.result === "reject" && safeRequiredNegative.expected.code === "NEGOTIATION_NO_COMMON_VERSION" && !safeRequiredNegative.input.offer.capabilities.extensions.includes(safeExtension) && safeRequiredNegative.input.offer.capabilities.requiredCapabilities.includes(safeExtension), "registered required extension omitted-axis negative witness differs");
  check(deterministicExtensions?.expected.result === "accept" && canonical(deterministicExtensions.input.offer.capabilities.extensions) === canonical([auditExtension, safeExtension]) && canonical(deterministicExtensions.input.serverSelection.extensions) === canonical([safeExtension, auditExtension]), "extension selection does not prove compatibility-row order independent of offer order");
  check(cleartextLoopback?.expected.result === "reject" && cleartextLoopback.expected.code === "NEGOTIATION_DOWNGRADE_REJECTED" && cleartextLoopback.input.transportScheme === "http" && cleartextLoopback.input.tlsVersion === "1.3" && cleartextLoopback.input.loopbackConformance === true && cleartextLoopback.expected.mutationCount === 0, "cleartext loopback negotiation rejection witness differs");
  check(replayAuthorizationCoverage === 1, "mandatory replay authorization coverage is missing or duplicated");
  for (const caseId of [
    "idempotency-future-issued-key-requires-new-key", "idempotency-retry-only-unused-key-first-execution", "idempotency-zero-tombstone-retention-first-execution", "idempotency-already-expired-key-requires-new-key", "idempotency-max-lifetime-replay", "idempotency-lifetime-too-long", "idempotency-retention-before-expiry-replay", "idempotency-key-reuse-schema-version",
    "idempotency-key-issued-at-field-mismatch", "idempotency-key-expires-at-field-mismatch", "idempotency-initial-authorization-denied", "idempotency-attempt-projection-index-out-of-range", "idempotency-projection-missing-schema-version", "idempotency-projection-unknown-field", "idempotency-route-retryable-required", "idempotency-key-required",
  ]) check(caseIds.has(caseId), `idempotency authority case ${caseId} is missing`);
  for (const dimension of ["subject", "tenant", "repository", "operation", "query"]) check(caseIds.has(`cursor-wrong-${dimension}`), `cursor scope coverage omits ${dimension}`);
  for (const caseId of ["cursor-scope-unknown-field", "cursor-scope-missing-operation", "cursor-issued-at-max-expiry-overflow"]) check(caseIds.has(caseId), `cursor scope/numeric shape case ${caseId} is missing`);
  for (const caseId of ["negotiation-server-nonce-noncanonical-base64url", "negotiation-server-nonce-max-64-bytes", "negotiation-server-nonce-max-plus-one-65-bytes", "negotiation-receipt-expired-invalid-mac"]) check(caseIds.has(caseId), `negotiation canonical/authenticity case ${caseId} is missing`);
  const nonce64 = scenariosById.get("negotiation-server-nonce-max-64-bytes");
  const nonce65 = scenariosById.get("negotiation-server-nonce-max-plus-one-65-bytes");
  const noncanonicalNonce = scenariosById.get("negotiation-server-nonce-noncanonical-base64url");
  check(nonce64?.expected.result === "accept" && canonicalBase64url(nonce64.input.serverNonce, 64, 64), "64-byte canonical server nonce positive boundary differs");
  check(nonce65?.expected.result === "reject" && nonce65.expected.code === "PROTOCOL_MALFORMED" && canonicalBase64url(nonce65.input.serverNonce, 65, 65) && !canonicalBase64url(nonce65.input.serverNonce, 16, 64), "65-byte canonical server nonce negative boundary differs");
  check(noncanonicalNonce?.expected.result === "reject" && noncanonicalNonce.expected.code === "PROTOCOL_MALFORMED" && Buffer.from(noncanonicalNonce.input.serverNonce, "base64url").toString("base64url") !== noncanonicalNonce.input.serverNonce, "noncanonical server nonce spelling witness differs");
  const zeroReceiptLifetime = scenariosById.get("malformed-negotiation-zero-receipt-lifetime");
  const zeroCursorTtl = scenariosById.get("malformed-cursor-zero-ttl");
  const cursorIssuedAtOverflow = scenariosById.get("cursor-issued-at-max-expiry-overflow");
  check(zeroReceiptLifetime?.operation === "validate-envelope" && zeroReceiptLifetime.input.targetSchema === "NegotiationCaseInput" && zeroReceiptLifetime.input.document.receiptLifetimeMs === 0 && zeroReceiptLifetime.expected.result === "reject" && zeroReceiptLifetime.expected.code === "PROTOCOL_MALFORMED", "zero receipt lifetime schema-validation witness differs");
  check(zeroCursorTtl?.operation === "validate-envelope" && zeroCursorTtl.input.targetSchema === "CursorCaseInput" && zeroCursorTtl.input.document.ttlMs === 0 && zeroCursorTtl.expected.result === "reject" && zeroCursorTtl.expected.code === "PROTOCOL_MALFORMED", "zero cursor TTL schema-validation witness differs");
  check(cursorIssuedAtOverflow?.operation === "validate-cursor" && cursorIssuedAtOverflow.input.issuedAtUnixMs === Number.MAX_SAFE_INTEGER && cursorIssuedAtOverflow.input.readAtUnixMs === Number.MAX_SAFE_INTEGER && cursorIssuedAtOverflow.input.ttlMs === 1 && !Number.isSafeInteger(cursorIssuedAtOverflow.input.issuedAtUnixMs + cursorIssuedAtOverflow.input.ttlMs) && cursorIssuedAtOverflow.expected.code === "PROTOCOL_MALFORMED", "cursor issuedAt MAX derived-expiry overflow witness differs");
  for (const caseId of ["stream-frame-missing-schema-version", "stream-frame-missing-kind", "stream-frame-missing-stream-id", "stream-frame-unknown-field", "stream-empty-eof-incomplete", "stream-mid-frame-eof-incomplete"]) check(caseIds.has(caseId), `stream framing case ${caseId} is missing`);
  for (const caseId of ["transfer-resume-without-validator", "transfer-malformed-non-grant-before-invalid-grant", "transfer-invalid-range-before-invalid-grant", "transfer-authz-wrong-permission", "transfer-grant-explicit-object-count-negative", "transfer-explicit-object-list", "transfer-configured-grant-bytes-then-malformed-shape", "transfer-grant-explicit-object-count-max-safe"]) check(caseIds.has(caseId), `transfer preflight/grant case ${caseId} is missing`);
  for (const [caseId, count] of [["transfer-grant-explicit-object-count-negative", -1], ["transfer-explicit-object-list", 1], ["transfer-grant-explicit-object-count-max-safe", Number.MAX_SAFE_INTEGER]]) {
    const scenario = scenariosById.get(caseId);
    check(scenario?.input.probe.grant.explicitObjectCount === count && scenario.expected.result === "reject" && scenario.expected.code === "TRANSFER_GRANT_INVALID" && transferProbePreflightOutcome(scenario.input, schemaSummary.schemaDocuments) === "TRANSFER_GRANT_INVALID", `grant explicitObjectCount ${count} does not execute the named grant-shape failure`);
  }
  const configuredGrantShape = scenariosById.get("transfer-configured-grant-bytes-then-malformed-shape");
  const configuredGrantEnvelopeBytes = decodedBase64urlBytes(configuredGrantShape?.input.probe.grant.envelope);
  const configuredGrantWrapperBytes = Buffer.byteLength(canonical(configuredGrantShape?.input.probe.grant), "utf8");
  check(configuredGrantShape?.configuredLimits?.maxGrantBytes === configuredGrantEnvelopeBytes
    && configuredGrantEnvelopeBytes === 741
    && configuredGrantWrapperBytes > configuredGrantEnvelopeBytes
    && configuredGrantShape.input.probe.grant.explicitObjectCount === 1
    && configuredGrantShape.expected.result === "reject"
    && configuredGrantShape.expected.code === "TRANSFER_GRANT_INVALID"
    && transferProbePreflightOutcome(configuredGrantShape.input, schemaSummary.schemaDocuments) === "TRANSFER_GRANT_INVALID",
  "configured grant-byte preflight does not measure only the envelope before the named grant-shape failure");
  for (const caseId of ["cursor-gap-explicit", "cursor-gap-wrong-problem-code", "stream-explicit-gap", "stream-gap-wrong-problem-code"]) check(caseIds.has(caseId), `gap semantic case ${caseId} is missing`);
  for (const caseId of ["envelope-retry-after-match", "envelope-retry-after-missing", "envelope-retry-after-mismatch", "envelope-retry-after-duplicate-case-folded", "envelope-retry-after-malformed", "envelope-retry-after-http-date", "envelope-retry-after-without-safe-parameter"]) check(caseIds.has(caseId), `Retry-After case ${caseId} is missing`);
  for (const status of ["complete", "partial", "interrupted", "rejected"]) check(caseIds.has(`transfer-result-${status}`), `transfer result coverage omits ${status}`);
  const zeroProgressInterrupted = scenariosById.get("transfer-result-interrupted-zero-progress");
  check(zeroProgressInterrupted?.expected.result === "accept" && zeroProgressInterrupted.input.probeResult.status === "interrupted" && zeroProgressInterrupted.input.probeResult.acceptedStart === zeroProgressInterrupted.input.probeResult.acceptedEndExclusive && zeroProgressInterrupted.input.probeResult.acceptedEndExclusive < zeroProgressInterrupted.input.probeResult.totalBytes, "zero-progress interrupted transfer result coverage differs");
  check([...caseIds].filter((caseId) => caseId.startsWith("transfer-result-") && !["transfer-result-complete", "transfer-result-partial", "transfer-result-interrupted", "transfer-result-rejected"].includes(caseId)).length >= 8, "transfer result cross-state negatives are incomplete");
  for (const caseId of [
    "transfer-http-no-range-200", "transfer-http-no-range-open-end-200", "transfer-http-range-roundtrip-206", "transfer-http-range-open-end-206", "transfer-http-resume-if-range-strong",
    "transfer-http-content-digest-missing", "transfer-http-content-digest-malformed-present", "transfer-http-content-digest-duplicate-case-folded", "transfer-http-content-digest-body-mismatch", "transfer-http-content-digest-expected-mismatch",
    "transfer-http-etag-missing", "transfer-http-etag-weak", "transfer-http-etag-malformed", "transfer-http-etag-duplicate-case-folded", "transfer-http-etag-resume-mismatch",
    "transfer-http-unsatisfied-range-416", "transfer-http-unsatisfied-content-digest-forbidden", "transfer-http-unsatisfied-etag-forbidden", "transfer-http-range-request-off-by-one", "transfer-http-content-range-total-mismatch",
    "transfer-http-if-range-weak", "transfer-http-if-range-mismatch", "transfer-http-range-malformed", "transfer-http-range-duplicate-case-folded", "transfer-http-content-range-duplicate-case-folded", "transfer-http-content-length-missing", "transfer-http-content-length-mismatch", "transfer-http-negative-total-bytes", "transfer-http-unsupported-status-without-validators",
  ]) check(caseIds.has(caseId), `HTTP Range carrier case ${caseId} is missing`);
  const negativeTotal = scenariosById.get("transfer-http-negative-total-bytes");
  check(negativeTotal?.input.transportResponse.totalBytes === -1 && negativeTotal.expected.result === "reject" && negativeTotal.expected.code === "PROTOCOL_MALFORMED" && transferHttpRangeOutcome(negativeTotal.input, schemaSummary.schemaDocuments) === "PROTOCOL_MALFORMED", "negative transfer total does not fail as malformed before range semantics");
  check(hostileMemberDigests.length === 2 && new Set(hostileMemberDigests).size === 1, "prototype-sensitive raw JSON parsing/canonicalization cases are missing or inconsistent");
  check(releaseCoverage > 0, "release-preflight has no OGVCS-041-AC-05 coverage");
  check(ac04Operations.has("negotiate"), "AC-04 has no negotiation leak coverage");
  check(caseIds.has("security-hidden-cardinality-error"), "AC-04 has no hidden cardinality/count leak coverage");
  check(predecessorCaseIds.size === 16, `protocol carrier binds ${predecessorCaseIds.size}, expected all 16 authorization vectors`);
  check(total === manifest.counts.scenarios && accepts === manifest.counts.acceptScenarios && rejects === manifest.counts.rejectScenarios, "contract manifest scenario counts differ");
  return total;
}

async function validatePredecessors(repositoryRoot, manifest) {
  const expectedGeneratorInputs = new Map([
    ["spec/authorization/v1/LICENSE", "authorization-license-provenance"],
    ["spec/authorization/v1/manifest.json", "authorization-manifest-authority"],
    ["spec/authorization/v1/vectors/grants.json", "authorization-grant-conformance-input"],
  ]);
  check(Array.isArray(manifest.generatorInputs) && manifest.generatorInputs.length === expectedGeneratorInputs.size, "offline predecessor generator input inventory differs");
  let priorGeneratorInput = "";
  for (const input of manifest.generatorInputs) {
    check(relativeIsSafe(input.path) && expectedGeneratorInputs.get(input.path) === input.role, `generator input ${String(input.path)} is undeclared or unsafe`);
    check(compareText(priorGeneratorInput, input.path) <= 0 && Number.isSafeInteger(input.bytes) && input.bytes > 0 && /^[0-9a-f]{64}$/.test(input.sha256), `generator input ${input.path} metadata is invalid`);
    check(["application/json", "text/plain; charset=utf-8"].includes(input.mediaType), `generator input ${input.path} media type is invalid`);
    priorGeneratorInput = input.path;
  }
  const expected = {
    authorization: ["spec/authorization/v1/manifest.json", "registrySetSha256"],
    path: ["spec/path-filesystem/v1/manifest.json", "registrySetSha256"],
    repository: ["spec/repository-format/v1/vectors/manifest.json", null],
  };
  for (const [axis, [relativePath, registryField]] of Object.entries(expected)) {
    const pin = manifest.predecessorPins?.[axis];
    check(pin && pin.manifestPath === relativePath && /^[0-9a-f]{64}$/.test(pin.manifestSha256), `${axis} predecessor pin is invalid`);
    const filePath = path.join(repositoryRoot, relativePath);
    try {
      const bytes = await fs.readFile(filePath);
      check(sha256(bytes) === pin.manifestSha256, `${axis} predecessor manifest drifted`);
      if (registryField) {
        const predecessor = JSON.parse(bytes.toString("utf8"));
        check(predecessor[registryField] === pin.registrySetSha256, `${axis} predecessor registry set drifted`);
      }
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const repositorySnapshot = path.join(repositoryRoot, "spec/repository-format/v1/vectors/registries/live-snapshot.json");
  try {
    const snapshot = JSON.parse(await fs.readFile(repositorySnapshot, "utf8"));
    check(snapshot.registrySetSha256 === manifest.predecessorPins.repository.registrySetSha256, "repository predecessor registry set drifted");
  } catch (error) { if (error.code !== "ENOENT") throw error; }
  const grantsPath = path.join(repositoryRoot, "spec/authorization/v1/vectors/grants.json");
  try {
    const bytes = await fs.readFile(grantsPath);
    const grants = JSON.parse(bytes.toString("utf8"));
    const grantInput = manifest.generatorInputs.find((entry) => entry.path === "spec/authorization/v1/vectors/grants.json");
    const authorizationManifestInput = manifest.generatorInputs.find((entry) => entry.path === manifest.predecessorPins.authorization.manifestPath);
    const authorizationManifestBytes = await fs.readFile(path.join(repositoryRoot, manifest.predecessorPins.authorization.manifestPath));
    const authorizationManifest = JSON.parse(authorizationManifestBytes.toString("utf8"));
    const grantArtifact = authorizationManifest.artifacts?.find((entry) => entry.path === "vectors/grants.json");
    check(authorizationManifestInput.bytes === authorizationManifestBytes.length && authorizationManifestInput.sha256 === sha256(authorizationManifestBytes) && authorizationManifestInput.sha256 === manifest.predecessorPins.authorization.manifestSha256, "authorization manifest generator input differs from the predecessor pin");
    check(grantArtifact?.sha256 === grantInput.sha256 && grantInput.bytes === bytes.length && grantInput.sha256 === sha256(bytes), "authorization grant generator input lacks exact manifest provenance");
    const licenseInput = manifest.generatorInputs.find((entry) => entry.path === "spec/authorization/v1/LICENSE");
    const licenseBytes = await fs.readFile(path.join(repositoryRoot, licenseInput.path));
    check(licenseInput.bytes === licenseBytes.length && licenseInput.sha256 === sha256(licenseBytes) && licenseBytes.toString("utf8").includes("MIT License"), "authorization license generator input differs or is not MIT");
    const cases = new Map(grants.cases.map((entry) => [entry.id, entry]));
    const protocolVectorRoot = path.join(repositoryRoot, "spec/protocols/v1");
    const protocolVectorManifest = JSON.parse(await fs.readFile(path.join(protocolVectorRoot, "vectors/manifest.json"), "utf8"));
    for (const artifact of protocolVectorManifest.artifacts.filter((entry) => Number.isSafeInteger(entry.cases))) {
      const vector = JSON.parse(await fs.readFile(path.join(protocolVectorRoot, artifact.path), "utf8"));
      for (const scenario of vector.cases.filter((entry) => entry.predecessorCase !== undefined)) {
        const binding = scenario.predecessorCase;
        check(binding.vectorSha256 === sha256(bytes), `${scenario.id} authorization vector digest differs`);
        check(cases.has(binding.caseId) && canonicalDigest(cases.get(binding.caseId)) === binding.caseSha256, `${scenario.id} authorization case digest differs`);
        const predecessorCase = cases.get(binding.caseId);
        const requestRootCase = cases.get("valid-request-root");
        const envelopeBytes = Buffer.from(scenario.input.probe.grant.envelope, "base64url");
        check(envelopeBytes.toString("base64url") === scenario.input.probe.grant.envelope, `${scenario.id} carried grant envelope is not canonical base64url`);
        let carriedEnvelope;
        try { carriedEnvelope = JSON.parse(envelopeBytes.toString("utf8")); } catch { fail(`${scenario.id} carried grant envelope is not JSON`); }
        check(canonical(carriedEnvelope) === envelopeBytes.toString("utf8"), `${scenario.id} carried grant envelope is not canonical JSON`);
        let expectedContext;
        if (binding.applicability === "native-request-root" || binding.applicability === "excluded-explicit-object-carrier") {
          check(canonical(carriedEnvelope) === canonical(predecessorCase.envelope), `${scenario.id} carried native grant differs from its harness-only predecessor binding`);
          expectedContext = structuredClone(predecessorCase.context);
        } else {
          check(Object.hasOwn(DERIVED_REQUEST_ROOT_CONTEXT_FIELDS, binding.caseId) || ["transfer-authz-wrong-tenant", "transfer-authz-wrong-permission"].includes(scenario.id), `${scenario.id} has no registered request-root derivation`);
          expectedContext = structuredClone(requestRootCase.context);
          for (const name of DERIVED_REQUEST_ROOT_CONTEXT_FIELDS[binding.caseId] ?? []) expectedContext[name] = structuredClone(predecessorCase.context[name]);
          if (binding.caseId === "replayed") {
            check(carriedEnvelope.claims?.replay === "single-use" && carriedEnvelope.claims.nonce === "protocol-root-replay-0001", `${scenario.id} derived replay claims differ`);
            const normalizedClaims = { ...carriedEnvelope.claims, replay: requestRootCase.envelope.claims.replay, nonce: requestRootCase.envelope.claims.nonce };
            check(canonical(normalizedClaims) === canonical(requestRootCase.envelope.claims), `${scenario.id} derived replay fixture changes unrelated claims`);
            expectedContext.consumedNonces = [carriedEnvelope.claims.nonce];
          } else if (binding.caseId === "altered-claims") {
            const expectedEnvelope = structuredClone(requestRootCase.envelope);
            expectedEnvelope.signature = `${expectedEnvelope.signature[0] === "A" ? "B" : "A"}${expectedEnvelope.signature.slice(1)}`;
            check(canonical(carriedEnvelope) === canonical(expectedEnvelope), `${scenario.id} bad-signature fixture is not the fixed request-root bit flip`);
          } else check(canonical(carriedEnvelope) === canonical(requestRootCase.envelope), `${scenario.id} derived grant is not the authenticated request-root base`);
          if (scenario.id === "transfer-authz-wrong-tenant") expectedContext.tenant = "tenant-private-041";
          if (scenario.id === "transfer-authz-wrong-permission") expectedContext.permission = "content.inspect";
        }
        if (binding.applicability === "excluded-explicit-object-carrier") {
          check(carriedEnvelope.claims?.requestRoot === null && carriedEnvelope.claims.objectIds?.length === 1, `${scenario.id} excluded grant is not an explicit-object carrier`);
        } else check(typeof carriedEnvelope.claims?.requestRoot === "string" && carriedEnvelope.claims.objectIds?.length === 0 && scenario.input.probe.grant.representation === "request-root" && scenario.input.probe.grant.explicitObjectCount === 0, `${scenario.id} does not execute the compact request-root verifier path`);
        check(canonical(scenario.input.authorizationContext) === canonical(expectedContext), `${scenario.id} carried authorization context differs from its declared derivation`);
        check(canonical(scenario.input.authorizationPublicJwk) === canonical(grants.key.publicJwk), `${scenario.id} carried authorization public JWK differs from the predecessor witness`);
      }
    }
  } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function validateCompatibility(specRoot, manifest) {
  const compatibility = (await readCanonicalJson(path.join(specRoot, "registries/compatibility.json"))).value;
  check(compatibility.selectionDigestAuthority === "negotiationRegistrySetSha256", "compatibility selection digest authority differs");
  check(canonical(compatibility.predecessorPins) === canonical(manifest.predecessorPins), "compatibility predecessor pins differ");
  check(compatibility.entries.length > 0, "compatibility registry is empty");
  for (const entry of compatibility.entries) {
    const selection = entry.selection;
    check(selection.protocolRegistrySetSha256 === manifest.negotiationRegistrySetSha256, "compatibility negotiation registry digest differs");
    check(selection.authorizationRegistrySha256 === manifest.predecessorPins.authorization.registrySetSha256, "compatibility authorization digest differs");
    check(selection.pathRegistrySha256 === manifest.predecessorPins.path.registrySetSha256, "compatibility path digest differs");
    check(selection.repositoryRegistrySha256 === manifest.predecessorPins.repository.registrySetSha256, "compatibility repository digest differs");
    check(entry.authorizationManifestSha256 === manifest.predecessorPins.authorization.manifestSha256 && entry.pathManifestSha256 === manifest.predecessorPins.path.manifestSha256 && entry.repositoryManifestSha256 === manifest.predecessorPins.repository.manifestSha256, "compatibility predecessor manifests differ");
  }
}

async function validateAdapterExecutionView(specRoot, manifest) {
  const viewPath = path.join(specRoot, "adapter-execution-view.json");
  const { bytes: viewBytes, value: view } = await readCanonicalJson(viewPath);
  check(view.schemaVersion === "ogvcs.protocol/adapter-execution-view/v1" && view.contractVersion === manifest.contractVersion && view.license === "MIT", "adapter execution view header differs");
  check(view.contractManifestPath === "manifest.json" && view.contractManifestSha256 === undefined, "adapter execution view manifest relationship differs");
  check(Object.keys(view).sort().join("\0") === ["authorityArtifacts", "authoritySetSha256", "contractManifestPath", "contractVersion", "excludedNamespaces", "license", "limitsRegistryPath", "predecessorPins", "schemaVersion"].sort().join("\0"), "adapter execution view exposes an undeclared authority or generator input");
  check(manifest.adapterExecutionView?.path === "adapter-execution-view.json" && manifest.adapterExecutionView.bytes === viewBytes.length && manifest.adapterExecutionView.sha256 === sha256(viewBytes), "contract manifest does not authenticate adapter execution view bytes");
  check(canonical(view.predecessorPins) === canonical(manifest.predecessorPins), "adapter execution view predecessor pins differ");
  check(view.limitsRegistryPath === "registries/limits.json" && canonical(view.excludedNamespaces) === canonical(["docs/", "vectors/"]), "adapter execution view exclusions differ");
  const expected = manifest.artifacts.filter((artifact) => artifact.path.startsWith("profiles/") || artifact.path.startsWith("registries/") || artifact.path.startsWith("schemas/"));
  check(canonical(view.authorityArtifacts) === canonical(expected), "adapter execution view authority inventory differs");
  check(artifactSetDigest(view.authorityArtifacts) === view.authoritySetSha256, "adapter execution view authority digest differs");
  check(view.authoritySetSha256 === manifest.adapterExecutionView.authoritySetSha256, "adapter execution view authority digest is not manifest-bound");
  check(!view.authorityArtifacts.some((artifact) => !["profiles/", "registries/", "schemas/"].some((prefix) => artifact.path.startsWith(prefix)) || artifact.path.startsWith("vectors/") || artifact.path.startsWith("docs/") || artifact.path.includes("expected")), "adapter execution view exposes non-authority data or conformance oracles");
  for (const artifact of view.authorityArtifacts) {
    const bytes = await fs.readFile(path.join(specRoot, artifact.path));
    check(bytes.length === artifact.bytes && sha256(bytes) === artifact.sha256, `adapter authority ${artifact.path} differs`);
  }
}

async function validateSecuritySchemas(specRoot) {
  const selection = (await readCanonicalJson(path.join(specRoot, "schemas/NegotiationSelection.schema.json"))).value;
  for (const field of ["authorizationContract", "authorizationRegistrySha256", "pathContract", "pathProfile", "pathRegistrySha256", "repositoryFormat", "repositoryRegistrySha256"]) check(selection.required.includes(field), `selection does not independently bind ${field}`);
  const claims = (await readCanonicalJson(path.join(specRoot, "schemas/NegotiationReceiptClaims.schema.json"))).value;
  for (const field of ["selection", "subjectDigest", "tenantDigest", "authorityEpoch", "sessionId", "clientNonce", "serverNonce", "issuedAtUnixMs", "expiresAtUnixMs"]) check(claims.required.includes(field), `receipt claims do not bind ${field}`);
  check(claims["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "canonicalBase64url" && entry.field === "serverNonce" && entry.minimumDecodedBytes === 16 && entry.maximumDecodedBytes === 64), "receipt claims lack canonical server nonce authority");
  const receipt = (await readCanonicalJson(path.join(specRoot, "schemas/NegotiationReceipt.schema.json"))).value;
  check(receipt.properties.algorithm.const === "HMAC-SHA-256" && receipt.required.includes("mac"), "receipt is not MACed");
  const negotiationCase = (await readCanonicalJson(path.join(specRoot, "schemas/NegotiationCaseInput.schema.json"))).value;
  for (const kind of ["canonicalBase64url", "negotiationTransport", "receiptVerificationOrder"]) check(negotiationCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === kind), `negotiation case lacks ${kind} authority`);
  check(negotiationCase.properties.serverNonce.maxLength === 87 && negotiationCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "canonicalBase64url" && entry.field === "serverNonce" && entry.minimumDecodedBytes === 16 && entry.maximumDecodedBytes === 64), "negotiation nonce conformance carrier/semantic bounds differ");
  check(negotiationCase["x-ogvcs-semantic-constraints"].some((entry) => entry.kind === "negotiationTransport" && entry.schemeField === "transportScheme" && entry.tlsField === "tlsVersion" && entry.loopbackField === "loopbackConformance" && entry.requiredScheme === "https" && entry.requiredTls === "1.3" && entry.loopbackException === false), "negotiation HTTPS/TLS transport authority differs");
  check(negotiationCase.properties.receiptLifetimeMs.minimum === 1, "negotiation receipt lifetime is not strictly positive");
  const problem = (await readCanonicalJson(path.join(specRoot, "schemas/ProblemDetails.schema.json"))).value;
  check(problem.additionalProperties === false && !problem.properties.detail && !problem.properties.instance, "problem schema is not closed/safe");
  const parameter = (await readCanonicalJson(path.join(specRoot, "schemas/SafeParameter.schema.json"))).value;
  const branches = parameter.allOf?.[0]?.oneOf;
  check(Array.isArray(branches) && branches.length === 3, "safe parameter schema is not a closed three-domain union");
  const retryBranch = branches.find((branch) => branch.properties?.name?.const === "retryAfterMs");
  const retryPattern = new RegExp(retryBranch?.properties?.value?.pattern ?? "(?!)", "u");
  check(retryPattern.test("86400000") && !retryPattern.test("86400001") && !retryPattern.test("99999999") && !retryPattern.test("01"), "retryAfterMs canonical decimal bounds differ");
  check(!JSON.stringify(parameter).includes("currentGeneration"), "R0 SafeParameter schema exposes currentGeneration");
  const cursor = (await readCanonicalJson(path.join(specRoot, "schemas/Cursor.schema.json"))).value;
  check(Object.keys(cursor.properties).join("") === "token", "public cursor exposes non-opaque state");
  const cursorScope = (await readCanonicalJson(path.join(specRoot, "schemas/CursorScopeInput.schema.json"))).value;
  check(cursorScope.additionalProperties === false && canonical([...cursorScope.required].sort()) === canonical(["subject", "tenant", "repository", "operation", "queryDigest"].sort()) && canonical(Object.keys(cursorScope.properties).sort()) === canonical(["subject", "tenant", "repository", "operation", "queryDigest"].sort()), "cursor scope is not the exact closed five-dimension carrier");
  const cursorCase = (await readCanonicalJson(path.join(specRoot, "schemas/CursorCaseInput.schema.json"))).value;
  check(cursorCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "cursorScopes" && entry.projectionSchema === "CursorScopeInput"), "cursor case does not bind both scopes to the closed projection schema");
  check(cursorCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "cursorLifetime" && entry.issuedAtField === "issuedAtUnixMs" && entry.ttlField === "ttlMs" && entry.maximumExpiry === Number.MAX_SAFE_INTEGER), "cursor expiry checked-addition authority differs");
  check(cursorCase.properties.ttlMs.minimum === 1, "cursor TTL is not strictly positive");
  const grant = (await readCanonicalJson(path.join(specRoot, "schemas/CompactTransferGrant.schema.json"))).value;
  check(grant.properties.explicitObjectCount.minimum === 0 && grant.properties.explicitObjectCount.maximum === 0 && !grant.properties.objectIds, "transfer grant admits explicit object identifiers");
  check(grant.properties.envelope["x-ogvcs-sensitive"] === true && grant.properties.envelope["x-ogvcs-fingerprint"] === false, "transfer grant envelope is not marked protected");
  const probe = (await readCanonicalJson(path.join(specRoot, "schemas/TransferProbe.schema.json"))).value;
  check(probe.properties.contentEncoding.const === "identity" && probe.properties.followRedirects.const === false, "transfer probe permits compression or redirects");
  check(probe.properties.grant["x-ogvcs-sensitive"] === true && probe.properties.grant["x-ogvcs-fingerprint"] === false, "transfer probe grant carrier is not marked protected");
  const stream = (await readCanonicalJson(path.join(specRoot, "schemas/StreamFrame.schema.json"))).value;
  check(stream.properties.kind.enum.includes("terminal") && stream.required.includes("sequence") && stream.properties.finalDigest === undefined, "stream schema lacks explicit typed terminal semantics or retains finalDigest" );
  const envelopeCase = (await readCanonicalJson(path.join(specRoot, "schemas/EnvelopeCaseInput.schema.json"))).value;
  check(envelopeCase.properties.headers.items.$ref === "TransportHeaderInput.schema.json" && envelopeCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "retryAfterHeader"), "envelope case lacks case-insensitive Retry-After authority");
  check(["NegotiationCaseInput", "CursorCaseInput"].every((name) => envelopeCase.properties.targetSchema.enum.includes(name)), "envelope schema-validation route omits lifetime-boundary target schemas");
  const traceHeader = (await readCanonicalJson(path.join(specRoot, "schemas/TraceHeader.schema.json"))).value;
  check(traceHeader.properties.name.pattern === "^[a-z0-9-]+$", "emitted trace header names are not canonical lowercase");
  const transferResult = (await readCanonicalJson(path.join(specRoot, "schemas/TransferProbeResult.schema.json"))).value;
  check(transferResult["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "transferResultState" && entry.partialProgress === "acceptedStart<acceptedEndExclusive<totalBytes" && entry.interruptedProgress === "acceptedStart<=acceptedEndExclusive<totalBytes") && transferResult.allOf?.[0]?.oneOf?.length === 4, "transfer result state authority is missing");
  const runnerControl = (await readCanonicalJson(path.join(specRoot, "schemas/RunnerExecutionControl.schema.json"))).value;
  check(runnerControl["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "runnerClockSamples" && entry.samplesField === "clockSamplesUnixMs" && entry.order === "nondecreasing" && entry.elapsedComputation === "checked-last-minus-first" && entry.configuredLimit === "maxOperationTimeMs" && entry.hardMaximumMs === 120_000 && entry.expirationComparison === "elapsed>=effectiveMaximum" && entry.decreasingOutcome === "PROTOCOL_MALFORMED" && entry.expirationOutcome === "DEADLINE_EXCEEDED"), "runner clock/deadline authority differs");
  const runnerCase = (await readCanonicalJson(path.join(specRoot, "schemas/RunnerCase.schema.json"))).value;
  check(!runnerCase.properties.resourceRecipe && runnerCase.properties.configuredLimits && runnerCase.properties.serverContext?.["x-ogvcs-sensitive"] === true, "RunnerCase retains virtual recipes or lacks sensitive server context");
  check(runnerCase.allOf?.[0]?.oneOf?.length === OPERATIONS.size, "RunnerCase operation inputs are not independently schema-bound");
  const transferCase = (await readCanonicalJson(path.join(specRoot, "schemas/TransferCaseInput.schema.json"))).value;
  check(transferCase.properties.authorizationContext?.$ref === "#/$defs/JsonValue" && transferCase.properties.authorizationContext["x-ogvcs-sensitive"] === true && transferCase.properties.authorizationContext["x-ogvcs-fingerprint"] === false, "authorization context is not a bounded protected generic carrier");
  check(transferCase.properties.authorizationPublicJwk?.$ref === "#/$defs/JsonValue" && transferCase.properties.authorizationPublicJwk["x-ogvcs-sensitive"] === false && transferCase.properties.authorizationPublicJwk["x-ogvcs-fingerprint"] === false, "authorization public JWK carrier policy differs");
  for (const field of ["grantVerification", "authorizationVectorPath", "authorizationCaseId", "authorizationCaseSha256", "authorizationContextPatch"]) check(!Object.hasOwn(transferCase.properties, field), `TransferCaseInput exposes harness-only ${field}`);
  const transferNonGrant = (await readCanonicalJson(path.join(specRoot, "schemas/TransferProbeNonGrantInput.schema.json"))).value;
  check(transferNonGrant.additionalProperties === false && transferNonGrant.properties.grant === undefined && transferNonGrant["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "transferProbeRange"), "transfer non-grant preflight schema differs");
  check(transferNonGrant.properties.schemaVersion.const === "ogvcs.protocol/transfer-probe-non-grant-input/v1" && transferNonGrant.properties.schemaVersion.const !== probe.properties.schemaVersion.const, "transfer non-grant projection does not have a distinct schema selector");
  check(transferCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === "transferProbePreflight" && entry.projectionSchema === "TransferProbeNonGrantInput" && entry.sourceSchemaVersion === probe.properties.schemaVersion.const && entry.projectionSchemaVersion === transferNonGrant.properties.schemaVersion.const), "transfer case lacks non-grant-before-grant preflight authority");
  const adapterResult = (await readCanonicalJson(path.join(specRoot, "schemas/AdapterResult.schema.json"))).value;
  const adapterTrace = (await readCanonicalJson(path.join(specRoot, "schemas/AdapterTrace.schema.json"))).value;
  check(adapterResult.required.includes("trace") && adapterResult.properties.trace.$ref === "AdapterTrace.schema.json", "AdapterResult does not carry the public trace");
  check(["responseBody", "responseHeaders", "streamFrames", "logEntries", "semanticOutput"].every((field) => adapterTrace.required.includes(field)), "AdapterTrace omits an observable public surface");
  const runnerResult = (await readCanonicalJson(path.join(specRoot, "schemas/RunnerResult.schema.json"))).value;
  check(runnerResult.required.includes("traceDigest") && !runnerResult.properties.trace, "RunnerResult is not trace-digest-only");
  const report = (await readCanonicalJson(path.join(specRoot, "schemas/RunnerReport.schema.json"))).value;
  check(report.properties.results.maxItems === 1_024 && report.properties.results.items.$ref === "RunnerResult.schema.json", "RunnerReport is not sanitized/report-safe");
  const descriptor = (await readCanonicalJson(path.join(specRoot, "schemas/IdempotencyDescriptor.schema.json"))).value;
  const fingerprintCase = (await readCanonicalJson(path.join(specRoot, "schemas/FingerprintCaseInput.schema.json"))).value;
  const projection = (await readCanonicalJson(path.join(specRoot, "schemas/IdempotencyProjectionInput.schema.json"))).value;
  check(projection.additionalProperties === false && canonical([...projection.required].sort()) === canonical(["schemaVersion", "operation", "body", "extensions"].sort()) && canonical(Object.keys(projection.properties).sort()) === canonical(["schemaVersion", "operation", "body", "extensions"].sort()), "idempotency projection schema is not exact and closed");
  for (const kind of ["selfDatingIdempotencyKey", "idempotencyProjections", "indexIntoArray", "idempotencyExecution"]) check(fingerprintCase["x-ogvcs-semantic-constraints"]?.some((entry) => entry.kind === kind), `fingerprint case lacks ${kind} authority`);
  const descriptorConstraint = descriptor["x-ogvcs-semantic-constraints"]?.find((entry) => entry.kind === "selfDatingIdempotencyKey");
  check(descriptor.required.includes("issuedAtUnixMs") && descriptor.required.includes("expiresAtUnixMs"), "idempotency descriptor omits lifetime fields");
  check(descriptor.properties.key.pattern === "^ik1\\.(?:0|[1-9][0-9]{0,15})\\.(?:0|[1-9][0-9]{0,15})\\.[A-Za-z0-9_-]{22,218}$", "idempotency key syntax differs");
  check(descriptor.properties.key["x-ogvcs-sensitive"] === true && descriptor.properties.key["x-ogvcs-fingerprint"] === false, "idempotency key is not marked protected");
  check(cursor.properties.token["x-ogvcs-sensitive"] === true && cursor.properties.token["x-ogvcs-fingerprint"] === false, "cursor token is not marked protected");
  check(receipt.properties.mac["x-ogvcs-sensitive"] === true && receipt.properties.mac["x-ogvcs-fingerprint"] === false, "receipt MAC is not marked protected");
  check(descriptorConstraint?.keyField === "key" && descriptorConstraint.issuedAtField === "issuedAtUnixMs" && descriptorConstraint.expiresAtField === "expiresAtUnixMs" && descriptorConstraint.maxLifetimeMs === 86_400_000 && descriptorConstraint.maxFutureIssueSkewMs === 0, "idempotency descriptor semantic lifetime authority differs");
}

async function validateBindingManifest(repositoryRoot, specRoot, bindingsRoot, contractManifestBytes, manifest, schemaSummary) {
  let bindingBytes;
  try { bindingBytes = await fs.readFile(path.join(bindingsRoot, "manifest.json")); } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  const bindingManifest = JSON.parse(bindingBytes.toString("utf8"));
  check(Buffer.from(canonical(bindingManifest), "utf8").equals(bindingBytes), "binding manifest is not canonical JSON");
  check(bindingManifest.schemaVersion === "ogvcs.protocol/binding-manifest/v1" && bindingManifest.contractVersion === manifest.contractVersion && bindingManifest.license === "MIT", "binding manifest header differs");
  check(bindingManifest.contractManifestPath === "spec/protocols/v1/manifest.json" && bindingManifest.contractManifestSha256 === sha256(contractManifestBytes), "binding manifest does not pin contract manifest");
  check(bindingManifest.modelSha256 === manifest.modelSha256, "binding model digest differs");
  const actual = (await listFiles(bindingsRoot)).filter((relativePath) => relativePath !== "manifest.json");
  await validateArtifactInventory(bindingsRoot, bindingManifest.artifacts, actual, "binding");
  check(artifactSetDigest(bindingManifest.artifacts) === bindingManifest.bindingSetSha256, "binding set digest differs");
  const descriptorDocument = (await readCanonicalJson(path.join(bindingsRoot, "descriptors.json"), "binding descriptors")).value;
  check(descriptorDocument.schemaVersion === "ogvcs.protocol/binding-descriptors/v1" && descriptorDocument.contractVersion === manifest.contractVersion && descriptorDocument.contractManifestSha256 === sha256(contractManifestBytes) && descriptorDocument.license === "MIT", "binding descriptor header differs");
  check(jsonEqual(descriptorDocument.messages, schemaSummary.descriptors.messages) && jsonEqual(descriptorDocument.fields, schemaSummary.descriptors.fields), "binding descriptors differ from field assignments or schemas");
  check(descriptorDocument.messages.length === schemaSummary.messageCount && descriptorDocument.fields.length === schemaSummary.fieldCount, "binding descriptor count differs");
  check(bindingManifest.languages.map((entry) => entry.language).sort().join("\0") === ["cpp", "csharp", "rust", "typescript"].join("\0"), "binding language set differs");
  for (const language of bindingManifest.languages) {
    const modelBytes = await fs.readFile(path.join(bindingsRoot, language.modelPath), "utf8");
    check(modelBytes.includes(bindingManifest.contractManifestSha256), `${language.language} model does not pin contract manifest`);
    const descriptorSymbol = language.language === "csharp" ? "ProtocolDescriptors" : language.language === "cpp" ? "field_descriptors" : "FIELD_DESCRIPTORS";
    check(modelBytes.includes(descriptorSymbol), `${language.language} model omits its immutable descriptor table`);
    check((await fs.readFile(path.join(bindingsRoot, `${language.language}/LICENSE`), "utf8")).startsWith("MIT License"), `${language.language} license differs`);
  }
  const csharp = bindingManifest.languages.find((entry) => entry.language === "csharp");
  const nugetConfig = await fs.readFile(path.join(bindingsRoot, "csharp/NuGet.Config"), "utf8");
  check(nugetConfig.includes("<packageSources>") && nugetConfig.includes("<clear />") && csharp.command.includes("--configfile") && csharp.command.includes("--no-restore") && !csharp.command.includes("ignore-failed"), "C# offline restore is not fail-closed");
  const sourceRecords = [];
  for (const source of manifest.generatorSources) {
    const bytes = await fs.readFile(path.join(repositoryRoot, "foundation/protocol-baseline/codegen", source.path));
    check(sha256(bytes) === source.sha256, `generator source ${source.path} digest differs`);
    sourceRecords.push({ path: source.path, sha256: source.sha256 });
  }
  check(canonicalDigest(sourceRecords) === manifest.generatorSha256 && bindingManifest.codegenSha256 === manifest.generatorSha256, "generator source-set digest differs");
}

export async function validateProtocolContract(options = {}) {
  const repositoryRoot = options.repositoryRoot ?? DEFAULT_REPOSITORY_ROOT;
  const specRoot = options.specRoot ?? DEFAULT_SPEC_ROOT;
  const bindingsRoot = options.bindingsRoot ?? path.join(repositoryRoot, "foundation/protocol-baseline/bindings");
  const { bytes: manifestBytes, value: manifest } = await readCanonicalJson(path.join(specRoot, "manifest.json"), "manifest.json");
  check(manifest.schemaVersion === "ogvcs.protocol/contract-manifest/v1", "manifest schemaVersion differs");
  check(manifest.contractVersion === "1.0.0-rc.1" && manifest.state === "candidate" && manifest.ratified === false, "candidate lifecycle/version differs");
  check(manifest.packageName === "@opengamevcs/protocol-contract-v1" && manifest.license === "MIT", "package identity/license differs");
  check(canonical(manifest.distributedSupportFilesExcludedFromArtifactDigest) === canonical(["adapter-execution-view.json", "validate-spec.mjs"]) && canonical(manifest.developmentFilesExcluded) === canonical(["test/**"]), "manifest support/development exclusions differ");
  const packageDocument = (await readCanonicalJson(path.join(specRoot, "package.json"))).value;
  check(packageDocument.scripts?.check === "node validate-spec.mjs" && packageDocument.scripts?.test === "node validate-spec.mjs" && packageDocument.scripts?.generate === undefined, "installed package scripts are not self-contained");
  check(packageDocument.files.includes("validate-spec.mjs") && packageDocument.files.includes("adapter-execution-view.json"), "installed package omits its validator or adapter view");
  check(manifest.counts.profiles === 2 && manifest.counts.documents === 9 && manifest.counts.vectorCategories === VECTOR_CATEGORIES.length, "profile/document/vector-category counts differ");
  const distributed = ["LICENSE", "README.md", "package.json"];
  for (const directory of ["docs", "profiles", "registries", "schemas", "vectors"]) distributed.push(...await listFiles(specRoot, directory));
  await validateArtifactInventory(specRoot, manifest.artifacts, distributed, "contract");
  const schemaSummary = await validateSchemasAndAssignments(specRoot);
  check(schemaSummary.messageCount === manifest.counts.messages && schemaSummary.fieldCount === manifest.counts.assignedFields, "schema/field manifest counts differ");
  const registrySummary = await validateRegistries(specRoot, manifest, schemaSummary);
  check(registrySummary.errors.length === manifest.counts.errors && registrySummary.limits.length === manifest.counts.limits, "error/limit manifest counts differ");
  await validateProfiles(specRoot);
  await validateSecuritySchemas(specRoot);
  await validateCompatibility(specRoot, manifest);
  await validateAdapterExecutionView(specRoot, manifest);
  await validatePredecessors(repositoryRoot, manifest);
  const scenarios = await validateVectors(specRoot, registrySummary.errorNames, registrySummary.limits, manifest, schemaSummary);
  await validateBindingManifest(repositoryRoot, specRoot, bindingsRoot, manifestBytes, manifest, schemaSummary);
  return { artifacts: manifest.artifacts.length, messages: schemaSummary.messageCount, fields: schemaSummary.fieldCount, errors: registrySummary.errors.length, limits: registrySummary.limits.length, scenarios, manifestSha256: sha256(manifestBytes) };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const summary = await validateProtocolContract();
  console.log(`validated protocol contract ${summary.manifestSha256}: ${summary.artifacts} artifacts, ${summary.messages} schemas, ${summary.scenarios} scenarios`);
}
