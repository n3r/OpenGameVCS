#!/usr/bin/env node
// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  AUTHORIZATION_CASE_DIGESTS,
  AUTHORIZATION_GRANT_VECTOR_SHA256,
  CAPABILITIES,
  COMPATIBILITY,
  CONTRACT,
  DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE,
  DOCS,
  ERROR_CODES,
  GOLDEN_STREAM_FRAMES,
  GOLDEN_STREAM_JSONL,
  IDEMPOTENCY_KEY_MAX_FUTURE_ISSUE_SKEW_MS,
  IDEMPOTENCY_KEY_MAX_LIFETIME_MS,
  LIMITS,
  MESSAGES,
  PREDECESSORS,
  REGISTRIES,
  RELEASE_ALLOWED_ADDITIONS,
  RELEASE_ASSIGNMENTS,
  RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN,
  RELEASE_ASSIGNMENT_SNAPSHOT_SHA256,
  RELEASE_COMPATIBILITY_POLICY,
  RUNNER_OPERATIONS,
  SAFE_PARAMETER_DOMAINS,
  SCENARIOS,
  SUPPORTED_TYPE_KINDS,
  TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION,
  TRANSFER_PROBE_SCHEMA_VERSION,
  VECTOR_CATEGORIES,
} from "./model.mjs";
import { canonicalBytes, canonicalJsonLine, canonicalSha256, semanticFingerprint, sha256 } from "./canonical.mjs";

const CODEGEN_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(CODEGEN_ROOT, "../../..");
const SPEC_ROOT = path.join(REPOSITORY_ROOT, "spec/protocols/v1");
const BINDINGS_ROOT = path.join(REPOSITORY_ROOT, "foundation/protocol-baseline/bindings");
const CHECK = process.argv.slice(2).includes("--check");
const unknownArgs = process.argv.slice(2).filter((value) => value !== "--check");
if (unknownArgs.length) throw new Error(`unsupported arguments: ${unknownArgs.join(", ")}`);

const LICENSE = `MIT License

Copyright (c) 2026 OpenGameVCS contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

const JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";
const SCHEMA_BASE = "https://schemas.opengamevcs.dev/protocol/v1/";
const MAX_SAFE = Number.MAX_SAFE_INTEGER;
const RUNNER_INPUT_SCHEMAS = Object.freeze({
  negotiate: "NegotiationCaseInput",
  "validate-envelope": "EnvelopeCaseInput",
  fingerprint: "FingerprintCaseInput",
  "validate-cursor": "CursorCaseInput",
  "validate-stream": "StreamCaseInput",
  "transfer-probe": "TransferCaseInput",
  "contract-load": "ContractLoadCaseInput",
  "runner-batch": "RunnerBatchCaseInput",
  "release-preflight": "ReleasePreflightCaseInput",
});

function invariant(condition, message) {
  if (!condition) throw new Error(`protocol model invalid: ${message}`);
}

function validateIdentifier(value, label) {
  invariant(typeof value === "string" && /^[A-Za-z][A-Za-z0-9]*$/.test(value), `${label} is not a generated-language identifier`);
}

function validateType(type, label, messageNames, active = new Set()) {
  invariant(type && typeof type === "object" && !Array.isArray(type), `${label} has no type object`);
  invariant(SUPPORTED_TYPE_KINDS.includes(type.kind), `${label} uses unsupported type kind ${String(type.kind)}`);
  if (active.has(type)) throw new Error(`protocol model invalid: ${label} contains a cyclic type declaration`);
  active.add(type);
  switch (type.kind) {
    case "string":
      invariant(Number.isSafeInteger(type.minLength) && Number.isSafeInteger(type.maxLength) && type.minLength >= 0 && type.maxLength >= type.minLength, `${label} string bounds are invalid`);
      invariant(type.maxLength <= LIMITS.find((entry) => entry.name === "maxStringUtf8Bytes").value, `${label} exceeds global string bound`);
      if (type.pattern !== undefined) {
        invariant(typeof type.pattern === "string" && type.pattern.length <= 512, `${label} pattern is invalid`);
        new RegExp(type.pattern, "u");
      }
      if (type.maxUtf8Bytes !== undefined) invariant(Number.isSafeInteger(type.maxUtf8Bytes) && type.maxUtf8Bytes >= 0, `${label} maxUtf8Bytes is invalid`);
      break;
    case "integer":
      invariant(Number.isSafeInteger(type.minimum) && Number.isSafeInteger(type.maximum) && type.minimum >= -MAX_SAFE && type.maximum <= MAX_SAFE && type.minimum <= type.maximum, `${label} integer bounds are invalid`);
      break;
    case "boolean":
      invariant(type.const === undefined || typeof type.const === "boolean", `${label} boolean const is invalid`);
      break;
    case "enum":
      invariant(Array.isArray(type.values) && type.values.length > 0, `${label} enum is empty`);
      invariant(new Set(type.values.map((value) => `${typeof value}:${String(value)}`)).size === type.values.length, `${label} enum has duplicates`);
      invariant(type.values.every((value) => typeof value === "string" || (Number.isSafeInteger(value) && Math.abs(value) <= MAX_SAFE)), `${label} enum has unsupported values`);
      invariant(new Set(type.values.map((value) => typeof value)).size === 1, `${label} mixes enum primitive types`);
      break;
    case "reference":
      invariant(messageNames.has(type.name), `${label} references unknown message ${type.name}`);
      break;
    case "array":
      invariant(Number.isSafeInteger(type.minItems) && Number.isSafeInteger(type.maxItems) && type.minItems >= 0 && type.maxItems >= type.minItems, `${label} array bounds are invalid`);
      invariant(type.maxItems <= LIMITS.find((entry) => entry.name === "maxArrayItems").value, `${label} exceeds global array bound`);
      invariant(type.uniqueItems === undefined || typeof type.uniqueItems === "boolean", `${label} uniqueItems is invalid`);
      validateType(type.items, `${label}[]`, messageNames, active);
      break;
    case "map":
      invariant(Number.isSafeInteger(type.minProperties) && Number.isSafeInteger(type.maxProperties) && type.minProperties >= 0 && type.maxProperties >= type.minProperties, `${label} map bounds are invalid`);
      invariant(type.maxProperties <= LIMITS.find((entry) => entry.name === "maxObjectMembers").value, `${label} exceeds global object-member bound`);
      invariant(typeof type.keyPattern === "string" && type.keyPattern.length <= 512, `${label} map key pattern is invalid`);
      new RegExp(type.keyPattern, "u");
      invariant(Number.isSafeInteger(type.maxKeyUtf8Bytes) && type.maxKeyUtf8Bytes >= 1 && type.maxKeyUtf8Bytes <= 256, `${label} map key byte bound is invalid`);
      validateType(type.values, `${label}{}`, messageNames, active);
      break;
    case "json":
      invariant(Number.isSafeInteger(type.maxDepth) && type.maxDepth >= 1 && type.maxDepth <= LIMITS.find((entry) => entry.name === "maxJsonDepth").value, `${label} JSON depth is invalid`);
      invariant(Number.isSafeInteger(type.maxNodes) && type.maxNodes >= 1 && type.maxNodes <= LIMITS.find((entry) => entry.name === "maxJsonNodes").value, `${label} JSON node bound is invalid`);
      break;
    default:
      throw new Error(`protocol model invalid: ${label} reached unsupported type kind ${type.kind}`);
  }
  active.delete(type);
}

export function assertSupportedModelType(type, referenceNames = []) {
  validateType(type, "test.type", new Set(referenceNames));
  return true;
}

function validateModel() {
  invariant(CONTRACT.version === "1.0.0-rc.1", "candidate version must remain 1.0.0-rc.1 until predecessors ratify");
  invariant(CONTRACT.license === "MIT", "contract license must be MIT");
  const messageCodes = new Set();
  const messageNames = new Set(MESSAGES.map((message) => message.name));
  const schemaVersionSelectors = new Map();
  invariant(messageNames.size === MESSAGES.length, "message names are not unique");
  for (const message of MESSAGES) {
    validateIdentifier(message.name, `message ${message.name}`);
    invariant(Number.isInteger(message.code) && message.code > 0 && message.code <= 65_535, `${message.name} message code is invalid`);
    invariant(!messageCodes.has(message.code), `message code ${message.code} is reused`);
    messageCodes.add(message.code);
    invariant(Array.isArray(message.fields) && message.fields.length > 0, `${message.name} has no fields`);
    const ids = new Set();
    const names = new Set();
    for (const entry of message.fields) {
      invariant(Number.isInteger(entry.id) && entry.id > 0 && entry.id <= 65_535, `${message.name}.${entry.name} field id is invalid`);
      invariant(!ids.has(entry.id), `${message.name} reuses field id ${entry.id}`);
      invariant(!names.has(entry.name), `${message.name} reuses field name ${entry.name}`);
      validateIdentifier(entry.name, `${message.name}.${entry.name}`);
      invariant(typeof entry.required === "boolean" && typeof entry.sensitive === "boolean" && typeof entry.fingerprint === "boolean", `${message.name}.${entry.name} policies are invalid`);
      ids.add(entry.id);
      names.add(entry.name);
      validateType(entry.type, `${message.name}.${entry.name}`, messageNames);
    }
    const schemaVersionField = message.fields.find((entry) => entry.name === "schemaVersion");
    if (schemaVersionField?.required && schemaVersionField.type.kind === "enum" && schemaVersionField.type.values.length === 1 && typeof schemaVersionField.type.values[0] === "string") {
      const selector = schemaVersionField.type.values[0];
      invariant(!schemaVersionSelectors.has(selector), `${message.name} reuses schemaVersion selector ${selector} from ${schemaVersionSelectors.get(selector)}`);
      schemaVersionSelectors.set(selector, message.name);
    }
    for (const reserved of message.reservedFields ?? []) {
      invariant(Number.isInteger(reserved.id) && reserved.id > 0 && reserved.id <= 65_535 && !ids.has(reserved.id), `${message.name} reserved field id is invalid or active`);
      invariant(typeof reserved.name === "string" && reserved.name.length > 0 && !names.has(reserved.name), `${message.name} reserved field name is invalid or active`);
      invariant(typeof reserved.reason === "string" && reserved.reason.length > 0, `${message.name} reserved field reason is missing`);
      ids.add(reserved.id);
      names.add(reserved.name);
    }
    for (const constraint of message.constraints ?? []) {
      const constraintFields = {
        successOutcome: [constraint.discriminator, constraint.successField, constraint.failureField],
        registeredProblem: [],
        safeParameterValue: [constraint.nameField, constraint.valueField],
        pageState: [constraint.discriminator, constraint.cursorField, constraint.problemField],
        streamKind: [constraint.discriminator, constraint.payloadField, constraint.problemField],
        nonEmptyObject: [],
        encodedDocument: [constraint.encodingField, constraint.documentField, constraint.rawField],
        retryAfterHeader: [constraint.documentField, constraint.headersField],
        transferResultState: [constraint.statusField, constraint.startField, constraint.endField, constraint.totalField, constraint.terminalField, constraint.problemField],
        transferCaseResult: [constraint.routeField, constraint.resultField],
        transferHttpRange: [constraint.routeField, constraint.probeField, constraint.responseStatusField, constraint.requestHeadersField, constraint.responseHeadersField, constraint.responseBodyHexField],
        runnerOperation: [constraint.operationField, constraint.inputField],
        mutationWitness: [constraint.preMutationField, constraint.mutationCountField],
        selfDatingIdempotencyKey: [constraint.keyField, constraint.issuedAtField, constraint.expiresAtField],
        canonicalBase64url: [constraint.field],
        negotiationTransport: [constraint.schemeField, constraint.tlsField, constraint.loopbackField],
        runnerClockSamples: [constraint.samplesField],
        receiptVerificationOrder: [constraint.routeField, constraint.macMutationField, constraint.verifyAtField, constraint.issueAtField, constraint.lifetimeField],
        idempotencyProjections: [constraint.arrayField],
        indexIntoArray: [constraint.indexArrayField, constraint.targetArrayField],
        idempotencyExecution: [constraint.routeField, constraint.retryableField, constraint.keyField],
        cursorScopes: [constraint.issueField, constraint.readField],
        cursorLifetime: [constraint.issuedAtField, constraint.readAtField, constraint.ttlField],
        transferProbeRange: [constraint.startField, constraint.endField, constraint.validatorField],
        transferProbePreflight: [constraint.routeField, constraint.probeField],
      }[constraint.kind];
      invariant(constraintFields !== undefined, `${message.name} uses unsupported constraint ${constraint.kind}`);
      for (const name of constraintFields) {
        invariant(names.has(name), `${message.name} constraint references unknown field ${name}`);
      }
      if (constraint.kind === "selfDatingIdempotencyKey") {
        invariant(Number.isSafeInteger(constraint.maxLifetimeMs) && constraint.maxLifetimeMs > 0, `${message.name} idempotency key lifetime is invalid`);
        invariant(Number.isSafeInteger(constraint.maxFutureIssueSkewMs) && constraint.maxFutureIssueSkewMs >= 0, `${message.name} idempotency future issue skew is invalid`);
        invariant(constraint.allowEmptyKey === undefined || typeof constraint.allowEmptyKey === "boolean", `${message.name} empty idempotency key policy is invalid`);
        if (constraint.evaluatorTimeField !== undefined) invariant(names.has(constraint.evaluatorTimeField), `${message.name} idempotency evaluator time field is unknown`);
      }
      if (constraint.kind === "canonicalBase64url") {
        invariant(Number.isSafeInteger(constraint.minimumDecodedBytes) && constraint.minimumDecodedBytes >= 0, `${message.name} canonical base64url minimum is invalid`);
        invariant(Number.isSafeInteger(constraint.maximumDecodedBytes) && constraint.maximumDecodedBytes >= constraint.minimumDecodedBytes, `${message.name} canonical base64url maximum is invalid`);
      }
      if (constraint.kind === "negotiationTransport") {
        invariant(constraint.requiredScheme === "https" && constraint.requiredTls === "1.3" && constraint.loopbackException === false, `${message.name} negotiation transport policy is invalid`);
      }
      if (constraint.kind === "cursorLifetime") {
        invariant(constraint.maximumExpiry === Number.MAX_SAFE_INTEGER, `${message.name} cursor expiry maximum is invalid`);
      }
      if (constraint.kind === "runnerClockSamples") {
        const hardMaximum = LIMITS.find((entry) => entry.name === constraint.configuredLimit)?.value;
        invariant(constraint.order === "nondecreasing" && constraint.elapsedComputation === "checked-last-minus-first" && constraint.hardMaximumMs === hardMaximum && constraint.expirationComparison === "elapsed>=effectiveMaximum" && constraint.decreasingOutcome === "PROTOCOL_MALFORMED" && constraint.expirationOutcome === "DEADLINE_EXCEEDED", `${message.name} runner clock policy is invalid`);
      }
      if (constraint.kind === "transferProbePreflight") {
        invariant(typeof constraint.grantField === "string" && constraint.grantField.length > 0, `${message.name} transfer preflight grant field is invalid`);
        invariant(messageNames.has(constraint.projectionSchema), `${message.name} transfer preflight schema is unknown`);
      }
      if (constraint.kind === "idempotencyProjections" || constraint.kind === "cursorScopes") invariant(messageNames.has(constraint.projectionSchema), `${message.name} projection schema is unknown`);
    }
  }
  const limitCodes = new Set();
  const limitNames = new Set();
  for (const limit of LIMITS) {
    invariant(Number.isInteger(limit.code) && limit.code > 0 && !limitCodes.has(limit.code), `limit code ${limit.code} is invalid or reused`);
    invariant(!limitNames.has(limit.name), `limit name ${limit.name} is reused`);
    invariant(Number.isSafeInteger(limit.value) && limit.value >= 0, `limit ${limit.name} value is invalid`);
    limitCodes.add(limit.code);
    limitNames.add(limit.name);
  }
  const errorCodes = new Set();
  const errorNames = new Set();
  invariant(Object.keys(SAFE_PARAMETER_DOMAINS).length === 3, "safe parameter domain set is not closed");
  invariant(SAFE_PARAMETER_DOMAINS.conflictClass.type === "string" && SAFE_PARAMETER_DOMAINS.conflictClass.values.length > 0, "conflictClass domain is invalid");
  invariant(SAFE_PARAMETER_DOMAINS.gapClass.type === "string" && SAFE_PARAMETER_DOMAINS.gapClass.values.length > 0, "gapClass domain is invalid");
  invariant(SAFE_PARAMETER_DOMAINS.retryAfterMs.type === "canonical-decimal" && SAFE_PARAMETER_DOMAINS.retryAfterMs.minimum === 0 && SAFE_PARAMETER_DOMAINS.retryAfterMs.maximum === 86_400_000, "retryAfterMs domain is invalid");
  for (const error of ERROR_CODES) {
    invariant(Number.isInteger(error.code) && error.code > 0 && !errorCodes.has(error.code), `error code ${error.code} is invalid or reused`);
    invariant(/^[A-Z][A-Z0-9_]+$/.test(error.name) && !errorNames.has(error.name), `error name ${error.name} is invalid or reused`);
    invariant(Number.isInteger(error.status) && error.status >= 400 && error.status <= 599, `error ${error.name} status is invalid`);
    invariant(![...error.safeParameters].some((name) => !Object.hasOwn(SAFE_PARAMETER_DOMAINS, name)), `error ${error.name} has unsafe parameter`);
    errorCodes.add(error.code);
    errorNames.add(error.name);
  }
  invariant(RELEASE_ALLOWED_ADDITIONS.length > 0, "release addition authority is empty");
  const priorReleaseNames = new Set(RELEASE_ASSIGNMENTS.map((entry) => `${entry.kind}\0${entry.scope}\0${entry.name}`));
  const priorReleaseCodes = new Set(RELEASE_ASSIGNMENTS.map((entry) => `${entry.kind}\0${entry.scope}\0${entry.code}`));
  invariant(RELEASE_ASSIGNMENTS.every((entry) => /^[0-9a-f]{64}$/u.test(entry.semanticSha256)), "release semantic SHA-256 authority is invalid");
  for (const addition of RELEASE_ALLOWED_ADDITIONS) {
    const assignment = addition.assignment;
    const registration = REGISTRIES.extensions.find((entry) => entry.id === assignment.name);
    invariant(addition.registry === "extensions" && addition.state === "candidate" && addition.requirement === "optional" && addition.major === 1, "release addition policy is not optional candidate v1");
    invariant(assignment.kind === "extension" && assignment.scope === "extension-registry" && registration?.code === assignment.code && registration.state === addition.state && registration.requirement === addition.requirement && assignment.name.endsWith("@1"), "release addition is not bound to its registry");
    invariant(/^[0-9a-f]{64}$/u.test(assignment.semanticSha256), "release addition semantic SHA-256 is invalid");
    invariant(!priorReleaseNames.has(`${assignment.kind}\0${assignment.scope}\0${assignment.name}`) && !priorReleaseCodes.has(`${assignment.kind}\0${assignment.scope}\0${assignment.code}`), "release addition collides with the prior snapshot");
  }
  const scenarioIds = new Set();
  for (const scenario of SCENARIOS) {
    invariant(!scenarioIds.has(scenario.id) && /^[a-z0-9][a-z0-9-]{0,127}$/.test(scenario.id), `scenario id ${scenario.id} is invalid or reused`);
    invariant(VECTOR_CATEGORIES.includes(scenario.category), `scenario ${scenario.id} has unknown category`);
    invariant(RUNNER_OPERATIONS.includes(scenario.operation), `scenario ${scenario.id} has unknown operation`);
    invariant(["accept", "reject"].includes(scenario.expected.result), `scenario ${scenario.id} has invalid result`);
    invariant(scenario.expected.result === "accept" ? scenario.expected.code === "NONE" : errorNames.has(scenario.expected.code), `scenario ${scenario.id} has unregistered expected code`);
    invariant(typeof scenario.expected.preMutation === "boolean" && Number.isSafeInteger(scenario.expected.mutationCount) && scenario.expected.mutationCount >= 0, `scenario ${scenario.id} has an invalid mutation witness`);
    invariant(scenario.expected.preMutation === (scenario.expected.mutationCount === 0), `scenario ${scenario.id} mutation witness is inconsistent`);
    if (scenario.expected.mutationCount > 0) invariant(scenario.category === "idempotency" && scenario.expected.mutationCount === 1, `scenario ${scenario.id} permits an unsupported post-mutation outcome`);
    scenarioIds.add(scenario.id);
  }
}

function jsonValueDefinition(type) {
  return {
    anyOf: [
      { type: "null" },
      { type: "boolean" },
      { type: "integer", minimum: -MAX_SAFE, maximum: MAX_SAFE },
      { type: "string", maxLength: 65_536, "x-ogvcs-maxUtf8Bytes": 65_536 },
      { type: "array", maxItems: 4_096, items: { $ref: "#/$defs/JsonValue" } },
      { type: "object", maxProperties: 256, propertyNames: { maxLength: 256, "x-ogvcs-maxUtf8Bytes": 256 }, additionalProperties: { $ref: "#/$defs/JsonValue" } },
    ],
    "x-ogvcs-maxDepth": type.maxDepth,
    "x-ogvcs-maxNodes": type.maxNodes,
  };
}

function schemaForType(type) {
  switch (type.kind) {
    case "string": {
      const schema = { type: "string", minLength: type.minLength, maxLength: type.maxLength };
      if (type.pattern !== undefined) schema.pattern = type.pattern;
      if (type.format !== undefined) schema.format = type.format;
      if (type.maxUtf8Bytes !== undefined) schema["x-ogvcs-maxUtf8Bytes"] = type.maxUtf8Bytes;
      return schema;
    }
    case "integer":
      return { type: "integer", minimum: type.minimum, maximum: type.maximum };
    case "boolean":
      return type.const === undefined ? { type: "boolean" } : { type: "boolean", const: type.const };
    case "enum":
      return type.values.length === 1 ? { const: type.values[0] } : { enum: type.values };
    case "reference":
      return { $ref: `${type.name}.schema.json` };
    case "array": {
      const schema = { type: "array", minItems: type.minItems, maxItems: type.maxItems, items: schemaForType(type.items) };
      if (type.uniqueItems !== undefined) schema.uniqueItems = type.uniqueItems;
      return schema;
    }
    case "map":
      return {
        type: "object",
        minProperties: type.minProperties,
        maxProperties: type.maxProperties,
        propertyNames: { type: "string", minLength: 1, maxLength: type.maxKeyUtf8Bytes, pattern: type.keyPattern, "x-ogvcs-maxUtf8Bytes": type.maxKeyUtf8Bytes },
        additionalProperties: schemaForType(type.values),
      };
    case "json":
      return { $ref: "#/$defs/JsonValue", "x-ogvcs-maxDepth": type.maxDepth, "x-ogvcs-maxNodes": type.maxNodes };
    default:
      throw new Error(`unsupported schema type ${type.kind}`);
  }
}

function nestedJsonType(type) {
  if (type.kind === "json") return type;
  if (type.kind === "array") return nestedJsonType(type.items);
  if (type.kind === "map") return nestedJsonType(type.values);
  return undefined;
}

function schemaForMessage(message) {
  const properties = {};
  let jsonType;
  for (const entry of message.fields) {
    const property = schemaForType(entry.type);
    property.description = entry.description;
    property["x-ogvcs-field-id"] = entry.id;
    property["x-ogvcs-sensitive"] = entry.sensitive;
    property["x-ogvcs-fingerprint"] = entry.fingerprint;
    properties[entry.name] = property;
    jsonType ??= nestedJsonType(entry.type);
  }
  const schema = {
    $schema: JSON_SCHEMA_DIALECT,
    $id: `${SCHEMA_BASE}${message.name}.schema.json`,
    title: message.name,
    description: message.description,
    type: "object",
    additionalProperties: false,
    properties,
    required: message.fields.filter((entry) => entry.required).map((entry) => entry.name),
    "x-ogvcs-message-code": message.code,
    "x-ogvcs-license": "MIT",
  };
  if (jsonType) schema.$defs = { JsonValue: jsonValueDefinition(jsonType) };
  if (message.constraints?.length) {
    schema["x-ogvcs-semantic-constraints"] = message.constraints;
    schema.allOf = message.constraints.map((constraint) => {
      switch (constraint.kind) {
        case "successOutcome":
          return {
            if: { properties: { [constraint.discriminator]: { const: true } }, required: [constraint.discriminator] },
            then: { required: [constraint.successField], not: { required: [constraint.failureField] } },
            else: { required: [constraint.failureField], not: { required: [constraint.successField] } },
          };
        case "registeredProblem":
          return {
            oneOf: ERROR_CODES.map((entry) => ({
              properties: {
                type: { const: entry.type },
                title: { const: entry.title },
                status: { const: entry.status },
                code: { const: entry.name },
                retryable: { const: entry.retryable },
                parameters: entry.safeParameters.length === 0
                  ? { maxItems: 0 }
                  : { items: { allOf: [{ $ref: "SafeParameter.schema.json" }, { properties: { name: { enum: entry.safeParameters } }, required: ["name"] }] } },
              },
              required: ["type", "title", "status", "code", "retryable"],
            })),
          };
        case "safeParameterValue":
          return {
            oneOf: [
              {
                properties: {
                  [constraint.nameField]: { const: "conflictClass" },
                  [constraint.valueField]: { type: "string", enum: SAFE_PARAMETER_DOMAINS.conflictClass.values, maxLength: 26, "x-ogvcs-maxUtf8Bytes": 26 },
                },
                required: [constraint.nameField, constraint.valueField],
              },
              {
                properties: {
                  [constraint.nameField]: { const: "gapClass" },
                  [constraint.valueField]: { type: "string", enum: SAFE_PARAMETER_DOMAINS.gapClass.values, maxLength: 18, "x-ogvcs-maxUtf8Bytes": 18 },
                },
                required: [constraint.nameField, constraint.valueField],
              },
              {
                properties: {
                  [constraint.nameField]: { const: "retryAfterMs" },
                  [constraint.valueField]: {
                    type: "string",
                    pattern: "^(?:0|[1-9][0-9]{0,6}|[1-7][0-9]{7}|8[0-5][0-9]{6}|86[0-3][0-9]{5}|86400000)$",
                    maxLength: 8,
                    "x-ogvcs-maxUtf8Bytes": 8,
                  },
                },
                required: [constraint.nameField, constraint.valueField],
              },
            ],
          };
        case "pageState":
          return {
            oneOf: [
              { properties: { [constraint.discriminator]: { const: "more" } }, required: [constraint.discriminator, constraint.cursorField], not: { required: [constraint.problemField] } },
              { properties: { [constraint.discriminator]: { const: "complete" } }, required: [constraint.discriminator], allOf: [{ not: { required: [constraint.cursorField] } }, { not: { required: [constraint.problemField] } }] },
              { properties: { [constraint.discriminator]: { const: "gap" }, [constraint.problemField]: { properties: { code: { const: "CURSOR_GAP" } }, required: ["code"] } }, required: [constraint.discriminator, constraint.problemField], not: { required: [constraint.cursorField] } },
            ],
          };
        case "streamKind": {
          const without = (...fields) => ({ allOf: fields.map((fieldName) => ({ not: { required: [fieldName] } })) });
          return {
            oneOf: [
              { properties: { [constraint.discriminator]: { const: "data" } }, required: [constraint.discriminator, constraint.payloadField], ...without(constraint.problemField) },
              { properties: { [constraint.discriminator]: { const: "terminal" } }, required: [constraint.discriminator], ...without(constraint.payloadField, constraint.problemField) },
              { properties: { [constraint.discriminator]: { const: "gap" }, [constraint.problemField]: { properties: { code: { const: "CURSOR_GAP" } }, required: ["code"] } }, required: [constraint.discriminator, constraint.problemField], ...without(constraint.payloadField) },
              { properties: { [constraint.discriminator]: { const: "error" } }, required: [constraint.discriminator, constraint.problemField], ...without(constraint.payloadField) },
              { properties: { [constraint.discriminator]: { const: "cancelled" } }, required: [constraint.discriminator], ...without(constraint.payloadField, constraint.problemField) },
            ],
          };
        }
        case "nonEmptyObject":
          return { minProperties: 1 };
        case "encodedDocument":
          return {
            oneOf: [
              {
                properties: { [constraint.encodingField]: { const: "semantic-json" } },
                required: [constraint.encodingField, constraint.documentField],
                not: { required: [constraint.rawField] },
              },
              {
                properties: { [constraint.encodingField]: { enum: ["raw-json", "raw-hex"] } },
                required: [constraint.encodingField, constraint.rawField],
                not: { required: [constraint.documentField] },
              },
            ],
          };
        case "retryAfterHeader":
          // The document/header relationship, case-folded duplicate detection,
          // and millisecond-to-delta-second conversion are a generated semantic
          // constraint exercised by the envelope vectors.
          return {};
        case "transferResultState":
          return {
            oneOf: [
              { properties: { [constraint.statusField]: { const: "complete" }, [constraint.terminalField]: { const: true } }, required: [constraint.statusField, constraint.terminalField], not: { required: [constraint.problemField] } },
              { properties: { [constraint.statusField]: { const: "partial" }, [constraint.terminalField]: { const: false } }, required: [constraint.statusField, constraint.terminalField], not: { required: [constraint.problemField] } },
              { properties: { [constraint.statusField]: { const: "interrupted" }, [constraint.terminalField]: { const: false } }, required: [constraint.statusField, constraint.terminalField], not: { required: [constraint.problemField] } },
              { properties: { [constraint.statusField]: { const: "rejected" }, [constraint.terminalField]: { const: false } }, required: [constraint.statusField, constraint.terminalField, constraint.problemField] },
            ],
          };
        case "transferCaseResult":
          return {
            if: { properties: { [constraint.routeField]: { const: "validate-result" } }, required: [constraint.routeField] },
            then: { required: [constraint.resultField] },
          };
        case "transferHttpRange":
          // Header case-folding, duplicate detection, half-open/inclusive
          // conversion, response-state, and exact-length relationships are
          // the named generated semantic constraint exercised by vectors.
          return {};
        case "runnerOperation":
          return {
            oneOf: RUNNER_OPERATIONS.map((operation) => ({
              properties: {
                [constraint.operationField]: { const: operation },
                [constraint.inputField]: { $ref: `${RUNNER_INPUT_SCHEMAS[operation]}.schema.json` },
              },
              required: [constraint.operationField, constraint.inputField],
            })),
          };
        case "mutationWitness":
          return {
            oneOf: [
              {
                properties: {
                  [constraint.preMutationField]: { const: true },
                  [constraint.mutationCountField]: { const: 0 },
                },
                required: [constraint.preMutationField, constraint.mutationCountField],
              },
              {
                properties: {
                  [constraint.preMutationField]: { const: false },
                  [constraint.mutationCountField]: { minimum: 1 },
                },
                required: [constraint.preMutationField, constraint.mutationCountField],
              },
            ],
          };
        case "selfDatingIdempotencyKey":
          // JSON Schema validates the closed fields and key grammar. The exact
          // embedded-time equality/order/lifetime relation is the named,
          // generated semantic constraint consumed by protocol runtimes.
          return {};
        case "canonicalBase64url":
        case "negotiationTransport":
        case "runnerClockSamples":
        case "receiptVerificationOrder":
        case "idempotencyProjections":
        case "indexIntoArray":
        case "idempotencyExecution":
        case "cursorScopes":
        case "cursorLifetime":
        case "transferProbeRange":
        case "transferProbePreflight":
          // These bounded cross-value/order rules are named in generated schema
          // authority and executed by both protocol implementations and vectors.
          return {};
        default:
          throw new Error(`unsupported message constraint ${constraint.kind}`);
      }
    });
  }
  return schema;
}

function jsonOutput(value) {
  return canonicalBytes(value);
}

function textOutput(value) {
  return Buffer.from(value.replaceAll("\r\n", "\n"), "utf8");
}

function mediaType(relativePath) {
  if (relativePath.endsWith(".json")) return "application/json";
  if (relativePath.endsWith(".jsonl")) return "application/jsonl";
  if (relativePath.endsWith(".md")) return "text/markdown; charset=utf-8";
  if (relativePath.endsWith(".rs")) return "text/x-rust; charset=utf-8";
  if (relativePath.endsWith(".hpp") || relativePath.endsWith(".cpp")) return "text/x-c++; charset=utf-8";
  if (relativePath.endsWith(".cs")) return "text/x-csharp; charset=utf-8";
  if (relativePath.endsWith(".ts")) return "text/typescript; charset=utf-8";
  if (relativePath.endsWith(".js") || relativePath.endsWith(".mjs")) return "text/javascript; charset=utf-8";
  return "text/plain; charset=utf-8";
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function artifactEntries(outputs) {
  return [...outputs.entries()].sort(([left], [right]) => compareText(left, right)).map(([relativePath, bytes]) => ({
    path: relativePath,
    bytes: bytes.length,
    sha256: sha256(bytes),
    mediaType: mediaType(relativePath),
  }));
}

function setDigest(entries) {
  return canonicalSha256(entries.map(({ path: artifactPath, sha256: digestValue }) => ({ path: artifactPath, sha256: digestValue })));
}

function normalizedType(type) {
  switch (type.kind) {
    case "string": case "integer": case "boolean": case "json": return type.kind;
    case "enum": return `enum<${typeof type.values[0] === "number" ? "integer" : "string"}>`;
    case "reference": return "reference";
    case "array": return `array<${normalizedType(type.items)}>`;
    case "map": return `map<${normalizedType(type.values)}>`;
    default: throw new Error(`unsupported descriptor type ${type.kind}`);
  }
}

function referencedType(type) {
  if (type.kind === "reference") return type.name;
  if (type.kind === "array") return referencedType(type.items);
  if (type.kind === "map") return referencedType(type.values);
  return null;
}

function bindingDescriptors() {
  return {
    messages: MESSAGES.map((message) => ({ code: message.code, name: message.name, fieldCount: message.fields.length })),
    fields: MESSAGES.flatMap((message) => message.fields.map((entry) => ({
      messageCode: message.code,
      messageName: message.name,
      wireName: entry.name,
      number: entry.id,
      normalizedType: normalizedType(entry.type),
      reference: referencedType(entry.type),
      required: entry.required,
      presence: entry.required ? "required" : "optional",
      fingerprint: entry.fingerprint,
      sensitive: entry.sensitive,
    }))),
  };
}

function fieldAssignments() {
  return {
    schemaVersion: "ogvcs.protocol/field-assignments/v1",
    version: 1,
    license: "MIT",
    immutability: "Numbers and names are never reused within protocol model major version 1.",
    messages: MESSAGES.map((message) => ({
      code: message.code,
      name: message.name,
      fields: message.fields.map((entry) => ({
        id: entry.id,
        name: entry.name,
        required: entry.required,
        presence: entry.required ? "required" : "optional",
        sensitive: entry.sensitive,
        fingerprint: entry.fingerprint,
        type: entry.type.kind,
        normalizedType: normalizedType(entry.type),
        reference: referencedType(entry.type),
      })),
      ...(message.reservedFields?.length ? { reservedFields: message.reservedFields } : {}),
    })),
  };
}

function registryDocument(registry, entries, extra = {}) {
  return { schemaVersion: "ogvcs.protocol/registry/v1", registry, version: 1, license: "MIT", entries, ...extra };
}

function profileDocuments() {
  return {
    "profiles/control-https-json-v1.json": {
      schemaVersion: "ogvcs.protocol/control-profile/v1",
      id: CONTRACT.protocolVersion,
      version: 1,
      state: "candidate",
      license: "MIT",
      transport: { tls: "1.3", http: "1.1", hostnameVerification: "required", certificateVerification: "required", cleartext: "forbidden-for-negotiation-and-mutations", loopbackCleartext: "envelope-conformance-harness-only", proxy: "explicit-CONNECT" },
      control: { mediaType: "application/json", schemaDialect: JSON_SCHEMA_DIALECT, producerCanonicalization: "RFC8785", receiverInput: "bounded-duplicate-free-I-JSON", contentCoding: "identity", mutationRedirects: "forbidden", grantRedirects: "forbidden", idempotentRedirects: "forbidden" },
      retryAfter: { header: "retry-after", fieldNameComparison: "ASCII-case-insensitive", producerFieldName: "retry-after", syntax: "RFC9110-delta-seconds", httpDate: "forbidden", presence: "iff-safe-retryAfterMs", conversion: "ceil-milliseconds-divided-by-1000", maximumSeconds: 86_400, duplicates: "reject-after-lowercase-normalization" },
      idempotency: { keySyntax: "ik1.<issuedAtUnixMs>.<expiresAtUnixMs>.<base64url-entropy>", maxKeyLifetimeMs: IDEMPOTENCY_KEY_MAX_LIFETIME_MS, maxFutureIssueSkewMs: IDEMPOTENCY_KEY_MAX_FUTURE_ISSUE_SKEW_MS, expiryOutcome: "IDEMPOTENCY_KEY_REQUIRED", postExpiryReuse: "new-key-required-even-after-tombstone-retirement", minimumRetention: "committed-outcome-and-tombstone-through-embedded-expiry", retryWithoutRecord: "first-execution-exactly-once" },
      stream: { mediaType: "application/jsonl", frameCanonicalization: "RFC8785", lineTerminator: "LF", explicitTerminalRequired: true, eofIsSuccess: false },
      resourceLimitsRegistry: "registries/limits.json",
    },
    "profiles/transfer-probe-v1.json": {
      schemaVersion: "ogvcs.protocol/transfer-profile/v1",
      id: CONTRACT.transferProfile,
      version: 1,
      state: "candidate",
      license: "MIT",
      scope: "application-neutral-conformance-probe",
      representation: { contentCoding: "identity", ranges: "bounded-half-open", validator: "strong", digest: "RFC9530", completion: "explicit" },
      httpFieldMapping: {
        validator: { semanticFields: ["validatorTag"], header: "ETag", syntax: "RFC9110-quoted-strong" },
        digest: { semanticFields: ["expectedSha256", "contentSha256"], header: "Content-Digest", syntax: "RFC9530-sha-256-byte-sequence" },
      },
      httpRangeCarrier: {
        request: { header: "range", boundedSyntax: "bytes=start-endInclusive-or-start-open", semanticEnd: "endOffsetExclusive=endInclusive+1", noRangeStatus: 200 },
        response: {
          allowedStatuses: [200, 206, 416],
          unsupportedStatusOutcome: "PROTOCOL_MALFORMED-before-validator-or-range-semantics",
          satisfiableStatus: 206,
          satisfiableContentRange: "bytes start-endInclusive/total",
          successfulValidators: { etag: "exactly-one-canonical-RFC9110-quoted-strong", contentDigest: "exactly-one-canonical-RFC9530-sha-256" },
          bodyCarrier: "bounded-lowercase-even-length-responseBodyHex",
          digestAuthority: "SHA-256(decoded-responseBodyHex)",
          unsatisfiedStatus: 416,
          unsatisfiedContentRange: "bytes */total",
          unsatisfiedBody: "empty",
          unsatisfiedValidators: "content-digest-and-etag-absent",
          contentLength: "exact-decoded-response-body-bytes",
        },
        resume: { header: "if-range", value: "exact-RFC9110-quoted-strong-etag", weak: "reject", mismatch: "reject" },
        receiveFieldNames: "ASCII-case-insensitive-reject-duplicates-after-lowercase",
        contentCoding: "identity",
      },
      preflight: {
        projectionSchema: "TransferProbeNonGrantInput",
        sourceSchemaVersion: TRANSFER_PROBE_SCHEMA_VERSION,
        projectionSchemaVersion: TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION,
        beforeGrant: true,
        failureOrder: ["non-grant-shape", "range", "resume-validator", "grant-shape", "grant-verification"],
      },
      grant: { authority: CONTRACT.authorizationContract, carrier: "Authorization", representation: "request-root", explicitObjectCount: 0, queryString: "forbidden" },
      excluded: ["production-routes", "upload-sessions", "multipart", "pack-layout", "compression", "placement", "availability"],
    },
  };
}

function readme() {
  return `# OpenGameVCS protocol contract v1

This package is the normative, application-neutral public protocol baseline for
OpenGameVCS. The candidate version is \`${CONTRACT.version}\`; it is not ratified
while the repository-format and path predecessors remain in validation.

The reference control profile is TLS 1.3 over HTTP/1.1 with bounded I-JSON,
RFC 8785 producer emission, semantic (not raw-input) fingerprints, identity
content coding, no redirected mutation, and canonical JSONL streams with an
explicit terminal. Negotiation selects protocol, schema, repository format,
authorization contract, path contract/profile, event, transfer, and extension
axes independently. A MACed receipt binds the selected tuple but grants no
authorization.

The transfer contract is only \`${CONTRACT.transferProfile}\`: an
application-neutral range/resume probe. Production routes, sessions, packs,
compression, placement, and availability belong to OGVCS-008.

## Installed-package self-check

After installing or unpacking this package:

\`\`\`sh
npm run check
npm test
\`\`\`

Both commands run the shipped, self-contained contract validator and require no
repository checkout or network access.

## Repository regeneration

In an OpenGameVCS source checkout, regeneration is intentionally owned by
\`foundation/protocol-baseline/codegen/generate.mjs\`. Repository CI invokes
that generator with \`--check\`, then runs the packaged validator and the
repository-only tests. The generator is not part of this published contract
package.

Generated Rust, C++, C#, and TypeScript packages are type models and immutable
assignment constants only. They intentionally do not implement JSON, JSONL,
HTTP, TLS, MAC, cursor, authorization, or storage runtimes.

License: MIT.
`;
}

function packageJson() {
  return {
    name: CONTRACT.packageName,
    version: CONTRACT.version,
    description: "Normative OpenGameVCS protocol-v1 schemas, registries, profiles, and conformance vectors",
    type: "module",
    license: "MIT",
    exports: {
      "./profiles/*": "./profiles/*",
      "./registries/*": "./registries/*",
      "./schemas/*": "./schemas/*",
      "./vectors/*": "./vectors/*",
      "./manifest.json": "./manifest.json",
      "./adapter-execution-view.json": "./adapter-execution-view.json",
      "./package.json": "./package.json",
    },
    files: ["profiles", "registries", "schemas", "vectors", "docs", "manifest.json", "adapter-execution-view.json", "validate-spec.mjs", "README.md", "LICENSE"],
    scripts: {
      check: "node validate-spec.mjs",
      test: "node validate-spec.mjs",
    },
    engines: { node: ">=22" },
  };
}

function docsOutputs() {
  const outputs = new Map();
  for (const [fileName, title, body] of DOCS) {
    outputs.set(`docs/${fileName}`, textOutput(`# ${title}\n\n${body}\n\n## Normative authority\n\nThe generated schemas, numbered field registry, compatibility registry, limits, and vectors are normative. Prose cannot widen them. Unknown fields outside the explicit extension container, unsafe error details, raw-byte idempotency fingerprints, compressed control messages, redirected mutations, and EOF-only stream completion are nonconformant.\n\nLicense: MIT.\n`));
  }
  return outputs;
}

function goldenFingerprintRecords() {
  const left = { schemaVersion: "ogvcs.protocol/request-envelope/v1", operation: "repository.example/mutate@1", body: { b: 2, a: 1 }, extensions: {} };
  const right = { extensions: {}, body: { a: 1, b: 2 }, operation: "repository.example/mutate@1", schemaVersion: "ogvcs.protocol/request-envelope/v1" };
  const domain = "ogvcs.protocol/idempotency/v1";
  return [{
    id: "semantic-member-order-equivalence",
    domain,
    left,
    right,
    leftCanonicalJcs: canonicalBytes(left).toString("utf8"),
    rightCanonicalJcs: canonicalBytes(right).toString("utf8"),
    fingerprint: semanticFingerprint(domain, left),
    equal: true,
    rawInputFingerprintForbidden: true,
  }];
}

function materializeGeneratedValue(value, negotiationRegistrySetSha256, authorization) {
  if (value === "@generated:registry-set-sha256") return negotiationRegistrySetSha256;
  if (typeof value === "string" && value.startsWith("@generated:authorization-envelope:")) {
    const [mode, caseId, ...extra] = value.slice("@generated:authorization-envelope:".length).split(":");
    invariant(extra.length === 0 && ["native", "derived-context", "bad-signature", "fixed-replay"].includes(mode), `authorization grant envelope mode ${mode} is invalid`);
    const grantCase = authorization.cases.get(caseId);
    invariant(grantCase !== undefined, `authorization grant case ${caseId} is missing`);
    let envelope;
    if (mode === "native") envelope = grantCase.envelope;
    else if (mode === "fixed-replay") envelope = DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE;
    else {
      envelope = structuredClone(authorization.cases.get("valid-request-root").envelope);
      if (mode === "bad-signature") envelope.signature = `${envelope.signature[0] === "A" ? "B" : "A"}${envelope.signature.slice(1)}`;
    }
    return canonicalBytes(envelope).toString("base64url");
  }
  if (Array.isArray(value)) return value.map((entry) => materializeGeneratedValue(entry, negotiationRegistrySetSha256, authorization));
  if (value && typeof value === "object") {
    if (Object.hasOwn(value, "@generated:authorization-context")) {
      const caseId = value["@generated:authorization-context"];
      const grantCase = authorization.cases.get(caseId);
      invariant(grantCase !== undefined, `authorization grant context ${caseId} is missing`);
      const baseCase = authorization.cases.get(value.baseCase);
      invariant(baseCase !== undefined && Array.isArray(value.contextFields) && value.contextFields.every((name) => typeof name === "string" && Object.hasOwn(grantCase.context, name)), `authorization grant context derivation ${caseId} is invalid`);
      invariant(value.derivedPatch && typeof value.derivedPatch === "object" && !Array.isArray(value.derivedPatch) && value.patch && typeof value.patch === "object" && !Array.isArray(value.patch), `authorization grant context patch ${caseId} is invalid`);
      const context = structuredClone(baseCase.context);
      for (const name of value.contextFields) context[name] = structuredClone(grantCase.context[name]);
      return { ...context, ...structuredClone(value.derivedPatch), ...structuredClone(value.patch) };
    }
    if (value["@generated:authorization-public-jwk"] === true) return structuredClone(authorization.publicJwk);
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, materializeGeneratedValue(entry, negotiationRegistrySetSha256, authorization)]));
  }
  return value;
}

async function authorizationGrantAuthority() {
  const manifestPath = PREDECESSORS.authorization.manifestPath;
  const grantPath = "spec/authorization/v1/vectors/grants.json";
  const licensePath = "spec/authorization/v1/LICENSE";
  const [manifestBytes, bytes, licenseBytes] = await Promise.all([
    fs.readFile(path.join(REPOSITORY_ROOT, manifestPath)),
    fs.readFile(path.join(REPOSITORY_ROOT, grantPath)),
    fs.readFile(path.join(REPOSITORY_ROOT, licensePath)),
  ]);
  invariant(sha256(manifestBytes) === PREDECESSORS.authorization.manifestSha256, "authorization predecessor manifest digest differs from the pin");
  let predecessorManifest;
  try { predecessorManifest = JSON.parse(manifestBytes.toString("utf8")); } catch (error) { throw new Error(`authorization predecessor manifest is not JSON: ${error.message}`); }
  const grantArtifact = predecessorManifest.artifacts?.find((entry) => entry.path === "vectors/grants.json");
  invariant(grantArtifact?.sha256 === AUTHORIZATION_GRANT_VECTOR_SHA256, "authorization predecessor manifest does not bind the frozen grant vector");
  invariant(sha256(bytes) === grantArtifact.sha256, "authorization grant vector digest differs from predecessor provenance");
  let document;
  try { document = JSON.parse(bytes.toString("utf8")); } catch (error) { throw new Error(`authorization grant vector is not JSON: ${error.message}`); }
  invariant(Buffer.concat([canonicalBytes(document), Buffer.from("\n", "ascii")]).equals(bytes), "authorization grant vector is not canonical JSON plus LF");
  invariant(document?.key?.publicJwk?.kty === "OKP" && document.key.publicJwk.crv === "Ed25519" && /^[A-Za-z0-9_-]{43}$/.test(document.key.publicJwk.x), "authorization public JWK is invalid");
  const cases = new Map();
  for (const entry of document.cases ?? []) {
    invariant(typeof entry?.id === "string" && !cases.has(entry.id), "authorization grant case identifier is invalid or reused");
    invariant(AUTHORIZATION_CASE_DIGESTS[entry.id] === canonicalSha256(entry), `authorization grant case ${entry.id} digest differs`);
    cases.set(entry.id, entry);
  }
  invariant(cases.size === Object.keys(AUTHORIZATION_CASE_DIGESTS).length, "authorization grant case inventory differs");
  const requestRoot = cases.get("valid-request-root");
  invariant(requestRoot?.envelope?.claims?.requestRoot === DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.claims.requestRoot && requestRoot.envelope.claims.objectIds.length === 0, "derived replay base request-root differs");
  const replayClaims = { ...DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.claims, nonce: requestRoot.envelope.claims.nonce, replay: requestRoot.envelope.claims.replay };
  invariant(canonicalSha256(replayClaims) === canonicalSha256(requestRoot.envelope.claims), "derived replay fixture changes claims outside replay and nonce");
  invariant(DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.claims.replay === "single-use" && DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.claims.nonce === "protocol-root-replay-0001" && /^[A-Za-z0-9_-]{86}$/.test(DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.signature), "derived replay fixture is invalid");
  return {
    cases,
    publicJwk: document.key.publicJwk,
    generatorInputs: [
      { path: licensePath, bytes: licenseBytes.length, sha256: sha256(licenseBytes), mediaType: "text/plain; charset=utf-8", role: "authorization-license-provenance" },
      { path: manifestPath, bytes: manifestBytes.length, sha256: sha256(manifestBytes), mediaType: "application/json", role: "authorization-manifest-authority" },
      { path: grantPath, bytes: bytes.length, sha256: sha256(bytes), mediaType: "application/json", role: "authorization-grant-conformance-input" },
    ].sort((left, right) => compareText(left.path, right.path)),
  };
}

function problemForTrace(code, correlationId) {
  const authority = ERROR_CODES.find((entry) => entry.name === code);
  invariant(authority !== undefined, `trace oracle uses unknown problem code ${code}`);
  return {
    type: authority.type,
    status: authority.status,
    title: authority.title,
    code: authority.name,
    retryable: authority.retryable,
    correlationId,
  };
}

function traceEnvelope(code, configuredLimits, overrides = {}) {
  const semanticOutput = overrides.semanticOutput ?? { code, exercisedLimits: Object.keys(configuredLimits ?? {}).sort(compareText) };
  return {
    responseBody: overrides.responseBody ?? null,
    responseHeaders: overrides.responseHeaders ?? [],
    streamFrames: overrides.streamFrames ?? [],
    logEntries: overrides.logEntries ?? [],
    semanticOutput,
  };
}

function parsedStreamFrames(input) {
  if (input.encoding === "frames") return structuredClone(input.frames);
  invariant(input.jsonl.endsWith("\n"), "accepted trace stream is not LF-terminated");
  return input.jsonl.slice(0, -1).split("\n").map((line) => JSON.parse(line));
}

function expectedTraceForScenario(scenario, negotiationRegistrySetSha256) {
  const input = scenario.input;
  if (scenario.expected.result === "reject") {
    if (scenario.operation === "validate-envelope" && input.route === "authorize") {
      const correlationId = input.document.correlationId;
      return traceEnvelope(scenario.expected.code, scenario.configuredLimits, {
        responseBody: {
          schemaVersion: "ogvcs.protocol/response-envelope/v1",
          success: false,
          correlationId,
          problem: problemForTrace(scenario.expected.code, correlationId),
        },
      });
    }
    return traceEnvelope(scenario.expected.code, scenario.configuredLimits);
  }

  switch (scenario.operation) {
    case "negotiate": {
      const selection = structuredClone(input.route === "verify-receipt" ? input.verificationSelection : input.serverSelection);
      if (input.route !== "verify-receipt") selection.protocolRegistrySetSha256 = negotiationRegistrySetSha256;
      return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: selection });
    }
    case "validate-envelope": {
      let document;
      if (input.encoding === "semantic-json") document = structuredClone(input.document);
      else if (input.encoding === "raw-hex") document = JSON.parse(Buffer.from(input.rawInput, "hex").toString("utf8"));
      else document = JSON.parse(input.rawInput);
      return traceEnvelope("NONE", scenario.configuredLimits, {
        semanticOutput: input.targetSchema === "JsonValue" ? document : { targetSchema: input.targetSchema, validated: true },
      });
    }
    case "fingerprint": {
      if (Object.hasOwn(scenario.configuredLimits ?? {}, "maxIdempotencyKeyBytes")) return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { keyPreflight: true } });
      if (input.route !== "fingerprint") {
        const firstExecution = input.attemptSchedule.length === 1 && input.attemptSchedule[0] === "retry" && input.attemptProjectionIndexes.length === 1 && input.attemptAuthorizationDecisions[0] === "allow";
        return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: firstExecution ? { firstExecution: true, replay: false } : { replay: true } });
      }
      return traceEnvelope("NONE", scenario.configuredLimits, {
        semanticOutput: { fingerprints: input.projections.map((projection) => semanticFingerprint("ogvcs.protocol/idempotency/v1", projection)) },
      });
    }
    case "validate-cursor": {
      if (input.route === "validate-page") return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { state: input.page.state, itemCount: input.page.items.length } });
      if (input.route === "validate-token") return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { tokenAccepted: true } });
      return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { expiresAt: input.issuedAtUnixMs + input.ttlMs, generation: input.generation, issuedAt: input.issuedAtUnixMs, position: 0 } });
    }
    case "validate-stream": {
      const frames = parsedStreamFrames(input);
      const terminal = frames.at(-1);
      return traceEnvelope("NONE", scenario.configuredLimits, {
        streamFrames: frames,
        semanticOutput: { streamId: frames[0].streamId, frames: frames.length, terminalKind: terminal.kind },
      });
    }
    case "transfer-probe": {
      if (input.route === "validate-result") return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: structuredClone(input.probeResult) });
      if (input.route === "http-range") {
        const totalBytes = input.transportResponse.totalBytes;
        const etag = input.responseHeaders.find((header) => header.name.toLowerCase() === "etag").value;
        const contentSha256 = sha256(Buffer.from(input.responseBodyHex, "hex"));
        return traceEnvelope("NONE", scenario.configuredLimits, {
          semanticOutput: {
            status: input.responseStatus,
            acceptedStart: input.probe.startOffset,
            acceptedEndExclusive: input.probe.endOffsetExclusive ?? totalBytes,
            totalBytes,
            validatorTag: etag.slice(1, -1),
            contentSha256,
          },
        });
      }
      return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { acceptedStart: input.probe.startOffset, rangeBytes: input.transportResponse.rangeBytes } });
    }
    case "contract-load": {
      if (input.route === "inventory") return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { artifacts: input.artifacts.length, bytes: input.artifacts.reduce((total, artifact) => total + artifact.bytesHex.length / 2, 0) } });
      return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { registryEntries: input.registryEntries.length } });
    }
    case "runner-batch": return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { cases: input.cases.length } });
    case "release-preflight": return traceEnvelope("NONE", scenario.configuredLimits, { semanticOutput: { compatible: true, assignmentCount: input.proposedAssignments.length, priorAssignmentSnapshotSha256: input.priorAssignmentSnapshotSha256 } });
    default: throw new Error(`unsupported trace-oracle operation ${scenario.operation}`);
  }
}

async function vectorOutputs(negotiationRegistrySetSha256, authorization) {
  const outputs = new Map();
  const vectorArtifacts = [];
  const traceRecords = [];
  const vectorArtifactByteLimit = Math.min(
    LIMITS.find((entry) => entry.name === "maxCanonicalInputBytes").value,
    LIMITS.find((entry) => entry.name === "maxControlMessageBytes").value,
  );
  for (const category of VECTOR_CATEGORIES) {
    const cases = SCENARIOS.filter((scenario) => scenario.category === category).map((scenario) => materializeGeneratedValue({
      schemaVersion: "ogvcs.protocol/scenario/v1",
      ...scenario,
    }, negotiationRegistrySetSha256, authorization));
    for (const scenario of cases) {
      const trace = expectedTraceForScenario(scenario, negotiationRegistrySetSha256);
      const traceDigest = canonicalSha256(trace);
      scenario.expected.traceDigest = traceDigest;
      traceRecords.push({ id: scenario.id, trace, traceDigest });
    }
    const documents = [];
    let pending = [];
    for (const scenario of cases) {
      const next = [...pending, scenario];
      const nextDocument = {
        schemaVersion: "ogvcs.protocol/scenario-set/v1",
        category,
        license: "MIT",
        cases: next,
        ...(category === "idempotency" && documents.length === 0 ? { goldens: goldenFingerprintRecords() } : {}),
      };
      if (jsonOutput(nextDocument).length > vectorArtifactByteLimit) {
        invariant(pending.length > 0, `${scenario.id} cannot fit within the configured vector artifact byte limit`);
        documents.push(pending);
        pending = [scenario];
        const singleDocument = {
          schemaVersion: "ogvcs.protocol/scenario-set/v1",
          category,
          license: "MIT",
          cases: pending,
          ...(category === "idempotency" && documents.length === 0 ? { goldens: goldenFingerprintRecords() } : {}),
        };
        invariant(jsonOutput(singleDocument).length <= vectorArtifactByteLimit, `${scenario.id} cannot fit within the configured vector artifact byte limit`);
      } else pending = next;
    }
    invariant(pending.length > 0, `${category} has no generated scenarios`);
    documents.push(pending);
    for (const [index, documentCases] of documents.entries()) {
      const document = {
        schemaVersion: "ogvcs.protocol/scenario-set/v1",
        category,
        license: "MIT",
        cases: documentCases,
        ...(category === "idempotency" && index === 0 ? { goldens: goldenFingerprintRecords() } : {}),
      };
      const relativePath = documents.length === 1
        ? `vectors/${category}.json`
        : `vectors/${category}-${String(index + 1).padStart(2, "0")}.json`;
      const bytes = jsonOutput(document);
      invariant(bytes.length <= vectorArtifactByteLimit, `${relativePath} exceeds the configured vector artifact byte limit`);
      outputs.set(relativePath, bytes);
      vectorArtifacts.push({ path: relativePath, bytes: bytes.length, sha256: sha256(bytes), cases: documentCases.length });
    }
  }
  traceRecords.sort((left, right) => compareText(left.id, right.id));
  const traceBytes = textOutput(traceRecords.map(canonicalJsonLine).join(""));
  outputs.set("vectors/golden-traces.jsonl", traceBytes);
  vectorArtifacts.push({ path: "vectors/golden-traces.jsonl", bytes: traceBytes.length, sha256: sha256(traceBytes), traces: traceRecords.length });
  const jsonlBytes = textOutput(GOLDEN_STREAM_JSONL);
  outputs.set("vectors/golden-stream.jsonl", jsonlBytes);
  vectorArtifacts.push({ path: "vectors/golden-stream.jsonl", bytes: jsonlBytes.length, sha256: sha256(jsonlBytes), frames: GOLDEN_STREAM_FRAMES.length });
  const manifest = {
    schemaVersion: "ogvcs.protocol/vector-manifest/v1",
    contractVersion: CONTRACT.version,
    license: "MIT",
    totalCases: SCENARIOS.length,
    acceptCases: SCENARIOS.filter((entry) => entry.expected.result === "accept").length,
    rejectCases: SCENARIOS.filter((entry) => entry.expected.result === "reject").length,
    categories: Object.fromEntries(VECTOR_CATEGORIES.map((category) => [category, SCENARIOS.filter((entry) => entry.category === category).length])),
    artifacts: vectorArtifacts.sort((left, right) => compareText(left.path, right.path)),
    vectorSetSha256: setDigest(vectorArtifacts),
  };
  outputs.set("vectors/manifest.json", jsonOutput(manifest));
  return outputs;
}

async function codegenSourceDigest() {
  const names = ["canonical.mjs", "generate.mjs", "model.mjs"];
  const records = [];
  for (const name of names) records.push({ path: name, sha256: sha256(await fs.readFile(path.join(CODEGEN_ROOT, name))) });
  return { records, sha256: canonicalSha256(records) };
}

function registryOutputs(schemas, negotiationRegistrySetSha256 = undefined) {
  const outputs = new Map();
  outputs.set("registries/field-assignments.json", jsonOutput(fieldAssignments()));
  outputs.set("registries/capabilities.json", jsonOutput(registryDocument("capabilities", CAPABILITIES)));
  outputs.set("registries/error-codes.json", jsonOutput(registryDocument("error-codes", ERROR_CODES, {
    rfc9457Subset: "closed-safe",
    forbiddenMembers: ["detail", "instance"],
    parameterDomains: SAFE_PARAMETER_DOMAINS,
    excludedParameters: [{ name: "currentGeneration", reason: "R0 has no authenticated visibility-proof carrier" }],
  })));
  outputs.set("registries/limits.json", jsonOutput(registryDocument("limits", LIMITS)));
  outputs.set("registries/release-assignments.json", jsonOutput(registryDocument("release-assignments", RELEASE_ASSIGNMENTS, {
    snapshotSha256: RELEASE_ASSIGNMENT_SNAPSHOT_SHA256,
    compatibilityPolicy: RELEASE_COMPATIBILITY_POLICY,
    semanticHash: {
      algorithm: "SHA-256",
      canonicalization: "RFC8785",
      domain: RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN,
      projection: "{kind,scope,name,code,policy}",
    },
    allowedAdditions: RELEASE_ALLOWED_ADDITIONS,
  })));
  outputs.set("registries/protocol-versions.json", jsonOutput(registryDocument("protocol-versions", REGISTRIES.protocolVersions)));
  outputs.set("registries/schema-versions.json", jsonOutput(registryDocument("schema-versions", REGISTRIES.schemaVersions)));
  outputs.set("registries/repository-formats.json", jsonOutput(registryDocument("repository-formats", REGISTRIES.repositoryFormats)));
  outputs.set("registries/authorization-contracts.json", jsonOutput(registryDocument("authorization-contracts", REGISTRIES.authorizationContracts)));
  outputs.set("registries/path-contracts.json", jsonOutput(registryDocument("path-contracts", REGISTRIES.pathContracts)));
  outputs.set("registries/path-profiles.json", jsonOutput(registryDocument("path-profiles", REGISTRIES.pathProfiles)));
  outputs.set("registries/event-versions.json", jsonOutput(registryDocument("event-versions", REGISTRIES.eventVersions)));
  outputs.set("registries/transfer-profiles.json", jsonOutput(registryDocument("transfer-profiles", REGISTRIES.transferProfiles)));
  outputs.set("registries/extensions.json", jsonOutput(registryDocument("extensions", REGISTRIES.extensions)));
  const schemaEntries = [...schemas.entries()].map(([relativePath, bytes]) => {
    const message = MESSAGES.find((entry) => relativePath === `schemas/${entry.name}.schema.json`);
    return { code: message.code, id: `${SCHEMA_BASE}${message.name}.schema.json`, message: message.name, path: relativePath, sha256: sha256(bytes), state: "candidate" };
  }).sort((left, right) => left.code - right.code);
  outputs.set("registries/schemas.json", jsonOutput(registryDocument("schemas", schemaEntries)));
  if (negotiationRegistrySetSha256 !== undefined) {
    const entries = structuredClone(COMPATIBILITY);
    for (const entry of entries) entry.selection.protocolRegistrySetSha256 = negotiationRegistrySetSha256;
    outputs.set("registries/compatibility.json", jsonOutput(registryDocument("compatibility", entries, {
      selectionDigestAuthority: "negotiationRegistrySetSha256",
      predecessorPins: PREDECESSORS,
    })));
  }
  return outputs;
}

async function buildSpecOutputs() {
  const outputs = new Map();
  const authorization = await authorizationGrantAuthority();
  outputs.set("LICENSE", textOutput(LICENSE));
  outputs.set("README.md", textOutput(readme()));
  outputs.set("package.json", jsonOutput(packageJson()));
  for (const [relativePath, document] of Object.entries(profileDocuments())) outputs.set(relativePath, jsonOutput(document));
  for (const [relativePath, bytes] of docsOutputs()) outputs.set(relativePath, bytes);
  const schemas = new Map(MESSAGES.map((message) => [`schemas/${message.name}.schema.json`, jsonOutput(schemaForMessage(message))]));
  for (const [relativePath, bytes] of schemas) outputs.set(relativePath, bytes);
  const baseRegistries = registryOutputs(schemas);
  const baseRegistryEntries = artifactEntries(baseRegistries);
  const negotiationRegistrySetSha256 = setDigest(baseRegistryEntries);
  const registries = registryOutputs(schemas, negotiationRegistrySetSha256);
  for (const [relativePath, bytes] of registries) outputs.set(relativePath, bytes);
  for (const [relativePath, bytes] of await vectorOutputs(negotiationRegistrySetSha256, authorization)) outputs.set(relativePath, bytes);
  const codegen = await codegenSourceDigest();
  const registryEntries = artifactEntries(new Map([...outputs].filter(([relativePath]) => relativePath.startsWith("registries/"))));
  const schemaEntries = artifactEntries(schemas);
  const vectorEntries = artifactEntries(new Map([...outputs].filter(([relativePath]) => relativePath.startsWith("vectors/"))));
  const artifacts = artifactEntries(outputs);
  const modelSha256 = canonicalSha256({ CONTRACT, PREDECESSORS, LIMITS, ERROR_CODES, SAFE_PARAMETER_DOMAINS, CAPABILITIES, REGISTRIES, MESSAGES, RELEASE_ASSIGNMENTS, RELEASE_ALLOWED_ADDITIONS, RELEASE_ASSIGNMENT_SNAPSHOT_SHA256, COMPATIBILITY, RUNNER_OPERATIONS, SCENARIOS, VECTOR_CATEGORIES, DOCS, SUPPORTED_TYPE_KINDS });
  const authorityArtifacts = artifacts.filter((artifact) => artifact.path.startsWith("profiles/") || artifact.path.startsWith("registries/") || artifact.path.startsWith("schemas/"));
  const authoritySetSha256 = setDigest(authorityArtifacts);
  const adapterExecutionViewBytes = jsonOutput({
    schemaVersion: "ogvcs.protocol/adapter-execution-view/v1",
    contractVersion: CONTRACT.version,
    contractManifestPath: "manifest.json",
    license: "MIT",
    predecessorPins: PREDECESSORS,
    limitsRegistryPath: "registries/limits.json",
    authorityArtifacts,
    authoritySetSha256,
    excludedNamespaces: ["docs/", "vectors/"],
  });
  const manifest = {
    schemaVersion: CONTRACT.schemaVersion,
    contractVersion: CONTRACT.version,
    packageName: CONTRACT.packageName,
    license: "MIT",
    state: "candidate",
    ratified: false,
    modelVersion: CONTRACT.modelVersion,
    modelSha256,
    generatorSha256: codegen.sha256,
    generatorSources: codegen.records,
    predecessorPins: PREDECESSORS,
    generatorInputs: authorization.generatorInputs,
    negotiationRegistrySetSha256,
    registrySetSha256: setDigest(registryEntries),
    schemaSetSha256: setDigest(schemaEntries),
    vectorSetSha256: setDigest(vectorEntries),
    adapterExecutionView: {
      path: "adapter-execution-view.json",
      bytes: adapterExecutionViewBytes.length,
      sha256: sha256(adapterExecutionViewBytes),
      authoritySetSha256,
    },
    counts: {
      artifacts: artifacts.length,
      messages: MESSAGES.length,
      assignedFields: MESSAGES.reduce((sum, message) => sum + message.fields.length, 0),
      schemas: schemaEntries.length,
      registries: registryEntries.length,
      limits: LIMITS.length,
      errors: ERROR_CODES.length,
      profiles: [...outputs.keys()].filter((relativePath) => relativePath.startsWith("profiles/")).length,
      documents: [...outputs.keys()].filter((relativePath) => relativePath.startsWith("docs/")).length,
      vectorCategories: VECTOR_CATEGORIES.length,
      scenarios: SCENARIOS.length,
      acceptScenarios: SCENARIOS.filter((entry) => entry.expected.result === "accept").length,
      rejectScenarios: SCENARIOS.filter((entry) => entry.expected.result === "reject").length,
    },
    artifacts,
    distributedSupportFilesExcludedFromArtifactDigest: ["adapter-execution-view.json", "validate-spec.mjs"],
    developmentFilesExcluded: ["test/**"],
  };
  outputs.set("adapter-execution-view.json", adapterExecutionViewBytes);
  outputs.set("manifest.json", jsonOutput(manifest));
  const contractManifestSha256 = sha256(outputs.get("manifest.json"));
  return { outputs, manifest, contractManifestSha256 };
}

function snake(value) {
  return value.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replaceAll(/[^A-Za-z0-9]+/g, "_").toLowerCase();
}

function pascal(value) {
  return value.replace(/(^|[^A-Za-z0-9]+)([A-Za-z0-9])/g, (_match, _prefix, character) => character.toUpperCase());
}

function upperSnake(value) {
  return snake(value).toUpperCase();
}

function rustField(value) {
  const identifier = snake(value);
  const reserved = new Set(["as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn"]);
  return reserved.has(identifier) ? `r#${identifier}` : identifier;
}

function rustType(type) {
  switch (type.kind) {
    case "string": return "String";
    case "enum": return typeof type.values[0] === "number" ? "i64" : "String";
    case "integer": return "i64";
    case "boolean": return "bool";
    case "reference": return type.name;
    case "array": return `Vec<${rustType(type.items)}>`;
    case "map": return `BTreeMap<String, ${rustType(type.values)}>`;
    case "json": return "JsonValue";
    default: throw new Error(`unsupported Rust type ${type.kind}`);
  }
}

function rustBinding(contractManifestSha256) {
  const descriptors = bindingDescriptors();
  const lines = [
    "// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.",
    "// @generated by foundation/protocol-baseline/codegen/generate.mjs; do not edit.",
    "#![forbid(unsafe_code)]",
    "",
    "use std::collections::BTreeMap;",
    "",
    `pub const CONTRACT_VERSION: &str = ${JSON.stringify(CONTRACT.version)};`,
    `pub const CONTRACT_MANIFEST_SHA256: &str = ${JSON.stringify(contractManifestSha256)};`,
    `pub const PROTOCOL_VERSION: &str = ${JSON.stringify(CONTRACT.protocolVersion)};`,
    `pub const MESSAGE_SCHEMA_VERSION: &str = ${JSON.stringify(CONTRACT.messageSchemaVersion)};`,
    `pub const AUTHORIZATION_CONTRACT: &str = ${JSON.stringify(CONTRACT.authorizationContract)};`,
    `pub const PATH_CONTRACT: &str = ${JSON.stringify(CONTRACT.pathContract)};`,
    `pub const PATH_PROFILE: &str = ${JSON.stringify(CONTRACT.pathProfile)};`,
    `pub const REPOSITORY_FORMAT: &str = ${JSON.stringify(CONTRACT.repositoryFormat)};`,
    "",
    "#[derive(Clone, Debug, PartialEq, Eq)]",
    "pub enum JsonValue {",
    "    Null,",
    "    Boolean(bool),",
    "    Integer(i64),",
    "    String(String),",
    "    Array(Vec<JsonValue>),",
    "    Object(BTreeMap<String, JsonValue>),",
    "}",
    "",
  ];
  lines.push(
    "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    "pub struct MessageDescriptor {",
    "    pub code: u16,",
    "    pub name: &'static str,",
    "    pub field_count: usize,",
    "}",
    "",
    "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    "pub struct FieldDescriptor {",
    "    pub message_code: u16,",
    "    pub message_name: &'static str,",
    "    pub wire_name: &'static str,",
    "    pub number: u16,",
    "    pub normalized_type: &'static str,",
    "    pub reference: Option<&'static str>,",
    "    pub required: bool,",
    "    pub presence: &'static str,",
    "    pub fingerprint: bool,",
    "    pub sensitive: bool,",
    "}",
    "",
    "pub static MESSAGE_DESCRIPTORS: &[MessageDescriptor] = &[",
  );
  for (const descriptor of descriptors.messages) lines.push(`    MessageDescriptor { code: ${descriptor.code}, name: ${JSON.stringify(descriptor.name)}, field_count: ${descriptor.fieldCount} },`);
  lines.push("];", "", "pub static FIELD_DESCRIPTORS: &[FieldDescriptor] = &[");
  for (const descriptor of descriptors.fields) {
    const reference = descriptor.reference === null ? "None" : `Some(${JSON.stringify(descriptor.reference)})`;
    lines.push(`    FieldDescriptor { message_code: ${descriptor.messageCode}, message_name: ${JSON.stringify(descriptor.messageName)}, wire_name: ${JSON.stringify(descriptor.wireName)}, number: ${descriptor.number}, normalized_type: ${JSON.stringify(descriptor.normalizedType)}, reference: ${reference}, required: ${descriptor.required}, presence: ${JSON.stringify(descriptor.presence)}, fingerprint: ${descriptor.fingerprint}, sensitive: ${descriptor.sensitive} },`);
  }
  lines.push("];", "");
  for (const message of MESSAGES) {
    lines.push("#[derive(Clone, Debug, PartialEq, Eq)]", `pub struct ${message.name} {`);
    for (const entry of message.fields) {
      const base = rustType(entry.type);
      lines.push(`    pub ${rustField(entry.name)}: ${entry.required ? base : `Option<${base}>`},`);
    }
    lines.push("}", "", `pub mod ${snake(message.name)}_fields {`, `    pub const MESSAGE_CODE: u16 = ${message.code};`);
    for (const entry of message.fields) lines.push(`    pub const ${upperSnake(entry.name)}: u16 = ${entry.id};`);
    lines.push("}", "");
  }
  lines.push("pub mod limits {");
  for (const limit of LIMITS) lines.push(`    pub const ${upperSnake(limit.name)}: u64 = ${limit.value};`);
  lines.push("}", "", "pub mod error_codes {");
  for (const error of ERROR_CODES) lines.push(`    pub const ${error.name}: u16 = ${error.code};`);
  lines.push("}", "");
  return `${lines.join("\n")}\n`;
}

function cppType(type) {
  switch (type.kind) {
    case "string": return "std::string";
    case "enum": return typeof type.values[0] === "number" ? "std::int64_t" : "std::string";
    case "integer": return "std::int64_t";
    case "boolean": return "bool";
    case "reference": return type.name;
    case "array": return `std::vector<${cppType(type.items)}>`;
    case "map": return `std::map<std::string, ${cppType(type.values)}>`;
    case "json": return "JsonValue";
    default: throw new Error(`unsupported C++ type ${type.kind}`);
  }
}

function referencedMessageNames(type, result = new Set()) {
  if (type.kind === "reference") result.add(type.name);
  else if (type.kind === "array") referencedMessageNames(type.items, result);
  else if (type.kind === "map") referencedMessageNames(type.values, result);
  return result;
}

function topologicalMessages() {
  const byName = new Map(MESSAGES.map((message) => [message.name, message]));
  const visiting = new Set();
  const visited = new Set();
  const result = [];
  const visit = (message) => {
    if (visited.has(message.name)) return;
    invariant(!visiting.has(message.name), `C++ binding reference cycle includes ${message.name}`);
    visiting.add(message.name);
    const dependencies = new Set();
    for (const entry of message.fields) referencedMessageNames(entry.type, dependencies);
    for (const dependency of [...dependencies].sort(compareText)) visit(byName.get(dependency));
    visiting.delete(message.name);
    visited.add(message.name);
    result.push(message);
  };
  for (const message of MESSAGES) visit(message);
  return result;
}

function cppBinding(contractManifestSha256) {
  const descriptors = bindingDescriptors();
  const lines = [
    "// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.",
    "// @generated by foundation/protocol-baseline/codegen/generate.mjs; do not edit.",
    "#pragma once",
    "#include <array>",
    "#include <cstddef>",
    "#include <cstdint>",
    "#include <map>",
    "#include <optional>",
    "#include <string>",
    "#include <variant>",
    "#include <vector>",
    "",
    "namespace opengamevcs::protocol::v1 {",
    `inline constexpr const char* contract_version = ${JSON.stringify(CONTRACT.version)};`,
    `inline constexpr const char* contract_manifest_sha256 = ${JSON.stringify(contractManifestSha256)};`,
    `inline constexpr const char* protocol_version = ${JSON.stringify(CONTRACT.protocolVersion)};`,
    `inline constexpr const char* message_schema_version = ${JSON.stringify(CONTRACT.messageSchemaVersion)};`,
    `inline constexpr const char* authorization_contract = ${JSON.stringify(CONTRACT.authorizationContract)};`,
    `inline constexpr const char* path_contract = ${JSON.stringify(CONTRACT.pathContract)};`,
    `inline constexpr const char* path_profile = ${JSON.stringify(CONTRACT.pathProfile)};`,
    `inline constexpr const char* repository_format = ${JSON.stringify(CONTRACT.repositoryFormat)};`,
    "",
    "struct JsonValue {",
    "  using array_type = std::vector<JsonValue>;",
    "  using object_type = std::map<std::string, JsonValue>;",
    "  std::variant<std::nullptr_t, bool, std::int64_t, std::string, array_type, object_type> value;",
    "};",
    "",
  ];
  lines.push(
    "struct message_descriptor { std::uint16_t code; const char* name; std::size_t field_count; };",
    "struct field_descriptor { std::uint16_t message_code; const char* message_name; const char* wire_name; std::uint16_t number; const char* normalized_type; const char* reference; bool required; const char* presence; bool fingerprint; bool sensitive; };",
    "",
    `inline constexpr std::array<message_descriptor, ${descriptors.messages.length}> message_descriptors{{`,
  );
  for (const descriptor of descriptors.messages) lines.push(`  message_descriptor{${descriptor.code}, ${JSON.stringify(descriptor.name)}, ${descriptor.fieldCount}},`);
  lines.push("}};", "", `inline constexpr std::array<field_descriptor, ${descriptors.fields.length}> field_descriptors{{`);
  for (const descriptor of descriptors.fields) {
    const reference = descriptor.reference === null ? "nullptr" : JSON.stringify(descriptor.reference);
    lines.push(`  field_descriptor{${descriptor.messageCode}, ${JSON.stringify(descriptor.messageName)}, ${JSON.stringify(descriptor.wireName)}, ${descriptor.number}, ${JSON.stringify(descriptor.normalizedType)}, ${reference}, ${descriptor.required}, ${JSON.stringify(descriptor.presence)}, ${descriptor.fingerprint}, ${descriptor.sensitive}},`);
  }
  lines.push("}};", "");
  for (const message of MESSAGES) lines.push(`struct ${message.name};`);
  lines.push("");
  for (const message of topologicalMessages()) {
    lines.push(`struct ${message.name} {`);
    for (const entry of message.fields) {
      const base = cppType(entry.type);
      lines.push(`  ${entry.required ? base : `std::optional<${base}>`} ${entry.name};`);
    }
    lines.push("};", "", `namespace assignments::${snake(message.name)} {`, `inline constexpr std::uint16_t message_code = ${message.code};`);
    for (const entry of message.fields) lines.push(`inline constexpr std::uint16_t ${snake(entry.name)} = ${entry.id};`);
    lines.push("}", "");
  }
  lines.push("namespace limits {");
  for (const limit of LIMITS) lines.push(`inline constexpr std::uint64_t ${snake(limit.name)} = ${limit.value}ULL;`);
  lines.push("}", "", "namespace error_codes {");
  for (const error of ERROR_CODES) lines.push(`inline constexpr std::uint16_t ${snake(error.name)} = ${error.code};`);
  lines.push("}", "", "} // namespace opengamevcs::protocol::v1", "");
  return lines.join("\n");
}

function csharpType(type) {
  switch (type.kind) {
    case "string": return "string";
    case "enum": return typeof type.values[0] === "number" ? "long" : "string";
    case "integer": return "long";
    case "boolean": return "bool";
    case "reference": return type.name;
    case "array": return `IReadOnlyList<${csharpType(type.items)}>`;
    case "map": return `IReadOnlyDictionary<string, ${csharpType(type.values)}>`;
    case "json": return "ProtocolJsonValue";
    default: throw new Error(`unsupported C# type ${type.kind}`);
  }
}

function csharpDefault(type) {
  switch (type.kind) {
    case "string": return " = string.Empty;";
    case "enum": return typeof type.values[0] === "number" ? "" : " = string.Empty;";
    case "reference": case "json": return " = new();";
    case "array": return ` = Array.Empty<${csharpType(type.items)}>();`;
    case "map": return ` = new Dictionary<string, ${csharpType(type.values)}>();`;
    default: return "";
  }
}

function csharpBinding(contractManifestSha256) {
  const descriptors = bindingDescriptors();
  const lines = [
    "// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.",
    "// <auto-generated by foundation/protocol-baseline/codegen/generate.mjs />",
    "using System;",
    "using System.Collections.Generic;",
    "",
    "namespace OpenGameVcs.Protocol.V1;",
    "",
    "public static class ProtocolConstants",
    "{",
    `    public const string ContractVersion = ${JSON.stringify(CONTRACT.version)};`,
    `    public const string ContractManifestSha256 = ${JSON.stringify(contractManifestSha256)};`,
    `    public const string ProtocolVersion = ${JSON.stringify(CONTRACT.protocolVersion)};`,
    `    public const string MessageSchemaVersion = ${JSON.stringify(CONTRACT.messageSchemaVersion)};`,
    `    public const string AuthorizationContract = ${JSON.stringify(CONTRACT.authorizationContract)};`,
    `    public const string PathContract = ${JSON.stringify(CONTRACT.pathContract)};`,
    `    public const string PathProfile = ${JSON.stringify(CONTRACT.pathProfile)};`,
    `    public const string RepositoryFormat = ${JSON.stringify(CONTRACT.repositoryFormat)};`,
    "}",
    "",
    "public sealed record ProtocolJsonValue(object? Value = null);",
    "",
  ];
  lines.push(
    "public readonly record struct ProtocolMessageDescriptor(ushort Code, string Name, int FieldCount);",
    "public readonly record struct ProtocolFieldDescriptor(ushort MessageCode, string MessageName, string WireName, ushort Number, string NormalizedType, string? Reference, bool Required, string Presence, bool Fingerprint, bool Sensitive);",
    "",
    "public static class ProtocolDescriptors",
    "{",
    "    public static IReadOnlyList<ProtocolMessageDescriptor> Messages { get; } = Array.AsReadOnly(new ProtocolMessageDescriptor[]",
    "    {",
  );
  for (const descriptor of descriptors.messages) lines.push(`        new(${descriptor.code}, ${JSON.stringify(descriptor.name)}, ${descriptor.fieldCount}),`);
  lines.push("    });", "", "    public static IReadOnlyList<ProtocolFieldDescriptor> Fields { get; } = Array.AsReadOnly(new ProtocolFieldDescriptor[]", "    {");
  for (const descriptor of descriptors.fields) {
    const reference = descriptor.reference === null ? "null" : JSON.stringify(descriptor.reference);
    const required = descriptor.required ? "true" : "false";
    const fingerprint = descriptor.fingerprint ? "true" : "false";
    const sensitive = descriptor.sensitive ? "true" : "false";
    lines.push(`        new(${descriptor.messageCode}, ${JSON.stringify(descriptor.messageName)}, ${JSON.stringify(descriptor.wireName)}, ${descriptor.number}, ${JSON.stringify(descriptor.normalizedType)}, ${reference}, ${required}, ${JSON.stringify(descriptor.presence)}, ${fingerprint}, ${sensitive}),`);
  }
  lines.push("    });", "}", "");
  for (const message of MESSAGES) {
    lines.push(`public sealed class ${message.name}`, "{");
    for (const entry of message.fields) {
      const base = csharpType(entry.type);
      const type = entry.required ? base : `${base}?`;
      lines.push(`    public ${type} ${pascal(entry.name)} { get; init; }${entry.required ? csharpDefault(entry.type) : ""}`);
    }
    lines.push("}", "", `public static class ${message.name}Fields`, "{", `    public const ushort MessageCode = ${message.code};`);
    for (const entry of message.fields) lines.push(`    public const ushort ${pascal(entry.name)} = ${entry.id};`);
    lines.push("}", "");
  }
  lines.push("public static class ProtocolLimits", "{");
  for (const limit of LIMITS) lines.push(`    public const ulong ${pascal(limit.name)} = ${limit.value}UL;`);
  lines.push("}", "", "public static class ProtocolErrorCodes", "{");
  for (const error of ERROR_CODES) lines.push(`    public const ushort ${pascal(error.name.toLowerCase())} = ${error.code};`);
  lines.push("}", "");
  return lines.join("\n");
}

function tsType(type) {
  switch (type.kind) {
    case "string": return "string";
    case "enum": return type.values.map((value) => JSON.stringify(value)).join(" | ");
    case "integer": return "number";
    case "boolean": return type.const === undefined ? "boolean" : String(type.const);
    case "reference": return type.name;
    case "array": return `ReadonlyArray<${tsType(type.items)}>`;
    case "map": return `Readonly<Record<string, ${tsType(type.values)}>>`;
    case "json": return "JsonValue";
    default: throw new Error(`unsupported TypeScript type ${type.kind}`);
  }
}

function tsBinding(contractManifestSha256) {
  const lines = [
    "// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.",
    "// @generated by foundation/protocol-baseline/codegen/generate.mjs; do not edit.",
    "export type JsonValue = null | boolean | number | string | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue };",
    "",
    `export declare const CONTRACT_VERSION: ${JSON.stringify(CONTRACT.version)};`,
    `export declare const CONTRACT_MANIFEST_SHA256: ${JSON.stringify(contractManifestSha256)};`,
    `export declare const PROTOCOL_VERSION: ${JSON.stringify(CONTRACT.protocolVersion)};`,
    `export declare const MESSAGE_SCHEMA_VERSION: ${JSON.stringify(CONTRACT.messageSchemaVersion)};`,
    `export declare const AUTHORIZATION_CONTRACT: ${JSON.stringify(CONTRACT.authorizationContract)};`,
    `export declare const PATH_CONTRACT: ${JSON.stringify(CONTRACT.pathContract)};`,
    `export declare const PATH_PROFILE: ${JSON.stringify(CONTRACT.pathProfile)};`,
    `export declare const REPOSITORY_FORMAT: ${JSON.stringify(CONTRACT.repositoryFormat)};`,
    "",
    "export interface ProtocolMessageDescriptor { readonly code: number; readonly name: string; readonly fieldCount: number; }",
    "export interface ProtocolFieldDescriptor { readonly messageCode: number; readonly messageName: string; readonly wireName: string; readonly number: number; readonly normalizedType: string; readonly reference: string | null; readonly required: boolean; readonly presence: \"required\" | \"optional\"; readonly fingerprint: boolean; readonly sensitive: boolean; }",
    "export declare const MESSAGE_DESCRIPTORS: ReadonlyArray<ProtocolMessageDescriptor>;",
    "export declare const FIELD_DESCRIPTORS: ReadonlyArray<ProtocolFieldDescriptor>;",
    "",
  ];
  for (const message of MESSAGES) {
    lines.push(`export interface ${message.name} {`);
    for (const entry of message.fields) lines.push(`  readonly ${entry.name}${entry.required ? "" : "?"}: ${tsType(entry.type)};`);
    lines.push("}", "");
  }
  lines.push("export declare const FIELD_ASSIGNMENTS: Readonly<Record<string, Readonly<{ messageCode: number; fields: Readonly<Record<string, number>> }>>>;", "export declare const LIMITS: Readonly<Record<string, number>>;", "export declare const ERROR_CODES: Readonly<Record<string, number>>;", "");
  return lines.join("\n");
}

function tsRuntimeConstants(contractManifestSha256) {
  const descriptors = bindingDescriptors();
  const assignments = Object.fromEntries(MESSAGES.map((message) => [message.name, { messageCode: message.code, fields: Object.fromEntries(message.fields.map((entry) => [entry.name, entry.id])) }]));
  const limitMap = Object.fromEntries(LIMITS.map((entry) => [entry.name, entry.value]));
  const errorMap = Object.fromEntries(ERROR_CODES.map((entry) => [entry.name, entry.code]));
  const frozenAssignments = `{${Object.entries(assignments).map(([name, value]) => `${JSON.stringify(name)}:Object.freeze({messageCode:${value.messageCode},fields:Object.freeze(${JSON.stringify(value.fields)})})`).join(",")}}`;
  const frozenMessages = `Object.freeze([${descriptors.messages.map((entry) => `Object.freeze(${JSON.stringify(entry)})`).join(",")}])`;
  const frozenFields = `Object.freeze([${descriptors.fields.map((entry) => `Object.freeze(${JSON.stringify(entry)})`).join(",")}])`;
  return `// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\n// @generated; constants only, no JSON or transport runtime.\nexport const CONTRACT_VERSION = ${JSON.stringify(CONTRACT.version)};\nexport const CONTRACT_MANIFEST_SHA256 = ${JSON.stringify(contractManifestSha256)};\nexport const PROTOCOL_VERSION = ${JSON.stringify(CONTRACT.protocolVersion)};\nexport const MESSAGE_SCHEMA_VERSION = ${JSON.stringify(CONTRACT.messageSchemaVersion)};\nexport const AUTHORIZATION_CONTRACT = ${JSON.stringify(CONTRACT.authorizationContract)};\nexport const PATH_CONTRACT = ${JSON.stringify(CONTRACT.pathContract)};\nexport const PATH_PROFILE = ${JSON.stringify(CONTRACT.pathProfile)};\nexport const REPOSITORY_FORMAT = ${JSON.stringify(CONTRACT.repositoryFormat)};\nexport const MESSAGE_DESCRIPTORS = ${frozenMessages};\nexport const FIELD_DESCRIPTORS = ${frozenFields};\nexport const FIELD_ASSIGNMENTS = Object.freeze(${frozenAssignments});\nexport const LIMITS = Object.freeze(${JSON.stringify(limitMap)});\nexport const ERROR_CODES = Object.freeze(${JSON.stringify(errorMap)});\n`;
}

function bindingReadme(language, command) {
  return `# OpenGameVCS protocol v1 ${language} types

Generated, standard-library-only type models and immutable assignment constants
for \`${CONTRACT.packageName}@${CONTRACT.version}\`.

This package deliberately contains no JSON/JCS, JSONL, HTTP, TLS, MAC,
authorization, cursor, transfer, or storage runtime. Consumers must use a
bounded implementation and validate against the normative schemas.

Smoke command: \`${command}\`.

License: MIT.
`;
}

function buildBindingOutputs(contractManifestSha256) {
  const outputs = new Map();
  const descriptors = bindingDescriptors();
  outputs.set("LICENSE", textOutput(LICENSE));
  outputs.set("README.md", textOutput(`# OpenGameVCS protocol-v1 generated bindings\n\nThese four packages are generated type models and immutable numeric assignment constants. The authoritative contract manifest SHA-256 is \`${contractManifestSha256}\`. See each language directory for a bounded offline smoke command.\n\nLicense: MIT.\n`));
  outputs.set("descriptors.json", jsonOutput({
    schemaVersion: "ogvcs.protocol/binding-descriptors/v1",
    contractVersion: CONTRACT.version,
    contractManifestSha256,
    license: "MIT",
    ...descriptors,
  }));

  outputs.set("rust/LICENSE", textOutput(LICENSE));
  outputs.set("rust/README.md", textOutput(bindingReadme("Rust", "cargo test --manifest-path Cargo.toml --offline")));
  outputs.set("rust/Cargo.toml", textOutput(`[package]\nname = "opengamevcs-protocol-v1"\nversion = "${CONTRACT.version}"\nedition = "2021"\nlicense = "MIT"\ndescription = "Generated OpenGameVCS protocol-v1 type models"\npublish = false\n\n[lib]\npath = "src/lib.rs"\n`));
  outputs.set("rust/src/lib.rs", textOutput(rustBinding(contractManifestSha256)));
  outputs.set("rust/tests/smoke.rs", textOutput(`// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\nuse std::collections::BTreeSet;\nuse opengamevcs_protocol_v1::{capability_axes_fields, CapabilityAxes, CONTRACT_MANIFEST_SHA256, FIELD_DESCRIPTORS, MESSAGE_DESCRIPTORS};\n\n#[test]\nfn generated_types_and_assignments_are_usable() {\n    let axes = CapabilityAxes {\n        protocol_versions: vec!["ogvcs.control.https-json@1".into()],\n        schema_versions: vec!["ogvcs.protocol.schema@1".into()],\n        repository_formats: vec!["ogvcs.repository-format@1".into()],\n        authorization_contracts: vec!["ogvcs.authorization@1".into()],\n        path_contracts: vec!["ogvcs.path-filesystem@1".into()],\n        path_profiles: vec!["path.opengamevcs/portable@1".into()],\n        event_versions: vec!["ogvcs.events.base@1".into()],\n        transfer_profiles: vec!["ogvcs.transfer.range-resume-probe@1".into()],\n        extensions: vec![],\n        required_capabilities: vec![],\n    };\n    assert_eq!(axes.protocol_versions.len(), 1);\n    assert_eq!(capability_axes_fields::PROTOCOL_VERSIONS, 1);\n    assert_eq!(CONTRACT_MANIFEST_SHA256.len(), 64);\n    assert_eq!(MESSAGE_DESCRIPTORS.iter().map(|entry| entry.field_count).sum::<usize>(), FIELD_DESCRIPTORS.len());\n    let mut seen = BTreeSet::new();\n    for field in FIELD_DESCRIPTORS {\n        let message = MESSAGE_DESCRIPTORS.iter().find(|entry| entry.code == field.message_code).expect("field message descriptor");\n        assert_eq!(message.name, field.message_name);\n        assert!(seen.insert((field.message_code, field.number)));\n        assert_eq!(field.required, field.presence == "required");\n        assert_eq!(field.reference.is_some(), field.normalized_type.contains("reference"));\n    }\n}\n`));

  outputs.set("cpp/LICENSE", textOutput(LICENSE));
  outputs.set("cpp/README.md", textOutput(bindingReadme("C++", "cmake -S . -B build -DOGVCS_PROTOCOL_BUILD_TESTS=ON && cmake --build build && ctest --test-dir build")));
  outputs.set("cpp/include/opengamevcs/protocol/v1/types.hpp", textOutput(cppBinding(contractManifestSha256)));
  outputs.set("cpp/CMakeLists.txt", textOutput(`cmake_minimum_required(VERSION 3.16)\nproject(OpenGameVcsProtocolV1 LANGUAGES CXX)\nadd_library(opengamevcs_protocol_v1 INTERFACE)\ntarget_include_directories(opengamevcs_protocol_v1 INTERFACE \"$<BUILD_INTERFACE:${'${CMAKE_CURRENT_SOURCE_DIR}'}/include>\")\ntarget_compile_features(opengamevcs_protocol_v1 INTERFACE cxx_std_17)\noption(OGVCS_PROTOCOL_BUILD_TESTS \"Build generated type smoke test\" OFF)\nif(OGVCS_PROTOCOL_BUILD_TESTS)\n  enable_testing()\n  add_executable(opengamevcs_protocol_v1_smoke test/smoke.cpp)\n  target_link_libraries(opengamevcs_protocol_v1_smoke PRIVATE opengamevcs_protocol_v1)\n  add_test(NAME opengamevcs_protocol_v1_smoke COMMAND opengamevcs_protocol_v1_smoke)\nendif()\n`));
  outputs.set("cpp/test/smoke.cpp", textOutput(`// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\n#include <opengamevcs/protocol/v1/types.hpp>\n#include <cstring>\nint main() {\n  using namespace opengamevcs::protocol::v1;\n  CapabilityAxes axes{};\n  axes.protocolVersions.push_back(protocol_version);\n  if (axes.protocolVersions.size() != 1 || assignments::capability_axes::protocol_versions != 1 || std::strlen(contract_manifest_sha256) != 64) return 1;\n  std::size_t expected_fields = 0;\n  for (const auto& message : message_descriptors) expected_fields += message.field_count;\n  if (expected_fields != field_descriptors.size()) return 2;\n  for (std::size_t index = 0; index < field_descriptors.size(); ++index) {\n    const auto& field = field_descriptors[index];\n    bool message_found = false;\n    for (const auto& message : message_descriptors) if (message.code == field.message_code && std::strcmp(message.name, field.message_name) == 0) message_found = true;\n    if (!message_found || field.required != (std::strcmp(field.presence, "required") == 0) || ((field.reference != nullptr) != (std::strstr(field.normalized_type, "reference") != nullptr))) return 3;\n    for (std::size_t prior = 0; prior < index; ++prior) if (field_descriptors[prior].message_code == field.message_code && field_descriptors[prior].number == field.number) return 4;\n  }\n  return 0;\n}\n`));

  outputs.set("csharp/LICENSE", textOutput(LICENSE));
  outputs.set("csharp/README.md", textOutput(bindingReadme("C#", "dotnet restore Smoke/OpenGameVcs.Protocol.Smoke.csproj --configfile NuGet.Config && dotnet run --project Smoke/OpenGameVcs.Protocol.Smoke.csproj --no-restore")));
  outputs.set("csharp/NuGet.Config", textOutput(`<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
  </packageSources>
</configuration>
`));
  outputs.set("csharp/OpenGameVcs.Protocol.csproj", textOutput(`<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n    <ImplicitUsings>disable</ImplicitUsings>\n    <Nullable>enable</Nullable>\n    <Version>${CONTRACT.version}</Version>\n    <PackageId>OpenGameVcs.Protocol</PackageId>\n    <PackageLicenseExpression>MIT</PackageLicenseExpression>\n  </PropertyGroup>\n  <ItemGroup><Compile Remove="Smoke/**/*.cs" /></ItemGroup>\n</Project>\n`));
  outputs.set("csharp/Generated/Types.g.cs", textOutput(csharpBinding(contractManifestSha256)));
  outputs.set("csharp/Smoke/OpenGameVcs.Protocol.Smoke.csproj", textOutput(`<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework><Nullable>enable</Nullable></PropertyGroup>\n  <ItemGroup><ProjectReference Include="../OpenGameVcs.Protocol.csproj" /></ItemGroup>\n</Project>\n`));
  outputs.set("csharp/Smoke/Program.cs", textOutput(`// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\nusing System;\nusing System.Collections.Generic;\nusing OpenGameVcs.Protocol.V1;\nif (ProtocolConstants.ContractManifestSha256.Length != 64 || CapabilityAxesFields.ProtocolVersions != 1) Environment.Exit(1);\nvar axes = new CapabilityAxes { ProtocolVersions = new[] { ProtocolConstants.ProtocolVersion } };\nif (axes.ProtocolVersions.Count != 1) Environment.Exit(1);\nvar expectedFields = 0;\nforeach (var message in ProtocolDescriptors.Messages) expectedFields += message.FieldCount;\nif (expectedFields != ProtocolDescriptors.Fields.Count) Environment.Exit(2);\nvar seen = new HashSet<(ushort, ushort)>();\nforeach (var field in ProtocolDescriptors.Fields)\n{\n    ProtocolMessageDescriptor? owner = null;\n    foreach (var message in ProtocolDescriptors.Messages) if (message.Code == field.MessageCode && message.Name == field.MessageName) owner = message;\n    if (owner is null || !seen.Add((field.MessageCode, field.Number)) || field.Required != (field.Presence == "required") || ((field.Reference is not null) != field.NormalizedType.Contains("reference", StringComparison.Ordinal))) Environment.Exit(3);\n}\n`));

  outputs.set("typescript/LICENSE", textOutput(LICENSE));
  outputs.set("typescript/README.md", textOutput(bindingReadme("TypeScript", "tsc -p tsconfig.json --noEmit && node smoke.mjs")));
  outputs.set("typescript/package.json", jsonOutput({ name: "@opengamevcs/protocol-types-v1", version: CONTRACT.version, description: "Generated OpenGameVCS protocol-v1 type models and assignments", type: "module", license: "MIT", exports: { ".": { types: "./index.d.ts", default: "./index.js" } }, files: ["index.d.ts", "index.js", "README.md", "LICENSE"], scripts: { check: "tsc -p tsconfig.json --noEmit", test: "node smoke.mjs" }, engines: { node: ">=22" } }));
  outputs.set("typescript/index.d.ts", textOutput(tsBinding(contractManifestSha256)));
  outputs.set("typescript/index.js", textOutput(tsRuntimeConstants(contractManifestSha256)));
  outputs.set("typescript/smoke.mjs", textOutput(`// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\nimport { CONTRACT_MANIFEST_SHA256, FIELD_ASSIGNMENTS, FIELD_DESCRIPTORS, MESSAGE_DESCRIPTORS, PROTOCOL_VERSION } from "./index.js";\nif (CONTRACT_MANIFEST_SHA256.length !== 64) throw new Error("manifest digest is not pinned");\nif (PROTOCOL_VERSION !== "ogvcs.control.https-json@1") throw new Error("protocol mismatch");\nif (FIELD_ASSIGNMENTS.CapabilityAxes.fields.protocolVersions !== 1) throw new Error("field assignment mismatch");\nif (MESSAGE_DESCRIPTORS.reduce((sum, entry) => sum + entry.fieldCount, 0) !== FIELD_DESCRIPTORS.length) throw new Error("descriptor count mismatch");\nconst seen = new Set();\nfor (const field of FIELD_DESCRIPTORS) {\n  const owner = MESSAGE_DESCRIPTORS.find((entry) => entry.code === field.messageCode);\n  const key = \`${'${field.messageCode}'}:${'${field.number}'}\`;\n  if (!owner || owner.name !== field.messageName || seen.has(key)) throw new Error("descriptor ownership mismatch");\n  if (field.required !== (field.presence === "required") || ((field.reference !== null) !== field.normalizedType.includes("reference"))) throw new Error("descriptor policy mismatch");\n  seen.add(key);\n}\n`));
  outputs.set("typescript/smoke.ts", textOutput(`// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.\nimport type { CapabilityAxes, RunnerCase } from "./index.js";\nconst axes: CapabilityAxes = {\n  protocolVersions: ["ogvcs.control.https-json@1"], schemaVersions: ["ogvcs.protocol.schema@1"],\n  repositoryFormats: ["ogvcs.repository-format@1"], authorizationContracts: ["ogvcs.authorization@1"],\n  pathContracts: ["ogvcs.path-filesystem@1"], pathProfiles: ["path.opengamevcs/portable@1"],\n  eventVersions: ["ogvcs.events.base@1"], transferProfiles: ["ogvcs.transfer.range-resume-probe@1"],\n  extensions: [], requiredCapabilities: [],\n};\nconst runnerCase: RunnerCase = { schemaVersion: "ogvcs.protocol/runner-case/v1", id: "typescript-smoke", operation: "negotiate", input: {}, inputKind: "semantic-value", control: { cancellation: "none", clockSamplesUnixMs: [0] } };\nvoid [axes, runnerCase];\n`));
  outputs.set("typescript/tsconfig.json", jsonOutput({ compilerOptions: { exactOptionalPropertyTypes: true, module: "ESNext", moduleResolution: "Bundler", noEmit: true, strict: true, target: "ES2022" }, files: ["index.d.ts", "smoke.ts"] }));
  return outputs;
}

async function writeOrCheck(root, outputs) {
  let failures = 0;
  for (const [relativePath, expected] of [...outputs.entries()].sort(([left], [right]) => compareText(left, right))) {
    const destination = path.join(root, relativePath);
    if (CHECK) {
      let actual;
      try { actual = await fs.readFile(destination); } catch (error) {
        if (error.code === "ENOENT") { console.error(`missing generated artifact: ${path.relative(REPOSITORY_ROOT, destination)}`); failures += 1; continue; }
        throw error;
      }
      if (!actual.equals(expected)) { console.error(`generated artifact drift: ${path.relative(REPOSITORY_ROOT, destination)}`); failures += 1; }
    } else {
      await fs.mkdir(path.dirname(destination), { recursive: true });
      await fs.writeFile(destination, expected);
    }
  }
  return failures;
}

async function main() {
  validateModel();
  const spec = await buildSpecOutputs();
  const bindings = buildBindingOutputs(spec.contractManifestSha256);
  const bindingArtifacts = artifactEntries(bindings);
  const codegen = await codegenSourceDigest();
  const bindingManifest = {
    schemaVersion: "ogvcs.protocol/binding-manifest/v1",
    contractVersion: CONTRACT.version,
    license: "MIT",
    contractManifestPath: "spec/protocols/v1/manifest.json",
    contractManifestSha256: spec.contractManifestSha256,
    modelSha256: spec.manifest.modelSha256,
    codegenSha256: codegen.sha256,
    bindingSetSha256: setDigest(bindingArtifacts),
    languages: [
      { language: "rust", package: "opengamevcs-protocol-v1", version: CONTRACT.version, modelPath: "rust/src/lib.rs", smokePath: "rust/tests/smoke.rs", command: "cargo test --manifest-path foundation/protocol-baseline/bindings/rust/Cargo.toml --offline" },
      { language: "cpp", package: "OpenGameVcsProtocolV1", version: CONTRACT.version, modelPath: "cpp/include/opengamevcs/protocol/v1/types.hpp", smokePath: "cpp/test/smoke.cpp", command: "cmake -S foundation/protocol-baseline/bindings/cpp -B <build> -DOGVCS_PROTOCOL_BUILD_TESTS=ON && cmake --build <build> && ctest --test-dir <build>" },
      { language: "csharp", package: "OpenGameVcs.Protocol", version: CONTRACT.version, modelPath: "csharp/Generated/Types.g.cs", smokePath: "csharp/Smoke/Program.cs", command: "dotnet restore foundation/protocol-baseline/bindings/csharp/Smoke/OpenGameVcs.Protocol.Smoke.csproj --configfile foundation/protocol-baseline/bindings/csharp/NuGet.Config && dotnet run --project foundation/protocol-baseline/bindings/csharp/Smoke/OpenGameVcs.Protocol.Smoke.csproj --no-restore" },
      { language: "typescript", package: "@opengamevcs/protocol-types-v1", version: CONTRACT.version, modelPath: "typescript/index.d.ts", smokePath: "typescript/smoke.ts", command: "tsc -p foundation/protocol-baseline/bindings/typescript/tsconfig.json --noEmit && node foundation/protocol-baseline/bindings/typescript/smoke.mjs" },
    ],
    artifacts: bindingArtifacts,
  };
  bindings.set("manifest.json", jsonOutput(bindingManifest));
  const failures = (await writeOrCheck(SPEC_ROOT, spec.outputs)) + (await writeOrCheck(BINDINGS_ROOT, bindings));
  if (failures) throw new Error(`${failures} generated artifacts differ`);
  console.log(`${CHECK ? "verified" : "generated"} ${spec.outputs.size} contract and ${bindings.size} binding artifacts; ${SCENARIOS.length} bounded scenarios`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) await main();
