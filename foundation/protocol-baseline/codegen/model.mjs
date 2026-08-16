// Copyright (c) 2026 OpenGameVCS contributors. MIT licensed.
// This is the sole declarative authority for protocol-v1 wire model assignments.

import { createHash } from "node:crypto";

const string = (minLength, maxLength, extra = {}) => ({ kind: "string", minLength, maxLength, ...extra });
const integer = (minimum, maximum, extra = {}) => ({ kind: "integer", minimum, maximum, ...extra });
const boolean = (extra = {}) => ({ kind: "boolean", ...extra });
const enumeration = (values) => ({ kind: "enum", values });
const reference = (name) => ({ kind: "reference", name });
const array = (items, minItems, maxItems, extra = {}) => ({ kind: "array", items, minItems, maxItems, ...extra });
const map = (values, minProperties, maxProperties, extra = {}) => ({ kind: "map", values, minProperties, maxProperties, ...extra });
const json = (maxDepth = 32, maxNodes = 10_000) => ({ kind: "json", maxDepth, maxNodes });
const field = (id, name, type, options = {}) => ({
  id,
  name,
  type,
  required: options.required ?? true,
  sensitive: options.sensitive ?? false,
  fingerprint: options.fingerprint ?? true,
  description: options.description ?? name,
});

export const CONTRACT = Object.freeze({
  packageName: "@opengamevcs/protocol-contract-v1",
  version: "1.0.0-rc.1",
  schemaVersion: "ogvcs.protocol/contract-manifest/v1",
  modelVersion: "ogvcs.protocol/model/v1",
  protocolVersion: "ogvcs.control.https-json@1",
  messageSchemaVersion: "ogvcs.protocol.schema@1",
  repositoryFormat: "ogvcs.repository-format@1",
  authorizationContract: "ogvcs.authorization@1",
  pathContract: "ogvcs.path-filesystem@1",
  pathProfile: "path.opengamevcs/portable@1",
  eventVersion: "ogvcs.events.base@1",
  transferProfile: "ogvcs.transfer.range-resume-probe@1",
  fingerprintAlgorithm: "OGVCS-SEMANTIC-JCS-SHA-256",
  receiptAlgorithm: "HMAC-SHA-256",
  license: "MIT",
});

export const PREDECESSORS = Object.freeze({
  authorization: {
    contract: CONTRACT.authorizationContract,
    contractVersion: "1.0.0",
    manifestPath: "spec/authorization/v1/manifest.json",
    manifestSha256: "3fb4dd4a89eb914f93a589b013bda8afcf4744c0d27171ee5849ca3b7bf62447",
    registrySetSha256: "293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc",
  },
  path: {
    contract: CONTRACT.pathContract,
    contractVersion: "1.0.0",
    profile: CONTRACT.pathProfile,
    manifestPath: "spec/path-filesystem/v1/manifest.json",
    manifestSha256: "15251e63487e442f46ea689850f8d4d8db9ef65f1f1eeb961d9594686531b000",
    registrySetSha256: "bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42",
  },
  repository: {
    format: CONTRACT.repositoryFormat,
    formatVersion: 1,
    manifestPath: "spec/repository-format/v1/vectors/manifest.json",
    manifestSha256: "07d9c6f26d885e09d38a202d0277e28d536da3c293bf3d58c57f43fddf386be8",
    registrySetSha256: "6ca55f10d2cd20139e77a19ae0d297757a0f05b0acd3a3b38a6ee473e2bf84c6",
  },
});

export const AUTHORIZATION_GRANT_VECTOR_SHA256 = "e40e9e6ebfd5a6fb4fecbc8ccb02fe35ab9f153ca8fe76c9a5b8aa7781a42216";
const VALID_REQUEST_ROOT_GRANT_BYTES = 741;

export const LIMITS = Object.freeze([
  { code: 1, name: "maxControlMessageBytes", value: 1_048_576, unit: "bytes", enforcement: "before-parse-and-during-read" },
  { code: 2, name: "maxCanonicalInputBytes", value: 1_048_576, unit: "bytes", enforcement: "before-fingerprint" },
  { code: 3, name: "maxJsonDepth", value: 64, unit: "levels", enforcement: "during-parse" },
  { code: 4, name: "maxJsonNodes", value: 100_000, unit: "nodes", enforcement: "during-parse" },
  { code: 5, name: "maxObjectMembers", value: 256, unit: "members", enforcement: "during-parse" },
  { code: 6, name: "maxArrayItems", value: 4_096, unit: "items", enforcement: "during-parse" },
  { code: 7, name: "maxStringUtf8Bytes", value: 65_536, unit: "bytes", enforcement: "during-parse" },
  { code: 8, name: "maxExtensionEntries", value: 32, unit: "entries", enforcement: "before-extension-dispatch" },
  { code: 9, name: "maxCapabilityItems", value: 128, unit: "items-per-axis", enforcement: "before-negotiation" },
  { code: 10, name: "maxErrorParameters", value: 16, unit: "items", enforcement: "before-error-emission", configuredMinimum: 0 },
  { code: 11, name: "maxPageItems", value: 1_000, unit: "items", enforcement: "before-page-emission" },
  { code: 12, name: "maxJsonlFrameBytes", value: 1_048_576, unit: "bytes", enforcement: "before-frame-parse" },
  { code: 13, name: "maxJsonlFrames", value: 100_000, unit: "frames", enforcement: "during-stream" },
  { code: 14, name: "maxCursorBytes", value: 1_024, unit: "bytes", enforcement: "before-cursor-lookup" },
  { code: 15, name: "maxIdempotencyKeyBytes", value: 256, unit: "bytes", enforcement: "before-idempotency-lookup" },
  { code: 16, name: "maxReceiptBytes", value: 16_384, unit: "bytes", enforcement: "before-receipt-verification" },
  { code: 17, name: "maxGrantBytes", value: 16_384, unit: "bytes", enforcement: "before-grant-verification" },
  { code: 18, name: "maxTransferRangeBytes", value: 1_073_741_824, unit: "bytes", enforcement: "before-transfer" },
  { code: 19, name: "maxHeaderBytes", value: 32_768, unit: "bytes", enforcement: "before-header-decode" },
  { code: 20, name: "maxCorrelationIdBytes", value: 128, unit: "bytes", enforcement: "during-schema-validation" },
  { code: 21, name: "maxOperationBytes", value: 256, unit: "bytes", enforcement: "during-schema-validation" },
  { code: 22, name: "maxRunnerCases", value: 1_024, unit: "cases", enforcement: "before-run-and-before-report-allocation" },
  { code: 23, name: "maxSafeParameterBytes", value: 1_024, unit: "bytes", enforcement: "before-error-emission" },
  { code: 24, name: "maxDeadlineHorizonMs", value: 86_400_000, unit: "milliseconds", enforcement: "before-operation" },
  { code: 25, name: "maxReceiptLifetimeMs", value: 300_000, unit: "milliseconds", enforcement: "before-receipt-issue" },
  { code: 26, name: "maxCursorLifetimeMs", value: 86_400_000, unit: "milliseconds", enforcement: "before-cursor-issue" },
  { code: 27, name: "maxRegistryEntries", value: 4_096, unit: "entries", enforcement: "before-registry-load" },
  { code: 28, name: "maxJsonKeyUtf8Bytes", value: 256, unit: "bytes", enforcement: "during-parse" },
  { code: 29, name: "maxJsonCollectionItems", value: 100_000, unit: "aggregate-items", enforcement: "during-parse" },
  { code: 30, name: "maxJsonlStreamBytes", value: 67_108_864, unit: "bytes", enforcement: "during-stream" },
  { code: 31, name: "maxWorkingMemoryBytes", value: 67_108_864, unit: "bytes", enforcement: "before-allocation-and-during-operation" },
  { code: 32, name: "maxOperationTimeMs", value: 120_000, unit: "milliseconds", enforcement: "shared-deadline" },
  { code: 33, name: "maxSchemaEvaluationSteps", value: 1_000_000, unit: "steps", enforcement: "during-schema-validation" },
  { code: 34, name: "maxContractArtifacts", value: 4_096, unit: "artifacts", enforcement: "before-contract-load" },
  { code: 35, name: "maxContractBytes", value: 67_108_864, unit: "bytes", enforcement: "during-contract-load" },
]);

export const SAFE_PARAMETER_DOMAINS = Object.freeze({
  conflictClass: Object.freeze({ type: "string", values: Object.freeze(["idempotency-input-mismatch"]) }),
  gapClass: Object.freeze({ type: "string", values: Object.freeze(["generation-changed", "retention-gap"]) }),
  retryAfterMs: Object.freeze({ type: "canonical-decimal", minimum: 0, maximum: 86_400_000 }),
});

export const IDEMPOTENCY_KEY_MAX_LIFETIME_MS = 86_400_000;
export const IDEMPOTENCY_KEY_MAX_FUTURE_ISSUE_SKEW_MS = 0;
export const TRANSFER_PROBE_SCHEMA_VERSION = "ogvcs.protocol/transfer-probe/v1";
export const TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION = "ogvcs.protocol/transfer-probe-non-grant-input/v1";

export const ERROR_CODES = Object.freeze([
  [1, "PROTOCOL_MALFORMED", 400, "Malformed protocol message", false, []],
  [2, "PROTOCOL_LIMIT_EXCEEDED", 413, "Protocol resource limit exceeded", true, ["retryAfterMs"]],
  [3, "PROTOCOL_UNSUPPORTED", 426, "Protocol profile unsupported", false, []],
  [4, "NEGOTIATION_NO_COMMON_VERSION", 409, "No compatible capability tuple", false, []],
  [5, "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN", 409, "Required capability unavailable", false, []],
  [6, "NEGOTIATION_DOWNGRADE_REJECTED", 409, "Negotiation downgrade rejected", false, []],
  [7, "NEGOTIATION_RECEIPT_INVALID", 401, "Negotiation receipt invalid", false, []],
  [8, "NEGOTIATION_RECEIPT_EXPIRED", 401, "Negotiation receipt expired", true, ["retryAfterMs"]],
  [9, "AUTHORIZATION_DENIED", 403, "Operation not authorized", false, []],
  [10, "IDEMPOTENCY_KEY_REQUIRED", 400, "Idempotency key required", false, []],
  [11, "IDEMPOTENCY_KEY_REUSE", 409, "Idempotency key input mismatch", false, ["conflictClass"]],
  [12, "CURSOR_INVALID", 400, "Cursor invalid", false, []],
  [13, "CURSOR_SCOPE_MISMATCH", 403, "Cursor scope mismatch", false, []],
  [14, "CURSOR_EXPIRED", 410, "Cursor expired", true, ["retryAfterMs"]],
  [15, "CURSOR_GAP", 409, "Cursor retention gap", false, ["gapClass"]],
  [16, "STREAM_INCOMPLETE", 502, "Stream terminated without completion", true, []],
  [17, "STREAM_SEQUENCE_INVALID", 400, "Stream sequence invalid", false, []],
  [18, "TRANSFER_RANGE_INVALID", 416, "Transfer range invalid", false, []],
  [19, "TRANSFER_VALIDATOR_MISMATCH", 412, "Transfer validator mismatch", true, []],
  [20, "TRANSFER_GRANT_INVALID", 403, "Transfer grant invalid", false, []],
  [21, "REDIRECT_FORBIDDEN", 409, "Redirect forbidden", false, []],
  [22, "COMPRESSION_FORBIDDEN", 415, "Content coding forbidden", false, []],
  [23, "DEADLINE_EXCEEDED", 504, "Deadline exceeded", true, ["retryAfterMs"]],
  [24, "CANCELLED", 408, "Operation cancelled", true, []],
  [25, "INTERNAL_ERROR", 500, "Internal protocol error", true, ["retryAfterMs"]],
].map(([code, name, status, title, retryable, safeParameters]) => ({
  code,
  name,
  status,
  title,
  retryable,
  safeParameters,
  type: `https://errors.opengamevcs.dev/protocol/v1/${name.toLowerCase().replaceAll("_", "-")}`,
})));

export const CAPABILITIES = Object.freeze([
  { code: 1, id: CONTRACT.protocolVersion, axis: "protocol", state: "required", fallback: "reject" },
  { code: 2, id: CONTRACT.messageSchemaVersion, axis: "schema", state: "required", fallback: "reject" },
  { code: 3, id: CONTRACT.repositoryFormat, axis: "repository-format", state: "candidate", fallback: "reject" },
  { code: 4, id: CONTRACT.authorizationContract, axis: "authorization-contract", state: "required", fallback: "reject" },
  { code: 5, id: CONTRACT.pathContract, axis: "path-contract", state: "required", fallback: "reject" },
  { code: 6, id: CONTRACT.pathProfile, axis: "path-profile", state: "required", fallback: "reject" },
  { code: 7, id: CONTRACT.eventVersion, axis: "event", state: "required", fallback: "reject" },
  { code: 8, id: CONTRACT.transferProfile, axis: "transfer", state: "required", fallback: "reject" },
  { code: 9, id: "ogvcs.extension.safe-optional@1", axis: "extension", state: "optional", fallback: "ignore" },
  { code: 10, id: "ogvcs.receipt.hmac-sha256@1", axis: "feature", state: "required", fallback: "reject" },
  { code: 11, id: "ogvcs.stream.explicit-terminal@1", axis: "feature", state: "required", fallback: "reject" },
  { code: 12, id: "ogvcs.idempotency.semantic-jcs@1", axis: "feature", state: "required", fallback: "reject" },
]);

export const REGISTRIES = Object.freeze({
  protocolVersions: [{ code: 1, id: CONTRACT.protocolVersion, state: "candidate", tls: "1.3", http: "1.1", json: "RFC8785", contentCoding: "identity", mutationRedirects: "forbidden" }],
  schemaVersions: [{ code: 1, id: CONTRACT.messageSchemaVersion, state: "candidate", dialect: "https://json-schema.org/draft/2020-12/schema" }],
  repositoryFormats: [{ code: 1, id: CONTRACT.repositoryFormat, state: "candidate", predecessor: "repository" }],
  authorizationContracts: [{ code: 1, id: CONTRACT.authorizationContract, state: "ratified", predecessor: "authorization" }],
  pathContracts: [{ code: 1, id: CONTRACT.pathContract, state: "ratified", predecessor: "path" }],
  pathProfiles: [{ code: 1, id: CONTRACT.pathProfile, state: "ratified", predecessor: "path" }],
  eventVersions: [{ code: 1, id: CONTRACT.eventVersion, state: "candidate", terminalRequired: true }],
  transferProfiles: [{ code: 1, id: CONTRACT.transferProfile, state: "candidate", scope: "application-neutral-probe", contentCoding: "identity" }],
  extensions: [
    { code: 1, id: "ogvcs.extension.safe-optional@1", owner: "OpenGameVCS", state: "candidate", requirement: "optional", fallback: "ignore", securityImpact: "none", dataImpact: "none", affectedSchemas: ["RequestEnvelope", "ResponseEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
    { code: 2, id: "ogvcs.extension.legacy-optional@1", owner: "OpenGameVCS", state: "deprecated", requirement: "optional", fallback: "ignore", securityImpact: "none", dataImpact: "none", affectedSchemas: ["RequestEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
    { code: 3, id: "ogvcs.extension.reserved@1", owner: "OpenGameVCS", state: "reserved", requirement: "optional", fallback: "reject", securityImpact: "unknown", dataImpact: "unknown", affectedSchemas: [], minimumProtocol: CONTRACT.protocolVersion },
    { code: 4, id: "ogvcs.extension.response-only@1", owner: "OpenGameVCS", state: "candidate", requirement: "optional", fallback: "reject", securityImpact: "none", dataImpact: "none", affectedSchemas: ["ResponseEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
    { code: 5, id: "ogvcs.extension.audit-optional@1", owner: "OpenGameVCS", state: "candidate", requirement: "optional", fallback: "ignore", securityImpact: "none", dataImpact: "none", affectedSchemas: ["RequestEnvelope", "ResponseEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
    { code: 6, id: "ogvcs.extension.count-probe@1", owner: "OpenGameVCS", state: "candidate", requirement: "optional", fallback: "ignore", securityImpact: "none", dataImpact: "none", affectedSchemas: ["RequestEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
    { code: 7, id: "ogvcs.extension.release-probe@1", owner: "OpenGameVCS", state: "candidate", requirement: "optional", fallback: "ignore", securityImpact: "none", dataImpact: "none", affectedSchemas: ["RequestEnvelope", "ResponseEnvelope"], minimumProtocol: CONTRACT.protocolVersion },
  ],
});

const identifier = string(1, 256, { pattern: "^[a-z0-9][a-z0-9._/-]*(?:@[0-9]+)?$", maxUtf8Bytes: 256 });
const extensionKeyPattern = "^[a-z0-9][a-z0-9._/-]*@[0-9]+$";
const digest = string(64, 64, { pattern: "^[0-9a-f]{64}$", maxUtf8Bytes: 64 });
const base64url = (min = 16, max = 1024) => string(min, max, { pattern: "^[A-Za-z0-9_-]+$", maxUtf8Bytes: max });
const token = (max = 1024) => string(16, max, { pattern: "^[A-Za-z0-9._~-]+$", maxUtf8Bytes: max });
const timestamp = integer(0, Number.MAX_SAFE_INTEGER);
const idempotencyKeyPattern = "^ik1\\.(?:0|[1-9][0-9]{0,15})\\.(?:0|[1-9][0-9]{0,15})\\.[A-Za-z0-9_-]{22,218}$";
const idempotencyKey = string(30, 256, { pattern: idempotencyKeyPattern, maxUtf8Bytes: 256 });
const optionalIdempotencyKey = string(0, 256, { pattern: `^(?:|${idempotencyKeyPattern.slice(1, -1)})$`, maxUtf8Bytes: 256 });
const capabilityList = array(identifier, 1, 128, { uniqueItems: true });
const optionalCapabilityList = array(identifier, 0, 128, { uniqueItems: true });
export const RUNNER_OPERATIONS = Object.freeze([
  "negotiate",
  "validate-envelope",
  "fingerprint",
  "validate-cursor",
  "validate-stream",
  "transfer-probe",
  "contract-load",
  "runner-batch",
  "release-preflight",
]);

export const MESSAGES = Object.freeze([
  {
    code: 1,
    name: "CapabilityAxes",
    description: "Independent offered capability axes; axis order never implies coupling.",
    fields: [
      field(1, "protocolVersions", capabilityList),
      field(2, "schemaVersions", capabilityList),
      field(3, "repositoryFormats", capabilityList),
      field(4, "authorizationContracts", capabilityList),
      field(5, "pathContracts", capabilityList),
      field(6, "pathProfiles", capabilityList),
      field(7, "eventVersions", capabilityList),
      field(8, "transferProfiles", capabilityList),
      field(9, "extensions", optionalCapabilityList),
      field(10, "requiredCapabilities", optionalCapabilityList),
    ],
  },
  {
    code: 2,
    name: "NegotiationOffer",
    description: "Client negotiation offer authenticated only after receipt issuance.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/negotiation-offer/v1"])),
      field(2, "clientNonce", base64url(22, 86), { sensitive: true, fingerprint: false }),
      field(3, "correlationId", token(128), { fingerprint: false }),
      field(4, "capabilities", reference("CapabilityAxes")),
      field(5, "deadlineUnixMs", timestamp, { required: false, fingerprint: false }),
    ],
  },
  {
    code: 3,
    name: "NegotiationSelection",
    description: "Deterministically selected independent capability tuple.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/negotiation-selection/v1"])),
      field(2, "protocolVersion", enumeration([CONTRACT.protocolVersion])),
      field(3, "messageSchemaVersion", enumeration([CONTRACT.messageSchemaVersion])),
      field(4, "repositoryFormat", enumeration([CONTRACT.repositoryFormat])),
      field(5, "authorizationContract", enumeration([CONTRACT.authorizationContract])),
      field(6, "authorizationRegistrySha256", digest),
      field(7, "pathContract", enumeration([CONTRACT.pathContract])),
      field(8, "pathProfile", enumeration([CONTRACT.pathProfile])),
      field(9, "pathRegistrySha256", digest),
      field(10, "eventVersion", enumeration([CONTRACT.eventVersion])),
      field(11, "transferProfile", enumeration([CONTRACT.transferProfile])),
      field(12, "extensions", optionalCapabilityList),
      field(13, "protocolRegistrySetSha256", digest),
      field(14, "repositoryRegistrySha256", digest),
    ],
  },
  {
    code: 4,
    name: "NegotiationReceiptClaims",
    description: "MAC-bound selection and authenticated request principal/session context.",
    constraints: [{ kind: "canonicalBase64url", field: "serverNonce", minimumDecodedBytes: 16, maximumDecodedBytes: 64 }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/negotiation-receipt-claims/v1"])),
      field(2, "selection", reference("NegotiationSelection")),
      field(3, "subjectDigest", digest, { sensitive: true }),
      field(4, "tenantDigest", digest, { sensitive: true }),
      field(5, "authorityEpoch", integer(0, Number.MAX_SAFE_INTEGER)),
      field(6, "sessionId", token(256), { sensitive: true }),
      field(7, "clientNonce", base64url(22, 86), { sensitive: true }),
      field(8, "serverNonce", base64url(22, 86), { sensitive: true }),
      field(9, "issuedAtUnixMs", timestamp),
      field(10, "expiresAtUnixMs", timestamp),
    ],
  },
  {
    code: 5,
    name: "NegotiationReceipt",
    description: "Authenticated downgrade-evidence receipt; never an authorization grant.",
    fields: [
      field(1, "algorithm", enumeration([CONTRACT.receiptAlgorithm])),
      field(2, "keyId", identifier),
      field(3, "claims", reference("NegotiationReceiptClaims"), { sensitive: true, fingerprint: false }),
      field(4, "mac", base64url(43, 43), { sensitive: true, fingerprint: false }),
    ],
  },
  {
    code: 6,
    name: "IdempotencyDescriptor",
    description: "Self-dating semantic JCS request identity; raw request bytes are excluded.",
    constraints: [{ kind: "selfDatingIdempotencyKey", keyField: "key", issuedAtField: "issuedAtUnixMs", expiresAtField: "expiresAtUnixMs", maxLifetimeMs: IDEMPOTENCY_KEY_MAX_LIFETIME_MS, maxFutureIssueSkewMs: IDEMPOTENCY_KEY_MAX_FUTURE_ISSUE_SKEW_MS }],
    fields: [
      field(1, "key", idempotencyKey, { sensitive: true, fingerprint: false }),
      field(2, "algorithm", enumeration([CONTRACT.fingerprintAlgorithm])),
      field(3, "projectionVersion", enumeration(["ogvcs.protocol/fingerprint-projection@1"])),
      field(4, "fingerprint", digest, { fingerprint: false }),
      field(5, "issuedAtUnixMs", timestamp, { fingerprint: false }),
      field(6, "expiresAtUnixMs", timestamp, { fingerprint: false }),
    ],
  },
  {
    code: 7,
    name: "RequestEnvelope",
    description: "Closed bounded control request envelope.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/request-envelope/v1"])),
      field(2, "operation", identifier),
      field(3, "correlationId", token(128), { fingerprint: false }),
      field(4, "deadlineUnixMs", timestamp, { required: false, fingerprint: false }),
      field(5, "negotiationReceipt", reference("NegotiationReceipt"), { sensitive: true, fingerprint: false }),
      field(6, "idempotency", reference("IdempotencyDescriptor"), { required: false, sensitive: true, fingerprint: false }),
      field(7, "body", json(32, 10_000)),
      field(8, "extensions", map(json(8, 1_000), 0, 32, { keyPattern: extensionKeyPattern, maxKeyUtf8Bytes: 256 }), { required: false }),
    ],
  },
  {
    code: 8,
    name: "SafeParameter",
    description: "Registered bounded authorization-safe problem parameter.",
    constraints: [{ kind: "safeParameterValue", nameField: "name", valueField: "value" }],
    fields: [
      field(1, "name", enumeration(Object.keys(SAFE_PARAMETER_DOMAINS))),
      field(2, "value", string(1, 1024, { maxUtf8Bytes: 1024 })),
    ],
  },
  {
    code: 9,
    name: "ProblemDetails",
    description: "Closed RFC 9457-safe problem subset; detail and instance are forbidden.",
    constraints: [{ kind: "registeredProblem" }],
    fields: [
      field(1, "type", enumeration(ERROR_CODES.map((entry) => entry.type))),
      field(2, "title", enumeration(ERROR_CODES.map((entry) => entry.title))),
      field(3, "status", enumeration([...new Set(ERROR_CODES.map((entry) => entry.status))])),
      field(4, "code", enumeration(ERROR_CODES.map((entry) => entry.name))),
      field(5, "retryable", boolean()),
      field(6, "correlationId", token(128)),
      field(7, "parameters", array(reference("SafeParameter"), 0, 16), { required: false }),
    ],
  },
  {
    code: 10,
    name: "ResponseEnvelope",
    description: "Closed bounded control response envelope.",
    constraints: [{ kind: "successOutcome", discriminator: "success", successField: "body", failureField: "problem" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/response-envelope/v1"])),
      field(2, "correlationId", token(128)),
      field(3, "success", boolean()),
      field(4, "body", json(32, 10_000), { required: false }),
      field(5, "problem", reference("ProblemDetails"), { required: false }),
      field(6, "extensions", map(json(8, 1_000), 0, 32, { keyPattern: extensionKeyPattern, maxKeyUtf8Bytes: 256 }), { required: false }),
    ],
  },
  {
    code: 11,
    name: "Cursor",
    description: "Opaque public cursor token; scope and position remain server-side and MAC-bound.",
    fields: [field(1, "token", token(1024), { sensitive: true, fingerprint: false })],
  },
  {
    code: 12,
    name: "PageEnvelope",
    description: "Page with explicit continuation/completion/gap state.",
    constraints: [{ kind: "pageState", discriminator: "state", cursorField: "nextCursor", problemField: "problem" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/page-envelope/v1"])),
      field(2, "correlationId", token(128)),
      field(3, "items", array(json(16, 1_000), 0, 1_000)),
      field(4, "state", enumeration(["complete", "more", "gap"])),
      field(5, "nextCursor", reference("Cursor"), { required: false, sensitive: true }),
      field(6, "problem", reference("ProblemDetails"), { required: false }),
    ],
  },
  {
    code: 13,
    name: "StreamFrame",
    description: "One canonical JSONL frame with explicit terminal semantics.",
    constraints: [{ kind: "streamKind", discriminator: "kind", payloadField: "payload", problemField: "problem" }],
    reservedFields: [{ id: 7, name: "finalDigest", reason: "R0 typed terminal semantics do not define a separate transcript digest or MAC" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/stream-frame/v1"])),
      field(2, "streamId", token(256)),
      field(3, "sequence", integer(0, Number.MAX_SAFE_INTEGER)),
      field(4, "kind", enumeration(["data", "terminal", "gap", "cancelled", "error"])),
      field(5, "payload", json(16, 10_000), { required: false }),
      field(6, "problem", reference("ProblemDetails"), { required: false }),
    ],
  },
  {
    code: 14,
    name: "CompactTransferGrant",
    description: "Opaque OGVCS-003 request-root grant carrier; explicit object sets are forbidden.",
    fields: [
      field(1, "scheme", enumeration(["OGVCS-Grant"])),
      field(2, "representation", enumeration(["request-root"])),
      field(3, "explicitObjectCount", integer(0, 0)),
      field(4, "envelope", base64url(16, 16_384), { sensitive: true, fingerprint: false }),
      field(5, "authorizationManifestSha256", enumeration([PREDECESSORS.authorization.manifestSha256])),
    ],
  },
  {
    code: 15,
    name: "TransferProbe",
    description: "Application-neutral identity-coded range/resume conformance probe.",
    fields: [
      field(1, "schemaVersion", enumeration([TRANSFER_PROBE_SCHEMA_VERSION])),
      field(2, "operation", enumeration(["probe", "read", "write"])),
      field(3, "grant", reference("CompactTransferGrant"), { sensitive: true, fingerprint: false }),
      field(4, "resourceTag", token(256)),
      field(5, "startOffset", integer(0, Number.MAX_SAFE_INTEGER)),
      field(6, "endOffsetExclusive", integer(1, Number.MAX_SAFE_INTEGER), { required: false }),
      field(7, "validatorTag", token(256), { required: false }),
      field(8, "expectedSha256", digest, { required: false }),
      field(9, "contentEncoding", enumeration(["identity"])),
      field(10, "followRedirects", boolean({ const: false })),
    ],
  },
  {
    code: 16,
    name: "TransferProbeResult",
    description: "Application-neutral range/resume probe result.",
    constraints: [{
      kind: "transferResultState",
      statusField: "status",
      startField: "acceptedStart",
      endField: "acceptedEndExclusive",
      totalField: "totalBytes",
      terminalField: "terminal",
      problemField: "problem",
      partialProgress: "acceptedStart<acceptedEndExclusive<totalBytes",
      interruptedProgress: "acceptedStart<=acceptedEndExclusive<totalBytes",
    }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/transfer-probe-result/v1"])),
      field(2, "status", enumeration(["complete", "partial", "interrupted", "rejected"])),
      field(3, "acceptedStart", integer(0, Number.MAX_SAFE_INTEGER)),
      field(4, "acceptedEndExclusive", integer(0, Number.MAX_SAFE_INTEGER)),
      field(5, "totalBytes", integer(0, Number.MAX_SAFE_INTEGER)),
      field(6, "validatorTag", token(256)),
      field(7, "contentSha256", digest),
      field(8, "terminal", boolean()),
      field(9, "problem", reference("ProblemDetails"), { required: false }),
    ],
  },
  {
    code: 17,
    name: "ExtensionRegistration",
    description: "Namespaced extension lifecycle and fallback declaration.",
    fields: [
      field(1, "code", integer(1, 65_535)),
      field(2, "id", identifier),
      field(3, "owner", string(1, 256, { maxUtf8Bytes: 256 })),
      field(4, "state", enumeration(["candidate", "ratified", "deprecated", "reserved"])),
      field(5, "requirement", enumeration(["optional", "required"])),
      field(6, "fallback", enumeration(["ignore", "reject"])),
      field(7, "securityImpact", string(1, 1024, { maxUtf8Bytes: 1024 })),
      field(8, "dataImpact", string(1, 1024, { maxUtf8Bytes: 1024 })),
      field(9, "affectedSchemas", array(identifier, 1, 64, { uniqueItems: true })),
      field(10, "minimumProtocol", identifier),
    ],
  },
  {
    code: 18,
    name: "CompatibilityEntry",
    description: "One allowed independently selected predecessor/capability tuple.",
    fields: [
      field(1, "code", integer(1, 65_535)),
      field(2, "state", enumeration(["candidate", "ratified", "deprecated"])),
      field(3, "selection", reference("NegotiationSelection")),
      field(4, "requiredCapabilities", capabilityList),
      field(5, "authorizationManifestSha256", digest),
      field(6, "pathManifestSha256", digest),
      field(7, "repositoryManifestSha256", digest),
    ],
  },
  {
    code: 19,
    name: "RunnerHello",
    description: "Offline contract-runner adapter handshake.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/runner-hello/v1"])),
      field(2, "adapterId", identifier),
      field(3, "contractManifestSha256", digest),
      field(4, "operations", array(enumeration(RUNNER_OPERATIONS), 1, 16, { uniqueItems: true })),
    ],
  },
  {
    code: 20,
    name: "RunnerCase",
    description: "One public executable semantic conformance case with no oracle fields.",
    constraints: [{ kind: "runnerOperation", operationField: "operation", inputField: "input" }],
    reservedFields: [{ id: 6, name: "resourceRecipe", reason: "virtual boundary recipes are forbidden" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/runner-case/v1"])),
      field(2, "id", identifier),
      field(3, "operation", enumeration(RUNNER_OPERATIONS)),
      field(4, "input", json(32, 10_000)),
      field(5, "inputKind", enumeration(["semantic-value", "raw-json", "raw-bytes", "jsonl"])),
      field(7, "configuredLimits", reference("RunnerConfiguredLimits"), { required: false }),
      field(8, "control", reference("RunnerExecutionControl")),
      field(9, "serverContext", json(8, 256), { required: false, sensitive: true, fingerprint: false }),
    ],
  },
  {
    code: 21,
    name: "RunnerResult",
    description: "Sanitized semantic result from one independent adapter.",
    constraints: [{ kind: "mutationWitness", preMutationField: "preMutation", mutationCountField: "mutationCount" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/runner-result/v1"])),
      field(2, "id", identifier),
      field(3, "result", enumeration(["accept", "reject"])),
      field(4, "code", enumeration(["NONE", ...ERROR_CODES.map((entry) => entry.name)])),
      field(5, "preMutation", boolean(), { description: "True exactly when no mutation began anywhere in the complete executable case." }),
      field(6, "mutationCount", integer(0, Number.MAX_SAFE_INTEGER), { description: "Total mutations begun across every attempt in the complete executable case." }),
      field(7, "semanticDigest", digest, { required: false }),
      field(8, "traceDigest", digest),
    ],
  },
  {
    code: 22,
    name: "RunnerReport",
    description: "Deterministic aggregate contract-runner report.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/runner-report/v1"])),
      field(2, "adapterId", identifier),
      field(3, "contractManifestSha256", digest),
      field(4, "results", array(reference("RunnerResult"), 1, 1_024)),
      field(5, "passed", integer(0, 1_024)),
      field(6, "failed", integer(0, 1_024)),
      field(7, "reportDigest", digest),
    ],
  },
  {
    code: 23,
    name: "RunnerConfiguredLimits",
    description: "Conformance-only lowered ceilings, each capped by its normative hard maximum.",
    constraints: [{ kind: "nonEmptyObject" }],
    fields: LIMITS.map((limit, index) => field(index + 1, limit.name, integer(limit.configuredMinimum ?? 1, limit.value), { required: false })),
  },
  {
    code: 24,
    name: "RunnerExecutionControl",
    description: "Deterministic cancellation and clock controls for executable conformance cases.",
    constraints: [{
      kind: "runnerClockSamples",
      samplesField: "clockSamplesUnixMs",
      order: "nondecreasing",
      elapsedComputation: "checked-last-minus-first",
      configuredLimit: "maxOperationTimeMs",
      hardMaximumMs: LIMITS.find((entry) => entry.name === "maxOperationTimeMs").value,
      expirationComparison: "elapsed>=effectiveMaximum",
      decreasingOutcome: "PROTOCOL_MALFORMED",
      expirationOutcome: "DEADLINE_EXCEEDED",
    }],
    fields: [
      field(1, "cancellation", enumeration(["none", "before-operation", "after-first-stream-frame"])),
      field(2, "clockSamplesUnixMs", array(timestamp, 1, 16)),
    ],
  },
  {
    code: 25,
    name: "RunnerPrincipal",
    description: "Public conformance principal binding used for receipt verification.",
    fields: [
      field(1, "subjectDigest", digest),
      field(2, "tenantDigest", digest),
      field(3, "authorityEpoch", integer(0, Number.MAX_SAFE_INTEGER)),
      field(4, "sessionId", token(256)),
    ],
  },
  {
    code: 26,
    name: "NegotiationCaseInput",
    description: "Executable negotiation offer, server selection, receipt key, and verification context.",
    constraints: [
      { kind: "canonicalBase64url", field: "serverNonce", minimumDecodedBytes: 16, maximumDecodedBytes: 64 },
      { kind: "negotiationTransport", schemeField: "transportScheme", tlsField: "tlsVersion", loopbackField: "loopbackConformance", requiredScheme: "https", requiredTls: "1.3", loopbackException: false },
      { kind: "receiptVerificationOrder", routeField: "route", macMutationField: "receiptMacXor", verifyAtField: "verifyAtUnixMs", issueAtField: "issueAtUnixMs", lifetimeField: "receiptLifetimeMs", failureOrder: ["canonical-input", "mac", "expiry", "principal-binding", "selection-binding"] },
    ],
    fields: [
      field(1, "route", enumeration(["negotiate", "verify-receipt"])),
      field(2, "offer", reference("NegotiationOffer")),
      field(3, "serverSelection", reference("NegotiationSelection")),
      field(4, "principal", reference("RunnerPrincipal")),
      field(5, "verificationPrincipal", reference("RunnerPrincipal")),
      field(6, "minimumCapabilities", optionalCapabilityList),
      field(7, "transportScheme", enumeration(["https", "http"])),
      field(8, "tlsVersion", enumeration(["1.3", "1.2"])),
      field(9, "loopbackConformance", boolean()),
      field(10, "receiptKeyId", identifier),
      field(11, "receiptKeyBase64url", base64url(43, 43), { sensitive: true, fingerprint: false }),
      // The conformance carrier admits the canonical one-byte-over witness;
      // canonicalBase64url remains the normative decoded 16..64-byte limit.
      field(12, "serverNonce", base64url(22, 87)),
      field(13, "issueAtUnixMs", timestamp),
      field(14, "verifyAtUnixMs", timestamp),
      field(15, "receiptMacXor", integer(0, 255)),
      field(16, "receiptLifetimeMs", integer(1, 300_000)),
      field(17, "verificationSelection", reference("NegotiationSelection")),
    ],
  },
  {
    code: 27,
    name: "EnvelopeCaseInput",
    description: "Executable bounded JSON/schema/envelope and transport context.",
    constraints: [
      { kind: "encodedDocument", encodingField: "encoding", documentField: "document", rawField: "rawInput" },
      { kind: "retryAfterHeader", documentField: "document", headersField: "headers" },
    ],
    fields: [
      field(1, "route", enumeration(["validate-document", "validate-extension", "authorize", "emit-problem"])),
      field(2, "targetSchema", enumeration(["JsonValue", "RequestEnvelope", "ResponseEnvelope", "ProblemDetails", "PageEnvelope", "NegotiationCaseInput", "CursorCaseInput"])),
      field(3, "encoding", enumeration(["semantic-json", "raw-json", "raw-hex"])),
      field(4, "document", json(32, 10_000), { required: false }),
      field(5, "rawInput", string(0, 65_536, { maxUtf8Bytes: 65_536 }), { required: false }),
      field(6, "atUnixMs", timestamp),
      field(7, "transportScheme", enumeration(["https", "http"])),
      field(8, "tlsVersion", enumeration(["1.3", "1.2"])),
      field(9, "method", enumeration(["GET", "POST"])),
      field(10, "contentEncoding", string(1, 64, { pattern: "^[a-z0-9-]+$", maxUtf8Bytes: 64 })),
      field(11, "redirectStatus", integer(300, 399), { required: false }),
      field(12, "originChanged", boolean()),
      field(13, "httpStatus", integer(100, 599), { required: false }),
      field(14, "authorizationDecision", enumeration(["allow", "deny", "error"])),
      field(15, "forwardedSubjectMatches", boolean()),
      field(16, "forwardedTenantMatches", boolean()),
      field(17, "allowSameOriginRedirect", boolean()),
      field(18, "headers", array(reference("TransportHeaderInput"), 0, 256)),
      field(19, "selectedExtensions", optionalCapabilityList),
      field(20, "rawInputUtf16CodeUnits", array(integer(0, 65_535), 1, 4_096), { required: false }),
    ],
  },
  {
    code: 28,
    name: "FingerprintCaseInput",
    description: "Executable semantic projections and self-dating idempotency attempt sequence.",
    constraints: [
      { kind: "selfDatingIdempotencyKey", keyField: "idempotencyKey", issuedAtField: "idempotencyIssuedAtUnixMs", expiresAtField: "idempotencyExpiresAtUnixMs", evaluatorTimeField: "atUnixMs", maxLifetimeMs: IDEMPOTENCY_KEY_MAX_LIFETIME_MS, maxFutureIssueSkewMs: IDEMPOTENCY_KEY_MAX_FUTURE_ISSUE_SKEW_MS, allowEmptyKey: true },
      { kind: "idempotencyProjections", arrayField: "projections", projectionSchema: "IdempotencyProjectionInput" },
      { kind: "indexIntoArray", indexArrayField: "attemptProjectionIndexes", targetArrayField: "projections" },
      { kind: "idempotencyExecution", routeField: "route", retryableField: "retryableMutation", keyField: "idempotencyKey" },
    ],
    fields: [
      field(1, "route", enumeration(["fingerprint", "idempotency"])),
      field(2, "projections", array(json(16, 2_000), 1, 4)),
      field(3, "rawInputs", array(string(0, 65_536, { maxUtf8Bytes: 65_536 }), 0, 4)),
      field(4, "algorithm", string(1, 64, { pattern: "^[A-Z0-9-]+$", maxUtf8Bytes: 64 })),
      field(5, "idempotencyKey", optionalIdempotencyKey),
      field(6, "retryableMutation", boolean()),
      field(7, "attemptProjectionIndexes", array(integer(0, 3), 1, 16)),
      field(8, "attemptSchedule", array(enumeration(["fingerprint", "begin-mutation", "commit", "lose-response", "deadline", "expire-key", "retire-tombstone", "retry"]), 1, 16)),
      field(9, "idempotencyIssuedAtUnixMs", timestamp),
      field(10, "idempotencyExpiresAtUnixMs", timestamp),
      field(11, "atUnixMs", timestamp),
      field(12, "tombstoneRetentionMs", integer(0, IDEMPOTENCY_KEY_MAX_LIFETIME_MS)),
      field(13, "attemptAuthorizationDecisions", array(enumeration(["allow", "deny"]), 1, 16)),
    ],
  },
  {
    code: 29,
    name: "CursorCaseInput",
    description: "Executable page or opaque-cursor lifecycle with explicit scope and time.",
    constraints: [
      { kind: "cursorScopes", issueField: "issueScope", readField: "readScope", projectionSchema: "CursorScopeInput" },
      { kind: "cursorLifetime", issuedAtField: "issuedAtUnixMs", readAtField: "readAtUnixMs", ttlField: "ttlMs", maximumExpiry: Number.MAX_SAFE_INTEGER },
    ],
    fields: [
      field(1, "route", enumeration(["validate-page", "validate-token", "token-lifecycle", "token-byte-preflight"])),
      field(2, "page", json(16, 2_000)),
      field(3, "issueScope", json(8, 128), { sensitive: true, fingerprint: false }),
      field(4, "readScope", json(8, 128), { sensitive: true, fingerprint: false }),
      field(5, "issuedAtUnixMs", timestamp),
      field(6, "readAtUnixMs", timestamp),
      field(7, "ttlMs", integer(1, 86_400_000)),
      field(8, "generation", integer(0, Number.MAX_SAFE_INTEGER)),
      field(9, "minimumRetainedGeneration", integer(0, Number.MAX_SAFE_INTEGER)),
      field(10, "tokenMutation", enumeration(["none", "tamper", "unknown"])),
      field(11, "suppliedToken", string(0, 1_024, { maxUtf8Bytes: 1_024 })),
      field(12, "tokenSource", enumeration(["issued", "supplied"])),
      field(13, "lifecycleActions", array(enumeration(["issue", "expire", "issue-unrelated", "prune", "read"]), 1, 16)),
      field(14, "tombstoneRetentionMs", integer(1, 86_400_000)),
    ],
  },
  {
    code: 30,
    name: "StreamCaseInput",
    description: "Executable canonical JSONL or frame writer input with explicit source closure.",
    fields: [
      field(1, "route", enumeration(["parse", "write-roundtrip"])),
      field(2, "encoding", enumeration(["frames", "jsonl"])),
      field(3, "frames", array(json(16, 2_000), 0, 4_096)),
      field(4, "jsonl", string(0, 65_536, { maxUtf8Bytes: 65_536 })),
      field(5, "sourceCloses", boolean()),
    ],
  },
  {
    code: 31,
    name: "TransferCaseInput",
    description: "Executable application-neutral probe, carried authorization verification authority, transport response, and declarative TLS/proxy policy check.",
    constraints: [
      { kind: "transferCaseResult", routeField: "route", resultField: "probeResult" },
      { kind: "transferHttpRange", routeField: "route", probeField: "probe", responseStatusField: "responseStatus", requestHeadersField: "requestHeaders", responseHeadersField: "responseHeaders", responseBodyHexField: "responseBodyHex" },
      {
        kind: "transferProbePreflight",
        routeField: "route",
        probeField: "probe",
        grantField: "grant",
        projectionSchema: "TransferProbeNonGrantInput",
        sourceSchemaVersion: TRANSFER_PROBE_SCHEMA_VERSION,
        projectionSchemaVersion: TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION,
        failureOrder: ["non-grant-shape", "range", "resume-validator", "grant-shape", "grant-verification"],
      },
    ],
    reservedFields: [
      { id: 5, name: "grantVerification", reason: "descriptive verification outcomes are harness oracles and must never reach adapters" },
      { id: 10, name: "authorizationVectorPath", reason: "adapters verify carried authorization authority and never read predecessor vectors" },
      { id: 11, name: "authorizationCaseId", reason: "predecessor case identities are harness-only provenance" },
      { id: 12, name: "authorizationCaseSha256", reason: "predecessor case digests are harness-only provenance" },
      { id: 13, name: "authorizationContextPatch", reason: "the complete concrete context is carried directly" },
      { id: 22, name: "responseBodyBytes", reason: "a count cannot authenticate response content; R0 carries bounded responseBodyHex instead" },
    ],
    fields: [
      field(1, "route", enumeration(["probe", "verify-grant", "transport-policy", "validate-result", "http-range"])),
      field(2, "probe", json(16, 2_000)),
      field(3, "transportResponse", json(16, 2_000)),
      field(4, "grantLocation", enumeration(["header", "query"])),
      field(6, "responseStatus", integer(100, 599)),
      field(7, "originChanged", boolean()),
      field(8, "digestMatches", boolean()),
      field(9, "logGrant", boolean()),
      field(14, "proxyMode", enumeration(["direct", "connect"])),
      field(15, "proxyConfigured", boolean()),
      field(16, "connectResult", enumeration(["not-attempted", "success", "failure", "bypassed"])),
      field(17, "certificateValid", boolean()),
      field(18, "hostnameMatches", boolean()),
      field(19, "probeResult", json(8, 256), { required: false }),
      field(20, "requestHeaders", array(reference("TransportHeaderInput"), 0, 256)),
      field(21, "responseHeaders", array(reference("TransportHeaderInput"), 0, 256)),
      field(23, "authorizationContext", json(8, 10_000), { sensitive: true, fingerprint: false, description: "Bounded conformance carrier passed unchanged to the pinned OGVCS-003 verifier; this schema does not restate authorization semantics." }),
      field(24, "authorizationPublicJwk", json(4, 32), { fingerprint: false, description: "Bounded public verification-key carrier passed unchanged to the pinned OGVCS-003 verifier." }),
      field(25, "responseBodyHex", string(0, 65_536, { pattern: "^(?:[0-9a-f]{2})*$", maxUtf8Bytes: 65_536 }), { description: "Bounded lowercase-hex response body bytes authenticated by Content-Digest on the HTTP Range conformance route." }),
    ],
  },
  {
    code: 32,
    name: "ContractArtifactInput",
    description: "One bounded in-memory contract-loader artifact.",
    fields: [
      field(1, "path", string(1, 256, { pattern: "^[a-z0-9][A-Za-z0-9._/-]*$", maxUtf8Bytes: 256 })),
      field(2, "bytesHex", string(0, 65_536, { pattern: "^(?:[0-9a-f]{2})*$", maxUtf8Bytes: 65_536 })),
    ],
  },
  {
    code: 33,
    name: "ContractLoadCaseInput",
    description: "Executable in-memory contract inventory or registry-load input.",
    fields: [
      field(1, "route", enumeration(["inventory", "registry"])),
      field(2, "artifacts", array(reference("ContractArtifactInput"), 0, 4_096)),
      field(3, "registryEntries", array(json(8, 128), 0, 4_096)),
    ],
  },
  {
    code: 34,
    name: "RunnerBatchEntry",
    description: "One bounded runner collection entry.",
    fields: [
      field(1, "id", identifier),
      field(2, "operation", enumeration(RUNNER_OPERATIONS)),
    ],
  },
  {
    code: 35,
    name: "RunnerBatchCaseInput",
    description: "Executable runner collection, validation, ordering, and count input.",
    fields: [
      field(1, "cases", array(reference("RunnerBatchEntry"), 0, 1_024)),
    ],
  },
  {
    code: 36,
    name: "TraceHeader",
    description: "One normalized public response header observation.",
    fields: [
      field(1, "name", string(1, 128, { pattern: "^[a-z0-9-]+$", maxUtf8Bytes: 128 })),
      field(2, "value", string(0, 8_192, { maxUtf8Bytes: 8_192 })),
    ],
  },
  {
    code: 37,
    name: "TraceLogEntry",
    description: "One sanitized public conformance log observation.",
    fields: [
      field(1, "event", identifier),
      field(2, "fields", map(json(8, 256), 0, 32, { keyPattern: "^[A-Za-z][A-Za-z0-9]*$", maxKeyUtf8Bytes: 128 })),
    ],
  },
  {
    code: 38,
    name: "AdapterTrace",
    description: "Bounded actual public output inspected by the harness before sanitization.",
    fields: [
      field(1, "responseBody", json(32, 10_000)),
      field(2, "responseHeaders", array(reference("TraceHeader"), 0, 256)),
      field(3, "streamFrames", array(reference("StreamFrame"), 0, 4_096)),
      field(4, "logEntries", array(reference("TraceLogEntry"), 0, 4_096)),
      field(5, "semanticOutput", json(16, 10_000)),
    ],
  },
  {
    code: 39,
    name: "AdapterResult",
    description: "Per-case adapter outcome plus actual public trace; never retained in RunnerReport.",
    constraints: [{ kind: "mutationWitness", preMutationField: "preMutation", mutationCountField: "mutationCount" }],
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/adapter-result/v1"])),
      field(2, "id", identifier),
      field(3, "result", enumeration(["accept", "reject"])),
      field(4, "code", enumeration(["NONE", ...ERROR_CODES.map((entry) => entry.name)])),
      field(5, "preMutation", boolean(), { description: "True exactly when no mutation began anywhere in the complete executable case." }),
      field(6, "mutationCount", integer(0, Number.MAX_SAFE_INTEGER), { description: "Total mutations begun across every attempt in the complete executable case." }),
      field(7, "trace", reference("AdapterTrace")),
    ],
  },
  {
    code: 40,
    name: "ReleaseAssignment",
    description: "One immutable prior or proposed numeric and semantic assignment used by release governance.",
    fields: [
      field(1, "kind", enumeration(["message", "field", "limit", "error", "capability", "extension"])),
      field(2, "scope", string(1, 256, { maxUtf8Bytes: 256 })),
      field(3, "name", string(1, 256, { maxUtf8Bytes: 256 })),
      field(4, "code", integer(1, 65_535)),
      field(5, "semanticSha256", digest),
    ],
  },
  {
    code: 41,
    name: "ReleasePreflightCaseInput",
    description: "Concrete proposed capability tuple, predecessor pins, and assignment snapshot for release governance.",
    fields: [
      field(1, "proposedSelection", reference("ReleaseSelectionProposal")),
      field(2, "requiredCapabilities", optionalCapabilityList),
      field(3, "authorizationManifestSha256", digest),
      field(4, "pathManifestSha256", digest),
      field(5, "repositoryManifestSha256", digest),
      field(6, "priorAssignmentSnapshotSha256", digest),
      field(7, "proposedAssignments", array(reference("ReleaseAssignment"), 1, 1_024, { uniqueItems: true })),
    ],
  },
  {
    code: 42,
    name: "ReleaseSelectionProposal",
    description: "Schema-valid proposed independent tuple whose values need not already be registered.",
    fields: [
      field(1, "schemaVersion", enumeration(["ogvcs.protocol/release-selection-proposal/v1"])),
      field(2, "protocolVersion", identifier),
      field(3, "messageSchemaVersion", identifier),
      field(4, "repositoryFormat", identifier),
      field(5, "authorizationContract", identifier),
      field(6, "authorizationRegistrySha256", digest),
      field(7, "pathContract", identifier),
      field(8, "pathProfile", identifier),
      field(9, "pathRegistrySha256", digest),
      field(10, "eventVersion", identifier),
      field(11, "transferProfile", identifier),
      field(12, "extensions", optionalCapabilityList),
      field(13, "protocolRegistrySetSha256", digest),
      field(14, "repositoryRegistrySha256", digest),
    ],
  },
  {
    code: 43,
    name: "TransportHeaderInput",
    description: "Bounded received HTTP field with ASCII-case-insensitive name comparison.",
    fields: [
      field(1, "name", string(1, 128, { pattern: "^[A-Za-z0-9-]+$", maxUtf8Bytes: 128 })),
      field(2, "value", string(0, 8_192, { maxUtf8Bytes: 8_192 })),
    ],
  },
  {
    code: 44,
    name: "CursorScopeInput",
    description: "Closed server-owned opaque-cursor scope compared before token lookup or lifecycle evaluation.",
    fields: [
      field(1, "subject", token(256), { sensitive: true, fingerprint: false }),
      field(2, "tenant", token(256), { sensitive: true, fingerprint: false }),
      field(3, "repository", token(256), { sensitive: true, fingerprint: false }),
      field(4, "operation", token(256), { sensitive: true, fingerprint: false }),
      field(5, "queryDigest", digest, { sensitive: true, fingerprint: false }),
    ],
  },
  {
    code: 45,
    name: "IdempotencyProjectionInput",
    description: "Closed semantic RequestEnvelope projection used by fingerprint and idempotency execution.",
    fields: [
      field(1, "schemaVersion", identifier),
      field(2, "operation", identifier),
      field(3, "body", json(32, 10_000)),
      field(4, "extensions", map(json(8, 1_000), 0, 32, { keyPattern: extensionKeyPattern, maxKeyUtf8Bytes: 256 })),
    ],
  },
  {
    code: 46,
    name: "TransferProbeNonGrantInput",
    description: "Closed non-grant TransferProbe projection validated before grant inspection or verification.",
    constraints: [{ kind: "transferProbeRange", startField: "startOffset", endField: "endOffsetExclusive", validatorField: "validatorTag" }],
    fields: [
      field(1, "schemaVersion", enumeration([TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION])),
      field(2, "operation", enumeration(["probe", "read", "write"])),
      field(3, "resourceTag", token(256)),
      field(4, "startOffset", integer(0, Number.MAX_SAFE_INTEGER)),
      field(5, "endOffsetExclusive", integer(1, Number.MAX_SAFE_INTEGER), { required: false }),
      field(6, "validatorTag", token(256), { required: false }),
      field(7, "expectedSha256", digest, { required: false }),
      field(8, "contentEncoding", enumeration(["identity"])),
      field(9, "followRedirects", boolean({ const: false })),
    ],
  },
]);

export const COMPATIBILITY = Object.freeze([
  {
    code: 1,
    state: "candidate",
    selection: {
      schemaVersion: "ogvcs.protocol/negotiation-selection/v1",
      protocolVersion: CONTRACT.protocolVersion,
      messageSchemaVersion: CONTRACT.messageSchemaVersion,
      repositoryFormat: CONTRACT.repositoryFormat,
      authorizationContract: CONTRACT.authorizationContract,
      authorizationRegistrySha256: PREDECESSORS.authorization.registrySetSha256,
      pathContract: CONTRACT.pathContract,
      pathProfile: CONTRACT.pathProfile,
      pathRegistrySha256: PREDECESSORS.path.registrySetSha256,
      eventVersion: CONTRACT.eventVersion,
      transferProfile: CONTRACT.transferProfile,
      extensions: ["ogvcs.extension.safe-optional@1", "ogvcs.extension.audit-optional@1"],
      protocolRegistrySetSha256: "@generated:registry-set-sha256",
      repositoryRegistrySha256: PREDECESSORS.repository.registrySetSha256,
    },
    requiredCapabilities: [
      CONTRACT.protocolVersion,
      CONTRACT.messageSchemaVersion,
      CONTRACT.authorizationContract,
      CONTRACT.pathContract,
      CONTRACT.pathProfile,
      CONTRACT.eventVersion,
      CONTRACT.transferProfile,
      "ogvcs.receipt.hmac-sha256@1",
      "ogvcs.stream.explicit-terminal@1",
      "ogvcs.idempotency.semantic-jcs@1",
    ],
    authorizationManifestSha256: PREDECESSORS.authorization.manifestSha256,
    pathManifestSha256: PREDECESSORS.path.manifestSha256,
    repositoryManifestSha256: PREDECESSORS.repository.manifestSha256,
  },
]);

export const VECTOR_CATEGORIES = Object.freeze([
  "negotiation",
  "envelopes",
  "idempotency",
  "cursors",
  "streams",
  "transfer",
  "malformed",
  "resources",
  "security",
  "release",
]);

const BASELINE_AXES = Object.freeze({
  protocolVersions: [CONTRACT.protocolVersion],
  schemaVersions: [CONTRACT.messageSchemaVersion],
  repositoryFormats: [CONTRACT.repositoryFormat],
  authorizationContracts: [CONTRACT.authorizationContract],
  pathContracts: [CONTRACT.pathContract],
  pathProfiles: [CONTRACT.pathProfile],
  eventVersions: [CONTRACT.eventVersion],
  transferProfiles: [CONTRACT.transferProfile],
  extensions: [],
  requiredCapabilities: ["ogvcs.receipt.hmac-sha256@1", "ogvcs.stream.explicit-terminal@1", "ogvcs.idempotency.semantic-jcs@1"],
});
const BASELINE_PRINCIPAL = Object.freeze({ subjectDigest: "1".repeat(64), tenantDigest: "2".repeat(64), authorityEpoch: 7, sessionId: "session-00000001" });
const BASELINE_SELECTION = Object.freeze({
  schemaVersion: "ogvcs.protocol/negotiation-selection/v1",
  protocolVersion: CONTRACT.protocolVersion,
  messageSchemaVersion: CONTRACT.messageSchemaVersion,
  repositoryFormat: CONTRACT.repositoryFormat,
  authorizationContract: CONTRACT.authorizationContract,
  authorizationRegistrySha256: PREDECESSORS.authorization.registrySetSha256,
  pathContract: CONTRACT.pathContract,
  pathProfile: CONTRACT.pathProfile,
  pathRegistrySha256: PREDECESSORS.path.registrySetSha256,
  eventVersion: CONTRACT.eventVersion,
  transferProfile: CONTRACT.transferProfile,
  extensions: [],
  protocolRegistrySetSha256: "0".repeat(64),
  repositoryRegistrySha256: PREDECESSORS.repository.registrySetSha256,
});
const BASELINE_RECEIPT = Object.freeze({
  algorithm: CONTRACT.receiptAlgorithm,
  keyId: "fixture-key@1",
  claims: {
    schemaVersion: "ogvcs.protocol/negotiation-receipt-claims/v1",
    selection: BASELINE_SELECTION,
    ...BASELINE_PRINCIPAL,
    clientNonce: "A".repeat(22),
    serverNonce: "B".repeat(22),
    issuedAtUnixMs: 1_000,
    expiresAtUnixMs: 301_000,
  },
  mac: "A".repeat(43),
});
const baselineRequest = () => ({
  schemaVersion: "ogvcs.protocol/request-envelope/v1",
  operation: "repository.example/read@1",
  correlationId: "correlation-0001",
  negotiationReceipt: structuredClone(BASELINE_RECEIPT),
  body: {},
  extensions: {},
});
const problemFor = (name, correlationId = "correlation-0001", parameters = undefined) => {
  const authority = ERROR_CODES.find((entry) => entry.name === name);
  return {
    type: authority.type,
    title: authority.title,
    status: authority.status,
    code: authority.name,
    retryable: authority.retryable,
    correlationId,
    ...(parameters === undefined ? {} : { parameters }),
  };
};
const pageFor = (state = "complete", items = [], nextCursor = undefined) => ({
  schemaVersion: "ogvcs.protocol/page-envelope/v1",
  correlationId: "correlation-0001",
  items,
  state,
  ...(nextCursor === undefined ? {} : { nextCursor: { token: nextCursor } }),
  ...(state === "gap" ? { problem: problemFor("CURSOR_GAP", "correlation-0001", [{ name: "gapClass", value: "retention-gap" }]) } : {}),
});
const controlFor = (extra = {}) => extra.control ?? { cancellation: "none", clockSamplesUnixMs: [1_000] };

function negotiationInput(input) {
  const capabilities = structuredClone(BASELINE_AXES);
  for (const axis of ["protocolVersions", "schemaVersions", "repositoryFormats", "authorizationContracts", "pathContracts", "pathProfiles", "eventVersions", "transferProfiles", "extensions"]) {
    if (input[axis] !== undefined) capabilities[axis] = structuredClone(input[axis]);
  }
  if (input.extension !== undefined) capabilities.extensions.push(input.extension);
  if (input.reorderAxes) capabilities.extensions.push("vendor.z/opaque@1", "vendor.a/opaque@1");
  if (input.requiredCapabilities !== undefined) capabilities.requiredCapabilities = structuredClone(input.requiredCapabilities);
  if (input.requiredExtension !== undefined) capabilities.requiredCapabilities.push(input.requiredExtension);
  if (input.stripClientMinimum) capabilities.requiredCapabilities = capabilities.requiredCapabilities.filter((entry) => entry !== "ogvcs.receipt.hmac-sha256@1");
  const verificationPrincipal = structuredClone(BASELINE_PRINCIPAL);
  if (input.changeSubjectAfterIssue) verificationPrincipal.subjectDigest = "4".repeat(64);
  if (input.changeTenantAfterIssue) verificationPrincipal.tenantDigest = "5".repeat(64);
  if (input.changeSessionAfterIssue) verificationPrincipal.sessionId = "foreign-session01";
  if (input.changeAuthorityEpochAfterIssue) verificationPrincipal.authorityEpoch += 1;
  const verificationSelection = structuredClone(BASELINE_SELECTION);
  if (input.changeSelectionAfterIssue) verificationSelection.extensions = ["ogvcs.extension.safe-optional@1"];
  const serverSelection = structuredClone(BASELINE_SELECTION);
  const offeredExtensions = new Set(capabilities.extensions);
  serverSelection.extensions = COMPATIBILITY[0].selection.extensions.filter((id) => offeredExtensions.has(id));
  return {
    route: Object.keys(input).some((key) => key.startsWith("change") || key.startsWith("receipt") || key === "mutateReceiptMac") ? "verify-receipt" : "negotiate",
    offer: {
      schemaVersion: "ogvcs.protocol/negotiation-offer/v1",
      clientNonce: "A".repeat(22),
      correlationId: "correlation-0001",
      capabilities,
    },
    serverSelection,
    principal: structuredClone(BASELINE_PRINCIPAL),
    verificationPrincipal,
    minimumCapabilities: ["ogvcs.receipt.hmac-sha256@1"],
    transportScheme: input.transport === "http" ? "http" : "https",
    tlsVersion: input.tls === "1.2" ? "1.2" : "1.3",
    loopbackConformance: input.loopbackConformance === true,
    receiptKeyId: "fixture-key@1",
    receiptKeyBase64url: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc",
    serverNonce: input.serverNonce ?? "CQkJCQkJCQkJCQkJCQkJCQ",
    issueAtUnixMs: 1_000,
    verifyAtUnixMs: 1_000 + (input.receiptAgeMs ?? 0),
    receiptMacXor: input.mutateReceiptMac ? 1 : 0,
    receiptLifetimeMs: input.receiptLifetimeMs ?? 300_000,
    verificationSelection,
  };
}

function envelopeInput(input, inputKind) {
  let document = baselineRequest();
  let route = "validate-document";
  let targetSchema = "RequestEnvelope";
  let encoding = "semantic-json";
  let rawInput;
  if (inputKind === "raw-json") { encoding = "raw-json"; rawInput = input.rawJson ?? input.integer ?? ""; }
  if (inputKind === "raw-bytes") { encoding = "raw-hex"; rawInput = input.bytesHex ?? ""; }
  if (input.problem !== undefined || input.problemCode !== undefined || input.fields !== undefined || input.bodyStatus !== undefined) {
    const requestedCode = input.problemCode ?? "AUTHORIZATION_DENIED";
    const code = requestedCode === "INTERNAL_SECRET" ? "INTERNAL_ERROR" : requestedCode;
    const parameters = input.retryAfterMs === undefined ? undefined : [{ name: "retryAfterMs", value: input.retryAfterMs }];
    const problem = { ...problemFor(code, "correlation-0001", parameters), ...(requestedCode === "INTERNAL_SECRET" ? { code: requestedCode } : {}), ...(input.problem ?? {}) };
    if (input.bodyStatus !== undefined) problem.status = input.bodyStatus;
    document = input.fields !== undefined
      ? { schemaVersion: "ogvcs.protocol/response-envelope/v1", correlationId: "correlation-0001", success: false, problem }
      : problem;
    targetSchema = input.fields !== undefined || input.bodyStatus !== undefined ? "ResponseEnvelope" : "ProblemDetails";
    route = input.fields !== undefined ? "emit-problem" : "validate-document";
  }
  if (input.unknownMember !== undefined) document[input.unknownMember] = true;
  if (input.omit !== undefined) delete document[input.omit];
  if (input.field !== undefined && input.field !== "mac") document[input.field] = input.value;
  if (input.field === "mac") document.negotiationReceipt = { ...document.negotiationReceipt, mac: input.value };
  if (input.extensionPayloadId !== undefined) {
    document.extensions = { [input.extensionPayloadId]: input.extensionPayload ?? { enabled: true } };
    route = "validate-extension";
  }
  if (input.deadline === "past") document.deadlineUnixMs = 1_999;
  if (input.canonical === true) { encoding = "raw-json"; rawInput = JSON.stringify(document); }
  if (input.canonical === false) { encoding = "raw-json"; rawInput = ` { "operation" : ${JSON.stringify(document.operation)}, "schemaVersion" : ${JSON.stringify(document.schemaVersion)}, "correlationId" : ${JSON.stringify(document.correlationId)}, "negotiationReceipt" : ${JSON.stringify(document.negotiationReceipt)}, "body" : {}, "extensions" : {} } `; }
  if (input.fault !== undefined || input.forwardedSubject !== undefined || input.forwardedTenant !== undefined || input.authorizationGrant === false) route = "authorize";
  const output = {
    route,
    targetSchema,
    encoding,
    ...(encoding === "semantic-json" ? { document } : { rawInput: String(rawInput) }),
    atUnixMs: 2_000,
    transportScheme: "https",
    tlsVersion: "1.3",
    method: input.method ?? "GET",
    contentEncoding: input.contentEncoding ?? "identity",
    ...(input.status === undefined ? {} : { redirectStatus: input.status }),
    originChanged: input.originChange === true,
    ...(input.httpStatus === undefined ? {} : { httpStatus: input.httpStatus }),
    authorizationDecision: input.fault === "throw" ? "error" : input.fault !== undefined || input.forwardedSubject !== undefined || input.forwardedTenant !== undefined || input.authorizationGrant === false ? "deny" : "allow",
    forwardedSubjectMatches: input.forwardedSubject === undefined || input.forwardedSubject === input.trustedSubject,
    forwardedTenantMatches: input.forwardedTenant === undefined || input.forwardedTenant === input.trustedTenant,
    allowSameOriginRedirect: input.allowSameOriginRedirect === true,
    headers: input.headers ?? [],
    selectedExtensions: input.selectedExtensions ?? [],
    ...(input.rawInputUtf16CodeUnits === undefined ? {} : { rawInputUtf16CodeUnits: input.rawInputUtf16CodeUnits }),
  };
  return output;
}

function fingerprintInput(input, inputKind) {
  const base = { schemaVersion: "ogvcs.protocol/request-envelope/v1", operation: "repository.example/mutate@1", body: { value: 1 }, extensions: {} };
  const issuedAtUnixMs = input.keyIssuedAtUnixMs ?? 1_000;
  const expiresAtUnixMs = input.keyExpiresAtUnixMs ?? 1_100;
  const embeddedIssuedAtUnixMs = input.keyEmbeddedIssuedAtUnixMs ?? issuedAtUnixMs;
  const embeddedExpiresAtUnixMs = input.keyEmbeddedExpiresAtUnixMs ?? expiresAtUnixMs;
  const nonce = input.keyNonce ?? "A".repeat(22);
  let projections = [base];
  let rawInputs = [];
  let route = "fingerprint";
  let attempts = [0];
  if (input.leftRaw !== undefined) {
    rawInputs = [input.leftRaw, input.rightRaw];
    projections = [{ ...base, body: JSON.parse(input.leftRaw) }, { ...base, body: JSON.parse(input.rightRaw) }];
  }
  if (input.vary !== undefined) {
    const first = baselineRequest();
    const second = baselineRequest();
    if (input.vary === "correlationId") {
      first.correlationId = "correlation-first";
      second.correlationId = "correlation-second";
    } else if (input.vary === "deadlineUnixMs") {
      first.deadlineUnixMs = 2_001;
      second.deadlineUnixMs = 2_002;
    } else if (input.vary === "negotiationReceipt") {
      first.negotiationReceipt.mac = "A".repeat(43);
      second.negotiationReceipt.mac = "B".repeat(43);
    }
    rawInputs = [canonicalText(first), canonicalText(second)];
    projections = [structuredClone(base), structuredClone(base)];
  }
  if (input.extensionPayloads === true) {
    projections = [
      { ...base, extensions: { "ogvcs.extension.safe-optional@1": { value: 1 } } },
      { ...base, extensions: { "ogvcs.extension.safe-optional@1": { value: 2 } } },
    ];
  }
  if (input.attempts !== undefined || input.sameKey !== undefined || input.retryableMutation) {
    route = "idempotency";
    const changed = input.change === "operation"
      ? { ...base, operation: "repository.example/other@1" }
      : input.change === "schemaVersion"
        ? { ...base, schemaVersion: "ogvcs.protocol/request-envelope/v2" }
        : { ...base, body: { value: 2 } };
    projections = input.sameKey ? [base, changed] : [base];
    attempts = input.sameKey ? [0, 1] : [0, 0];
  }
  if (input.attemptProjectionIndexes !== undefined) attempts = structuredClone(input.attemptProjectionIndexes);
  if (input.projectionOmit !== undefined) delete projections[0][input.projectionOmit];
  if (input.projectionUnknownField === true) projections[0].unexpected = true;
  if (inputKind === "raw-json") rawInputs = [input.rawJson];
  return {
    route,
    projections,
    rawInputs,
    algorithm: input.algorithm ?? CONTRACT.fingerprintAlgorithm,
    idempotencyKey: input.key === null ? "" : `ik1.${embeddedIssuedAtUnixMs}.${embeddedExpiresAtUnixMs}.${nonce}`,
    retryableMutation: input.retryableMutation === false ? false : input.retryableMutation === true || route === "idempotency",
    attemptProjectionIndexes: attempts,
    attemptSchedule: input.attemptSchedule ?? (route === "idempotency" ? ["begin-mutation", "commit", "retry"] : ["fingerprint"]),
    idempotencyIssuedAtUnixMs: issuedAtUnixMs,
    idempotencyExpiresAtUnixMs: expiresAtUnixMs,
    atUnixMs: input.atUnixMs ?? issuedAtUnixMs,
    tombstoneRetentionMs: input.tombstoneRetentionMs ?? 1_000,
    attemptAuthorizationDecisions: input.attemptAuthorizationDecisions ?? attempts.map(() => "allow"),
  };
}

const CURSOR_SCOPE = Object.freeze({
  subject: "cursor-subject-0001",
  tenant: "cursor-tenant-00001",
  repository: "cursor-repository-1",
  operation: "cursor-operation-list",
  queryDigest: "3".repeat(64),
});
function cursorInput(input) {
  const issueScope = structuredClone(CURSOR_SCOPE);
  const readScope = structuredClone(CURSOR_SCOPE);
  if (input.scopeChange !== undefined) readScope[input.scopeChange] = input.scopeChange === "queryDigest" ? "4".repeat(64) : "foreign-scope-0001";
  if (input.issueScopeUnknownField === true) issueScope.unexpected = "not-permitted";
  if (input.readScopeMissingField !== undefined) delete readScope[input.readScopeMissingField];
  const page = input.state !== undefined || input.nextCursor !== undefined
    ? pageFor(input.state, input.pageItems ?? [], input.nextCursor === undefined ? undefined : "cursor-token-0001")
    : pageFor("complete");
  if (input.gapProblemCode !== undefined) page.problem = problemFor(input.gapProblemCode);
  return {
    route: input.state !== undefined || input.nextCursor !== undefined ? "validate-page" : "token-lifecycle",
    page,
    issueScope,
    readScope,
    issuedAtUnixMs: input.issuedAtUnixMs ?? 1_000,
    readAtUnixMs: input.readAtUnixMs ?? (input.expired ? 1_101 : 1_000),
    ttlMs: input.ttlMs ?? 100,
    generation: 3,
    minimumRetainedGeneration: input.retained === false ? 4 : 0,
    tokenMutation: input.tamper ? "tamper" : input.token === "unknown" ? "unknown" : "none",
    suppliedToken: input.suppliedToken ?? "",
    tokenSource: input.tokenOwnerExists === true || input.suppliedToken !== undefined ? "supplied" : "issued",
    lifecycleActions: input.lifecycleActions ?? ["issue", "read"],
    tombstoneRetentionMs: input.tombstoneRetentionMs ?? 1_000,
  };
}

function streamInput(input, inputKind) {
  const frames = (input.frames ?? []).map((frame) => {
    const { problemCode, ...publicFrame } = frame;
    return {
      schemaVersion: "ogvcs.protocol/stream-frame/v1",
      streamId: "fixture-stream-01",
      ...publicFrame,
      ...(frame.kind === "data" ? { payload: null } : {}),
      ...(frame.kind === "gap" ? { problem: problemFor(problemCode ?? "CURSOR_GAP", "correlation-0001", problemCode === undefined || problemCode === "CURSOR_GAP" ? [{ name: "gapClass", value: "retention-gap" }] : undefined) } : {}),
      ...(frame.kind === "error" ? { problem: problemFor("INTERNAL_ERROR") } : {}),
    };
  });
  if (frames.length > 0) {
    if (input.frameMutation === "missing-schema-version") delete frames[0].schemaVersion;
    if (input.frameMutation === "missing-kind") delete frames[0].kind;
    if (input.frameMutation === "missing-stream-id") delete frames[0].streamId;
    if (input.frameMutation === "unknown-field") frames[0].unexpected = true;
  }
  return {
    route: inputKind === "jsonl" ? "parse" : "write-roundtrip",
    encoding: inputKind === "jsonl" ? "jsonl" : "frames",
    frames,
    jsonl: input.line ?? "",
    sourceCloses: input.transportClose === true || input.eof === true || inputKind === "jsonl",
  };
}

export const AUTHORIZATION_CASE_DIGESTS = Object.freeze({
  "valid-download": "cd8840162f3ffe246089ea72ea5612143f218723018792dce45efac1627d81bc",
  "valid-request-root": "ba10a189e10ceae4b0433808b4dc1c0088e2f9038393603cff399ebc4d1209d3",
  "wrong-audience": "379a8da111b5f5b885bf22a05015350c3fb51535bc9198624576122cfcfe3b8d",
  expired: "9bad3d6e75e3728b420678c746da9369586f37a2cdc6bd1774beefe3f36ea346",
  replayed: "dd55e228e6a0f545dab5fff1237f8fbae479a2f6f8fdae7259a7fa853602b485",
  "stale-epoch": "b16edc758b5a1bf043982560b364b66841b91e7e384b04c4cee80bd113912840",
  "stale-key-generation": "66e5ff8c73b25a09112a840520fe60e2c0d85e58731163b84cf5c2964549e4d4",
  "stale-key-id": "f73155ae0d51b1b66d24693beceab83de4e141f167a3533989cf5ceec20f4881",
  "wrong-repository": "8eb53470cae60fcd886cd79d64e6b72ff9912a8f1c4eccaafe731e414f1add4f",
  "wrong-object": "9cc25baf75fe7395b8c25f244bdf310a1a9585e9c890073863d5998497d3dc73",
  "altered-claims": "2f9c1586c2e8c6e872e858f1b4c68bb24a0e1b1e1b0cee3e1ab48aa6b67d918a",
  "wrong-subject": "2c4ed0d874416c277bd625ede3cf0aea9e5e97afb574c20cc2792bb23b85926e",
  "wrong-issuer": "0e3e19005cece78e08db6f3566880d912f194a7e1002b25585cbb80a8ed52d99",
  "wrong-operation": "840553bc3f7f1acc1fd48c4c222287225745a567479e908e0d9b85d78f28bf25",
  "request-root-object-not-member": "85d55905c9ab691a0e57a143593bc72267a3955f6d9427503ad01fb91f1fdb0a",
  "wrong-request-root-plan": "eaa0a362dacc6c6ba3cd9bfaa0c7a225d62ae04c898a35fc71c521bfdf4ed8c9",
});
export const DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE = Object.freeze({
  schemaVersion: "ogvcs.authorization/transfer-grant/v1",
  algorithm: "Ed25519",
  keyId: "conformance-key-1",
  claims: Object.freeze({
    audience: "cache-maldives-1",
    authorityEpoch: 3,
    expiresAt: 2_000_000_300,
    issuedAt: 2_000_000_000,
    issuer: "control-primary",
    keyGeneration: 11,
    keyId: "conformance-key-1",
    nonce: "protocol-root-replay-0001",
    objectIds: Object.freeze([]),
    operation: "download",
    permission: "content.materialize",
    replay: "single-use",
    repository: "game-main",
    requestRoot: "sha256:d1d02a4b543b4e0989dc18d693f5500b3794f468def95ca1fe472b10cc5a7512",
    schemaVersion: "ogvcs.authorization/transfer-grant-claims/v1",
    subject: "outsourcer-bob",
    tenant: "tenant-alpha",
  }),
  signature: "dwQhUtlRIuClESl25Ir8Up5KIhFiLAjuudbnau8ns17qhRvd9Wvd8fGG6bfenIMTvtSYxW665kh9UjENjW-gCg",
});
const REQUEST_ROOT_AUTHORIZATION_DERIVATIONS = Object.freeze({
  "wrong-audience": Object.freeze({ contextFields: Object.freeze(["audience"]) }),
  expired: Object.freeze({ contextFields: Object.freeze(["now"]) }),
  replayed: Object.freeze({ envelopeMode: "fixed-replay", contextPatch: Object.freeze({ consumedNonces: Object.freeze([DERIVED_REQUEST_ROOT_REPLAY_ENVELOPE.claims.nonce]) }) }),
  "stale-epoch": Object.freeze({ contextFields: Object.freeze(["authorityEpoch"]) }),
  "stale-key-generation": Object.freeze({ contextFields: Object.freeze(["keyGeneration"]) }),
  "stale-key-id": Object.freeze({ contextFields: Object.freeze(["keyId"]) }),
  "wrong-repository": Object.freeze({ contextFields: Object.freeze(["repository"]) }),
  "altered-claims": Object.freeze({ envelopeMode: "bad-signature" }),
  "wrong-subject": Object.freeze({ contextFields: Object.freeze(["subject"]) }),
  "wrong-issuer": Object.freeze({ contextFields: Object.freeze(["issuer"]) }),
  "wrong-operation": Object.freeze({ contextFields: Object.freeze(["operation", "permission"]) }),
});
const generatedAuthorizationEnvelope = (caseId) => {
  const derivation = REQUEST_ROOT_AUTHORIZATION_DERIVATIONS[caseId];
  return `@generated:authorization-envelope:${derivation?.envelopeMode ?? (derivation === undefined ? "native" : "derived-context")}:${caseId}`;
};
const generatedAuthorizationContext = (caseId, patch = {}) => {
  const derivation = REQUEST_ROOT_AUTHORIZATION_DERIVATIONS[caseId];
  return {
    "@generated:authorization-context": caseId,
    baseCase: derivation === undefined ? caseId : "valid-request-root",
    contextFields: derivation?.contextFields ?? [],
    derivedPatch: derivation?.contextPatch ?? {},
    patch,
  };
};
const generatedAuthorizationPublicJwk = () => ({ "@generated:authorization-public-jwk": true });
function transferResultFixture(status, overrides = {}) {
  const state = {
    complete: { acceptedStart: 0, acceptedEndExclusive: 1_024, totalBytes: 1_024, terminal: true },
    partial: { acceptedStart: 0, acceptedEndExclusive: 512, totalBytes: 1_024, terminal: false },
    interrupted: { acceptedStart: 512, acceptedEndExclusive: 768, totalBytes: 1_024, terminal: false },
    rejected: { acceptedStart: 0, acceptedEndExclusive: 0, totalBytes: 1_024, terminal: false },
  }[status];
  const result = {
    schemaVersion: "ogvcs.protocol/transfer-probe-result/v1",
    status,
    ...state,
    validatorTag: "validator-000001",
    contentSha256: "0".repeat(64),
    ...(status === "rejected" ? { problem: problemFor("TRANSFER_RANGE_INVALID") } : {}),
    ...overrides,
  };
  if (overrides.omitProblem === true) delete result.problem;
  delete result.omitProblem;
  return result;
}

function transferInput(input) {
  const authorizationCaseId = input.authorizationCaseId ?? ({ audience: "wrong-audience", expiry: "expired", replay: "replayed", requestRoot: "request-root-object-not-member" }[input.grantFault] ?? "valid-request-root");
  const result = {
    route: input.resultStatus !== undefined ? "validate-result" : input.httpRange === true ? "http-range" : input.transportPolicy === true ? "transport-policy" : input.grantFault !== undefined || input.authorizationCaseId !== undefined || input.grantLocation !== undefined || input.logGrant === true ? "verify-grant" : "probe",
    probe: {
      schemaVersion: "ogvcs.protocol/transfer-probe/v1",
      operation: input.operation ?? "read",
      grant: {
        scheme: "OGVCS-Grant",
        representation: "request-root",
        explicitObjectCount: input.explicitObjectCount ?? 0,
        envelope: generatedAuthorizationEnvelope(authorizationCaseId),
        authorizationManifestSha256: PREDECESSORS.authorization.manifestSha256,
      },
      resourceTag: "resource-tag-0001",
      startOffset: input.startOffset ?? 0,
      ...(input.endOffsetExclusive === undefined ? {} : { endOffsetExclusive: input.endOffsetExclusive }),
      ...(input.strongValidator === undefined && input.resume === undefined && input.headerRoundTrip !== true ? {} : { validatorTag: input.strongValidator ?? "validator-000001" }),
      ...(input.expectedSha256 !== undefined
        ? { expectedSha256: input.expectedSha256 }
        : input.digestMatches === undefined && input.headerRoundTrip !== true
          ? {}
          : { expectedSha256: "0".repeat(64) }),
      contentEncoding: input.contentEncoding ?? "identity",
      followRedirects: false,
    },
    transportResponse: {
      rangeBytes: input.rangeBytes ?? Math.max(0, (input.endOffsetExclusive ?? input.startOffset ?? 0) - (input.startOffset ?? 0)),
      totalBytes: input.totalBytes ?? 1_024,
      ...(input.interruptedAt === undefined ? {} : { interruptedAt: input.interruptedAt, resumeAt: input.resumeAt, sameValidator: input.sameValidator }),
      ...(input.headerRoundTrip === true ? {
        etagHeader: input.etagHeader ?? "\"validator-000001\"",
        contentDigestHeader: input.contentDigestHeader ?? `sha-256=:${Buffer.alloc(32).toString("base64")}:`,
      } : {}),
    },
    grantLocation: input.grantLocation ?? "header",
    responseStatus: input.status ?? 200,
    originChanged: input.originChange === true,
    digestMatches: input.digestMatches !== false,
    logGrant: input.logGrant === true,
    proxyMode: input.proxyMode ?? "direct",
    proxyConfigured: input.proxyConfigured === true,
    connectResult: input.connectResult ?? "not-attempted",
    certificateValid: input.certificateValid !== false,
    hostnameMatches: input.hostnameMatches !== false,
    ...(input.resultStatus === undefined ? {} : { probeResult: transferResultFixture(input.resultStatus, input.resultOverrides) }),
    requestHeaders: input.requestHeaders ?? [],
    responseHeaders: input.responseHeaders ?? [],
    responseBodyHex: input.responseBodyHex ?? "",
    authorizationContext: generatedAuthorizationContext(authorizationCaseId, input.authorizationContextPatch),
    authorizationPublicJwk: generatedAuthorizationPublicJwk(),
  };
  if (input.omitProbeField !== undefined) delete result.probe[input.omitProbeField];
  return result;
}

function transferHttpCase(options = {}) {
  const start = options.start ?? 0;
  const endExclusive = options.endExclusive;
  const total = options.total ?? 1_024;
  const status = options.status ?? (options.range === false ? 200 : 206);
  const requestHeaders = [];
  if (options.range !== false) {
    const rangeValue = options.rangeValue ?? `bytes=${start}-${endExclusive === undefined ? "" : endExclusive - 1}`;
    requestHeaders.push({ name: options.rangeName ?? "range", value: rangeValue });
    if (options.duplicateRange === true) requestHeaders.push({ name: "RaNgE", value: rangeValue });
  }
  if (options.ifRange !== undefined) requestHeaders.push({ name: "if-range", value: options.ifRange });
  const responseHeaders = [];
  if (status === 206) {
    const inclusiveEnd = endExclusive === undefined ? total - 1 : endExclusive - 1;
    responseHeaders.push({ name: "content-range", value: options.contentRangeValue ?? `bytes ${start}-${inclusiveEnd}/${options.responseTotal ?? total}` });
    if (options.duplicateContentRange === true) responseHeaders.push({ name: "Content-Range", value: responseHeaders[0].value });
  } else if (status === 416) responseHeaders.push({ name: "content-range", value: options.contentRangeValue ?? `bytes */${options.responseTotal ?? total}` });
  const bodyLength = status === 416 ? 0 : status === 200 ? total : (endExclusive ?? total) - start;
  const responseBody = options.responseBodyHex === undefined
    ? Buffer.from(Array.from({ length: bodyLength }, (_unused, index) => (start + index) % 251))
    : Buffer.from(options.responseBodyHex, "hex");
  const bodyDigestHex = createHash("sha256").update(responseBody).digest("hex");
  const responseValidatorTag = options.responseEtag ?? `"${options.responseValidatorTag ?? "validator-000001"}"`;
  if (status === 200 || status === 206) {
    if (options.omitEtag !== true) {
      responseHeaders.push({ name: options.etagName ?? "etag", value: responseValidatorTag });
      if (options.duplicateEtag === true) responseHeaders.push({ name: "ETag", value: responseValidatorTag });
    }
    if (options.omitContentDigest !== true) {
      const digestHex = options.contentDigestSha256 ?? bodyDigestHex;
      const contentDigestValue = options.contentDigestValue ?? `sha-256=:${Buffer.from(digestHex, "hex").toString("base64")}:`;
      responseHeaders.push({ name: options.contentDigestName ?? "content-digest", value: contentDigestValue });
      if (options.duplicateContentDigest === true) responseHeaders.push({ name: "Content-Digest", value: contentDigestValue });
    }
  } else {
    if (options.contentDigestValue !== undefined) responseHeaders.push({ name: "content-digest", value: options.contentDigestValue });
    if (options.responseEtag !== undefined) responseHeaders.push({ name: "etag", value: options.responseEtag });
  }
  if (options.omitContentLength !== true) responseHeaders.push({ name: options.contentLengthName ?? "content-length", value: options.contentLengthValue ?? String(responseBody.length) });
  if (options.contentEncoding !== undefined) responseHeaders.push({ name: "content-encoding", value: options.contentEncoding });
  return {
    httpRange: true,
    startOffset: start,
    ...(endExclusive === undefined ? {} : { endOffsetExclusive: endExclusive }),
    ...(options.validatorTag === undefined ? {} : { strongValidator: options.validatorTag }),
    totalBytes: total,
    status,
    requestHeaders,
    responseHeaders,
    responseBodyHex: responseBody.toString("hex"),
    rangeBytes: responseBody.length,
    ...((status === 200 || status === 206) ? { expectedSha256: options.expectedSha256 ?? bodyDigestHex } : {}),
  };
}

function executableInput(operation, input, inputKind = "semantic-value") {
  switch (operation) {
    case "negotiate": return negotiationInput(input);
    case "validate-envelope": return envelopeInput(input, inputKind);
    case "fingerprint": return fingerprintInput(input, inputKind);
    case "validate-cursor": return cursorInput(input);
    case "validate-stream": return streamInput(input, inputKind);
    case "transfer-probe": return transferInput(input);
    case "contract-load": return input;
    case "runner-batch": return input;
    case "release-preflight": return releasePreflightInput(input);
    default: throw new Error(`unsupported scenario operation ${operation}`);
  }
}

const scenario = (id, category, operation, outcome, code, input, extra = {}) => ({
  id,
  category,
  operation,
  inputKind: extra.inputKind ?? "semantic-value",
  input: extra.executableInput === true ? input : executableInput(operation, input, extra.inputKind),
  control: controlFor(extra),
  expected: { result: outcome, code, preMutation: true, mutationCount: 0, ...extra.expected },
  requirementIds: extra.requirementIds ?? (category === "release" ? ["OGVCS-041-AC-05", outcome === "accept" ? "OGVCS-041-AC-01" : "OGVCS-041-AC-02"] : [outcome === "accept" ? "OGVCS-041-AC-01" : "OGVCS-041-AC-02"]),
  forbiddenResponseFields: extra.forbiddenResponseFields ?? (outcome === "accept" ? ["detail", "instance", "stack", "grant", "credential", "policy"] : ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId"]),
  ...(extra.configuredLimits ? { configuredLimits: extra.configuredLimits } : {}),
  ...(extra.resourceWitness ? { resourceWitness: extra.resourceWitness } : {}),
  ...(extra.hiddenMarkerValues ? { hiddenMarkerValues: extra.hiddenMarkerValues } : {}),
  ...(extra.hiddenServerInputs ? { hiddenServerInputs: extra.hiddenServerInputs } : {}),
  ...(extra.predecessorCase ? { predecessorCase: extra.predecessorCase } : {}),
});
const accept = (id, category, operation, input, extra = {}) => scenario(id, category, operation, "accept", "NONE", input, extra);
const reject = (id, category, operation, code, input, extra = {}) => scenario(id, category, operation, "reject", code, input, extra);
const kebab = (value) => value.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
const resourceOperation = (name) => {
  if (name.includes("Contract") || name.includes("Registry")) return "contract-load";
  if (name.includes("Runner")) return "runner-batch";
  if (name.includes("Jsonl")) return "validate-stream";
  if (name.includes("Cursor")) return "validate-cursor";
  if (name.includes("Transfer") || name.includes("Grant")) return "transfer-probe";
  if (name.includes("Idempotency") || name.includes("Canonical")) return "fingerprint";
  if (name.includes("Receipt") || name.includes("Capability")) return "negotiate";
  return "validate-envelope";
};

function canonicalText(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalText).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalText(value[key])}`).join(",")}}`;
}

const RELEASE_ADDITION_EXTENSION_IDS = new Set(["ogvcs.extension.release-probe@1"]);
export const RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN = "ogvcs.protocol/release-assignment-semantics/v1";
export const RELEASE_COMPATIBILITY_POLICY = "immutable-code-name-scope-semantics-no-removal-unique-registered-optional-candidate-additions";
const releasePolicy = (entry, excluded) => Object.fromEntries(Object.entries(entry).filter(([name]) => !excluded.includes(name)));
const releaseSemanticSha256 = (assignment, policy) => createHash("sha256")
  .update(`${RELEASE_ASSIGNMENT_SEMANTIC_DOMAIN}\0`, "utf8")
  .update(canonicalText({ ...assignment, policy }), "utf8")
  .digest("hex");
const releaseAssignment = (assignment, policy) => Object.freeze({
  ...assignment,
  semanticSha256: releaseSemanticSha256(assignment, policy),
});
const messageReleasePolicy = (message) => ({
  closed: true,
  constraints: message.constraints ?? [],
  reservedFields: message.reservedFields ?? [],
});
const fieldReleasePolicy = (message, entry, overrides = {}) => ({
  type: overrides.type ?? entry.type,
  required: overrides.required ?? entry.required,
  presence: (overrides.required ?? entry.required) ? "required" : "optional",
  fingerprint: overrides.fingerprint ?? entry.fingerprint,
  sensitive: overrides.sensitive ?? entry.sensitive,
  messageConstraints: message.constraints ?? [],
});
const extensionReleaseAssignment = (entry) => releaseAssignment(
  { kind: "extension", scope: "extension-registry", name: entry.id, code: entry.code },
  releasePolicy(entry, ["code", "id"]),
);
export const RELEASE_ASSIGNMENTS = Object.freeze([
  ...MESSAGES.map((message) => releaseAssignment(
    { kind: "message", scope: "protocol", name: message.name, code: message.code },
    messageReleasePolicy(message),
  )),
  ...MESSAGES.flatMap((message) => message.fields.map((entry) => releaseAssignment(
    { kind: "field", scope: message.name, name: entry.name, code: entry.id },
    fieldReleasePolicy(message, entry),
  ))),
  ...LIMITS.map((entry) => releaseAssignment(
    { kind: "limit", scope: "protocol", name: entry.name, code: entry.code },
    releasePolicy(entry, ["code", "name"]),
  )),
  ...ERROR_CODES.map((entry) => releaseAssignment(
    { kind: "error", scope: "protocol", name: entry.name, code: entry.code },
    {
      ...releasePolicy(entry, ["code", "name"]),
      parameterDomains: Object.fromEntries(entry.safeParameters.map((name) => [name, SAFE_PARAMETER_DOMAINS[name]])),
    },
  )),
  ...CAPABILITIES.map((entry) => releaseAssignment(
    { kind: "capability", scope: entry.axis, name: entry.id, code: entry.code },
    releasePolicy(entry, ["code", "id"]),
  )),
  ...REGISTRIES.extensions.filter((entry) => !RELEASE_ADDITION_EXTENSION_IDS.has(entry.id)).map(extensionReleaseAssignment),
].sort((left, right) => left.kind < right.kind ? -1 : left.kind > right.kind ? 1 : left.scope < right.scope ? -1 : left.scope > right.scope ? 1 : left.code - right.code || (left.name < right.name ? -1 : left.name > right.name ? 1 : 0)).map(Object.freeze));
export const RELEASE_ALLOWED_ADDITIONS = Object.freeze(REGISTRIES.extensions.filter((entry) => RELEASE_ADDITION_EXTENSION_IDS.has(entry.id)).map((entry) => Object.freeze({
  assignment: extensionReleaseAssignment(entry),
  registry: "extensions",
  state: entry.state,
  requirement: entry.requirement,
  major: 1,
})));
export const RELEASE_ASSIGNMENT_SNAPSHOT_SHA256 = createHash("sha256").update(canonicalText(RELEASE_ASSIGNMENTS), "utf8").digest("hex");
const HOSTILE_JSON_MEMBER_VALUE = JSON.parse('{"__proto__":{"preserved":1},"constructor":"constructor-value","prototype":["prototype-value"]}');
const HOSTILE_JSON_MEMBER_DIGEST = createHash("sha256").update(canonicalText(HOSTILE_JSON_MEMBER_VALUE), "utf8").digest("hex");

function releasePreflightInput(input = {}) {
  const proposedAssignments = RELEASE_ASSIGNMENTS.map((entry) => ({ ...entry }));
  const syntheticAssignment = (assignment, probe) => ({ ...assignment, semanticSha256: releaseSemanticSha256(assignment, { probe }) });
  if (input.assignmentMutation === "reuse-code") proposedAssignments.push(syntheticAssignment({ kind: "field", scope: "RequestEnvelope", name: "replacementField", code: 1 }, "reuse-code"));
  if (input.assignmentMutation === "reuse-name") proposedAssignments.push(syntheticAssignment({ kind: "field", scope: "RequestEnvelope", name: "operation", code: 65_535 }, "reuse-name"));
  if (input.assignmentMutation === "add-compatible") proposedAssignments.push({ ...RELEASE_ALLOWED_ADDITIONS[0].assignment });
  if (input.assignmentMutation === "new-code-collision") proposedAssignments.push(
    syntheticAssignment({ kind: "extension", scope: "extension-registry", name: "vendor.test/addition-a@1", code: 65_000 }, "new-code-collision-a"),
    syntheticAssignment({ kind: "extension", scope: "extension-registry", name: "vendor.test/addition-b@1", code: 65_000 }, "new-code-collision-b"),
  );
  if (input.assignmentMutation === "new-name-collision") proposedAssignments.push(
    syntheticAssignment({ kind: "extension", scope: "extension-registry", name: "vendor.test/addition@1", code: 65_000 }, "new-name-collision-a"),
    syntheticAssignment({ kind: "extension", scope: "extension-registry", name: "vendor.test/addition@1", code: 65_001 }, "new-name-collision-b"),
  );
  if (input.assignmentMutation === "remove-field") {
    const index = proposedAssignments.findIndex((entry) => entry.kind === "field" && entry.scope === "RequestEnvelope" && entry.name === "operation");
    proposedAssignments.splice(index, 1);
  }
  if (["field-type", "field-presence", "field-fingerprint", "field-sensitivity"].includes(input.assignmentMutation)) {
    const message = MESSAGES.find((entry) => entry.name === "RequestEnvelope");
    const fieldEntry = message.fields.find((entry) => entry.name === "operation");
    const index = proposedAssignments.findIndex((entry) => entry.kind === "field" && entry.scope === message.name && entry.name === fieldEntry.name);
    const assignment = { kind: "field", scope: message.name, name: fieldEntry.name, code: fieldEntry.id };
    const overrides = input.assignmentMutation === "field-type"
      ? { type: integer(0, 65_535) }
      : input.assignmentMutation === "field-presence"
        ? { required: false }
        : input.assignmentMutation === "field-fingerprint"
          ? { fingerprint: !fieldEntry.fingerprint }
          : { sensitive: !fieldEntry.sensitive };
    proposedAssignments[index].semanticSha256 = releaseSemanticSha256(assignment, fieldReleasePolicy(message, fieldEntry, overrides));
  }
  if (input.assignmentMutation === "limit-policy") {
    const limit = LIMITS.find((entry) => entry.name === "maxControlMessageBytes");
    const index = proposedAssignments.findIndex((entry) => entry.kind === "limit" && entry.name === limit.name);
    const assignment = { kind: "limit", scope: "protocol", name: limit.name, code: limit.code };
    proposedAssignments[index].semanticSha256 = releaseSemanticSha256(assignment, { ...releasePolicy(limit, ["code", "name"]), enforcement: "after-parse" });
  }
  if (input.assignmentMutation === "error-parameter-domain") {
    const error = ERROR_CODES.find((entry) => entry.name === "PROTOCOL_LIMIT_EXCEEDED");
    const index = proposedAssignments.findIndex((entry) => entry.kind === "error" && entry.name === error.name);
    const assignment = { kind: "error", scope: "protocol", name: error.name, code: error.code };
    const parameterDomains = Object.fromEntries(error.safeParameters.map((name) => [name, SAFE_PARAMETER_DOMAINS[name]]));
    parameterDomains.retryAfterMs = { ...parameterDomains.retryAfterMs, maximum: parameterDomains.retryAfterMs.maximum + 1 };
    proposedAssignments[index].semanticSha256 = releaseSemanticSha256(assignment, {
      ...releasePolicy(error, ["code", "name"]),
      parameterDomains,
    });
  }
  const proposedSelection = structuredClone(COMPATIBILITY[0].selection);
  proposedSelection.schemaVersion = "ogvcs.protocol/release-selection-proposal/v1";
  if (input.absentTuple === true) proposedSelection.protocolVersion = "evil.vendor/non-vector-axis@1";
  if (input.omitExtension === true) proposedSelection.extensions = proposedSelection.extensions.slice(0, -1);
  if (input.addExtension === true) proposedSelection.extensions.push("ogvcs.extension.response-only@1");
  if (input.reorderExtensions === true) proposedSelection.extensions.reverse();
  const requiredCapabilities = [...COMPATIBILITY[0].requiredCapabilities];
  if (input.omitRequired === true) requiredCapabilities.pop();
  if (input.addRequired === true) requiredCapabilities.push("ogvcs.extension.safe-optional@1");
  if (input.reorderRequired === true) requiredCapabilities.reverse();
  return {
    proposedSelection,
    requiredCapabilities: input.unknownRequired === true ? [...requiredCapabilities, "evil.required@1"] : requiredCapabilities,
    authorizationManifestSha256: input.predecessorDrift === "authorization" ? "f".repeat(64) : PREDECESSORS.authorization.manifestSha256,
    pathManifestSha256: input.predecessorDrift === "path" ? "f".repeat(64) : PREDECESSORS.path.manifestSha256,
    repositoryManifestSha256: input.predecessorDrift === "repository" ? "f".repeat(64) : PREDECESSORS.repository.manifestSha256,
    priorAssignmentSnapshotSha256: RELEASE_ASSIGNMENT_SNAPSHOT_SHA256,
    proposedAssignments,
  };
}

const utf8Bytes = (value) => Buffer.byteLength(value, "utf8");
const nestedArrays = (depth) => {
  let value = null;
  for (let index = 0; index < depth; index += 1) value = [value];
  return value;
};
const jsonObject = (members, keyPrefix = "k") => Object.fromEntries(Array.from({ length: members }, (_unused, index) => [`${keyPrefix}${index}`, null]));
const genericEnvelope = (value) => ({ ...envelopeInput({}, "semantic-value"), targetSchema: "JsonValue", document: value });
const rawGenericEnvelope = (rawInput) => ({ ...envelopeInput({}, "raw-json"), targetSchema: "JsonValue", encoding: "raw-json", rawInput });
const schemaValidationEnvelope = (targetSchema, document) => ({
  ...envelopeInput({}, "semantic-value"),
  targetSchema,
  document,
});
const streamFrame = (sequence, kind, payload = null) => ({
  schemaVersion: "ogvcs.protocol/stream-frame/v1",
  streamId: "fixture-stream-01",
  sequence,
  kind,
  ...(kind === "data" ? { payload } : {}),
});
const canonicalStream = (frames) => frames.map((frame) => `${canonicalText(frame)}\n`).join("");
export const GOLDEN_STREAM_FRAMES = Object.freeze([
  Object.freeze({ schemaVersion: "ogvcs.protocol/stream-frame/v1", streamId: "golden-stream-0001", sequence: 0, kind: "data", payload: Object.freeze({ value: "alpha" }) }),
  Object.freeze({ schemaVersion: "ogvcs.protocol/stream-frame/v1", streamId: "golden-stream-0001", sequence: 1, kind: "terminal" }),
]);
export const GOLDEN_STREAM_JSONL = canonicalStream(GOLDEN_STREAM_FRAMES);
const canonicalJsonBytesOfLength = (byteLength) => {
  if (byteLength === 1) return "0";
  if (!Number.isSafeInteger(byteLength) || byteLength < 2) throw new Error("canonical JSON artifact byte length is invalid");
  return JSON.stringify("a".repeat(byteLength - 2));
};
const artifactRows = (count, bytesPerArtifact = 1) => Array.from({ length: count }, (_unused, index) => ({ path: `artifact-${index}.json`, bytesHex: Buffer.from(canonicalJsonBytesOfLength(bytesPerArtifact), "utf8").toString("hex") }));
const runnerRows = (count) => Array.from({ length: count }, (_unused, index) => ({ id: `case-${String(index).padStart(4, "0")}`, operation: "validate-envelope" }));

function configuredResource(limit, over) {
  const relation = over ? "max-plus-one" : "max";
  const step = over ? 1 : 0;
  let operation = resourceOperation(limit.name);
  let inputKind = "semantic-value";
  let input;
  let configuredMaximum;
  let observed;
  let route;
  switch (limit.name) {
    case "maxControlMessageBytes": {
      configuredMaximum = 32;
      const raw = JSON.stringify("a".repeat(30 + step));
      observed = utf8Bytes(raw);
      input = rawGenericEnvelope(raw);
      inputKind = "raw-json";
      route = "control-parser-bytes";
      break;
    }
    case "maxCanonicalInputBytes": {
      configuredMaximum = 32;
      const raw = JSON.stringify("a".repeat(30 + step));
      observed = utf8Bytes(raw);
      input = fingerprintInput({ rawJson: raw }, "raw-json");
      inputKind = "raw-json";
      route = "semantic-fingerprint-canonical-input";
      break;
    }
    case "maxJsonDepth":
      configuredMaximum = 4;
      observed = 4 + step;
      input = genericEnvelope(nestedArrays(observed));
      route = "bounded-json-depth";
      break;
    case "maxJsonNodes":
      configuredMaximum = 16;
      observed = 16 + step;
      input = genericEnvelope(Array.from({ length: observed - 1 }, () => null));
      route = "bounded-json-node-count";
      break;
    case "maxObjectMembers":
      configuredMaximum = 4;
      observed = 4 + step;
      input = genericEnvelope(jsonObject(observed));
      route = "bounded-json-object-members";
      break;
    case "maxArrayItems":
      configuredMaximum = 4;
      observed = 4 + step;
      input = genericEnvelope(Array.from({ length: observed }, () => null));
      route = "bounded-json-array-items";
      break;
    case "maxStringUtf8Bytes":
      configuredMaximum = 16;
      observed = 16 + step;
      input = genericEnvelope("a".repeat(observed));
      route = "bounded-json-string-bytes";
      break;
    case "maxExtensionEntries": {
      configuredMaximum = 2;
      observed = 2 + step;
      const extensionIds = [
        "ogvcs.extension.safe-optional@1",
        "ogvcs.extension.audit-optional@1",
        "ogvcs.extension.count-probe@1",
      ].slice(0, observed);
      const request = baselineRequest();
      request.extensions = Object.fromEntries(extensionIds.map((id) => [id, null]));
      input = { ...envelopeInput({ selectedExtensions: extensionIds }, "semantic-value"), document: request };
      route = "request-extension-dispatch";
      break;
    }
    case "maxCapabilityItems": {
      configuredMaximum = 3;
      observed = 3 + step;
      input = negotiationInput({ protocolVersions: [CONTRACT.protocolVersion, ...Array.from({ length: observed - 1 }, (_unused, index) => `rogue.vendor/protocol@${index + 2}`)] });
      route = "negotiation-axis-count";
      break;
    }
    case "maxErrorParameters": {
      configuredMaximum = 0;
      observed = step;
      const parameters = Array.from({ length: observed }, () => ({ name: "retryAfterMs", value: "1" }));
      input = { ...envelopeInput({}, "semantic-value"), targetSchema: "ProblemDetails", document: problemFor("PROTOCOL_LIMIT_EXCEEDED", "correlation-0001", parameters) };
      route = "problem-parameter-count";
      break;
    }
    case "maxPageItems":
      configuredMaximum = 2;
      observed = 2 + step;
      input = { ...envelopeInput({}, "semantic-value"), targetSchema: "PageEnvelope", document: pageFor("complete", Array.from({ length: observed }, () => null)) };
      route = "page-item-count";
      break;
    case "maxJsonlFrameBytes": {
      const terminal = streamFrame(1, "terminal");
      const terminalBytes = utf8Bytes(canonicalText(terminal));
      const emptyDataBytes = utf8Bytes(canonicalText(streamFrame(0, "data", "")));
      const padding = Math.max(0, terminalBytes - emptyDataBytes);
      const maxFrames = [streamFrame(0, "data", "a".repeat(padding)), terminal];
      const plusFrames = [streamFrame(0, "data", "a".repeat(padding + 1)), terminal];
      configuredMaximum = Math.max(...canonicalStream(maxFrames).trimEnd().split("\n").map(utf8Bytes));
      const frames = over ? plusFrames : maxFrames;
      observed = Math.max(...canonicalStream(frames).trimEnd().split("\n").map(utf8Bytes));
      input = { ...streamInput({ line: canonicalStream(frames) }, "jsonl"), frames };
      inputKind = "jsonl";
      route = "canonical-jsonl-frame-parser";
      break;
    }
    case "maxJsonlFrames": {
      configuredMaximum = 3;
      observed = 3 + step;
      const frames = [...Array.from({ length: observed - 1 }, (_unused, index) => streamFrame(index, "data", null)), streamFrame(observed - 1, "terminal")];
      input = { ...streamInput({ line: canonicalStream(frames) }, "jsonl"), frames };
      inputKind = "jsonl";
      route = "canonical-jsonl-frame-count";
      break;
    }
    case "maxCursorBytes":
      input = { ...cursorInput({}), route: "validate-token", suppliedToken: `c1.${Buffer.alloc(32).toString("base64url")}`, tokenSource: "supplied" };
      observed = utf8Bytes(input.suppliedToken);
      configuredMaximum = observed - step;
      route = "opaque-cursor-byte-count";
      break;
    case "maxIdempotencyKeyBytes":
      input = fingerprintInput({ attempts: 2 }, "semantic-value");
      observed = utf8Bytes(input.idempotencyKey);
      configuredMaximum = observed - step;
      route = "idempotency-key-byte-count";
      break;
    case "maxReceiptBytes": {
      const negotiation = negotiationInput({});
      negotiation.principal.sessionId = "s".repeat(16 + step);
      negotiation.verificationPrincipal.sessionId = negotiation.principal.sessionId;
      const receipt = { ...structuredClone(BASELINE_RECEIPT), claims: { ...structuredClone(BASELINE_RECEIPT.claims), sessionId: negotiation.principal.sessionId } };
      observed = utf8Bytes(canonicalText(receipt));
      const baseReceipt = { ...structuredClone(BASELINE_RECEIPT), claims: { ...structuredClone(BASELINE_RECEIPT.claims), sessionId: "s".repeat(16) } };
      configuredMaximum = utf8Bytes(canonicalText(baseReceipt));
      input = negotiation;
      route = "negotiation-receipt-byte-count";
      break;
    }
    case "maxGrantBytes": {
      observed = VALID_REQUEST_ROOT_GRANT_BYTES;
      configuredMaximum = observed - step;
      input = transferInput({ authorizationCaseId: "valid-request-root" });
      route = "authorization-grant-byte-count";
      break;
    }
    case "maxTransferRangeBytes":
      configuredMaximum = 16;
      observed = 16 + step;
      input = transferInput({ startOffset: 0, endOffsetExclusive: observed, rangeBytes: observed });
      route = "transfer-range-preflight";
      break;
    case "maxHeaderBytes": {
      const valueLength = 16 + step;
      const header = { name: "x-test", value: "h".repeat(valueLength) };
      observed = utf8Bytes(header.name) + 2 + utf8Bytes(header.value) + 2;
      configuredMaximum = utf8Bytes(header.name) + 2 + 16 + 2;
      input = { ...envelopeInput({ headers: [header] }, "semantic-value"), headers: [header] };
      route = "http-header-block";
      break;
    }
    case "maxCorrelationIdBytes": {
      configuredMaximum = 16;
      observed = 16 + step;
      const request = baselineRequest();
      request.correlationId = "c".repeat(observed);
      input = { ...envelopeInput({}, "semantic-value"), document: request };
      route = "request-correlation-id";
      break;
    }
    case "maxOperationBytes": {
      configuredMaximum = 32;
      observed = 32 + step;
      const request = baselineRequest();
      request.operation = `operation.${"a".repeat(observed - 10)}`;
      input = { ...envelopeInput({}, "semantic-value"), document: request };
      route = "request-operation-id";
      break;
    }
    case "maxRunnerCases":
      operation = "runner-batch";
      configuredMaximum = 3;
      observed = 3 + step;
      input = { cases: runnerRows(observed) };
      route = "runner-case-collection";
      break;
    case "maxSafeParameterBytes": {
      const value = "generation-changed";
      observed = utf8Bytes(value);
      configuredMaximum = observed - step;
      input = { ...envelopeInput({}, "semantic-value"), targetSchema: "ProblemDetails", document: problemFor("CURSOR_GAP", "correlation-0001", [{ name: "gapClass", value }]) };
      route = "safe-problem-parameter-bytes";
      break;
    }
    case "maxDeadlineHorizonMs": {
      configuredMaximum = 1_000;
      observed = 1_000 + step;
      const request = baselineRequest();
      request.deadlineUnixMs = 2_000 + observed;
      input = { ...envelopeInput({}, "semantic-value"), document: request, atUnixMs: 2_000 };
      route = "request-deadline-horizon";
      break;
    }
    case "maxReceiptLifetimeMs":
      configuredMaximum = 1_000;
      observed = 1_000 + step;
      input = negotiationInput({ receiptLifetimeMs: observed });
      route = "negotiation-receipt-lifetime";
      break;
    case "maxCursorLifetimeMs":
      configuredMaximum = 1_000;
      observed = 1_000 + step;
      input = { ...cursorInput({}), ttlMs: observed };
      route = "cursor-issue-lifetime";
      break;
    case "maxRegistryEntries":
      operation = "contract-load";
      configuredMaximum = 3;
      observed = 3 + step;
      input = { route: "registry", artifacts: [], registryEntries: Array.from({ length: observed }, (_unused, index) => ({ code: index + 1, id: `entry-${index}` })) };
      route = "contract-registry-entry-count";
      break;
    case "maxJsonKeyUtf8Bytes": {
      configuredMaximum = 16;
      observed = 16 + step;
      input = genericEnvelope({ ["k".repeat(observed)]: null });
      route = "bounded-json-key-bytes";
      break;
    }
    case "maxJsonCollectionItems":
      configuredMaximum = 8;
      observed = 8 + step;
      input = genericEnvelope(Array.from({ length: observed }, () => null));
      route = "bounded-json-aggregate-items";
      break;
    case "maxJsonlStreamBytes": {
      const maxFrames = [streamFrame(0, "data", "s".repeat(8)), streamFrame(1, "terminal")];
      const plusFrames = [streamFrame(0, "data", "s".repeat(9)), streamFrame(1, "terminal")];
      const maxJsonl = canonicalStream(maxFrames);
      const jsonl = canonicalStream(over ? plusFrames : maxFrames);
      configuredMaximum = utf8Bytes(maxJsonl);
      observed = utf8Bytes(jsonl);
      input = { ...streamInput({ line: jsonl }, "jsonl"), frames: over ? plusFrames : maxFrames };
      inputKind = "jsonl";
      route = "canonical-jsonl-stream-bytes";
      break;
    }
    case "maxWorkingMemoryBytes": {
      const raw = JSON.stringify("m".repeat(30 + step));
      observed = 128 + (4 * utf8Bytes(raw));
      configuredMaximum = over ? observed - 1 : observed;
      input = rawGenericEnvelope(raw);
      inputKind = "raw-json";
      route = "bounded-json-working-reservation";
      break;
    }
    case "maxOperationTimeMs":
      configuredMaximum = 4;
      observed = 3 + step;
      input = genericEnvelope(null);
      route = "shared-operation-deadline";
      break;
    case "maxSchemaEvaluationSteps":
      observed = 2;
      configuredMaximum = observed - step;
      input = genericEnvelope(null);
      route = "json-schema-evaluation-steps";
      break;
    case "maxContractArtifacts":
      operation = "contract-load";
      configuredMaximum = 3;
      observed = 3 + step;
      input = { route: "inventory", artifacts: artifactRows(observed), registryEntries: [] };
      route = "contract-inventory-count";
      break;
    case "maxContractBytes":
      operation = "contract-load";
      configuredMaximum = 256;
      observed = 256 + step;
      input = { route: "inventory", artifacts: artifactRows(1, observed), registryEntries: [] };
      route = "contract-asset-stream-bytes";
      break;
    default:
      throw new Error(`missing configured resource constructor for ${limit.name}`);
  }
  return {
    operation,
    inputKind,
    input,
    control: limit.name === "maxOperationTimeMs" ? { cancellation: "none", clockSamplesUnixMs: [0, observed] } : { cancellation: "none", clockSamplesUnixMs: [1_000] },
    configuredLimits: { [limit.name]: configuredMaximum },
    resourceWitness: { limit: limit.name, route, configuredMaximum, observed, relation, ...(limit.name === "maxCapabilityItems" ? { axis: "protocolVersions" } : {}) },
  };
}

const CAPABILITY_AXES = Object.freeze(["protocolVersions", "schemaVersions", "repositoryFormats", "authorizationContracts", "pathContracts", "pathProfiles", "eventVersions", "transferProfiles", "extensions", "requiredCapabilities"]);

function configuredCapabilityAxisOverflow(axis) {
  const configuredMaximum = 3;
  const observed = configuredMaximum + 1;
  const baseline = [...BASELINE_AXES[axis]];
  const entries = baseline.slice(0, configuredMaximum);
  while (entries.length < observed) entries.push(`vendor.test/${kebab(axis)}-${entries.length}@1`);
  const input = axis === "requiredCapabilities"
    ? negotiationInput({ requiredCapabilities: entries })
    : negotiationInput({ [axis]: entries });
  return {
    operation: "negotiate",
    inputKind: "semantic-value",
    input,
    control: { cancellation: "none", clockSamplesUnixMs: [1_000] },
    configuredLimits: { maxCapabilityItems: configuredMaximum },
    resourceWitness: { limit: "maxCapabilityItems", route: "negotiation-axis-count", configuredMaximum, observed, relation: "max-plus-one", axis },
  };
}

function configuredTransferRangeAsymmetry(dimension) {
  const configuredMaximum = 16;
  const requested = dimension === "request" ? configuredMaximum + 1 : configuredMaximum;
  const response = dimension === "response" ? configuredMaximum + 1 : configuredMaximum;
  return {
    operation: "transfer-probe",
    inputKind: "semantic-value",
    input: transferInput({ startOffset: 0, endOffsetExclusive: requested, rangeBytes: response }),
    control: { cancellation: "none", clockSamplesUnixMs: [1_000] },
    configuredLimits: { maxTransferRangeBytes: configuredMaximum },
    resourceWitness: { limit: "maxTransferRangeBytes", route: "transfer-range-preflight", configuredMaximum, observed: configuredMaximum + 1, relation: "max-plus-one", dimension },
  };
}

function resourceScenarios() {
  const pairs = LIMITS.flatMap((limit) => [false, true].map((over) => {
    const executable = configuredResource(limit, over);
    const extra = {
      inputKind: executable.inputKind,
      executableInput: true,
      configuredLimits: executable.configuredLimits,
      resourceWitness: executable.resourceWitness,
      control: executable.control,
      requirementIds: ["OGVCS-041-NFR-02"],
    };
    return over
      ? reject(`resource-${kebab(limit.name)}-max-plus-one`, "resources", executable.operation, "PROTOCOL_LIMIT_EXCEEDED", executable.input, extra)
      : accept(`resource-${kebab(limit.name)}-max`, "resources", executable.operation, executable.input, extra);
  }));
  const axisOverflows = CAPABILITY_AXES.filter((axis) => axis !== "protocolVersions").map((axis) => {
    const executable = configuredCapabilityAxisOverflow(axis);
    return reject(`resource-max-capability-items-max-plus-one-${kebab(axis)}`, "resources", "negotiate", "PROTOCOL_LIMIT_EXCEEDED", executable.input, {
      inputKind: executable.inputKind,
      executableInput: true,
      configuredLimits: executable.configuredLimits,
      resourceWitness: executable.resourceWitness,
      control: executable.control,
      requirementIds: ["OGVCS-041-NFR-02"],
    });
  });
  const asymmetricTransferRanges = ["request", "response"].map((dimension) => {
    const executable = configuredTransferRangeAsymmetry(dimension);
    return reject(`resource-max-transfer-range-bytes-${dimension}-max-plus-one-asymmetric`, "resources", "transfer-probe", "PROTOCOL_LIMIT_EXCEEDED", executable.input, {
      inputKind: executable.inputKind,
      executableInput: true,
      configuredLimits: executable.configuredLimits,
      resourceWitness: executable.resourceWitness,
      control: executable.control,
      requirementIds: ["OGVCS-041-NFR-02"],
    });
  });
  return [...pairs, ...axisOverflows, ...asymmetricTransferRanges];
}

const grantPredecessor = (caseId, applicability = "derived-request-root-context") => ({
  contract: PREDECESSORS.authorization.contract,
  manifestSha256: PREDECESSORS.authorization.manifestSha256,
  vectorPath: "vectors/grants.json",
  vectorSha256: AUTHORIZATION_GRANT_VECTOR_SHA256,
  caseId,
  caseSha256: AUTHORIZATION_CASE_DIGESTS[caseId],
  applicability,
});
const grantSecurityExtra = (caseId, marker, applicability) => ({
  requirementIds: ["OGVCS-041-FR-07", "OGVCS-041-AC-04"],
  predecessorCase: grantPredecessor(caseId, applicability),
  hiddenMarkerValues: [marker],
  hiddenServerInputs: { authorizationDiagnostic: marker },
  forbiddenResponseFields: ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "requestRoot", "subject", "tenant", "repository", "operation", "audience", "authorityEpoch", "keyId", "signature"],
});
const grantIntegrationExtra = (caseId, applicability) => ({
  requirementIds: ["OGVCS-041-FR-07"],
  predecessorCase: grantPredecessor(caseId, applicability),
});

export const SCENARIOS = Object.freeze([
  accept("negotiation-exact-baseline", "negotiation", "negotiate", { mode: "exact-baseline" }),
  accept("negotiation-unknown-optional-extension", "negotiation", "negotiate", { extension: "example.vendor/opaque@1", required: false }),
  accept("negotiation-required-safe-extension-selected", "negotiation", "negotiate", { extensions: ["ogvcs.extension.safe-optional@1"], requiredExtension: "ogvcs.extension.safe-optional@1" }),
  reject("negotiation-required-safe-extension-not-offered", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { requiredExtension: "ogvcs.extension.safe-optional@1" }),
  accept("negotiation-extension-selection-deterministic", "negotiation", "negotiate", { extensions: ["ogvcs.extension.audit-optional@1", "ogvcs.extension.safe-optional@1"] }),
  accept("negotiation-independent-axis-order", "negotiation", "negotiate", { reorderAxes: true, expectedSelection: "baseline" }),
  accept("negotiation-auth-before-repository", "negotiation", "negotiate", { authenticatePrincipalFirst: true }),
  reject("negotiation-cleartext-loopback-rejected", "negotiation", "negotiate", "NEGOTIATION_DOWNGRADE_REJECTED", { transport: "http", loopbackConformance: true }),
  reject("negotiation-no-protocol", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { protocolVersions: ["rogue.vendor/protocol@7"] }),
  reject("negotiation-no-schema", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { schemaVersions: ["other.vendor/schema@9"] }),
  reject("negotiation-no-repository-format", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { repositoryFormats: ["alien.vendor/repository@9"] }),
  reject("negotiation-no-authorization-contract", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { authorizationContracts: ["untrusted.vendor/authorization@9"] }),
  reject("negotiation-no-path-contract", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { pathContracts: ["foreign.vendor/path@9"] }),
  reject("negotiation-no-path-profile", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { pathProfiles: ["foreign.vendor/path-profile@9"] }),
  reject("negotiation-no-event-version", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { eventVersions: ["unseen.vendor/events@9"] }),
  reject("negotiation-no-transfer-profile", "negotiation", "negotiate", "NEGOTIATION_NO_COMMON_VERSION", { transferProfiles: ["unknown.vendor/transfer@9"] }),
  reject("negotiation-unknown-required", "negotiation", "negotiate", "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN", { requiredCapabilities: ["evil.required@1"] }),
  reject("negotiation-stripped-client-minimum", "negotiation", "negotiate", "NEGOTIATION_DOWNGRADE_REJECTED", { stripClientMinimum: true }),
  reject("negotiation-receipt-mac", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { mutateReceiptMac: true }),
  reject("negotiation-receipt-expired", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_EXPIRED", { receiptAgeMs: 300_001 }),
  reject("negotiation-server-nonce-noncanonical-base64url", "negotiation", "negotiate", "PROTOCOL_MALFORMED", { serverNonce: "CQkJCQkJCQkJCQkJCQkJCR" }),
  accept("negotiation-server-nonce-max-64-bytes", "negotiation", "negotiate", { serverNonce: Buffer.alloc(64, 9).toString("base64url") }),
  reject("negotiation-server-nonce-max-plus-one-65-bytes", "negotiation", "negotiate", "PROTOCOL_MALFORMED", { serverNonce: Buffer.alloc(65, 9).toString("base64url") }),
  reject("negotiation-receipt-expired-invalid-mac", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { receiptAgeMs: 300_001, mutateReceiptMac: true }),
  reject("negotiation-receipt-foreign-subject", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { changeSubjectAfterIssue: true }),
  reject("negotiation-receipt-foreign-tenant", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { changeTenantAfterIssue: true }),
  reject("negotiation-receipt-foreign-session", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { changeSessionAfterIssue: true }),
  reject("negotiation-receipt-epoch", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { changeAuthorityEpochAfterIssue: true }),
  reject("negotiation-receipt-different-selection", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { changeSelectionAfterIssue: true }),
  reject("negotiation-leak-protected-path", "negotiation", "negotiate", "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN", { requiredCapabilities: ["evil.required@1"] }, { requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["NEGOTIATION_PATH_MARKER_private/project/041"], hiddenServerInputs: { protectedPath: "NEGOTIATION_PATH_MARKER_private/project/041" } }),
  reject("negotiation-leak-protected-object", "negotiation", "negotiate", "NEGOTIATION_RECEIPT_INVALID", { mutateReceiptMac: true }, { requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["NEGOTIATION_OBJECT_MARKER_secret_041"], hiddenServerInputs: { protectedObjectId: "NEGOTIATION_OBJECT_MARKER_secret_041" } }),
  reject("negotiation-leak-policy-context", "negotiation", "negotiate", "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN", { requiredCapabilities: ["evil.required@1"] }, { requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["NEGOTIATION_POLICY_MARKER_deny_041"], hiddenServerInputs: { policyText: "NEGOTIATION_POLICY_MARKER_deny_041" } }),

  accept("release-preflight-current-candidate", "release", "release-preflight", {}),
  reject("release-preflight-unknown-required", "release", "release-preflight", "NEGOTIATION_REQUIRED_CAPABILITY_UNKNOWN", { unknownRequired: true }),
  reject("release-preflight-omitted-required", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { omitRequired: true }),
  reject("release-preflight-extra-required", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { addRequired: true }),
  accept("release-preflight-reordered-required-set", "release", "release-preflight", { reorderRequired: true }),
  reject("release-preflight-extension-omission", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { omitExtension: true }),
  reject("release-preflight-extension-addition", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { addExtension: true }),
  accept("release-preflight-extension-reorder", "release", "release-preflight", { reorderExtensions: true }),
  reject("release-preflight-absent-tuple", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { absentTuple: true }),
  reject("release-preflight-authorization-drift", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { predecessorDrift: "authorization" }),
  reject("release-preflight-path-drift", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { predecessorDrift: "path" }),
  reject("release-preflight-repository-drift", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { predecessorDrift: "repository" }),
  reject("release-preflight-field-code-reuse", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "reuse-code" }),
  reject("release-preflight-field-name-reuse", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "reuse-name" }),
  reject("release-preflight-field-removal", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "remove-field" }),
  reject("release-preflight-field-type-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "field-type" }),
  reject("release-preflight-field-presence-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "field-presence" }),
  reject("release-preflight-field-fingerprint-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "field-fingerprint" }),
  reject("release-preflight-field-sensitivity-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "field-sensitivity" }),
  reject("release-preflight-limit-policy-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "limit-policy" }),
  reject("release-preflight-error-parameter-domain-change", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "error-parameter-domain" }),
  accept("release-preflight-unique-optional-addition", "release", "release-preflight", { assignmentMutation: "add-compatible" }),
  reject("release-preflight-new-code-collision", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "new-code-collision" }),
  reject("release-preflight-new-name-collision", "release", "release-preflight", "PROTOCOL_UNSUPPORTED", { assignmentMutation: "new-name-collision" }),

  accept("envelope-canonical-request", "envelopes", "validate-envelope", { canonical: true, success: true }),
  accept("envelope-noncanonical-member-order", "envelopes", "validate-envelope", { canonical: false, duplicateKeys: false, semantic: "same" }),
  accept("envelope-safe-problem", "envelopes", "validate-envelope", { problemCode: "AUTHORIZATION_DENIED", fields: ["type", "title", "status", "code", "retryable", "correlationId"] }),
  accept("envelope-retry-after-match", "envelopes", "validate-envelope", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "86400000", headers: [{ name: "retry-after", value: "86400" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-01"] }),
  reject("envelope-retry-after-missing", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "1500", headers: [] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  reject("envelope-retry-after-mismatch", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "1500", headers: [{ name: "retry-after", value: "1" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  reject("envelope-retry-after-duplicate-case-folded", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "1500", headers: [{ name: "retry-after", value: "2" }, { name: "Retry-After", value: "2" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  reject("envelope-retry-after-malformed", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "1500", headers: [{ name: "retry-after", value: "02" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  reject("envelope-retry-after-http-date", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", retryAfterMs: "1500", headers: [{ name: "retry-after", value: "Sun, 06 Nov 1994 08:49:37 GMT" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  reject("envelope-retry-after-without-safe-parameter", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "PROTOCOL_LIMIT_EXCEEDED", headers: [{ name: "retry-after", value: "1" }] }, { requirementIds: ["OGVCS-041-FR-04", "OGVCS-041-AC-02"] }),
  accept("envelope-hostile-json-member-names-canonical", "envelopes", "validate-envelope", rawGenericEnvelope('{"__proto__":{"preserved":1},"constructor":"constructor-value","prototype":["prototype-value"]}'), { executableInput: true, inputKind: "raw-json", expected: { semanticDigest: HOSTILE_JSON_MEMBER_DIGEST } }),
  accept("envelope-hostile-json-member-names-reordered", "envelopes", "validate-envelope", rawGenericEnvelope('{"prototype":["prototype-value"],"constructor":"constructor-value","__proto__":{"preserved":1}}'), { executableInput: true, inputKind: "raw-json", expected: { semanticDigest: HOSTILE_JSON_MEMBER_DIGEST } }),
  accept("envelope-extension-selected-optional", "envelopes", "validate-envelope", { extensionPayloadId: "ogvcs.extension.safe-optional@1", selectedExtensions: ["ogvcs.extension.safe-optional@1"] }),
  reject("envelope-extension-unregistered", "envelopes", "validate-envelope", "PROTOCOL_UNSUPPORTED", { extensionPayloadId: "vendor.evil/payload@1", selectedExtensions: ["vendor.evil/payload@1"] }),
  reject("envelope-extension-unselected", "envelopes", "validate-envelope", "PROTOCOL_UNSUPPORTED", { extensionPayloadId: "ogvcs.extension.safe-optional@1", selectedExtensions: [] }),
  reject("envelope-extension-deprecated", "envelopes", "validate-envelope", "PROTOCOL_UNSUPPORTED", { extensionPayloadId: "ogvcs.extension.legacy-optional@1", selectedExtensions: ["ogvcs.extension.legacy-optional@1"] }),
  reject("envelope-extension-reserved", "envelopes", "validate-envelope", "PROTOCOL_UNSUPPORTED", { extensionPayloadId: "ogvcs.extension.reserved@1", selectedExtensions: ["ogvcs.extension.reserved@1"] }),
  reject("envelope-extension-wrong-affected-schema", "envelopes", "validate-envelope", "PROTOCOL_UNSUPPORTED", { extensionPayloadId: "ogvcs.extension.response-only@1", selectedExtensions: ["ogvcs.extension.response-only@1"] }),
  reject("envelope-unknown-member", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { unknownMember: "future" }),
  reject("envelope-duplicate-key", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "{\"body\":{},\"body\":{}}" }, { inputKind: "raw-json" }),
  reject("envelope-invalid-utf8", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { bytesHex: "c0af" }, { inputKind: "raw-bytes" }),
  reject("envelope-lone-surrogate", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "{\"body\":\"\\ud800\"}" }, { inputKind: "raw-json" }),
  reject("envelope-literal-unpaired-surrogate-code-unit", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "", rawInputUtf16CodeUnits: [0xd800] }, { inputKind: "raw-json" }),
  reject("envelope-unsafe-integer", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { integer: "9007199254740992" }, { inputKind: "raw-json" }),
  reject("envelope-nonfinite-number", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "{\"body\":NaN}" }, { inputKind: "raw-json" }),
  reject("envelope-problem-detail", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problem: { detail: "secret" } }),
  reject("envelope-problem-instance", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { problem: { instance: "https://internal/object/secret" } }),
  reject("envelope-problem-status-mismatch", "envelopes", "validate-envelope", "PROTOCOL_MALFORMED", { httpStatus: 404, bodyStatus: 403 }),
  reject("envelope-deadline-past", "envelopes", "validate-envelope", "DEADLINE_EXCEEDED", { deadline: "past" }),
  reject("envelope-hard-default-operation-time-expired", "envelopes", "validate-envelope", "DEADLINE_EXCEEDED", {}, {
    control: { cancellation: "none", clockSamplesUnixMs: [0, LIMITS.find((entry) => entry.name === "maxOperationTimeMs").value] },
  }),
  reject("envelope-compression", "envelopes", "validate-envelope", "COMPRESSION_FORBIDDEN", { contentEncoding: "gzip" }),
  reject("envelope-mutation-redirect", "envelopes", "validate-envelope", "REDIRECT_FORBIDDEN", { method: "POST", status: 307 }),
  reject("envelope-read-redirect-default-deny", "envelopes", "validate-envelope", "REDIRECT_FORBIDDEN", { method: "GET", status: 302, originChange: false, allowSameOriginRedirect: false }),
  accept("envelope-read-redirect-same-origin-allowed", "envelopes", "validate-envelope", { method: "GET", status: 302, originChange: false, allowSameOriginRedirect: true }),
  reject("envelope-pre-cancelled", "envelopes", "validate-envelope", "CANCELLED", { canonical: true }, {
    control: { cancellation: "before-operation", clockSamplesUnixMs: [1_000] },
  }),

  accept("idempotency-semantic-reordered", "idempotency", "fingerprint", { leftRaw: "{\"b\":2,\"a\":1}", rightRaw: "{\"a\":1,\"b\":2}", equal: true }),
  accept("idempotency-extension-payload-participates", "idempotency", "fingerprint", { extensionPayloads: true }),
  accept("idempotency-response-loss-replay", "idempotency", "fingerprint", { commitCount: 1, attempts: 2, sameOutcome: true, attemptSchedule: ["begin-mutation", "commit", "lose-response", "retry"] }, {
    expected: { preMutation: false, mutationCount: 1 },
  }),
  reject("idempotency-response-loss-replay-authorization-revoked", "idempotency", "fingerprint", "AUTHORIZATION_DENIED", {
    attempts: 2,
    attemptSchedule: ["begin-mutation", "commit", "lose-response", "retry"],
    attemptAuthorizationDecisions: ["allow", "deny"],
  }, {
    expected: { preMutation: false, mutationCount: 1 },
    requirementIds: ["OGVCS-041-AC-02", "OGVCS-041-AC-04"],
    hiddenMarkerValues: ["IDEMPOTENCY_STORED_OUTCOME_MARKER_041"],
    hiddenServerInputs: { committedOutcome: { confidential: "IDEMPOTENCY_STORED_OUTCOME_MARKER_041" } },
    forbiddenResponseFields: ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "storedOutcome", "committedOutcome"],
  }),
  reject("idempotency-timeout-late-commit-reconcile", "idempotency", "fingerprint", "DEADLINE_EXCEEDED", { attempts: 2, attemptSchedule: ["begin-mutation", "deadline", "commit", "retry"] }, {
    expected: { preMutation: false, mutationCount: 1 },
  }),
  reject("idempotency-after-retention-same-key-requires-new-key", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REQUIRED", {
    attempts: 2,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 1_100,
    atUnixMs: 2_101,
    tombstoneRetentionMs: 1_000,
    attemptSchedule: ["begin-mutation", "commit", "expire-key", "retire-tombstone", "retry"],
  }, {
    control: { cancellation: "none", clockSamplesUnixMs: [1_000, 1_100, 2_101] },
    expected: { preMutation: false, mutationCount: 1 },
  }),
  reject("idempotency-future-issued-key-requires-new-key", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REQUIRED", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_001,
    keyExpiresAtUnixMs: 1_101,
    atUnixMs: 1_000,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  accept("idempotency-retry-only-unused-key-first-execution", "idempotency", "fingerprint", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_001,
    keyExpiresAtUnixMs: 1_101,
    atUnixMs: 1_001,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
    attemptAuthorizationDecisions: ["allow"],
  }, {
    expected: { preMutation: false, mutationCount: 1 },
  }),
  accept("idempotency-zero-tombstone-retention-first-execution", "idempotency", "fingerprint", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_001,
    keyExpiresAtUnixMs: 1_101,
    atUnixMs: 1_001,
    tombstoneRetentionMs: 0,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
    attemptAuthorizationDecisions: ["allow"],
  }, {
    expected: { preMutation: false, mutationCount: 1 },
  }),
  reject("idempotency-already-expired-key-requires-new-key", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REQUIRED", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 1_100,
    atUnixMs: 1_100,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  reject("idempotency-key-issued-at-field-mismatch", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_000,
    keyEmbeddedIssuedAtUnixMs: 999,
    keyExpiresAtUnixMs: 1_100,
    atUnixMs: 1_000,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  reject("idempotency-key-expires-at-field-mismatch", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 1_100,
    keyEmbeddedExpiresAtUnixMs: 1_101,
    atUnixMs: 1_000,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  reject("idempotency-initial-authorization-denied", "idempotency", "fingerprint", "AUTHORIZATION_DENIED", {
    retryableMutation: true,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["begin-mutation"],
    attemptAuthorizationDecisions: ["deny"],
  }),
  reject("idempotency-attempt-projection-index-out-of-range", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    attemptProjectionIndexes: [1],
    attemptSchedule: ["retry"],
    attemptAuthorizationDecisions: ["allow"],
  }),
  reject("idempotency-projection-missing-schema-version", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    projectionOmit: "schemaVersion",
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  reject("idempotency-projection-unknown-field", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    projectionUnknownField: true,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  reject("idempotency-route-retryable-required", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    attempts: 1,
    retryableMutation: false,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  accept("idempotency-max-lifetime-replay", "idempotency", "fingerprint", {
    attempts: 2,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 86_401_000,
    atUnixMs: 1_000,
  }, {
    expected: { preMutation: false, mutationCount: 1 },
  }),
  reject("idempotency-lifetime-too-long", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", {
    retryableMutation: true,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 86_401_001,
    atUnixMs: 1_000,
    attemptProjectionIndexes: [0],
    attemptSchedule: ["retry"],
  }),
  accept("idempotency-retention-before-expiry-replay", "idempotency", "fingerprint", {
    attempts: 2,
    keyIssuedAtUnixMs: 1_000,
    keyExpiresAtUnixMs: 1_100,
    atUnixMs: 1_050,
    tombstoneRetentionMs: 10,
    attemptSchedule: ["begin-mutation", "commit", "retire-tombstone", "retry"],
  }, {
    control: { cancellation: "none", clockSamplesUnixMs: [1_000, 1_011, 1_050] },
    expected: { preMutation: false, mutationCount: 1 },
  }),
  accept("idempotency-excludes-correlation", "idempotency", "fingerprint", { vary: "correlationId", equal: true }),
  accept("idempotency-excludes-deadline", "idempotency", "fingerprint", { vary: "deadlineUnixMs", equal: true }),
  accept("idempotency-excludes-receipt", "idempotency", "fingerprint", { vary: "negotiationReceipt", equal: true }),
  reject("idempotency-key-required", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", { retryableMutation: true, key: null }),
  reject("idempotency-key-reuse-body", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REUSE", { sameKey: true, change: "body" }),
  reject("idempotency-key-reuse-operation", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REUSE", { sameKey: true, change: "operation" }),
  reject("idempotency-key-reuse-schema-version", "idempotency", "fingerprint", "IDEMPOTENCY_KEY_REUSE", { sameKey: true, change: "schemaVersion" }),
  reject("idempotency-raw-byte-fingerprint", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", { algorithm: "RAW-SHA-256" }),
  reject("idempotency-duplicate-before-fingerprint", "idempotency", "fingerprint", "PROTOCOL_MALFORMED", { rawJson: "{\"x\":1,\"x\":1}" }, { inputKind: "raw-json" }),

  accept("cursor-more-explicit", "cursors", "validate-cursor", { pageItems: [], state: "more", nextCursor: "opaque" }),
  accept("cursor-complete-explicit", "cursors", "validate-cursor", { pageItems: [], state: "complete" }),
  accept("cursor-gap-explicit", "cursors", "validate-cursor", { pageItems: [], state: "gap" }),
  reject("cursor-gap-wrong-problem-code", "cursors", "validate-cursor", "PROTOCOL_MALFORMED", { pageItems: [], state: "gap", gapProblemCode: "AUTHORIZATION_DENIED" }),
  reject("cursor-scope-unknown-field", "cursors", "validate-cursor", "PROTOCOL_MALFORMED", { issueScopeUnknownField: true }),
  reject("cursor-scope-missing-operation", "cursors", "validate-cursor", "PROTOCOL_MALFORMED", { readScopeMissingField: "operation" }),
  reject("cursor-issued-at-max-expiry-overflow", "cursors", "validate-cursor", "PROTOCOL_MALFORMED", { issuedAtUnixMs: Number.MAX_SAFE_INTEGER, readAtUnixMs: Number.MAX_SAFE_INTEGER, ttlMs: 1 }),
  reject("cursor-tampered", "cursors", "validate-cursor", "CURSOR_INVALID", { tamper: true }),
  reject("cursor-unknown", "cursors", "validate-cursor", "CURSOR_INVALID", { token: "unknown" }),
  reject("cursor-expired", "cursors", "validate-cursor", "CURSOR_EXPIRED", { expired: true }),
  reject("cursor-expired-after-unrelated-prune", "cursors", "validate-cursor", "CURSOR_EXPIRED", { expired: true, lifecycleActions: ["issue", "expire", "issue-unrelated", "prune", "read"], tombstoneRetentionMs: 1_000 }),
  reject("cursor-wrong-subject", "cursors", "validate-cursor", "CURSOR_SCOPE_MISMATCH", { scopeChange: "subject" }),
  reject("cursor-wrong-tenant", "cursors", "validate-cursor", "CURSOR_SCOPE_MISMATCH", { scopeChange: "tenant" }),
  reject("cursor-wrong-repository", "cursors", "validate-cursor", "CURSOR_SCOPE_MISMATCH", { scopeChange: "repository" }),
  reject("cursor-wrong-operation", "cursors", "validate-cursor", "CURSOR_SCOPE_MISMATCH", { scopeChange: "operation" }, {
    forbiddenResponseFields: ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "operation", "issueScope", "readScope"],
  }),
  reject("cursor-wrong-query", "cursors", "validate-cursor", "CURSOR_SCOPE_MISMATCH", { scopeChange: "queryDigest" }),
  reject("cursor-generation-gap", "cursors", "validate-cursor", "CURSOR_GAP", { retained: false }),
  reject("cursor-empty-page-not-completion", "cursors", "validate-cursor", "PROTOCOL_MALFORMED", { pageItems: [], state: null }),

  accept("stream-data-terminal", "streams", "validate-stream", { frames: [{ sequence: 0, kind: "data" }, { sequence: 1, kind: "terminal" }] }),
  accept("stream-golden-jsonl-byte-exact", "streams", "validate-stream", {
    ...streamInput({ line: GOLDEN_STREAM_JSONL }, "jsonl"),
    frames: structuredClone(GOLDEN_STREAM_FRAMES),
  }, { inputKind: "jsonl", executableInput: true, requirementIds: ["OGVCS-041-FR-10", "OGVCS-041-AC-02"] }),
  accept("stream-explicit-gap", "streams", "validate-stream", { frames: [{ sequence: 0, kind: "gap" }] }),
  reject("stream-gap-wrong-problem-code", "streams", "validate-stream", "PROTOCOL_MALFORMED", { frames: [{ sequence: 0, kind: "gap", problemCode: "AUTHORIZATION_DENIED" }] }),
  reject("stream-frame-missing-schema-version", "streams", "validate-stream", "PROTOCOL_MALFORMED", { frames: [{ sequence: 0, kind: "terminal" }], frameMutation: "missing-schema-version" }),
  reject("stream-frame-missing-kind", "streams", "validate-stream", "PROTOCOL_MALFORMED", { frames: [{ sequence: 0, kind: "terminal" }], frameMutation: "missing-kind" }),
  reject("stream-frame-missing-stream-id", "streams", "validate-stream", "PROTOCOL_MALFORMED", { frames: [{ sequence: 0, kind: "terminal" }], frameMutation: "missing-stream-id" }),
  reject("stream-frame-unknown-field", "streams", "validate-stream", "PROTOCOL_MALFORMED", { frames: [{ sequence: 0, kind: "terminal" }], frameMutation: "unknown-field" }),
  accept("stream-explicit-cancel", "streams", "validate-stream", { frames: [{ sequence: 0, kind: "cancelled" }] }),
  reject("stream-eof-without-terminal", "streams", "validate-stream", "STREAM_INCOMPLETE", { frames: [{ sequence: 0, kind: "data" }], eof: true }),
  reject("stream-duplicate-sequence", "streams", "validate-stream", "STREAM_SEQUENCE_INVALID", { frames: [{ sequence: 0, kind: "data" }, { sequence: 0, kind: "terminal" }] }),
  reject("stream-skipped-sequence", "streams", "validate-stream", "STREAM_SEQUENCE_INVALID", { frames: [{ sequence: 0, kind: "data" }, { sequence: 2, kind: "terminal" }] }),
  reject("stream-frame-after-terminal", "streams", "validate-stream", "STREAM_SEQUENCE_INVALID", { frames: [{ sequence: 0, kind: "terminal" }, { sequence: 1, kind: "data" }] }),
  reject("stream-two-terminals", "streams", "validate-stream", "STREAM_SEQUENCE_INVALID", { frames: [{ sequence: 0, kind: "terminal" }, { sequence: 1, kind: "terminal" }] }),
  reject("stream-transport-close-not-terminal", "streams", "validate-stream", "STREAM_INCOMPLETE", { frames: [], transportClose: true }),
  reject("stream-empty-eof-incomplete", "streams", "validate-stream", "STREAM_INCOMPLETE", { line: "" }, { inputKind: "jsonl" }),
  reject("stream-mid-frame-eof-incomplete", "streams", "validate-stream", "STREAM_INCOMPLETE", { line: "{\"schemaVersion\":\"ogvcs.protocol/stream-frame/v1\",\"streamId\":\"fixture-stream-01\"" }, { inputKind: "jsonl" }),
  reject("stream-noncanonical-line", "streams", "validate-stream", "PROTOCOL_MALFORMED", { line: "{ \"kind\":\"terminal\" }\n" }, { inputKind: "jsonl" }),
  reject("stream-cancelled-mid-flight", "streams", "validate-stream", "CANCELLED", { frames: [{ sequence: 0, kind: "data" }, { sequence: 1, kind: "terminal" }] }, {
    control: { cancellation: "after-first-stream-frame", clockSamplesUnixMs: [1_000, 1_001] },
  }),

  accept("transfer-full-probe", "transfer", "transfer-probe", { startOffset: 0, endOffsetExclusive: 1024, terminal: true, contentEncoding: "identity" }),
  accept("transfer-resume-strong-validator", "transfer", "transfer-probe", { startOffset: 512, endOffsetExclusive: 1024, strongValidator: "validator-000001", terminal: true }),
  reject("transfer-resume-without-validator", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", { startOffset: 512, endOffsetExclusive: 1_024 }),
  accept("transfer-interrupted-retry", "transfer", "transfer-probe", { interruptedAt: 512, resumeAt: 512, sameValidator: true }),
  accept("transfer-http-validator-digest-roundtrip", "transfer", "transfer-probe", { headerRoundTrip: true }),
  accept("transfer-http-no-range-200", "transfer", "transfer-probe", transferHttpCase({ range: false, start: 0, endExclusive: 1_024 })),
  accept("transfer-http-no-range-open-end-200", "transfer", "transfer-probe", transferHttpCase({ range: false, start: 0 })),
  accept("transfer-http-range-roundtrip-206", "transfer", "transfer-probe", transferHttpCase({ start: 100, endExclusive: 200 })),
  accept("transfer-http-range-open-end-206", "transfer", "transfer-probe", transferHttpCase({ start: 512 })),
  accept("transfer-http-resume-if-range-strong", "transfer", "transfer-probe", transferHttpCase({ start: 512, endExclusive: 1_024, validatorTag: "validator-000001", ifRange: "\"validator-000001\"", responseEtag: "\"validator-000001\"" })),
  reject("transfer-http-content-digest-missing", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, omitContentDigest: true })),
  reject("transfer-http-content-digest-malformed-present", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, contentDigestValue: "definitely-not-rfc9530" })),
  reject("transfer-http-content-digest-duplicate-case-folded", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, duplicateContentDigest: true })),
  reject("transfer-http-content-digest-body-mismatch", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", transferHttpCase({ start: 100, endExclusive: 200, contentDigestSha256: "0".repeat(64) })),
  reject("transfer-http-content-digest-expected-mismatch", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", transferHttpCase({ start: 100, endExclusive: 200, expectedSha256: "0".repeat(64) })),
  reject("transfer-http-etag-missing", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, omitEtag: true })),
  reject("transfer-http-etag-weak", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, responseEtag: "W/\"validator-000001\"" })),
  reject("transfer-http-etag-malformed", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, responseEtag: "validator-000001" })),
  reject("transfer-http-etag-duplicate-case-folded", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, duplicateEtag: true })),
  reject("transfer-http-etag-resume-mismatch", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", transferHttpCase({ start: 512, endExclusive: 1_024, validatorTag: "validator-000001", ifRange: "\"validator-000001\"", responseEtag: "\"validator-000002\"" })),
  reject("transfer-http-unsatisfied-range-416", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 2_048, status: 416 })),
  reject("transfer-http-unsatisfied-content-digest-forbidden", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 2_048, status: 416, contentDigestValue: `sha-256=:${Buffer.alloc(32).toString("base64")}:` })),
  reject("transfer-http-unsatisfied-etag-forbidden", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 2_048, status: 416, responseEtag: "\"validator-000001\"" })),
  reject("transfer-http-range-request-off-by-one", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 100, endExclusive: 200, rangeValue: "bytes=100-200" })),
  reject("transfer-http-content-range-off-by-one", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 100, endExclusive: 200, contentRangeValue: "bytes 100-200/1024" })),
  reject("transfer-http-content-range-total-mismatch", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 100, endExclusive: 200, responseTotal: 1_025 })),
  reject("transfer-http-if-range-weak", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", transferHttpCase({ start: 512, endExclusive: 1_024, validatorTag: "validator-000001", ifRange: "W/\"validator-000001\"", responseEtag: "\"validator-000001\"" })),
  reject("transfer-http-if-range-mismatch", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", transferHttpCase({ start: 512, endExclusive: 1_024, validatorTag: "validator-000001", ifRange: "\"validator-000002\"", responseEtag: "\"validator-000001\"" })),
  reject("transfer-http-range-malformed", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, rangeValue: "bytes=100" })),
  reject("transfer-http-range-duplicate-case-folded", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, duplicateRange: true })),
  reject("transfer-http-content-range-duplicate-case-folded", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, duplicateContentRange: true })),
  reject("transfer-http-content-length-missing", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, omitContentLength: true })),
  reject("transfer-http-content-length-mismatch", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 100, endExclusive: 200, contentLengthValue: "99" })),
  reject("transfer-http-negative-total-bytes", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 0, endExclusive: 1, total: -1, responseTotal: 1 })),
  reject("transfer-http-unsupported-status-without-validators", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", transferHttpCase({ start: 100, endExclusive: 200, status: 201 })),
  reject("transfer-http-range-response-200", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ start: 100, endExclusive: 200, status: 200 })),
  reject("transfer-http-no-range-response-206", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", transferHttpCase({ range: false, start: 0, endExclusive: 1_024, status: 206 })),
  reject("transfer-http-response-compression", "transfer", "transfer-probe", "COMPRESSION_FORBIDDEN", transferHttpCase({ start: 100, endExclusive: 200, contentEncoding: "br" })),
  accept("transfer-result-complete", "transfer", "transfer-probe", { resultStatus: "complete" }),
  accept("transfer-result-partial", "transfer", "transfer-probe", { resultStatus: "partial" }),
  accept("transfer-result-interrupted", "transfer", "transfer-probe", { resultStatus: "interrupted" }),
  accept("transfer-result-interrupted-zero-progress", "transfer", "transfer-probe", { resultStatus: "interrupted", resultOverrides: { acceptedStart: 512, acceptedEndExclusive: 512 } }),
  accept("transfer-result-rejected", "transfer", "transfer-probe", { resultStatus: "rejected" }),
  accept("transfer-authz-valid-request-root", "transfer", "transfer-probe", { authorizationCaseId: "valid-request-root" }, grantIntegrationExtra("valid-request-root", "native-request-root")),
  accept("transport-proxy-connect", "transfer", "transfer-probe", { transportPolicy: true, proxyMode: "connect", proxyConfigured: true, connectResult: "success" }),
  reject("transfer-invalid-range-order", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", { startOffset: 10, endOffsetExclusive: 9 }),
  reject("transfer-malformed-non-grant-before-invalid-grant", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { omitProbeField: "resourceTag", explicitObjectCount: 1 }),
  reject("transfer-invalid-range-before-invalid-grant", "transfer", "transfer-probe", "TRANSFER_RANGE_INVALID", { startOffset: 10, endOffsetExclusive: 9, explicitObjectCount: 1 }),
  reject("transfer-range-too-large", "transfer", "transfer-probe", "PROTOCOL_LIMIT_EXCEEDED", { rangeBytes: 1_073_741_825 }),
  reject("transfer-validator-changed", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", { resume: true, sameValidator: false }),
  reject("transfer-result-range-reversed", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "partial", resultOverrides: { acceptedStart: 600, acceptedEndExclusive: 500 } }),
  reject("transfer-result-end-past-total", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "partial", resultOverrides: { acceptedEndExclusive: 1_025 } }),
  reject("transfer-result-complete-nonterminal", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "complete", resultOverrides: { terminal: false } }),
  reject("transfer-result-complete-before-total", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "complete", resultOverrides: { acceptedEndExclusive: 1_023 } }),
  reject("transfer-result-partial-terminal", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "partial", resultOverrides: { terminal: true } }),
  reject("transfer-result-partial-at-total", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "partial", resultOverrides: { acceptedEndExclusive: 1_024 } }),
  reject("transfer-result-interrupted-at-total", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "interrupted", resultOverrides: { acceptedEndExclusive: 1_024 } }),
  reject("transfer-result-rejected-without-problem", "transfer", "transfer-probe", "PROTOCOL_MALFORMED", { resultStatus: "rejected", resultOverrides: { omitProblem: true } }),
  reject("transfer-grant-query", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { grantLocation: "query" }),
  reject("transfer-grant-explicit-object-count-negative", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { explicitObjectCount: -1 }),
  reject("transfer-explicit-object-list", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { explicitObjectCount: 1 }),
  reject("transfer-configured-grant-bytes-then-malformed-shape", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { explicitObjectCount: 1 }, {
    configuredLimits: { maxGrantBytes: VALID_REQUEST_ROOT_GRANT_BYTES },
  }),
  reject("transfer-grant-explicit-object-count-max-safe", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { explicitObjectCount: Number.MAX_SAFE_INTEGER }),
  reject("transfer-grant-wrong-audience", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { grantFault: "audience" }),
  reject("transfer-grant-wrong-root", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { grantFault: "requestRoot" }),
  reject("transfer-grant-expired", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { grantFault: "expiry" }, grantSecurityExtra("expired", "AUTHZ_MARKER_expired_041")),
  reject("transfer-grant-replay", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { grantFault: "replay" }),
  reject("transfer-authz-wrong-subject", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-subject" }, grantSecurityExtra("wrong-subject", "AUTHZ_MARKER_wrong_subject_041")),
  reject("transfer-authz-wrong-tenant", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "valid-request-root", authorizationContextPatch: { tenant: "tenant-private-041" } }, grantSecurityExtra("valid-request-root", "AUTHZ_MARKER_wrong_tenant_041")),
  reject("transfer-authz-wrong-repository", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-repository" }, grantSecurityExtra("wrong-repository", "AUTHZ_MARKER_wrong_repository_041")),
  reject("transfer-authz-wrong-operation", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-operation" }, grantSecurityExtra("wrong-operation", "AUTHZ_MARKER_wrong_operation_041")),
  reject("transfer-authz-wrong-permission", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "valid-request-root", authorizationContextPatch: { permission: "content.inspect" } }, grantSecurityExtra("valid-request-root", "AUTHZ_MARKER_permission_041", "derived-request-root-context")),
  reject("transfer-authz-wrong-audience", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-audience" }, grantSecurityExtra("wrong-audience", "AUTHZ_MARKER_wrong_audience_041")),
  reject("transfer-authz-stale-epoch", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "stale-epoch" }, grantSecurityExtra("stale-epoch", "AUTHZ_MARKER_stale_epoch_041")),
  reject("transfer-authz-stale-key-generation", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "stale-key-generation" }, grantSecurityExtra("stale-key-generation", "AUTHZ_MARKER_stale_key_generation_041")),
  reject("transfer-authz-unknown-key", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "stale-key-id" }, grantSecurityExtra("stale-key-id", "AUTHZ_MARKER_unknown_key_041")),
  reject("transfer-authz-wrong-issuer", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-issuer" }, grantSecurityExtra("wrong-issuer", "AUTHZ_MARKER_wrong_issuer_041")),
  reject("transfer-authz-bad-signature", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "altered-claims" }, grantSecurityExtra("altered-claims", "AUTHZ_MARKER_bad_signature_041")),
  reject("transfer-authz-request-root-replay", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "replayed" }, grantSecurityExtra("replayed", "AUTHZ_MARKER_request_root_replay_041")),
  reject("transfer-authz-request-root-membership", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "request-root-object-not-member" }, grantSecurityExtra("request-root-object-not-member", "AUTHZ_MARKER_request_root_membership_041", "native-request-root")),
  reject("transfer-authz-wrong-request-root-plan", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-request-root-plan" }, grantSecurityExtra("wrong-request-root-plan", "AUTHZ_MARKER_wrong_request_root_plan_041", "native-request-root")),
  reject("transfer-authz-explicit-valid-download-excluded", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "valid-download" }, grantIntegrationExtra("valid-download", "excluded-explicit-object-carrier")),
  reject("transfer-authz-explicit-wrong-object-excluded", "transfer", "transfer-probe", "TRANSFER_GRANT_INVALID", { authorizationCaseId: "wrong-object" }, grantIntegrationExtra("wrong-object", "excluded-explicit-object-carrier")),
  reject("transport-proxy-connect-failure", "transfer", "transfer-probe", "PROTOCOL_UNSUPPORTED", { transportPolicy: true, proxyMode: "connect", proxyConfigured: true, connectResult: "failure" }),
  reject("transport-proxy-bypass-forbidden", "transfer", "transfer-probe", "PROTOCOL_UNSUPPORTED", { transportPolicy: true, proxyMode: "direct", proxyConfigured: true, connectResult: "bypassed" }),
  reject("transport-certificate-invalid", "transfer", "transfer-probe", "PROTOCOL_UNSUPPORTED", { transportPolicy: true, certificateValid: false }),
  reject("transport-hostname-mismatch", "transfer", "transfer-probe", "PROTOCOL_UNSUPPORTED", { transportPolicy: true, hostnameMatches: false }),
  reject("transfer-compression", "transfer", "transfer-probe", "COMPRESSION_FORBIDDEN", { contentEncoding: "br" }),
  reject("transfer-redirect-mutation", "transfer", "transfer-probe", "REDIRECT_FORBIDDEN", { operation: "write", status: 307 }),
  reject("transfer-digest-mismatch", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", { digestMatches: false }),
  reject("transfer-http-etag-unquoted", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", { headerRoundTrip: true, etagHeader: "validator-000001" }),
  reject("transfer-http-content-digest-malformed", "transfer", "transfer-probe", "TRANSFER_VALIDATOR_MISMATCH", { headerRoundTrip: true, contentDigestHeader: `sha-256=${"0".repeat(64)}` }),

  reject("malformed-empty-input", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { bytesHex: "" }, { inputKind: "raw-bytes" }),
  reject("malformed-trailing-json", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "{}{}" }, { inputKind: "raw-json" }),
  reject("malformed-array-root", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "[]" }, { inputKind: "raw-json" }),
  reject("malformed-null-root", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { rawJson: "null" }, { inputKind: "raw-json" }),
  reject("malformed-missing-required", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { omit: "operation" }),
  reject("malformed-wrong-type", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { field: "operation", value: 7 }),
  reject("malformed-empty-operation", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { field: "operation", value: "" }),
  reject("malformed-receipt-mac-shape", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { field: "mac", value: "!" }),
  reject("malformed-problem-code", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", { problemCode: "INTERNAL_SECRET" }),
  reject("malformed-decreasing-clock-samples", "malformed", "validate-envelope", "PROTOCOL_MALFORMED", {}, {
    control: { cancellation: "none", clockSamplesUnixMs: [1_001, 1_000] },
  }),
  reject("malformed-negotiation-zero-receipt-lifetime", "malformed", "validate-envelope", "PROTOCOL_MALFORMED",
    schemaValidationEnvelope("NegotiationCaseInput", { ...negotiationInput({}), receiptLifetimeMs: 0 }),
    { executableInput: true }),
  reject("malformed-cursor-zero-ttl", "malformed", "validate-envelope", "PROTOCOL_MALFORMED",
    schemaValidationEnvelope("CursorCaseInput", { ...cursorInput({}), ttlMs: 0 }),
    { executableInput: true }),
  reject("malformed-negative-offset", "malformed", "transfer-probe", "PROTOCOL_MALFORMED", { startOffset: -1 }),

  ...resourceScenarios(),

  reject("security-protected-path-error", "security", "validate-envelope", "AUTHORIZATION_DENIED", { fault: "protected-path" }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["private/project/hidden.asset"], hiddenServerInputs: { protectedPath: "private/project/hidden.asset" },
  }),
  reject("security-protected-object-error", "security", "validate-envelope", "AUTHORIZATION_DENIED", { fault: "protected-object" }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: [`ogvcs:v1:chunk:sha256:${"d".repeat(64)}`], hiddenServerInputs: { protectedObjectId: `ogvcs:v1:chunk:sha256:${"d".repeat(64)}` },
  }),
  reject("security-policy-text-error", "security", "validate-envelope", "AUTHORIZATION_DENIED", { fault: "policy" }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["POLICY_MARKER_restricted-outsourcer-deny"], hiddenServerInputs: { policyText: "POLICY_MARKER_restricted-outsourcer-deny" },
  }),
  reject("security-stack-error", "security", "validate-envelope", "INTERNAL_ERROR", { fault: "throw" }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["STACK_MARKER_InternalPolicyFrame_041"], hiddenServerInputs: { stack: "STACK_MARKER_InternalPolicyFrame_041" },
  }),
  reject("security-hidden-cardinality-error", "security", "validate-envelope", "AUTHORIZATION_DENIED", { fault: "protected-cardinality" }, {
    requirementIds: ["OGVCS-041-AC-04"],
    hiddenMarkerValues: ["987654321", "1975308642"],
    hiddenServerInputs: { protectedCardinality: 987654321, derivedCardinalityCanary: "1975308642" },
    forbiddenResponseFields: ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "count", "cardinality", "totalCount", "protectedCardinality", "derivedCardinalityCanary"],
  }),
  reject("security-forwarded-subject", "security", "validate-envelope", "AUTHORIZATION_DENIED", { trustedSubject: "A", forwardedSubject: "B" }),
  reject("security-forwarded-tenant", "security", "validate-envelope", "AUTHORIZATION_DENIED", { trustedTenant: "A", forwardedTenant: "B" }),
  reject("security-cleartext-downgrade", "security", "negotiate", "NEGOTIATION_DOWNGRADE_REJECTED", { transport: "http", loopbackConformance: false }),
  reject("security-tls12-downgrade", "security", "negotiate", "NEGOTIATION_DOWNGRADE_REJECTED", { tls: "1.2" }),
  reject("security-receipt-is-not-authorization", "security", "validate-envelope", "AUTHORIZATION_DENIED", { receiptValid: true, authorizationGrant: false }),
  reject("security-cursor-oracle", "security", "validate-cursor", "CURSOR_INVALID", { tokenOwnerExists: true, discloseExistence: false }),
  reject("security-grant-log-redaction", "security", "transfer-probe", "TRANSFER_GRANT_INVALID", { logGrant: true }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["GRANT_MARKER_request_root_secret_041"], hiddenServerInputs: { grant: "GRANT_MARKER_request_root_secret_041" },
  }),
  reject("security-gap-parameter-redaction", "security", "validate-cursor", "CURSOR_GAP", { retained: false }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["GAP_MARKER_private/path/041"], hiddenServerInputs: { attemptedParameter: { name: "gapClass", value: "GAP_MARKER_private/path/041" } },
  }),
  reject("security-retry-parameter-redaction", "security", "validate-envelope", "INTERNAL_ERROR", { fault: "throw" }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["RETRY_MARKER_policy-secret_041"], hiddenServerInputs: { attemptedParameter: { name: "retryAfterMs", value: "RETRY_MARKER_policy-secret_041" } },
  }),
  reject("security-generation-parameter-excluded", "security", "validate-cursor", "CURSOR_GAP", { retained: false }, {
    requirementIds: ["OGVCS-041-AC-04"], hiddenMarkerValues: ["GENERATION_MARKER_hidden_041"], hiddenServerInputs: { attemptedParameter: { name: "currentGeneration", value: "GENERATION_MARKER_hidden_041" } },
    forbiddenResponseFields: ["detail", "instance", "stack", "grant", "credential", "policy", "protectedPath", "objectId", "currentGeneration"],
  }),
  reject("security-cross-origin-redirect", "security", "validate-envelope", "REDIRECT_FORBIDDEN", { method: "GET", originChange: true, explicitPolicy: false }),
  reject("security-cross-origin-redirect-policy-cannot-widen", "security", "validate-envelope", "REDIRECT_FORBIDDEN", { method: "GET", status: 302, originChange: true, allowSameOriginRedirect: true }),
]);

export const DOCS = Object.freeze([
  ["transport.md", "Transport and framing", `## Production profile

The baseline control profile is TLS 1.3 over HTTP/1.1. A production client
validates the peer certificate and hostname, refuses cleartext and older TLS,
and never silently substitutes HTTP/2, HTTP/3, gRPC, protobuf, or another
framing profile. Negotiation and every mutation-capable operation require HTTPS
over TLS 1.3. The loopbackConformance flag never authorizes cleartext
negotiation: HTTP fails before selection or receipt issuance. Any cleartext
loopback allowance is confined to the non-production EnvelopeCaseInput harness
and cannot produce negotiation or release evidence. Proxies use an explicit
CONNECT configuration; forwarding headers never establish origin, subject,
tenant, repository, or authorization.

Control bodies are duplicate-free bounded I-JSON. A receiver limits declared
and actual bytes before allocation, validates UTF-8 and duplicate members,
checks depth/nodes/collections while parsing, validates the closed schema, and
only then performs semantics. Producers emit RFC 8785 bytes. Receivers may
accept a noncanonical member order, but never hash the received bytes as the
semantic request. Content coding is identity; compressed control input is
rejected rather than decompressed.

## Redirects and streams

Mutations, grant-bearing requests, and requests with idempotency keys never
follow redirects. Read-only redirects require an explicit same-origin policy.
Each JSONL line is one bounded RFC 8785 StreamFrame followed by LF. Sequence
starts at zero and increases by one. Exactly one terminal, gap, cancelled, or
error frame ends the stream; data after it is invalid. EOF, timeout, proxy
closure, and an empty final read without such a frame are incomplete, never
success.`],
  ["negotiation.md", "Negotiation and receipts", `## Independent selection

The server authenticates subject, tenant, authority epoch, and session before
repository-specific selection. It then intersects protocol, message schema,
repository format, authorization contract, path contract, path profile, event,
transfer, and extension axes independently. Offer ordering is not preference.
For each mandatory axis the selected entry is the permitted common registry
entry with the lowest immutable numeric code. Required unknown capabilities,
forbidden lifecycle states, an empty axis, or removal of a client minimum fail
before mutation. Only candidate or ratified compatibility tuples are selectable
for new sessions. Deprecated tuples and reserved lifecycle entries are rejection
witnesses, not a read-compatibility path. Every identifier carried in the optional \`extensions\` list is
intrinsically optional; an unknown entry there is ignored. Required behavior
appears only in \`requiredCapabilities\` and must be registered and negotiated.
A registered required extension must also appear on the offered extension axis;
otherwise no compatibility tuple is common. Selected extensions follow the
authenticated compatibility-row order, independent of client offer order.

The selection carries separate authorization, path, repository, and protocol
registry digests. The negotiation digest is computed over every registry except
the compatibility registry, allowing the latter to bind that digest without a
circular hash. The contract manifest separately authenticates the complete
registry set, including compatibility.

Negotiation requires HTTPS over TLS 1.3 before selection or receipt issuance.
loopbackConformance is only an adversarial conformance input here and cannot
widen that rule; cleartext loopback testing belongs to the separate envelope
harness and is never bound as a negotiation receipt mode.

## Authenticated receipt

Receipt claims bind the complete selection, subject and tenant digests,
authority epoch, session, client/server nonces, issue time, and expiry. The
receipt MAC is HMAC-SHA-256 over \`ASCII("OGVCS-PROTOCOL-NEGOTIATION-RECEIPT-V1\\0")
|| ASCII(keyId) || 0x00 || JCS(claims)\` using the registered key.
The server nonce is canonical unpadded base64url whose decoded value is 16..64
bytes, inclusive; 65 decoded bytes are malformed. A spelling with nonzero
unused tail bits is malformed even when a
permissive decoder would produce the same bytes.
Receipt lifetime is strictly positive and cannot exceed maxReceiptLifetimeMs.
Every mutation verifies
the MAC before checking expiry, principal/session bindings, or selected
digests, then completes those checks before domain authorization or state
access. A receipt with both a corrupt MAC and expired claims returns
NEGOTIATION_RECEIPT_INVALID without exposing the expiry distinction. A receipt
is downgrade/tamper evidence; it is never an authorization grant.`],
  ["envelopes-and-errors.md", "Envelopes and safe errors", `## Closed envelopes

Request and response roots are closed. An application operation and body are
carried without defining domain routes in this contract. Unknown members are
permitted only as values of the namespaced extensions map, which is limited to
maxExtensionEntries. A successful ResponseEnvelope carries body and no problem;
a failed envelope carries problem and no body. Correlation and deadline fields
are operational metadata, not authorization or semantic-idempotency input.

## RFC 9457-safe subset

ProblemDetails is a closed authorization-safe subset of RFC 9457. The error
registry fixes code, type URI, title class, HTTP/body status, retryability, and
the only permitted parameter names. The body omits \`detail\` and \`instance\`.
Stack data, credentials, grants, policy text, protected paths/objects, hidden
counts, arbitrary parameters, and implementation messages are forbidden.
Parameters are bounded strings and must be permitted by the selected error
entry; names are unique. HTTP status, body status, title, type, code,
retryability, and retry headers must describe the same entry.

When and only when a safe \`retryAfterMs\` parameter is present, HTTP carries
exactly one RFC 9110 \`Retry-After\` delta-seconds field. Field-name comparison is
ASCII-case-insensitive and duplicate detection occurs after lowercase
normalization; canonical emission spells \`retry-after\`. The value is the
canonical nonnegative decimal \`ceil(retryAfterMs / 1000)\`, capped at 86400.
HTTP-date form, signs, leading zeroes, mismatches, missing fields, unexpected
fields, and case-folded duplicates are PROTOCOL_MALFORMED in v1.

Parsing, configured-resource, compatibility, receipt, authorization, cursor,
and idempotency failures are pre-mutation. An implementation maps unexpected
internal failures to INTERNAL_ERROR without copying exception text into the
wire body or retained conformance report.`],
  ["idempotency.md", "Semantic idempotency", `## Fingerprint

Every retryable mutation carries IdempotencyDescriptor. After bounded parsing,
duplicate rejection, schema validation, and semantic normalization, construct
the RequestEnvelope projection from fields whose assignment registry policy is
\`fingerprint=true\`: schemaVersion, operation, body, and the extensions map
(normalized to an empty map when absent). Correlation ID, deadline, negotiation
receipt, idempotency key, descriptor, and transport serialization are excluded.

Emit the projection with RFC 8785 and compute SHA-256 over UTF-8 bytes
\`ogvcs.protocol/idempotency/v1\\0 || JCS(projection)\`. This is
OGVCS-SEMANTIC-JCS-SHA-256. Hashing raw received bytes is nonconformant: harmless
member reordering must produce the same fingerprint, while any operation, body,
schema, or participating extension change must produce a different one.

Keys use the closed self-dating form

\`ik1.<issuedAtUnixMs>.<expiresAtUnixMs>.<base64url-entropy>\`.

The two canonical-decimal components must exactly equal the descriptor fields,
expiry must be later than issue time, lifetime must not exceed
${IDEMPOTENCY_KEY_MAX_LIFETIME_MS} milliseconds, and the entropy component is
22..218 base64url characters. Future issue skew is zero in the deterministic
runner: issue time must be no later than the explicit evaluator time. Production
implementations may choose a separately versioned small skew policy, but cannot
widen this R0 conformance profile. The evaluator rejects keys at or after their
embedded expiry and uses the supplied bounded clock; ambient wall-clock access
is not part of conformance execution.

## Reservation and replay

The server atomically reserves \`(authenticated scope, operation, key)\` before
mutation. Same key and fingerprint joins or returns the original committed
outcome, including when the first response was lost. Same key with a different
fingerprint returns IDEMPOTENCY_KEY_REUSE before mutation. A failed uncommitted
attempt may release its reservation; a committed result must not. Expiry and
tombstone policy cannot allow a previously committed key to execute silently a
second time. At or after embedded expiry, every use of that exact key returns
IDEMPOTENCY_KEY_REQUIRED before a new mutation, even after its stored outcome
and tombstone have been retired; the caller must issue a new self-dating key.
Tombstones may improve replay diagnostics but are not the security authority for
key freshness. A committed outcome and any tombstone needed to prevent reuse are
retained through embedded expiry even if a shorter ordinary retention interval
elapses. The ordinary \`tombstoneRetentionMs\` policy may be zero because embedded
key expiry remains the non-reuse authority. Authorization is rechecked on every
join/retry before a stored result is disclosed; denial returns
AUTHORIZATION_DENIED without the stored body or a second mutation.

The idempotency execution route requires \`retryableMutation=true\`, a nonempty
self-dating key, and a closed IdempotencyProjectionInput containing exactly
schemaVersion, operation, body, and extensions. Embedded key timestamps must
equal the explicit issued/expires fields, and every attemptProjectionIndex must
address a carried projection. Structural or relationship violations return
PROTOCOL_MALFORMED before authorization, lookup, reservation, or mutation. An
initial authorization denial likewise occurs before reservation and reports no
mutation.

A retry-labelled attempt with a valid unexpired self-dating key and no existing
reservation or committed record is not an internal error and is not a replay.
After the ordinary authorization check it is the first execution: the server
atomically reserves the key, performs the mutation exactly once, and records the
result. Conformance reports \`{firstExecution:true,replay:false}\` for this path.

RunnerResult and AdapterResult define preMutation over the complete executable
case, not only its final attempt: it is true exactly when mutationCount is zero.
Thus a replay denied after an earlier commit reports false/1 even though the
denied retry itself began no additional mutation.`],
  ["cursors-and-streams.md", "Opaque cursors and completion", `## Cursor state

The public Cursor schema exposes only an opaque bounded token. Implementations
use an unpredictable handle or an authenticated opaque encoding; neither may
reveal scope, identifiers, generation, or position. Server-owned state binds
subject, tenant, repository, operation/query digest, generation, position,
issue time, expiry, and any authorization epoch needed by the operation.
Lookup verifies token integrity and all scope fields before reading or
disclosing page state. Cursor TTL is strictly positive; a zero TTL is malformed
before token issuance or lifecycle evaluation.

CursorScopeInput is the closed conformance carrier for the five scope
dimensions: subject, tenant, repository, operation, and queryDigest. Both the
issue and read scopes are schema-validated before any token selection, lookup,
mutation, expiry, generation, or lifecycle decision. Missing or unknown scope
members return PROTOCOL_MALFORMED before those later stages.

Invalid/tampered or unknown tokens return CURSOR_INVALID. A valid cursor used
under another subject, tenant, repository, operation, or query returns
CURSOR_SCOPE_MISMATCH without revealing the original scope. Expiry returns
CURSOR_EXPIRED. A valid position no longer retained returns CURSOR_GAP with
only the registered safe gap class. R0 never emits a current generation because
this baseline has no authenticated resource-visibility witness.

Expiry tombstones are keyed independently of unrelated cursor issuance and
pruning. A once-valid token read during the declared tombstone-retention window
returns CURSOR_EXPIRED even if another cursor was issued or a prune interleaved.
After that retention window the implementation may discard the tombstone, and
the same token then transitions to the non-oracular CURSOR_INVALID result.

## Explicit completion

Page state is \`more\`, \`complete\`, or \`gap\`; an empty item array does not imply
completion. \`more\` supplies an opaque next cursor. \`complete\` is authoritative
without relying on socket closure. \`gap\` is explicit and carries only a safe
registered problem. Streaming uses the same rule: terminal state is an explicit
typed semantic frame, with no separate R0 transcript digest or MAC; EOF or
transport closure is STREAM_INCOMPLETE. Empty EOF and EOF within an unterminated
frame are incomplete rather than malformed; a complete decoded frame with a
missing/unknown member is instead PROTOCOL_MALFORMED before sequence checks.`],
  ["transfer-probe.md", "Application-neutral transfer probe", `## Carrier

The probe defines an identity-coded half-open byte range \`[startOffset,
endOffsetExclusive)\`, a strong representation validator, RFC 9530 content
digest, interruption, resume, and explicit completion. The end may be omitted
only where the carrier can bound the remaining representation before reading;
the requested and actual range never exceed maxTransferRangeBytes. Resume
requires the same strong validator. A validator or digest change rejects the
assembled representation rather than mixing generations.

TransferProbeResult always satisfies
\`0 <= acceptedStart <= acceptedEndExclusive <= totalBytes\`. \`complete\` is the
only terminal state and requires acceptedEndExclusive equal totalBytes.
\`partial\` is nonterminal with nonempty accepted progress strictly before total;
\`interrupted\` is nonterminal and also ends strictly before total, but may make
zero progress (acceptedStart equal acceptedEndExclusive). \`rejected\` is
nonterminal, accepts no bytes (start equals end), and requires a registered safe
problem. Complete, partial, and interrupted results forbid a problem.

## HTTP Range carrier

A bounded half-open probe range maps to one request field: \`Range:
bytes=start-(endOffsetExclusive-1)\`, or \`Range: bytes=start-\` when the
semantic end is omitted. A request without Range returns 200. Every satisfiable
Range request returns 206 and exactly one \`Content-Range: bytes
start-endInclusive/total\`; an unsatisfied range returns 416 with exactly one
\`Content-Range: bytes */total\`, an empty body, and neither \`Content-Digest\`
nor \`ETag\`. Resume sends \`If-Range\` with the exact quoted strong ETag. Weak
or mismatched validators reject.

For a request without Range, \`endOffsetExclusive\` may be absent. The 200
response still carries the complete representation and binds its total byte
length, validator, and content digest; omission is not interpreted as an empty
or partial body.

Field names are received ASCII-case-insensitively and duplicates are rejected
after lowercase normalization. Response \`Content-Length\` is the canonical
decimal exact body length, including zero for 416. Content coding remains
identity. The only response statuses on this carrier are 200, 206, and 416; any
other status is \`PROTOCOL_MALFORMED\` before validator-presence or range-semantic
checks. Malformed fields, inclusive/exclusive off-by-one conversions, total
mismatches, wrong 200/206/416 state, duplicate authority fields, and length
mismatches fail before accepting representation bytes. This carrier defines no
URL, route, session, or pack layout.

TransferProbe fields \`validatorTag\`, \`expectedSha256\`, and TransferProbeResult
fields \`validatorTag\`, \`contentSha256\` are semantic values, not literal HTTP
field syntax. At the HTTP/1.1 boundary a validator tag is encoded as a quoted
RFC 9110 strong ETag and a SHA-256 digest is encoded as RFC 9530
\`sha-256=:BASE64(32 digest bytes):\`. Receivers parse those exact forms back to
the semantic values before comparison. Every successful 200/206 carries exactly
one canonical strong \`ETag\` and one canonical \`Content-Digest\`. The digest is
SHA-256 of the decoded bounded \`responseBodyHex\`; \`Content-Length\` equals that
decoded byte length. On the HTTP Range conformance route, a present
\`expectedSha256\` is the expected response-body digest. A present
\`validatorTag\` is compared with the decoded ETag; otherwise the decoded ETag is
returned as the response validator. The accepted trace binds both decoded
values. Unquoted or weak ETags, hex in Content-Digest, another digest algorithm,
missing or duplicated fields, and body/digest mismatches do not silently coerce.

Before inspecting the grant carrier or invoking OGVCS-003, the receiver first
requires the public TransferProbe schemaVersion
\`${TRANSFER_PROBE_SCHEMA_VERSION}\`, then projects every non-grant field into
TransferProbeNonGrantInput with its distinct projection selector
\`${TRANSFER_PROBE_NON_GRANT_SCHEMA_VERSION}\`. It validates that closed shape,
range ordering, and resume rule. The projection selector is never accepted as a
public TransferProbe selector. A positive startOffset
requires validatorTag and otherwise returns TRANSFER_VALIDATOR_MISMATCH. Shape
failures return PROTOCOL_MALFORMED and reversed/empty half-open ranges return
TRANSFER_RANGE_INVALID before any grant-derived distinction. Only after that
preflight does a malformed grant map to TRANSFER_GRANT_INVALID and a valid grant
reach the pinned verifier.

The hard or configured \`maxGrantBytes\` ceiling measures only the decoded bytes
of \`CompactTransferGrant.envelope\`, never the canonical byte size of the compact
grant wrapper. An envelope at or below that ceiling proceeds to closed compact-
grant shape validation; a malformed wrapper then returns TRANSFER_GRANT_INVALID,
while PROTOCOL_LIMIT_EXCEEDED is reserved for an envelope that exceeds the
ceiling.

The Authorization carrier holds an opaque canonical OGVCS-003 envelope. At
this boundary it must represent one request-root grant and report
explicitObjectCount zero. Object-ID lists and grants in query strings are
forbidden. The authorization implementation still verifies issuer, key
generation, authority epoch, principal/repository scope, operation, audience,
expiry, request root, and replay rules; protocol code cannot reinterpret or
broaden the grant. Each public conformance TransferCaseInput carries the actual
opaque envelope, bounded authorization context, and public verification JWK.
The context and JWK are generic transport-bounded JSON carriers passed unchanged
to the pinned OGVCS-003 verifier; this contract deliberately does not duplicate
their semantic schema or maxima. Predecessor case identifiers, expected
outcomes, vector paths, and digests remain harness-only provenance and never
reach an adapter. Context-mismatch witnesses reuse the authenticated
valid-request-root envelope and project only the predecessor case's relevant
verification-context member. The replay witness is a fixed protocol-owned,
conformance-only envelope derived once from those request-root claims with a
distinct nonce and single-use replay policy and signed through the exact
predecessor conformance signer. Runtime protocol code never signs or issues
grants. The two explicit-object predecessor cases remain executable compact-
carrier rejection witnesses. RFC 9530 validates transferred representation
bytes and does not replace OGVCS-002 object identity validation.

## Ownership boundary

This profile is a synthetic application-neutral conformance probe. It defines
no production URL, object route, upload resource/session, multipart behavior,
pack layout, compression, storage placement, availability promise, or retry
queue. OGVCS-008 owns those choices and must preserve these carrier invariants.`],
  ["extensions-and-versioning.md", "Extensions and compatibility", `Every extension has an immutable numeric assignment, namespaced identifier,
owner, lifecycle, optional/required state, fallback, security/data impact,
affected schemas, and minimum protocol. Payloads live only in the explicit
closed extension map. Unknown top-level members never become extensions.

Only candidate and ratified entries may be selected or emitted, and only where
their lifecycle and selected compatibility tuple allow. Deprecated and reserved
entries are neither selected, emitted, nor interpreted in R0. This v1 contract
declares no deprecated-read compatibility window; such behavior would require a
future explicitly negotiated profile. The deprecated registry entry remains
solely as a rejection witness. Identifiers in the
optional \`extensions\` list are intrinsically optional and unknown entries are
ignored. Anything required appears in \`requiredCapabilities\`, where an unknown
or unnegotiated entry fails before mutation. Registry fallback applies only to
known registrations and never upgrades an optional list member into a
requirement.

The compatibility registry enumerates allowed independent selections and pins
authorization, path, and repository predecessor manifests. A release preflight
rejects a tuple not present in that registry, a changed predecessor digest, an
unknown required capability, or reuse/reassignment of a message/field/registry
number, name, or semantic SHA-256. The semantic digest is SHA-256 over
\`ogvcs.protocol/release-assignment-semantics/v1\\0 || JCS({kind,scope,name,code,policy})\`.
Field policy includes the complete declarative type and bounds, presence,
fingerprint and sensitivity policy, and owning cross-field constraints. Other
assignment kinds bind their complete registered policy semantics; descriptions
are excluded. Release preflight is executed by the frozen predecessor contract,
which compares proposed rows with its embedded prior rows. R0 admits only
additions explicitly pre-reserved in that predecessor's authenticated
\`allowedAdditions\`; the positive vector exercises that closed authority. Each
pre-reserved addition must be candidate-state, declared optional, same-major,
and unique by both kind/scope/name and kind/scope/code against prior and sibling
rows. Arbitrary new extension registration requires a future release-preflight
version that authenticates the proposed registry and manifest evidence.
Changing field meaning, presence, fingerprint participation, or safety policy
requires a new negotiated major version.`],
  ["security-and-privacy.md", "Security and privacy", `Untrusted forwarding headers cannot establish identity, origin, tenant,
repository, or authorization. Negotiation receipts prove the selected tuple,
not permission. Transfer grants remain OGVCS-003 artifacts and never appear in
URLs. Control and transfer compression are disabled, and mutation redirects
are refused so credentials and idempotency scope cannot cross origins.

The processing order is bounded framing, canonical JSON safety, closed schema,
authenticated negotiation/session binding, authorization, idempotency
reservation, then mutation. Every earlier failure has mutationCount zero.
Output remains staged and untrusted until the complete operation, digest, and
terminal checks succeed. Promise-based sources, sinks, adapters, and hooks race
a shared deadline and receive cancellation where supported; late caller-owned
side effects remain caller responsibility. Synchronous host calls are bounded
and checkpointed before and after because they cannot be preempted safely.

Errors, logs, telemetry, and retained reports contain only stable codes, safe
classes, correlation IDs, selected public versions, resource summaries, and
sanitized digests. They exclude payloads, credentials, grants, receipt MACs,
cursor tokens, subject/tenant raw values, protected paths/objects, policy text,
stack traces, and hidden cardinalities. Security vectors assert these absences.`],
  ["code-generation.md", "Generation and binding boundary", `## One authority

\`model.mjs\` is the sole authority for message and field numbers, wire names,
types, presence, limits, sensitivity, fingerprint participation, lifecycle,
registries, and executable scenario constructors. The offline Node generator validates that
model before writing. Unknown types/constraints, mixed primitive enums,
unbounded strings/collections, duplicate names/numbers, unresolved references,
unsafe integers, or host-dependent values make generation fail.

Generation emits RFC 8785 JSON schemas/registries/vectors, LF documentation,
and Rust, C++, C#, and TypeScript type packages. It uses no network, timestamp,
absolute output path, locale ordering, random value, or remote plugin.
\`--check\` recomputes expected bytes and reports drift. The independent spec
validator does not import model or generator code; it verifies canonical bytes,
inventory/digests, schema closure/bounds/references, assignments, predecessor
pins and declared offline generator inputs, semantic goldens, complete trace
goldens, the executable byte-identical golden JSONL stream, all 70 reduced
configured-limit executions, release preflights, and binding provenance.

RunnerCase contains only public operation input, configured ceilings,
deterministic clock/cancellation controls, and sensitive server context needed
to make leak tests non-vacuous. Oracle fields stay in the harness. An adapter
returns its actual bounded body, header rows, frames, log rows, and semantic
output in AdapterResult. The harness scans that trace before projecting
RunnerResult; \`semanticDigest\` is SHA-256 of RFC 8785 semanticOutput and
\`traceDigest\` is SHA-256 of the complete canonical AdapterTrace. Every scenario
contains a manifest-bound harness-only trace digest, and \`golden-traces.jsonl\`
contains the independently canonicalizable closed trace used to derive it.
Neither artifact is present in RunnerCase or the adapter execution view. AdapterResult
and every process line are capped by maxControlMessageBytes, header aggregates
by maxHeaderBytes, and all structural limits remain active. Reports retain
neither trace nor server context.

The 35 limit pairs use lowered ceilings only. Measurements come from actual
input bytes, collections, schema steps, stream frames, registry inventory, or
the operation clock—not expected results. Runner clock samples are
nondecreasing safe timestamps; elapsed time is the checked difference between
the final and first samples. A decreasing sequence is PROTOCOL_MALFORMED before
operation dispatch. The working-memory parser route
reserves \`128 + 4 * rawInputUtf8Bytes\`; elapsed time reaches its exclusive
deadline at \`elapsed >= maxOperationTimeMs\`. The configured lower ceiling
applies when present, while the normative 120000ms hard/default ceiling remains
active when the override is absent. All configured ceilings are positive except
the deliberate maxErrorParameters zero-ceiling pair. The
conformance-only \`rawInputUtf16CodeUnits\` carrier lets an adapter materialize a
JS unpaired code unit immediately before raw-input validation without making
the authenticated vector set itself non-I-JSON.

## Noncircular manifests and bindings

The contract manifest lists every distributed normative artifact except
itself. The vector manifest lists vector artifacts except itself. The
negotiation registry digest excludes compatibility so compatibility can pin it;
the complete registry digest includes compatibility. The binding manifest
points one way to the contract-manifest digest and lists every binding artifact
except itself. No digest graph is circular.

The contract manifest authenticates \`adapter-execution-view.json\` as a one-way
support view exposing only schemas, registries, profiles, limits, and
predecessor pins. It excludes vectors, expected outcomes, trace goldens, and the
authorization manifest/grant/license files declared as offline generator
inputs, so an external adapter receives randomized cases over stdin without
access to either oracle corpus or predecessor-vector outcomes.

Bindings contain standard-library type models and immutable assignment/limit/
error constants only. Applications provide bounded JSON/JCS, JSONL, HTTP/TLS,
MAC, cursor, authorization, and storage runtimes. Hand-patching generated output
or treating a binding as a wire runtime is nonconformant.`],
]);

export const SUPPORTED_TYPE_KINDS = Object.freeze(["array", "boolean", "enum", "integer", "json", "map", "reference", "string"]);
