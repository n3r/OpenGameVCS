import { cloneJson, inspectJson } from './canonical.mjs';
import { ERROR_CODES, contractError } from './errors.mjs';
import { ACTOR_CLASSES, AUDIT_CLASSES, AUDIT_CLASS_PERMISSIONS, CREDENTIAL_CLASSES, DECISION_CODES, PERMISSIONS, RESOURCE_TYPES } from './generated.mjs';

const ID = /^[a-z][a-z0-9.-]{0,127}$/;
const OPAQUE = /^[A-Za-z0-9._:-]{1,256}$/;
const REQUEST_ROOT = /^sha256:[0-9a-f]{64}$/;
const CODE = /^[A-Z][A-Z0-9_]{0,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FILE_ID = /^[0-9a-f]{32}$/;
const OBJECT_ID = /^[A-Za-z0-9:._-]{1,160}$/;
const BASE64URL_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const ACTOR_PSEUDONYM = /^pseudonym:[0-9a-f]{32}$/;

function invalid(message) {
  contractError(ERROR_CODES.INPUT_INVALID, message);
}

export function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid(`${label} must be an object`);
  return value;
}

function exact(value, required, label) {
  const keys = Object.keys(value).sort();
  const expected = [...required].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) invalid(`${label} has an invalid field set`);
}

function text(value, expression, label) {
  if (typeof value !== 'string' || !expression.test(value)) invalid(`${label} is invalid`);
  return value;
}

function safeText(value, label, nullable = false) {
  if (nullable && value === null) return value;
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > 256 || /[\u0000-\u001f\u007f]/u.test(value)) invalid(`${label} is invalid`);
  return value;
}

function canonicalPath(value, label, { allowEmpty = false } = {}) {
  if (allowEmpty && value === '') return value;
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > 4096 || /[\\\u0000-\u001f\u007f]/u.test(value) || value.normalize('NFC') !== value) invalid(`${label} is invalid`);
  const segments = value.split('/');
  if (segments.length > 256 || segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..' || Buffer.byteLength(segment, 'utf8') > 255)) invalid(`${label} is invalid`);
  return value;
}

function positive(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) invalid(`${label} must be a positive safe integer`);
  return value;
}

function nonNegative(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) invalid(`${label} must be a nonnegative safe integer`);
  return value;
}

function stringArray(value, label, options = {}) {
  if (!Array.isArray(value) || value.length < (options.minimum ?? 0) || value.length > (options.maximum ?? 128)) invalid(`${label} has invalid cardinality`);
  const result = value.map((item, index) => text(item, options.pattern ?? ID, `${label}[${index}]`));
  if (new Set(result).size !== result.length) invalid(`${label} contains duplicates`);
  if (options.allowed && result.some((item) => !options.allowed.includes(item))) invalid(`${label} contains an unknown assignment`);
  return result;
}

function requestObjectIds(value, label) {
  return stringArray(value, label, { maximum: 32_768, pattern: OBJECT_ID });
}

export function validateRequestObjectIds(input) {
  inspectJson(input);
  if (!Array.isArray(input) || input.length === 0) invalid('request object IDs must be a nonempty array');
  return cloneJson(requestObjectIds(input, 'request object IDs'));
}

export function validateAuthorizationRequest(input) {
  inspectJson(input);
  const value = object(input, 'authorization request');
  exact(value, ['schemaVersion', 'requestId', 'actor', 'tenant', 'repository', 'permission', 'reason', 'resource', 'context'], 'authorization request');
  if (value.schemaVersion !== 'ogvcs.authorization/request/v1') invalid('authorization request schemaVersion is invalid');
  text(value.requestId, OPAQUE, 'requestId');
  text(value.tenant, ID, 'tenant');
  text(value.repository, ID, 'repository');
  if (!PERMISSIONS.includes(value.permission)) invalid('permission is unknown');
  safeText(value.reason, 'reason', true);

  const actor = object(value.actor, 'actor');
  exact(actor, ['id', 'class', 'groups', 'credentialClass', 'credentialGeneration', 'credentialStatus', 'authorityEpoch'], 'actor');
  text(actor.id, ID, 'actor.id');
  text(actor.class, ID, 'actor.class');
  if (!ACTOR_CLASSES.includes(actor.class)) invalid('actor.class is unknown');
  stringArray(actor.groups, 'actor.groups', { maximum: 64 });
  text(actor.credentialClass, ID, 'actor.credentialClass');
  if (!CREDENTIAL_CLASSES.includes(actor.credentialClass)) invalid('actor.credentialClass is unknown');
  positive(actor.credentialGeneration, 'actor.credentialGeneration');
  if (!['active', 'revoked'].includes(actor.credentialStatus)) invalid('actor.credentialStatus is invalid');
  positive(actor.authorityEpoch, 'actor.authorityEpoch');

  const resource = object(value.resource, 'resource');
  exact(resource, ['type', 'path', 'fileId', 'objectId', 'name'], 'resource');
  if (!RESOURCE_TYPES.includes(resource.type)) invalid('resource.type is unknown');
  if (resource.path !== null) canonicalPath(resource.path, 'resource.path');
  if (resource.fileId !== null) text(resource.fileId, FILE_ID, 'resource.fileId');
  if (resource.objectId !== null) text(resource.objectId, OBJECT_ID, 'resource.objectId');
  safeText(resource.name, 'resource.name', true);

  const context = object(value.context, 'context');
  exact(context, ['reference', 'snapshot', 'policyGeneration', 'authorityEpoch'], 'context');
  if (context.reference !== null) text(context.reference, ID, 'context.reference');
  if (context.snapshot !== null) text(context.snapshot, OPAQUE, 'context.snapshot');
  positive(context.policyGeneration, 'context.policyGeneration');
  positive(context.authorityEpoch, 'context.authorityEpoch');
  return cloneJson(value);
}

export function validateAuthorizationDecision(input) {
  inspectJson(input);
  const value = object(input, 'authorization decision');
  exact(value, ['schemaVersion', 'requestId', 'allowed', 'code', 'policyVersion', 'policyGeneration', 'decisionFingerprint'], 'authorization decision');
  if (value.schemaVersion !== 'ogvcs.authorization/decision/v1') invalid('authorization decision schemaVersion is invalid');
  text(value.requestId, OPAQUE, 'decision.requestId');
  if (typeof value.allowed !== 'boolean') invalid('decision.allowed is invalid');
  if (!DECISION_CODES.includes(value.code) || value.code.startsWith('ALLOW_') !== value.allowed) invalid('decision code/allowed relationship is invalid');
  text(value.policyVersion, ID, 'decision.policyVersion');
  positive(value.policyGeneration, 'decision.policyGeneration');
  text(value.decisionFingerprint, SHA256, 'decision.decisionFingerprint');
  return cloneJson(value);
}

export function validateAuditEvent(input) {
  inspectJson(input);
  const value = object(input, 'authorization audit event');
  exact(value, ['schemaVersion', 'eventId', 'eventClass', 'occurredAt', 'tenant', 'repository', 'actorClass', 'actorPseudonym', 'permission', 'reason', 'outcomeCode', 'correlationId', 'details'], 'authorization audit event');
  if (value.schemaVersion !== 'ogvcs.authorization/audit-event/v1') invalid('audit event schemaVersion is invalid');
  text(value.eventId, OPAQUE, 'audit event eventId');
  if (!AUDIT_CLASSES.includes(value.eventClass)) invalid('audit event class is unknown');
  nonNegative(value.occurredAt, 'audit event occurredAt');
  text(value.tenant, ID, 'audit event tenant');
  text(value.repository, ID, 'audit event repository');
  if (!ACTOR_CLASSES.includes(value.actorClass)) invalid('audit event actorClass is unknown');
  text(value.actorPseudonym, ACTOR_PSEUDONYM, 'audit event actorPseudonym');
  if (!PERMISSIONS.includes(value.permission) || AUDIT_CLASS_PERMISSIONS[value.eventClass] !== value.permission) invalid('audit event permission does not match its class');
  safeText(value.reason, 'audit event reason');
  if (!DECISION_CODES.includes(value.outcomeCode)) invalid('audit event outcomeCode is unknown');
  text(value.correlationId, OPAQUE, 'audit event correlationId');
  const details = object(value.details, 'audit event details');
  exact(details, ['targetClass', 'changeRef'], 'audit event details');
  text(details.targetClass, ID, 'audit event targetClass');
  if (details.changeRef !== null) text(details.changeRef, OPAQUE, 'audit event changeRef');
  return cloneJson(value);
}

export function validatePolicyFixture(input) {
  inspectJson(input);
  const value = object(input, 'policy fixture');
  exact(value, ['schemaVersion', 'id', 'version', 'policyGeneration', 'authorityEpoch', 'default', 'composition', 'rules'], 'policy fixture');
  if (value.schemaVersion !== 'ogvcs.authorization/policy-fixture/v1' || value.default !== 'deny' || value.composition !== 'deny-overrides-v1') invalid('policy fixture envelope is invalid');
  text(value.id, ID, 'policy.id');
  text(value.version, ID, 'policy.version');
  if (!ID.test(`${value.id}.${value.version}`)) invalid('combined policy version is invalid');
  positive(value.policyGeneration, 'policy.policyGeneration');
  positive(value.authorityEpoch, 'policy.authorityEpoch');
  if (!Array.isArray(value.rules) || value.rules.length === 0 || value.rules.length > 1024) invalid('policy.rules cardinality is invalid');
  const ids = new Set();
  for (const [index, candidate] of value.rules.entries()) {
    const rule = object(candidate, `policy.rules[${index}]`);
    exact(rule, ['id', 'effect', 'actors', 'groups', 'actorClasses', 'tenants', 'repositories', 'references', 'pathPrefixes', 'resourceTypes', 'permissions'], `policy.rules[${index}]`);
    text(rule.id, ID, `policy.rules[${index}].id`);
    if (ids.has(rule.id)) invalid('policy rule IDs contain duplicates');
    ids.add(rule.id);
    if (!['allow', 'deny'].includes(rule.effect)) invalid('policy rule effect is invalid');
    stringArray(rule.actors, 'rule.actors');
    stringArray(rule.groups, 'rule.groups');
    stringArray(rule.actorClasses, 'rule.actorClasses', { maximum: 32, allowed: ACTOR_CLASSES });
    stringArray(rule.tenants, 'rule.tenants', { minimum: 1 });
    stringArray(rule.repositories, 'rule.repositories', { minimum: 1 });
    stringArray(rule.references, 'rule.references');
    if (!Array.isArray(rule.pathPrefixes) || rule.pathPrefixes.length > 128 || new Set(rule.pathPrefixes).size !== rule.pathPrefixes.length) invalid('rule.pathPrefixes is invalid');
    for (const prefix of rule.pathPrefixes) canonicalPath(prefix, 'rule.pathPrefixes', { allowEmpty: true });
    stringArray(rule.resourceTypes, 'rule.resourceTypes', { minimum: 1, allowed: RESOURCE_TYPES });
    stringArray(rule.permissions, 'rule.permissions', { minimum: 1, allowed: PERMISSIONS, pattern: /^[a-z][a-z0-9.-]{0,127}$/ });
  }
  return cloneJson(value);
}

export function validateTransferGrantClaims(input) {
  inspectJson(input);
  const value = object(input, 'transfer grant claims');
  exact(value, ['schemaVersion', 'issuer', 'keyId', 'keyGeneration', 'authorityEpoch', 'subject', 'tenant', 'repository', 'permission', 'operation', 'audience', 'issuedAt', 'expiresAt', 'nonce', 'replay', 'objectIds', 'requestRoot'], 'transfer grant claims');
  if (value.schemaVersion !== 'ogvcs.authorization/transfer-grant-claims/v1') invalid('transfer grant claims schemaVersion is invalid');
  for (const key of ['issuer', 'keyId', 'subject', 'tenant', 'repository', 'audience']) text(value[key], ID, `claims.${key}`);
  positive(value.keyGeneration, 'claims.keyGeneration');
  positive(value.authorityEpoch, 'claims.authorityEpoch');
  if (!['content.materialize', 'content.upload'].includes(value.permission)) invalid('claims.permission is invalid');
  if (!['download', 'upload'].includes(value.operation)) invalid('claims.operation is invalid');
  if ((value.operation === 'download' ? 'content.materialize' : 'content.upload') !== value.permission) invalid('claims operation does not match permission');
  nonNegative(value.issuedAt, 'claims.issuedAt');
  nonNegative(value.expiresAt, 'claims.expiresAt');
  if (value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 300) invalid('claims validity window is invalid');
  text(value.nonce, OPAQUE, 'claims.nonce');
  if (!['single-use', 'idempotent'].includes(value.replay)) invalid('claims.replay is invalid');
  stringArray(value.objectIds, 'claims.objectIds', { maximum: 4096, pattern: OBJECT_ID });
  if (value.requestRoot !== null) text(value.requestRoot, REQUEST_ROOT, 'claims.requestRoot');
  if ((value.objectIds.length === 0) === (value.requestRoot === null)) invalid('claims must bind exactly one of objectIds or requestRoot');
  return cloneJson(value);
}

export function validateTransferGrantEnvelope(input) {
  inspectJson(input);
  const value = object(input, 'transfer grant envelope');
  exact(value, ['schemaVersion', 'algorithm', 'keyId', 'claims', 'signature'], 'transfer grant envelope');
  if (value.schemaVersion !== 'ogvcs.authorization/transfer-grant/v1' || value.algorithm !== 'Ed25519') invalid('transfer grant envelope is invalid');
  text(value.keyId, ID, 'envelope.keyId');
  const claims = validateTransferGrantClaims(value.claims);
  if (value.keyId !== claims.keyId) invalid('envelope keyId does not bind claims');
  text(value.signature, BASE64URL_SIGNATURE, 'envelope.signature');
  if (Buffer.from(value.signature, 'base64url').toString('base64url') !== value.signature) invalid('envelope.signature is noncanonical');
  return { ...cloneJson(value), claims };
}

export function validateGrantContext(input) {
  inspectJson(input);
  const value = object(input, 'grant context');
  exact(value, ['schemaVersion', 'issuer', 'keyId', 'subject', 'permission', 'operation', 'audience', 'tenant', 'repository', 'authorityEpoch', 'keyGeneration', 'now', 'objectId', 'requestObjectIds', 'consumedNonces'], 'grant context');
  if (value.schemaVersion !== 'ogvcs.authorization/transfer-grant-context/v1') invalid('grant context schemaVersion is invalid');
  for (const key of ['issuer', 'keyId', 'subject', 'audience', 'tenant', 'repository']) text(value[key], ID, `grant context ${key}`);
  if (!['content.materialize', 'content.upload'].includes(value.permission)) invalid('grant context permission is invalid');
  if (!['download', 'upload'].includes(value.operation)) invalid('grant context operation is invalid');
  if ((value.operation === 'download' ? 'content.materialize' : 'content.upload') !== value.permission) invalid('grant context operation does not match permission');
  positive(value.authorityEpoch, 'grant context authorityEpoch');
  positive(value.keyGeneration, 'grant context keyGeneration');
  nonNegative(value.now, 'grant context now');
  text(value.objectId, OBJECT_ID, 'grant context objectId');
  requestObjectIds(value.requestObjectIds, 'grant context requestObjectIds');
  stringArray(value.consumedNonces, 'grant context consumedNonces', { maximum: 4096, pattern: OPAQUE });
  return cloneJson(value);
}

export function validateThreatVector(input) {
  inspectJson(input);
  const value = object(input, 'threat vector');
  exact(value, ['schemaVersion', 'id', 'abuseCase', 'category', 'kind', 'input', 'expected', 'forbiddenResponseFields'], 'threat vector');
  if (value.schemaVersion !== 'ogvcs.authorization/threat-vector/v1') invalid('threat vector schemaVersion is invalid');
  for (const key of ['id', 'abuseCase', 'category']) text(value[key], ID, `threat vector ${key}`);
  if (!['authorization', 'authorized-view', 'transfer-grant', 'deduplication', 'sandbox'].includes(value.kind)) invalid('threat vector kind is invalid');
  const vectorInput = object(value.input, 'threat vector input');
  if (value.kind === 'authorization') {
    exact(vectorInput, ['policy', 'request'], 'authorization vector input');
    text(vectorInput.policy, OPAQUE, 'authorization vector policy');
    validateAuthorizationRequest(vectorInput.request);
  } else if (value.kind === 'authorized-view') {
    text(vectorInput.policy, OPAQUE, 'authorized-view policy');
    text(vectorInput.actor, ID, 'authorized-view actor');
    if (!PERMISSIONS.includes(vectorInput.permission)) invalid('authorized-view permission is unknown');
    if (Object.hasOwn(vectorInput, 'candidates')) {
      exact(vectorInput, Object.hasOwn(vectorInput, 'projectionIdentity') ? ['policy', 'actor', 'permission', 'candidates', 'projectionIdentity'] : ['policy', 'actor', 'permission', 'candidates'], 'authorized-view input');
      if (!Array.isArray(vectorInput.candidates) || vectorInput.candidates.length > 100_000) invalid('authorized-view candidates are invalid');
      for (const [index, candidate] of vectorInput.candidates.entries()) object(candidate, `authorized-view candidate ${index}`);
      if (Object.hasOwn(vectorInput, 'projectionIdentity') && vectorInput.projectionIdentity !== 'distinct') invalid('authorized-view projection identity is invalid');
    } else {
      exact(vectorInput, ['policy', 'actor', 'permission', 'auditClass'], 'authorized-view audit input');
      text(vectorInput.auditClass, ID, 'authorized-view audit class');
    }
  } else if (value.kind === 'transfer-grant') {
    exact(vectorInput, ['envelope', 'context', 'publicJwk'], 'transfer-grant vector input');
    object(vectorInput.envelope, 'transfer-grant vector envelope');
    object(vectorInput.context, 'transfer-grant vector context');
    object(vectorInput.publicJwk, 'transfer-grant vector public key');
  } else if (value.kind === 'sandbox') {
    exact(vectorInput, ['profile', 'attempt'], 'sandbox vector input');
    text(vectorInput.profile, ID, 'sandbox vector profile');
    object(vectorInput.attempt, 'sandbox vector attempt');
  } else {
    if (Object.hasOwn(vectorInput, 'keyDerivation')) {
      exact(vectorInput, ['tenant', 'keyDerivation'], 'deduplication key vector input');
      text(vectorInput.tenant, ID, 'deduplication tenant');
      if (vectorInput.keyDerivation !== 'content-hash') invalid('deduplication key derivation is invalid');
    } else {
      exact(vectorInput, ['tenant', 'probedTenant', 'objectId'], 'deduplication probe vector input');
      text(vectorInput.tenant, ID, 'deduplication tenant');
      text(vectorInput.probedTenant, ID, 'deduplication probed tenant');
      text(vectorInput.objectId, OBJECT_ID, 'deduplication objectId');
    }
  }
  const expected = object(value.expected, 'threat vector expected');
  exact(expected, ['result', 'code'], 'threat vector expected');
  if (!['allow', 'deny'].includes(expected.result) || !DECISION_CODES.includes(expected.code) || (expected.code.startsWith('ALLOW_') ? 'allow' : 'deny') !== expected.result) invalid('threat vector expected outcome is invalid');
  stringArray(value.forbiddenResponseFields, 'threat vector forbiddenResponseFields', { minimum: 1, maximum: 64, pattern: /^[A-Za-z][A-Za-z0-9.-]{0,127}$/ });
  return cloneJson(value);
}

export function validateRunnerResult(input) {
  inspectJson(input, { maxBytes: 4 * 1024 * 1024 });
  const value = object(input, 'runner result');
  exact(value, ['schemaVersion', 'id', 'result', 'code'], 'runner result');
  if (value.schemaVersion !== 'ogvcs.authorization/runner-result/v1') invalid('runner result schemaVersion is invalid');
  text(value.id, ID, 'runner result id');
  if (!['allow', 'deny'].includes(value.result)) invalid('runner result result is invalid');
  text(value.code, CODE, 'runner result code');
  if (!DECISION_CODES.includes(value.code) || (value.code.startsWith('ALLOW_') ? 'allow' : 'deny') !== value.result) invalid('runner result code/result is invalid');
  return cloneJson(value);
}

export function safeRequestId(input) {
  return typeof input?.requestId === 'string' && OPAQUE.test(input.requestId) ? input.requestId : 'invalid-request';
}

export { CODE as DECISION_CODE_PATTERN, ID as IDENTIFIER_PATTERN, SHA256 as SHA256_PATTERN };
