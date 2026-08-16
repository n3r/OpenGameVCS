import { canonicalBytes, cloneJson, parseJson } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError, protocolSemanticError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';
import { validateProtocolValue } from './schema.mjs';

function bytesInput(input, maximum) {
  if (!(typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol envelope must be JSON text or bytes');
  if (typeof input === 'string') {
    if (input.length > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol envelope byte ceiling exceeded');
    const length = Buffer.byteLength(input, 'utf8');
    if (length > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol envelope byte ceiling exceeded');
    const bytes = Buffer.from(input, 'utf8');
    if (new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== input) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol envelope is not well-formed Unicode');
    if (bytes.length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol envelope is empty');
    return bytes;
  }
  if (input.byteLength > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol envelope byte ceiling exceeded');
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  if (bytes.length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol envelope is empty');
  return bytes;
}

function extensionCeiling(value, configured) {
  if (value.extensions !== undefined) {
    if (value.extensions === null || typeof value.extensions !== 'object' || Array.isArray(value.extensions)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol extensions must be a registered extension object');
    if (Object.keys(value.extensions).length > configured) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol extension-entry ceiling exceeded');
  }
}

function extensionPolicy(contract, value, schemaName, options) {
  if (value.extensions === undefined) return;
  const registry = contract?.registries?.extensions;
  if (registry?.registry !== 'extensions' || !Array.isArray(registry.entries)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol extension registry is invalid');
  const byId = new Map(registry.entries.map((entry) => [entry.id, entry]));
  const selected = new Set(options.selectedExtensions ?? []);
  for (const id of Object.keys(value.extensions)) {
    const entry = byId.get(id);
    if (!entry || !selected.has(id) || !['candidate', 'ratified'].includes(entry.state)
        || !entry.affectedSchemas.includes(schemaName)
        || entry.requirement !== 'optional' || !['ignore', 'reject'].includes(entry.fallback)) {
      protocolSemanticError('PROTOCOL_UNSUPPORTED', 'envelope extension is not selected for this schema');
    }
  }
}

function nowValue(options) {
  const value = options.atUnixMs ?? Date.now();
  if (!Number.isSafeInteger(value) || value < 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol wall-clock value is invalid');
  return value;
}

export function validateRequestEnvelope(contract, input, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxBytes, HARD_LIMITS.controlMessageBytes, HARD_LIMITS.controlMessageBytes, 'request maxBytes');
  const value = validateProtocolValue(contract, 'RequestEnvelope.schema.json', input, { ...options, maxBytes: maximum, deadline });
  extensionCeiling(value, boundedInteger(options.maxExtensionEntries, HARD_LIMITS.extensionEntries, HARD_LIMITS.extensionEntries, 'maxExtensionEntries'));
  extensionPolicy(contract, value, 'RequestEnvelope', options);
  if (value.deadlineUnixMs !== undefined) {
    const now = nowValue(options);
    if (value.deadlineUnixMs <= now) protocolSemanticError('DEADLINE_EXCEEDED', 'request deadline has elapsed');
    if (value.deadlineUnixMs - now > HARD_LIMITS.deadlineHorizonMs) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'request deadline horizon ceiling exceeded');
  }
  if (options.contentEncoding !== undefined && options.contentEncoding !== 'identity') protocolSemanticError('COMPRESSION_FORBIDDEN', 'control-message content coding is forbidden');
  if (options.redirectStatus !== undefined) {
    if (!Number.isSafeInteger(options.redirectStatus) || options.redirectStatus < 300 || options.redirectStatus > 399) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'redirect status is invalid');
    const explicitlySafe = options.allowSameOriginRedirect === true && options.originChanged === false
      && options.mutation !== true && options.grantBearing !== true && value.idempotency === undefined;
    if (!explicitlySafe) protocolSemanticError('REDIRECT_FORBIDDEN', 'redirect is forbidden for this request');
  }
  if (options.retryableMutation === true && value.idempotency === undefined) protocolSemanticError('IDEMPOTENCY_KEY_REQUIRED', 'retryable mutation requires an idempotency descriptor');
  deadline.checkpoint();
  return value;
}

export function parseRequestEnvelope(contract, input, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxBytes, HARD_LIMITS.controlMessageBytes, HARD_LIMITS.controlMessageBytes, 'request maxBytes');
  const value = parseJson(bytesInput(input, maximum), { requireCanonical: options.requireCanonical === true, maxBytes: maximum, deadline });
  return validateRequestEnvelope(contract, value, { ...options, maxBytes: maximum, deadline });
}

export function validateResponseEnvelope(contract, input, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxBytes, HARD_LIMITS.controlMessageBytes, HARD_LIMITS.controlMessageBytes, 'response maxBytes');
  const value = validateProtocolValue(contract, 'ResponseEnvelope.schema.json', input, { ...options, maxBytes: maximum, deadline });
  extensionCeiling(value, boundedInteger(options.maxExtensionEntries, HARD_LIMITS.extensionEntries, HARD_LIMITS.extensionEntries, 'maxExtensionEntries'));
  extensionPolicy(contract, value, 'ResponseEnvelope', options);
  if (value.success === true) {
    if (!Object.hasOwn(value, 'body') || Object.hasOwn(value, 'problem')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'successful response must carry only a body outcome');
  } else if (value.success === false) {
    if (!Object.hasOwn(value, 'problem') || Object.hasOwn(value, 'body')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'failed response must carry only a problem outcome');
    if (options.httpStatus !== undefined && options.httpStatus !== value.problem.status) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP status and response problem status disagree');
  }
  deadline.checkpoint();
  return value;
}

export function parseResponseEnvelope(contract, input, options = {}) {
  const deadline = deadlineFrom(options);
  const maximum = boundedInteger(options.maxBytes, HARD_LIMITS.controlMessageBytes, HARD_LIMITS.controlMessageBytes, 'response maxBytes');
  const value = parseJson(bytesInput(input, maximum), { requireCanonical: options.requireCanonical === true, maxBytes: maximum, deadline });
  return validateResponseEnvelope(contract, value, { ...options, maxBytes: maximum, deadline });
}

export function encodeRequestEnvelope(contract, input, options = {}) {
  return canonicalBytes(validateRequestEnvelope(contract, cloneJson(input, options), options), options);
}

export function encodeResponseEnvelope(contract, input, options = {}) {
  return canonicalBytes(validateResponseEnvelope(contract, cloneJson(input, options), options), options);
}
