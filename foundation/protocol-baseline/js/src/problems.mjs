import { canonicalJson, cloneJson, deepFreeze } from './canonical.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS } from './limits.mjs';
import { validateResponseEnvelope } from './envelopes.mjs';
import { validateProtocolValue } from './schema.mjs';

const RUNTIME_TO_WIRE = Object.freeze({
  [RUNTIME_ERROR_CODES.INPUT_INVALID]: 'PROTOCOL_MALFORMED',
  [RUNTIME_ERROR_CODES.CONTRACT_INVALID]: 'INTERNAL_ERROR',
  [RUNTIME_ERROR_CODES.LIMIT_EXCEEDED]: 'PROTOCOL_LIMIT_EXCEEDED',
  [RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED]: 'DEADLINE_EXCEEDED',
  [RUNTIME_ERROR_CODES.CANCELLED]: 'CANCELLED',
  [RUNTIME_ERROR_CODES.STATE_CONFLICT]: 'INTERNAL_ERROR',
  [RUNTIME_ERROR_CODES.STREAM_INCOMPLETE]: 'STREAM_INCOMPLETE',
  [RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL]: 'INTERNAL_ERROR',
  [RUNTIME_ERROR_CODES.ADAPTER_FAILED]: 'INTERNAL_ERROR',
  [RUNTIME_ERROR_CODES.IO]: 'INTERNAL_ERROR',
});

const PARAMETER_DOMAINS = Object.freeze({
  conflictClass: Object.freeze({ type: 'string', values: Object.freeze(['idempotency-input-mismatch']) }),
  gapClass: Object.freeze({ type: 'string', values: Object.freeze(['generation-changed', 'retention-gap']) }),
  retryAfterMs: Object.freeze({ maximum: 86_400_000, minimum: 0, type: 'canonical-decimal' }),
});
const RETRY_AFTER_PATTERN = /^(?:0|[1-9][0-9]{0,6}|[1-7][0-9]{7}|8[0-5][0-9]{6}|86[0-3][0-9]{5}|86400000)$/u;
const RETRY_AFTER_SECONDS_PATTERN = /^(?:0|[1-9][0-9]{0,4})$/u;

function retryAfterHeaders(headers, retryAfterMs, options = {}) {
  if (headers === undefined) return;
  const supplied = cloneJson(headers, {
    ...options,
    maxBytes: HARD_LIMITS.headerBytes,
    maxDepth: 3,
    maxNodes: 1024,
    maxStringBytes: HARD_LIMITS.headerBytes,
    maxCollectionItems: 1024,
  });
  if (!Array.isArray(supplied)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP headers must be an array');
  let bytes = 0;
  const retryHeaders = [];
  for (const header of supplied) {
    if (!header || typeof header !== 'object' || Array.isArray(header)
        || Object.keys(header).sort().join('\0') !== 'name\0value'
        || typeof header.name !== 'string' || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u.test(header.name)
        || typeof header.value !== 'string' || /[\r\n\0]/u.test(header.value)) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP problem header is malformed');
    }
    bytes += Buffer.byteLength(header.name, 'utf8') + Buffer.byteLength(header.value, 'utf8') + 4;
    if (!Number.isSafeInteger(bytes) || bytes > HARD_LIMITS.headerBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'HTTP problem header ceiling exceeded');
    if (header.name.toLowerCase() === 'retry-after') retryHeaders.push(header.value);
  }
  if (retryAfterMs === undefined) {
    if (retryHeaders.length !== 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Retry-After requires the registered retryAfterMs parameter');
    return;
  }
  if (retryHeaders.length !== 1) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'retryAfterMs requires exactly one Retry-After header');
  const secondsText = retryHeaders[0];
  if (!RETRY_AFTER_SECONDS_PATTERN.test(secondsText) || Number(secondsText) > 86_400) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Retry-After must be a canonical bounded delta-seconds value');
  if (Number(secondsText) !== Math.ceil(Number(retryAfterMs) / 1000)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'Retry-After and retryAfterMs disagree');
}

function registry(contract) {
  const value = contract?.registries?.['error-codes'];
  if (!value || value.schemaVersion !== 'ogvcs.protocol/registry/v1' || value.registry !== 'error-codes' || value.version !== 1 || value.license !== 'MIT' || value.rfc9457Subset !== 'closed-safe' || canonicalJson(value.forbiddenMembers) !== '["detail","instance"]' || canonicalJson(value.parameterDomains) !== canonicalJson(PARAMETER_DOMAINS) || canonicalJson(value.excludedParameters) !== '[{"name":"currentGeneration","reason":"R0 has no authenticated visibility-proof carrier"}]' || !Array.isArray(value.entries) || value.entries.length !== 25) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol error-code registry is invalid');
  }
  return value;
}

function staticEntry(entry) {
  const keys = ['code', 'name', 'retryable', 'safeParameters', 'status', 'title', 'type'];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join('\0') !== keys.join('\0') || !Number.isSafeInteger(entry.code) || entry.code < 1 || typeof entry.name !== 'string' || !/^[A-Z][A-Z0-9_]*$/u.test(entry.name) || !Number.isSafeInteger(entry.status) || entry.status < 400 || entry.status > 599 || typeof entry.title !== 'string' || entry.title.length === 0 || typeof entry.retryable !== 'boolean' || !Array.isArray(entry.safeParameters) || typeof entry.type !== 'string') {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol error-code entry is invalid');
  }
  try {
    const url = new URL(entry.type);
    if (url.protocol !== 'https:') throw new Error('not https');
  } catch (error) { protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol problem type is invalid', { cause: error }); }
  if (entry.safeParameters.length > HARD_LIMITS.errorParameters || new Set(entry.safeParameters).size !== entry.safeParameters.length || entry.safeParameters.some((name) => !Object.hasOwn(PARAMETER_DOMAINS, name))) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol error safe-parameter assignment is invalid');
}

function parameterValue(name, value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1 || Buffer.byteLength(value, 'utf8') > HARD_LIMITS.safeParameterBytes) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem parameter is not permitted');
  const domain = PARAMETER_DOMAINS[name];
  if (domain?.type === 'string' && !domain.values.includes(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem parameter is outside its closed domain');
  if (domain?.type === 'canonical-decimal' && !RETRY_AFTER_PATTERN.test(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem retry delay is outside its closed domain');
  return value;
}

export class ProtocolProblemCatalog {
  #byName = new Map();
  #contract;

  constructor(contract) {
    this.#contract = contract;
    const source = registry(contract);
    const codes = new Set();
    for (const entry of source.entries) {
      staticEntry(entry);
      if (this.#byName.has(entry.name) || codes.has(entry.code)) protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'protocol error assignment is duplicated');
      this.#byName.set(entry.name, cloneJson(entry));
      codes.add(entry.code);
    }
  }

  entry(code) {
    if (typeof code !== 'string' || !this.#byName.has(code)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol error code is not registered');
    return this.#byName.get(code);
  }

  create(code, options = {}) {
    const entry = this.entry(code);
    const supplied = options.parameters ?? [];
    if (!Array.isArray(supplied) || supplied.length > HARD_LIMITS.errorParameters) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'protocol problem parameter ceiling exceeded');
    const names = new Set();
    const parameters = supplied.map((parameter) => {
      if (!parameter || typeof parameter !== 'object' || Array.isArray(parameter) || Object.keys(parameter).sort().join('\0') !== 'name\0value' || !entry.safeParameters.includes(parameter.name) || names.has(parameter.name)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem parameter is not permitted');
      names.add(parameter.name);
      return { name: parameter.name, value: parameterValue(parameter.name, parameter.value) };
    }).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    const problem = {
      type: entry.type,
      title: entry.title,
      status: entry.status,
      code: entry.name,
      retryable: entry.retryable,
      correlationId: options.correlationId,
      ...(parameters.length > 0 ? { parameters } : {}),
    };
    return validateProtocolValue(this.#contract, 'ProblemDetails.schema.json', problem, options);
  }

  fromRuntimeError(error, options = {}) {
    const code = options.code ?? (this.#byName.has(error?.code) ? error.code : undefined) ?? RUNTIME_TO_WIRE[error?.code] ?? 'INTERNAL_ERROR';
    return this.create(code, options);
  }

  validate(problem, http = {}, options = {}) {
    const value = validateProtocolValue(this.#contract, 'ProblemDetails.schema.json', problem, options);
    const entry = this.entry(value.code);
    if (value.type !== entry.type || value.title !== entry.title || value.status !== entry.status || value.retryable !== entry.retryable) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem fields do not match their registry assignment');
    if (http.status !== undefined && http.status !== value.status) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP status and protocol problem status disagree');
    const allowed = new Set(entry.safeParameters);
    const names = new Set();
    for (const parameter of value.parameters ?? []) {
      if (!allowed.has(parameter.name) || names.has(parameter.name)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'protocol problem carries an unregistered parameter');
      names.add(parameter.name);
      parameterValue(parameter.name, parameter.value);
    }
    const retry = value.parameters?.find(({ name }) => name === 'retryAfterMs')?.value;
    if (http.retryAfterMs !== undefined && String(http.retryAfterMs) !== retry) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'HTTP retry metadata and protocol problem disagree');
    retryAfterHeaders(http.headers, retry, options);
    return value;
  }

  responseHeaders(problem, options = {}) {
    const value = this.validate(problem, {}, options);
    const retry = value.parameters?.find(({ name }) => name === 'retryAfterMs')?.value;
    return deepFreeze(retry === undefined ? [] : [{ name: 'Retry-After', value: String(Math.ceil(Number(retry) / 1000)) }]);
  }

  response(code, options = {}) {
    const problem = this.create(code, options);
    return validateResponseEnvelope(this.#contract, {
      schemaVersion: 'ogvcs.protocol/response-envelope/v1',
      correlationId: problem.correlationId,
      success: false,
      problem,
    }, options);
  }

  success(correlationId, body, options = {}) {
    return validateResponseEnvelope(this.#contract, {
      schemaVersion: 'ogvcs.protocol/response-envelope/v1',
      correlationId,
      success: true,
      body: cloneJson(body, options),
      ...(options.extensions === undefined ? {} : { extensions: cloneJson(options.extensions, options) }),
    }, options);
  }
}

export { RUNTIME_TO_WIRE };
