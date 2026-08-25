import { canonicalBytes, parseJson } from './canonical.mjs';
import { parseRequestEnvelope, parseResponseEnvelope, validateRequestEnvelope, validateResponseEnvelope } from './envelopes.mjs';
import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';

function byteInput(input, maximum, label, options = {}) {
  if (!(typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} must be JSON text or bytes`);
  if (typeof input === 'string' && (input.length > maximum || Buffer.byteLength(input, 'utf8') > maximum)
      || typeof input !== 'string' && input.byteLength > maximum) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} byte ceiling exceeded`);
  const maximumWorking = boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
  const liveBytes = typeof input === 'string'
    ? (2 * input.length) + Buffer.byteLength(input, 'utf8') + 1024
    : (Buffer.isBuffer(input) ? input.byteLength : 2 * input.byteLength) + 1024;
  if (!Number.isSafeInteger(liveBytes) || liveBytes > maximumWorking) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, `${label} working-memory ceiling exceeded`);
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input, typeof input === 'string' ? 'utf8' : undefined);
  if (typeof input === 'string' && new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== input) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is not well-formed Unicode`);
  if (bytes.length === 0) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, `${label} is empty`);
  return bytes;
}

function settings(options) {
  return Object.freeze({
    contract: options.contract,
    maxRequestBytes: boundedInteger(options.maxRequestBytes, 1024 * 1024, HARD_LIMITS.jsonBytes, 'maxRequestBytes'),
    maxResponseBytes: boundedInteger(options.maxResponseBytes, 1024 * 1024, HARD_LIMITS.jsonBytes, 'maxResponseBytes'),
    requestSchema: options.requestSchema ?? 'RequestEnvelope.schema.json',
    responseSchema: options.responseSchema ?? 'ResponseEnvelope.schema.json',
  });
}

export class BoundedLoopbackServer {
  #handler;
  #settings;

  constructor(options = {}) {
    this.#settings = settings(options);
    this.#handler = options.handler;
    if (typeof this.#handler !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'loopback server handler must be callable');
  }

  async exchange(input, options = {}) {
    const deadline = deadlineFrom(options);
    const requestBytes = byteInput(input, this.#settings.maxRequestBytes, 'loopback request', options);
    const request = this.#settings.requestSchema === 'RequestEnvelope.schema.json'
      ? parseRequestEnvelope(this.#settings.contract, requestBytes, { ...options, maxBytes: this.#settings.maxRequestBytes, deadline })
      : this.#settings.contract.validator.validate(parseJson(requestBytes, { ...options, maxBytes: this.#settings.maxRequestBytes, deadline }), this.#settings.requestSchema, { ...options, maxBytes: this.#settings.maxRequestBytes, deadline });
    deadline.checkpoint();
    const responseValue = await deadline.race(this.#handler(request, { deadline, signal: deadline.signal }), 'loopback request handler');
    const response = this.#settings.responseSchema === 'ResponseEnvelope.schema.json'
      ? validateResponseEnvelope(this.#settings.contract, responseValue, { ...options, maxBytes: this.#settings.maxResponseBytes, deadline })
      : this.#settings.contract.validator.validate(responseValue, this.#settings.responseSchema, { maxBytes: this.#settings.maxResponseBytes, deadline });
    return canonicalBytes(response, { ...options, maxBytes: this.#settings.maxResponseBytes, deadline });
  }
}

export class BoundedLoopbackClient {
  #exchange;
  #settings;

  constructor(options = {}) {
    this.#settings = settings(options);
    this.#exchange = options.exchange;
    if (typeof this.#exchange !== 'function') protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'loopback client exchange must be callable');
  }

  async call(value, options = {}) {
    const deadline = deadlineFrom(options);
    const request = this.#settings.requestSchema === 'RequestEnvelope.schema.json'
      ? validateRequestEnvelope(this.#settings.contract, value, { ...options, maxBytes: this.#settings.maxRequestBytes, deadline })
      : this.#settings.contract.validator.validate(value, this.#settings.requestSchema, { maxBytes: this.#settings.maxRequestBytes, deadline });
    const requestBytes = canonicalBytes(request, { ...options, maxBytes: this.#settings.maxRequestBytes, deadline });
    const rawResponse = await deadline.race(this.#exchange(requestBytes, { deadline, signal: deadline.signal }), 'loopback exchange');
    const responseBytes = byteInput(rawResponse, this.#settings.maxResponseBytes, 'loopback response', options);
    return this.#settings.responseSchema === 'ResponseEnvelope.schema.json'
      ? parseResponseEnvelope(this.#settings.contract, responseBytes, { ...options, maxBytes: this.#settings.maxResponseBytes, deadline })
      : this.#settings.contract.validator.validate(parseJson(responseBytes, { ...options, maxBytes: this.#settings.maxResponseBytes, deadline }), this.#settings.responseSchema, { ...options, maxBytes: this.#settings.maxResponseBytes, deadline });
  }
}

export function createBoundedLoopback(options = {}) {
  const server = new BoundedLoopbackServer(options);
  const client = new BoundedLoopbackClient({ ...options, exchange: (bytes, exchangeOptions) => server.exchange(bytes, exchangeOptions) });
  return Object.freeze({ client, server });
}
