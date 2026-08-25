import { types as utilTypes } from 'node:util';

export const RUNTIME_ERROR_CODES = Object.freeze({
  INPUT_INVALID: 'PROTOCOL_INPUT_INVALID',
  CONTRACT_INVALID: 'PROTOCOL_CONTRACT_INVALID',
  LIMIT_EXCEEDED: 'PROTOCOL_LIMIT_EXCEEDED',
  DEADLINE_EXCEEDED: 'PROTOCOL_DEADLINE_EXCEEDED',
  CANCELLED: 'PROTOCOL_CANCELLED',
  STATE_CONFLICT: 'PROTOCOL_STATE_CONFLICT',
  STREAM_INCOMPLETE: 'PROTOCOL_STREAM_INCOMPLETE',
  ADAPTER_PROTOCOL: 'PROTOCOL_ADAPTER_PROTOCOL',
  ADAPTER_FAILED: 'PROTOCOL_ADAPTER_FAILED',
  IO: 'PROTOCOL_IO_ERROR',
});

const VALUES = new Set(Object.values(RUNTIME_ERROR_CODES));

const SAFE_CLASSES = Object.freeze({
  [RUNTIME_ERROR_CODES.INPUT_INVALID]: 'input',
  [RUNTIME_ERROR_CODES.CONTRACT_INVALID]: 'contract',
  [RUNTIME_ERROR_CODES.LIMIT_EXCEEDED]: 'resource',
  [RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED]: 'resource',
  [RUNTIME_ERROR_CODES.CANCELLED]: 'resource',
  [RUNTIME_ERROR_CODES.STATE_CONFLICT]: 'state',
  [RUNTIME_ERROR_CODES.STREAM_INCOMPLETE]: 'stream',
  [RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL]: 'adapter',
  [RUNTIME_ERROR_CODES.ADAPTER_FAILED]: 'adapter',
  [RUNTIME_ERROR_CODES.IO]: 'io',
});

const EXIT_CODES = Object.freeze({
  [RUNTIME_ERROR_CODES.INPUT_INVALID]: 2,
  [RUNTIME_ERROR_CODES.CONTRACT_INVALID]: 3,
  [RUNTIME_ERROR_CODES.LIMIT_EXCEEDED]: 4,
  [RUNTIME_ERROR_CODES.DEADLINE_EXCEEDED]: 4,
  [RUNTIME_ERROR_CODES.CANCELLED]: 4,
  [RUNTIME_ERROR_CODES.STATE_CONFLICT]: 4,
  [RUNTIME_ERROR_CODES.STREAM_INCOMPLETE]: 4,
  [RUNTIME_ERROR_CODES.ADAPTER_PROTOCOL]: 4,
  [RUNTIME_ERROR_CODES.ADAPTER_FAILED]: 4,
  [RUNTIME_ERROR_CODES.IO]: 4,
});

function safeDetails(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('protocol error details must be an object');
  }
  if (utilTypes.isProxy(value)) throw new TypeError('protocol error details must be inert data');
  let prototype;
  let keys;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch (error) {
    throw new TypeError('protocol error details cannot be inspected safely', { cause: error });
  }
  if (prototype !== Object.prototype && prototype !== null
      || keys.some((key) => typeof key !== 'string')
      || keys.some((key) => !descriptors[key]?.enumerable || !Object.hasOwn(descriptors[key], 'value'))) {
    throw new TypeError('protocol error details must be inert data');
  }
  const output = Object.create(null);
  const entries = keys.map((key) => [key, descriptors[key].value]);
  if (entries.length > 16) throw new TypeError('protocol error details exceed their field ceiling');
  for (const [key, item] of entries) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/u.test(key) || key.length > 64) {
      throw new TypeError('protocol error detail name is invalid');
    }
    if (!(item === null || typeof item === 'boolean' || (typeof item === 'number' && Number.isSafeInteger(item)) || (typeof item === 'string' && Buffer.byteLength(item, 'utf8') <= 256))) {
      throw new TypeError('protocol error detail value is invalid');
    }
    output[key] = item;
  }
  return Object.freeze(output);
}

export class ProtocolBaselineError extends Error {
  constructor(code, message, options = {}) {
    if (!VALUES.has(code)) throw new TypeError('unknown protocol runtime error code');
    if (typeof message !== 'string' || message.length === 0 || Buffer.byteLength(message, 'utf8') > 512) {
      throw new TypeError('protocol runtime error message is invalid');
    }
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ProtocolBaselineError';
    this.code = code;
    this.exitCode = options.exitCode ?? EXIT_CODES[code];
    this.preMutation = options.preMutation ?? true;
    this.details = safeDetails(options.details);
  }

  toJSON() {
    return { code: this.code, safeClass: SAFE_CLASSES[this.code], preMutation: this.preMutation };
  }
}

export class ProtocolSemanticError extends Error {
  constructor(code, message, options = {}) {
    if (typeof code !== 'string' || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(code)) throw new TypeError('protocol semantic error code is invalid');
    if (typeof message !== 'string' || message.length === 0 || Buffer.byteLength(message, 'utf8') > 512) throw new TypeError('protocol semantic error message is invalid');
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ProtocolSemanticError';
    this.code = code;
    this.preMutation = true;
  }

  toJSON() {
    return { code: this.code, preMutation: true };
  }
}

export function protocolError(code, message, options) {
  throw new ProtocolBaselineError(code, message, options);
}

export function protocolSemanticError(code, message, options) {
  throw new ProtocolSemanticError(code, message, options);
}

export function asProtocolError(error, code = RUNTIME_ERROR_CODES.CONTRACT_INVALID, message = 'protocol operation failed') {
  if (error instanceof ProtocolBaselineError) return error;
  return new ProtocolBaselineError(code, message, { cause: error });
}
