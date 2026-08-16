import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { ERROR_CODES, contractError } from './errors.mjs';

export const JSON_LIMITS = Object.freeze({
  maxBytes: 4 * 1024 * 1024,
  maxDepth: 32,
  maxNodes: 200_000,
  maxStringBytes: 65_536,
  maxKeyBytes: 256,
});

function validUnicode(value) {
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

function ownDescriptors(value) {
  try {
    return { keys: Reflect.ownKeys(value), descriptors: Object.getOwnPropertyDescriptors(value) };
  } catch (error) {
    contractError(ERROR_CODES.INPUT_INVALID, 'JSON container cannot be inspected safely', { cause: error });
  }
}

function configuredLimits(options) {
  const limits = {};
  for (const [name, hardMaximum] of Object.entries(JSON_LIMITS)) {
    const value = options[name] ?? hardMaximum;
    if (!Number.isSafeInteger(value) || value <= 0 || value > hardMaximum) contractError(ERROR_CODES.INPUT_INVALID, `${name} is outside the supported JSON limit range`);
    limits[name] = value;
  }
  return limits;
}

export function inspectJson(value, options = {}) {
  const limits = configuredLimits(options);
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  let encodedBytes = 0;
  const addBytes = (valueToAdd) => {
    encodedBytes += valueToAdd;
    if (encodedBytes > limits.maxBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'canonical JSON byte ceiling exceeded');
  };
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > limits.maxNodes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON node ceiling exceeded');
    if (current.depth > limits.maxDepth) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON nesting ceiling exceeded');
    const item = current.value;
    if (item === null || typeof item === 'boolean') {
      addBytes(item === null ? 4 : item ? 4 : 5);
      continue;
    }
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || Object.is(item, -0)) contractError(ERROR_CODES.INPUT_INVALID, 'JSON number is not canonical');
      addBytes(Buffer.byteLength(JSON.stringify(item), 'utf8'));
      continue;
    }
    if (typeof item === 'string') {
      if (!validUnicode(item)) contractError(ERROR_CODES.INPUT_INVALID, 'JSON string is not well-formed Unicode');
      if (Buffer.byteLength(item, 'utf8') > limits.maxStringBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON string ceiling exceeded');
      addBytes(Buffer.byteLength(JSON.stringify(item), 'utf8'));
      continue;
    }
    if (typeof item === 'object' && utilTypes.isProxy(item)) contractError(ERROR_CODES.INPUT_INVALID, 'JSON proxy objects are forbidden');
    if (Array.isArray(item)) {
      const { keys, descriptors } = ownDescriptors(item);
      if (keys.some((key) => typeof key !== 'string') || keys.length !== item.length + 1 || !keys.includes('length')) {
        contractError(ERROR_CODES.INPUT_INVALID, 'JSON array must be dense and have no extra properties');
      }
      addBytes(2 + Math.max(0, item.length - 1));
      for (let index = item.length - 1; index >= 0; index -= 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
          contractError(ERROR_CODES.INPUT_INVALID, 'JSON array contains an accessor or sparse element');
        }
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
      continue;
    }
    if (typeof item === 'object' && (Object.getPrototypeOf(item) === Object.prototype || Object.getPrototypeOf(item) === null)) {
      const { keys, descriptors } = ownDescriptors(item);
      if (keys.some((key) => typeof key !== 'string')) contractError(ERROR_CODES.INPUT_INVALID, 'JSON object contains a symbol key');
      addBytes(2 + Math.max(0, keys.length - 1) + keys.length);
      for (let index = keys.length - 1; index >= 0; index -= 1) {
        const key = keys[index];
        const descriptor = descriptors[key];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
          contractError(ERROR_CODES.INPUT_INVALID, 'JSON object contains an accessor or hidden property');
        }
        if (!validUnicode(key)) contractError(ERROR_CODES.INPUT_INVALID, 'JSON key is not well-formed Unicode');
        if (Buffer.byteLength(key, 'utf8') > limits.maxKeyBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON key ceiling exceeded');
        addBytes(Buffer.byteLength(JSON.stringify(key), 'utf8'));
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
      continue;
    }
    contractError(ERROR_CODES.INPUT_INVALID, 'value is outside the canonical JSON domain');
  }
  return { nodes, encodedBytes };
}

function encode(value, output) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    output.push(JSON.stringify(value));
    return;
  }
  if (Array.isArray(value)) {
    output.push('[');
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) output.push(',');
      encode(value[index], output);
    }
    output.push(']');
    return;
  }
  output.push('{');
  const keys = Object.keys(value).sort();
  for (let index = 0; index < keys.length; index += 1) {
    if (index > 0) output.push(',');
    const key = keys[index];
    output.push(JSON.stringify(key), ':');
    encode(value[key], output);
  }
  output.push('}');
}

export function canonicalJson(value, options = {}) {
  inspectJson(value, options);
  const output = [];
  encode(value, output);
  return output.join('');
}

export function canonicalBytes(value, options = {}) {
  return Buffer.from(canonicalJson(value, options), 'utf8');
}

export function parseCanonicalJson(input, options = {}) {
  const maxBytes = options.maxBytes ?? JSON_LIMITS.maxBytes;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > JSON_LIMITS.maxBytes) contractError(ERROR_CODES.INPUT_INVALID, 'maxBytes is outside the supported JSON limit range');
  let bytes;
  let text;
  if (typeof input === 'string') {
    if (input.length > maxBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
    text = input;
    bytes = Buffer.from(input, 'utf8');
  } else if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    if (input.byteLength > maxBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
    bytes = Buffer.from(input);
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      contractError(ERROR_CODES.INPUT_INVALID, 'JSON is not valid UTF-8 text', { cause: error });
    }
  } else {
    contractError(ERROR_CODES.INPUT_INVALID, 'JSON input must be text or bytes');
  }
  if (bytes.length > maxBytes) contractError(ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
  if (text.includes('\u0000')) contractError(ERROR_CODES.INPUT_INVALID, 'JSON is not valid bounded UTF-8 text');
  const trailingNewline = options.trailingNewline === true;
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    contractError(ERROR_CODES.INPUT_INVALID, 'invalid JSON', { cause: error });
  }
  const expected = `${canonicalJson(value, options)}${trailingNewline ? '\n' : ''}`;
  if (text !== expected) contractError(ERROR_CODES.INPUT_INVALID, 'JSON is not in canonical form');
  return value;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function deepFreeze(value) {
  const stack = [value];
  const seen = new Set();
  while (stack.length > 0) {
    const item = stack.pop();
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    for (const child of Object.values(item)) stack.push(child);
    Object.freeze(item);
  }
  return value;
}

export function cloneJson(value, options = {}) {
  inspectJson(value, options);
  try {
    return structuredClone(value);
  } catch (error) {
    contractError(ERROR_CODES.INPUT_INVALID, 'JSON value cannot be cloned safely', { cause: error });
  }
}
