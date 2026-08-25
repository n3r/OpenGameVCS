import { createHash, timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { RUNTIME_ERROR_CODES, protocolError } from './errors.mjs';
import { HARD_LIMITS, boundedInteger, deadlineFrom } from './limits.mjs';

export const JSON_LIMITS = Object.freeze({
  maxBytes: HARD_LIMITS.jsonBytes,
  maxDepth: HARD_LIMITS.jsonDepth,
  maxNodes: HARD_LIMITS.jsonNodes,
  maxStringBytes: HARD_LIMITS.jsonStringBytes,
  maxKeyBytes: HARD_LIMITS.jsonKeyBytes,
  maxObjectMembers: HARD_LIMITS.objectMembers,
  maxArrayItems: HARD_LIMITS.arrayItems,
  maxCollectionItems: HARD_LIMITS.collectionItems,
});

function jsonLimits(options) {
  return Object.freeze({
    maxBytes: boundedInteger(options.maxBytes, JSON_LIMITS.maxBytes, JSON_LIMITS.maxBytes, 'maxBytes'),
    maxDepth: boundedInteger(options.maxDepth, JSON_LIMITS.maxDepth, JSON_LIMITS.maxDepth, 'maxDepth'),
    maxNodes: boundedInteger(options.maxNodes, JSON_LIMITS.maxNodes, JSON_LIMITS.maxNodes, 'maxNodes'),
    maxStringBytes: boundedInteger(options.maxStringBytes, JSON_LIMITS.maxStringBytes, JSON_LIMITS.maxStringBytes, 'maxStringBytes'),
    maxKeyBytes: boundedInteger(options.maxKeyBytes, JSON_LIMITS.maxKeyBytes, JSON_LIMITS.maxKeyBytes, 'maxKeyBytes'),
    maxObjectMembers: boundedInteger(options.maxObjectMembers, JSON_LIMITS.maxObjectMembers, JSON_LIMITS.maxObjectMembers, 'maxObjectMembers'),
    maxArrayItems: boundedInteger(options.maxArrayItems, JSON_LIMITS.maxArrayItems, JSON_LIMITS.maxArrayItems, 'maxArrayItems'),
    maxCollectionItems: boundedInteger(options.maxCollectionItems, JSON_LIMITS.maxCollectionItems, JSON_LIMITS.maxCollectionItems, 'maxCollectionItems'),
  });
}

function workingMemoryLimit(options) {
  return boundedInteger(options.maxWorkingMemoryBytes, HARD_LIMITS.stateBytes, HARD_LIMITS.stateBytes, 'maxWorkingMemoryBytes');
}

function reserveJsonWorkingBytes(encodedBytes, options) {
  const reservation = 128 + (4 * encodedBytes);
  if (!Number.isSafeInteger(reservation) || reservation > workingMemoryLimit(options)) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON working-memory ceiling exceeded');
  }
}

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

function ownData(value) {
  try {
    if (utilTypes.isProxy(value)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON proxy objects are forbidden');
    return { keys: Reflect.ownKeys(value), descriptors: Object.getOwnPropertyDescriptors(value) };
  } catch (error) {
    if (error?.code?.startsWith?.('PROTOCOL_')) throw error;
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON container cannot be inspected safely', { cause: error });
  }
}

function addBytes(state, count) {
  state.encodedBytes += count;
  if (!Number.isSafeInteger(state.encodedBytes) || state.encodedBytes > state.limits.maxBytes) {
    protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JCS byte ceiling exceeded');
  }
}

export function inspectJson(value, options = {}) {
  const limits = jsonLimits(options);
  const deadline = deadlineFrom(options);
  const state = { limits, encodedBytes: 0, nodes: 0, collectionItems: 0 };
  const stack = [{ value, depth: 0 }];
  while (stack.length > 0) {
    const current = stack.pop();
    state.nodes += 1;
    if ((state.nodes & 1023) === 0) deadline.checkpoint();
    if (state.nodes > limits.maxNodes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON node ceiling exceeded');
    if (current.depth > limits.maxDepth) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON nesting ceiling exceeded');
    const item = current.value;
    if (item === null) {
      addBytes(state, 4);
    } else if (typeof item === 'boolean') {
      addBytes(state, item ? 4 : 5);
    } else if (typeof item === 'number') {
      if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON number is outside the I-JSON domain');
      }
      addBytes(state, Buffer.byteLength(JSON.stringify(item), 'utf8'));
    } else if (typeof item === 'string') {
      if (!validUnicode(item)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON string is not well-formed Unicode');
      const stringBytes = Buffer.byteLength(item, 'utf8');
      if (stringBytes > limits.maxStringBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON string ceiling exceeded');
      addBytes(state, Buffer.byteLength(JSON.stringify(item), 'utf8'));
    } else if (Array.isArray(item)) {
      const { keys, descriptors } = ownData(item);
      if (keys.some((key) => typeof key !== 'string') || keys.length !== item.length + 1 || !keys.includes('length')) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON array must be dense and have no extra properties');
      }
      if (item.length > limits.maxArrayItems) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON array-item ceiling exceeded');
      state.collectionItems += item.length;
      if (state.collectionItems > limits.maxCollectionItems) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON collection-item ceiling exceeded');
      addBytes(state, 2 + Math.max(0, item.length - 1));
      for (let index = item.length - 1; index >= 0; index -= 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
          protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON array contains an accessor, hidden, or sparse element');
        }
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    } else if (typeof item === 'object' && item !== null) {
      // `Object.getPrototypeOf(proxy)` invokes the proxy's trap. Reject proxy
      // containers before any reflective operation so hostile host values can
      // only produce a typed protocol failure and never execute caller code.
      if (utilTypes.isProxy(item)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON proxy objects are forbidden');
      let prototype;
      try { prototype = Object.getPrototypeOf(item); } catch (error) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON container cannot be inspected safely', { cause: error });
      }
      if (prototype !== Object.prototype && prototype !== null) {
        protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'value is outside the I-JSON domain');
      }
      const { keys, descriptors } = ownData(item);
      if (keys.some((key) => typeof key !== 'string')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON object contains a symbol key');
      if (keys.length > limits.maxObjectMembers) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON object-member ceiling exceeded');
      state.collectionItems += keys.length;
      if (state.collectionItems > limits.maxCollectionItems) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON collection-item ceiling exceeded');
      addBytes(state, 2 + Math.max(0, keys.length - 1));
      for (let index = keys.length - 1; index >= 0; index -= 1) {
        const key = keys[index];
        const descriptor = descriptors[key];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
          protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON object contains an accessor or hidden property');
        }
        if (!validUnicode(key)) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON key is not well-formed Unicode');
        if (Buffer.byteLength(key, 'utf8') > limits.maxKeyBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON key ceiling exceeded');
        addBytes(state, Buffer.byteLength(JSON.stringify(key), 'utf8') + 1);
        stack.push({ value: descriptor.value, depth: current.depth + 1 });
      }
    } else {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'value is outside the I-JSON domain');
    }
  }
  deadline.checkpoint();
  return Object.freeze({ nodes: state.nodes, encodedBytes: state.encodedBytes, collectionItems: state.collectionItems });
}

function emit(value, output) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    output.push(JSON.stringify(value));
    return;
  }
  if (Array.isArray(value)) {
    output.push('[');
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) output.push(',');
      emit(value[index], output);
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
    emit(value[key], output);
  }
  output.push('}');
}

export function canonicalJson(value, options = {}) {
  const summary = inspectJson(value, options);
  reserveJsonWorkingBytes(summary.encodedBytes, options);
  const output = [];
  emit(value, output);
  const text = output.join('');
  if (Buffer.byteLength(text, 'utf8') !== summary.encodedBytes) {
    protocolError(RUNTIME_ERROR_CODES.CONTRACT_INVALID, 'JCS byte accounting invariant failed');
  }
  return text;
}

export function canonicalBytes(value, options = {}) {
  return Buffer.from(canonicalJson(value, options), 'utf8');
}

class JsonParser {
  constructor(text, limits, deadline) {
    this.text = text;
    this.limits = limits;
    this.deadline = deadline;
    this.index = 0;
    this.nodes = 0;
    this.collectionItems = 0;
  }

  fail(message, code = RUNTIME_ERROR_CODES.INPUT_INVALID) {
    protocolError(code, message, { details: { offset: Math.min(this.index, Number.MAX_SAFE_INTEGER) } });
  }

  checkpoint() {
    if ((this.nodes & 1023) === 0) this.deadline.checkpoint();
  }

  whitespace() {
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) this.index += 1;
      else break;
    }
  }

  value(depth) {
    this.whitespace();
    this.nodes += 1;
    this.checkpoint();
    if (this.nodes > this.limits.maxNodes) this.fail('JSON node ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
    if (depth > this.limits.maxDepth) this.fail('JSON nesting ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
    const token = this.text[this.index];
    if (token === '"') return this.string(false);
    if (token === '{') return this.object(depth);
    if (token === '[') return this.array(depth);
    if (token === '-' || (token >= '0' && token <= '9')) return this.number();
    if (this.text.startsWith('true', this.index)) { this.index += 4; return true; }
    if (this.text.startsWith('false', this.index)) { this.index += 5; return false; }
    if (this.text.startsWith('null', this.index)) { this.index += 4; return null; }
    this.fail('invalid JSON value');
  }

  string(isKey) {
    const start = this.index;
    this.index += 1;
    let closed = false;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        closed = true;
        break;
      }
      if (code < 0x20) this.fail('JSON string contains an unescaped control character');
      if (code === 0x5c) {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === 'u') {
          const hex = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(hex)) this.fail('JSON string contains an invalid Unicode escape');
          this.index += 5;
        } else if ('"\\/bfnrt'.includes(escaped)) {
          this.index += 1;
        } else {
          this.fail('JSON string contains an invalid escape');
        }
      } else {
        this.index += 1;
      }
      if (this.index - start > (this.limits.maxStringBytes * 6) + 2) {
        this.fail('JSON string ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
      }
    }
    if (!closed) this.fail('JSON string is unterminated');
    let value;
    try { value = JSON.parse(this.text.slice(start, this.index)); } catch (error) {
      protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON string is invalid', { cause: error });
    }
    if (!validUnicode(value)) this.fail('JSON string is not well-formed Unicode');
    const bytes = Buffer.byteLength(value, 'utf8');
    const maximum = isKey ? this.limits.maxKeyBytes : this.limits.maxStringBytes;
    if (bytes > maximum) this.fail(isKey ? 'JSON key ceiling exceeded' : 'JSON string ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
    return value;
  }

  number() {
    const start = this.index;
    if (this.text[this.index] === '-') this.index += 1;
    if (this.text[this.index] === '0') {
      this.index += 1;
      if (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.fail('JSON number contains a leading zero');
    } else if (this.text[this.index] >= '1' && this.text[this.index] <= '9') {
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
    } else this.fail('JSON number is invalid');
    if (this.text[this.index] === '.') {
      this.index += 1;
      const fraction = this.index;
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
      if (fraction === this.index) this.fail('JSON number fraction is empty');
    }
    if (this.text[this.index] === 'e' || this.text[this.index] === 'E') {
      this.index += 1;
      if (this.text[this.index] === '+' || this.text[this.index] === '-') this.index += 1;
      const exponent = this.index;
      while (this.text[this.index] >= '0' && this.text[this.index] <= '9') this.index += 1;
      if (exponent === this.index) this.fail('JSON number exponent is empty');
    }
    if (this.index - start > 128) this.fail('JSON number token ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
    const value = Number(this.text.slice(start, this.index));
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      this.fail('JSON number is outside the I-JSON domain');
    }
    return value;
  }

  countCollection() {
    this.collectionItems += 1;
    if (this.collectionItems > this.limits.maxCollectionItems) {
      this.fail('JSON collection-item ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
    }
  }

  array(depth) {
    this.index += 1;
    const output = [];
    this.whitespace();
    if (this.text[this.index] === ']') { this.index += 1; return output; }
    while (true) {
      if (output.length >= this.limits.maxArrayItems) this.fail('JSON array-item ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
      this.countCollection();
      output.push(this.value(depth + 1));
      this.whitespace();
      if (this.text[this.index] === ']') { this.index += 1; return output; }
      if (this.text[this.index] !== ',') this.fail('JSON array delimiter is invalid');
      this.index += 1;
    }
  }

  object(depth) {
    this.index += 1;
    const output = Object.create(null);
    const seen = new Set();
    this.whitespace();
    if (this.text[this.index] === '}') { this.index += 1; return output; }
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') this.fail('JSON object key must be a string');
      const key = this.string(true);
      if (seen.has(key)) this.fail('JSON object contains a duplicate key');
      if (seen.size >= this.limits.maxObjectMembers) this.fail('JSON object-member ceiling exceeded', RUNTIME_ERROR_CODES.LIMIT_EXCEEDED);
      seen.add(key);
      this.countCollection();
      this.whitespace();
      if (this.text[this.index] !== ':') this.fail('JSON object is missing a member separator');
      this.index += 1;
      output[key] = this.value(depth + 1);
      this.whitespace();
      if (this.text[this.index] === '}') { this.index += 1; return output; }
      if (this.text[this.index] !== ',') this.fail('JSON object delimiter is invalid');
      this.index += 1;
    }
  }

  parse() {
    const result = this.value(0);
    this.whitespace();
    if (this.index !== this.text.length) this.fail('JSON has trailing data');
    this.deadline.checkpoint();
    return result;
  }
}

function inputText(input, limits) {
  if (typeof input === 'string') {
    if (input.length > limits.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
    if (Buffer.byteLength(input, 'utf8') > limits.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
    return input;
  }
  if (!(Buffer.isBuffer(input) || input instanceof Uint8Array)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON input must be text or bytes');
  }
  if (input.byteLength > limits.maxBytes) protocolError(RUNTIME_ERROR_CODES.LIMIT_EXCEEDED, 'JSON byte ceiling exceeded');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch (error) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON is not valid UTF-8 text', { cause: error });
  }
}

export function deepFreeze(value) {
  const stack = [value];
  const seen = new Set();
  while (stack.length > 0) {
    const item = stack.pop();
    if (item === null || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    for (const child of Object.values(item)) stack.push(child);
    Object.freeze(item);
  }
  return value;
}

export function parseJson(input, options = {}) {
  const limits = jsonLimits(options);
  const deadline = deadlineFrom(options);
  const inputBytes = typeof input === 'string'
    ? (input.length > limits.maxBytes ? limits.maxBytes + 1 : Buffer.byteLength(input, 'utf8'))
    : (Buffer.isBuffer(input) || input instanceof Uint8Array ? input.byteLength : 0);
  reserveJsonWorkingBytes(inputBytes, options);
  let text = inputText(input, limits);
  const trailingNewline = options.trailingNewline === true;
  if (trailingNewline) {
    if (!text.endsWith('\n') || text.endsWith('\r\n')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON document must end with one LF');
    text = text.slice(0, -1);
  }
  if (text.length === 0 || text.includes('\0')) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON text is empty or contains NUL');
  const value = new JsonParser(text, limits, deadline).parse();
  inspectJson(value, { ...limits, deadline });
  if (options.requireCanonical === true && canonicalJson(value, { ...limits, deadline }) !== text) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'JSON is not in RFC 8785 canonical form');
  }
  return deepFreeze(value);
}

export function parseCanonicalJson(input, options = {}) {
  return parseJson(input, { ...options, requireCanonical: true });
}

export function cloneJson(value, options = {}) {
  return parseCanonicalJson(canonicalJson(value, options), options);
}

export function sha256Bytes(value) {
  return createHash('sha256').update(value).digest();
}

export function sha256(value) {
  return sha256Bytes(value).toString('hex');
}

export function base64urlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

export function base64urlDecode(value, options = {}) {
  const maxBytes = boundedInteger(options.maxBytes, 4096, JSON_LIMITS.maxBytes, 'base64url maxBytes');
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3) + 2 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'base64url value is invalid');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maxBytes || bytes.toString('base64url') !== value) protocolError(RUNTIME_ERROR_CODES.INPUT_INVALID, 'base64url value is not canonical');
  return bytes;
}

export function equalBytes(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
