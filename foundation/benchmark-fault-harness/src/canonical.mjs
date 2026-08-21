import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { inspectJson, parseJson } from '@opengamevcs/protocol-baseline';

export { inspectJson, parseJson };

const MAX_CANONICAL_BYTES = 67_108_864;
const MAX_CANONICAL_NODES = 2_500_000;
const MAX_CANONICAL_DEPTH = 64;
const MAX_WORKING_MEMORY_BYTES = 268_435_456;

export function codeUnitCompare(left, right) { return left < right ? -1 : left > right ? 1 : 0; }

function boundedOption(value, fallback, maximum, name) {
  const result = value ?? fallback;
  if (!Number.isSafeInteger(result) || result < 1 || result > maximum) throw new TypeError(`${name} is outside the benchmark canonical bound`);
  return result;
}

function ownData(value) {
  try {
    if (utilTypes.isProxy(value)) throw new TypeError('benchmark canonical data cannot contain a Proxy');
    return { keys: Reflect.ownKeys(value), descriptors: Object.getOwnPropertyDescriptors(value) };
  } catch (error) {
    if (error instanceof TypeError && error.message.startsWith('benchmark canonical')) throw error;
    throw new TypeError('benchmark canonical container cannot be inspected safely', { cause: error });
  }
}

export function canonicalJson(value, options = {}) {
  const maximumBytes = boundedOption(options.maxBytes, MAX_CANONICAL_BYTES, MAX_CANONICAL_BYTES, 'maxBytes');
  const maximumNodes = boundedOption(options.maxNodes, MAX_CANONICAL_NODES, MAX_CANONICAL_NODES, 'maxNodes');
  const maximumDepth = boundedOption(options.maxDepth, MAX_CANONICAL_DEPTH, MAX_CANONICAL_DEPTH, 'maxDepth');
  const maximumWorking = boundedOption(options.maxWorkingMemoryBytes, MAX_WORKING_MEMORY_BYTES, MAX_WORKING_MEMORY_BYTES, 'maxWorkingMemoryBytes');
  const seen = new Set();
  let nodes = 0;
  let encodedBytes = 0;
  let retainedTextBytes = 0;
  const addBytes = (count) => {
    encodedBytes += count;
    if (!Number.isSafeInteger(encodedBytes) || encodedBytes > maximumBytes) throw new TypeError('value exceeds canonical benchmark byte bounds');
  };
  const capacity = (bytes) => {
    const result = bytes * 2 + 64;
    if (!Number.isSafeInteger(result)) throw new TypeError('value exceeds canonical benchmark working-memory bounds');
    return result;
  };
  const retain = (bytes) => {
    retainedTextBytes += bytes;
    if (!Number.isSafeInteger(retainedTextBytes) || retainedTextBytes + 256 > maximumWorking) throw new TypeError('value exceeds canonical benchmark working-memory bounds');
  };
  const release = (bytes) => { retainedTextBytes -= bytes; };
  const encodedStringBytes = (input) => {
    let bytes = 2;
    for (let index = 0; index < input.length; index += 1) {
      const code = input.charCodeAt(index);
      if (code === 0x22 || code === 0x5c || code === 0x08 || code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d) bytes += 2;
      else if (code < 0x20) bytes += 6;
      else if (code < 0x80) bytes += 1;
      else if (code < 0x800) bytes += 2;
      else if (code >= 0xd800 && code <= 0xdbff) { bytes += 4; index += 1; }
      else bytes += 3;
      if (!Number.isSafeInteger(bytes) || bytes > maximumBytes) throw new TypeError('value exceeds canonical benchmark byte bounds');
    }
    return bytes;
  };
  const scalar = (input, knownBytes) => {
    const bytes = knownBytes ?? Buffer.byteLength(String(input));
    addBytes(bytes);
    const retained = capacity(bytes); retain(retained);
    const text = String(input);
    return { text, bytes, retained };
  };
  const stringScalar = (input) => {
    const bytes = encodedStringBytes(input);
    addBytes(bytes);
    const retained = capacity(bytes); retain(retained);
    const text = JSON.stringify(input);
    if (Buffer.byteLength(text) !== bytes) throw new TypeError('benchmark canonical string accounting invariant failed');
    return { text, bytes, retained };
  };
  function encode(input, depth) {
    nodes += 1;
    if (nodes > maximumNodes || depth > maximumDepth) throw new TypeError('value exceeds canonical benchmark data bounds');
    if (input === null) return scalar('null', 4);
    if (typeof input === 'boolean') return scalar(input ? 'true' : 'false', input ? 4 : 5);
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input)) throw new TypeError('benchmark canonical numbers must be safe integers');
      const output = Object.is(input, -0) ? '0' : String(input);
      return scalar(output, output.length);
    }
    if (typeof input === 'string') {
      if (input.length + 2 > maximumBytes || input.length * 2 + 320 > maximumWorking) throw new TypeError('value exceeds canonical benchmark byte or working-memory bounds');
      if (input.normalize('NFC') !== input || /[\uD800-\uDFFF]/u.test(input)) throw new TypeError('benchmark canonical strings must be scalar NFC text');
      return stringScalar(input);
    }
    if (typeof input !== 'object') throw new TypeError('value is outside benchmark canonical JSON');
    const { keys, descriptors } = ownData(input);
    if (seen.has(input)) throw new TypeError('benchmark canonical data contains a cycle');
    seen.add(input);
    let output;
    if (Array.isArray(input)) {
      if (keys.some((key) => typeof key !== 'string') || keys.length !== input.length + 1 || !keys.includes('length')) throw new TypeError('benchmark canonical arrays must be dense and have no extra properties');
      const punctuationBytes = 2 + Math.max(0, input.length - 1); addBytes(punctuationBytes);
      let bytes = punctuationBytes; let childrenRetained = 0; const parts = ['['];
      for (let index = 0; index < input.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) throw new TypeError('benchmark canonical arrays cannot contain accessors or hidden elements');
        if (index > 0) parts.push(',');
        const child = encode(descriptor.value, depth + 1); bytes += child.bytes; childrenRetained += child.retained; parts.push(child.text);
      }
      parts.push(']'); const retained = capacity(bytes); retain(retained); const text = parts.join(''); release(childrenRetained); output = { text, bytes, retained };
    } else {
      const prototype = Object.getPrototypeOf(input);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError('benchmark canonical objects must be plain data');
      if (keys.some((key) => typeof key !== 'string')) throw new TypeError('benchmark canonical objects cannot contain symbol properties');
      const punctuationBytes = 2 + Math.max(0, keys.length - 1) + keys.length; addBytes(punctuationBytes);
      let bytes = punctuationBytes; let childrenRetained = 0; const parts = ['{']; let index = 0;
      for (const key of [...keys].sort()) {
        const descriptor = descriptors[key];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) throw new TypeError('benchmark canonical objects cannot contain accessors or hidden properties');
        if (key.length + 2 > maximumBytes || key.length * 2 + 320 > maximumWorking) throw new TypeError('benchmark canonical key exceeds its byte or working-memory bounds');
        if (key.normalize('NFC') !== key || /[\uD800-\uDFFF]/u.test(key)) throw new TypeError('benchmark canonical keys must be scalar NFC text');
        if (index > 0) parts.push(','); index += 1;
        const encodedKey = stringScalar(key); const child = encode(descriptor.value, depth + 1);
        bytes += encodedKey.bytes + child.bytes; childrenRetained += encodedKey.retained + child.retained;
        parts.push(encodedKey.text, ':', child.text);
      }
      parts.push('}'); const retained = capacity(bytes); retain(retained); const text = parts.join(''); release(childrenRetained); output = { text, bytes, retained };
    }
    seen.delete(input);
    return output;
  }
  const output = encode(value, 0);
  if (output.bytes !== encodedBytes || Buffer.byteLength(output.text) !== encodedBytes || retainedTextBytes !== output.retained) throw new TypeError('benchmark canonical byte accounting invariant failed');
  return output.text;
}

export function canonicalBytes(value, options = {}) {
  const maximumWorking = boundedOption(options.maxWorkingMemoryBytes, MAX_WORKING_MEMORY_BYTES, MAX_WORKING_MEMORY_BYTES, 'maxWorkingMemoryBytes');
  const text = canonicalJson(value, { ...options, maxWorkingMemoryBytes: maximumWorking });
  const byteLength = Buffer.byteLength(text);
  if (byteLength * 3 + 320 > maximumWorking) throw new TypeError('value exceeds canonical benchmark aggregate output working-memory bounds');
  return Buffer.from(text, 'utf8');
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalDigest(value, domain = 'ogvcs.benchmark/value/v1') {
  const hash = createHash('sha256');
  hash.update(domain, 'utf8');
  hash.update(Buffer.from([0]));
  hash.update(canonicalBytes(value));
  return hash.digest('hex');
}

export function canonicalSequenceDigest(values, domain = 'ogvcs.benchmark/sequence/v1') {
  if (!Array.isArray(values)) throw new TypeError('benchmark canonical sequence must be an array');
  const hash = createHash('sha256');
  hash.update(domain, 'utf8');
  hash.update(Buffer.from([0]));
  for (const value of values) {
    const bytes = canonicalBytes(value, { maxBytes: 1_048_576, maxWorkingMemoryBytes: 8_388_608 });
    const length = Buffer.allocUnsafe(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest('hex');
}

export function cloneData(value) {
  return JSON.parse(canonicalJson(value));
}

export function parseLargeCanonical(input, options = {}) {
  const maximum = boundedOption(options.maxBytes, MAX_CANONICAL_BYTES, MAX_CANONICAL_BYTES, 'maxBytes');
  const maximumWorking = boundedOption(options.maxWorkingMemoryBytes, MAX_WORKING_MEMORY_BYTES, MAX_WORKING_MEMORY_BYTES, 'maxWorkingMemoryBytes');
  if (typeof input !== 'string' && !Buffer.isBuffer(input) && !(input instanceof Uint8Array)) throw new TypeError('benchmark JSON input must be text or bytes');
  const sourceBytes = Buffer.isBuffer(input) || input instanceof Uint8Array ? input.byteLength : Buffer.byteLength(input, 'utf8');
  if (sourceBytes < 1 || sourceBytes > maximum || sourceBytes * 10 + 256 > maximumWorking) throw new TypeError('benchmark JSON exceeds its byte or aggregate working-memory bound');
  const bytes = Buffer.isBuffer(input) || input instanceof Uint8Array ? Buffer.from(input) : Buffer.from(input, 'utf8');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) { throw new TypeError('benchmark JSON is not UTF-8', { cause: error }); }
  let value;
  try { value = JSON.parse(text); } catch (error) { throw new TypeError('benchmark JSON is malformed', { cause: error }); }
  const retainedInputWorking = bytes.length * 7 + 256;
  if (canonicalJson(value, { maxBytes: maximum, maxWorkingMemoryBytes: maximumWorking - retainedInputWorking }) !== text) throw new TypeError('benchmark JSON is not canonical');
  return deepFreeze(value);
}

export function deepFreeze(value) {
  const stack = [value]; const seen = new WeakSet(); let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === null || typeof current !== 'object' || seen.has(current)) continue;
    if (utilTypes.isProxy(current)) throw new TypeError('benchmark data cannot contain a Proxy');
    seen.add(current); nodes += 1;
    if (nodes > MAX_CANONICAL_NODES) throw new TypeError('benchmark data exceeds its freeze traversal bound');
    const prototype = Object.getPrototypeOf(current);
    if (Array.isArray(current) || prototype === Object.prototype || prototype === null) {
      const { descriptors } = ownData(current);
      for (const descriptor of Object.values(descriptors)) if (Object.hasOwn(descriptor, 'value')) stack.push(descriptor.value);
    }
    if (!Object.isFrozen(current)) Object.freeze(current);
  }
  return value;
}
