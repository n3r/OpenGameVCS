import { types as utilTypes } from 'node:util';

import { canonicalDigest, canonicalJson, deepFreeze } from './canonical.mjs';
import { harnessFail } from './errors.mjs';

const CREDENTIAL_KEY = /(?:authorization|credential|password|private.?key|secret|session.?token|access.?token|refresh.?token)/iu;
const PARTNER_KEY = /(?:partner|studio|customer|operator)(?:Id|Identifier|Name)?$/iu;
const REDACTED_IDENTIFIER = /^sha256:[0-9a-f]{64}$/u;
const MAX_NODES = 100_000;
const MAX_DEPTH = 32;
const MAX_ARRAY_ITEMS = 4_096;
const MAX_PROPERTIES = 256;

function scalarText(value, label) {
  if (typeof value !== 'string' || value.length > 65_536 || value.includes('\0') || value.normalize('NFC') !== value || /[\uD800-\uDFFF]/u.test(value)) harnessFail('HARNESS_INPUT_INVALID', `publication ${label} is not bounded scalar NFC text`);
  return value;
}

function snapshot(input) {
  try {
    if (utilTypes.isProxy(input)) harnessFail('HARNESS_INPUT_INVALID', 'publication input cannot contain a Proxy');
    const prototype = Object.getPrototypeOf(input);
    const descriptors = Object.getOwnPropertyDescriptors(input);
    const keys = Reflect.ownKeys(input);
    if (keys.some((key) => typeof key !== 'string')) harnessFail('HARNESS_INPUT_INVALID', 'publication input cannot contain symbol properties');
    if (Array.isArray(input)) {
      if (prototype !== Array.prototype || input.length > MAX_ARRAY_ITEMS || keys.length !== input.length + 1 || !keys.includes('length')) harnessFail('HARNESS_INPUT_INVALID', 'publication arrays must be bounded dense inert arrays');
      const values = [];
      for (let index = 0; index < input.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) harnessFail('HARNESS_INPUT_INVALID', 'publication arrays cannot contain accessors or hidden elements');
        values.push(descriptor.value);
      }
      return { kind: 'array', values };
    }
    if (prototype !== Object.prototype && prototype !== null || keys.length > MAX_PROPERTIES) harnessFail('HARNESS_INPUT_INVALID', 'publication objects must be bounded plain inert records');
    const values = [];
    for (const key of keys.sort()) {
      scalarText(key, 'property name');
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) harnessFail('HARNESS_INPUT_INVALID', 'publication objects cannot contain accessors or hidden properties');
      values.push([key, descriptor.value]);
    }
    return { kind: 'object', values };
  } catch (error) {
    if (error?.code?.startsWith?.('HARNESS_')) throw error;
    harnessFail('HARNESS_INPUT_INVALID', 'publication input could not be inspected without executing caller code', { cause: error });
  }
}

export function redactPublicData(value) {
  const state = { credentialsRemoved: 0, partnerIdentifiersHashed: 0, nodes: 0 };
  const ancestors = new Set();
  function visit(input, key = '', depth = 0) {
    state.nodes += 1;
    if (state.nodes > MAX_NODES || depth > MAX_DEPTH) harnessFail('HARNESS_LIMIT_EXCEEDED', 'publication redaction data bounds exceeded');
    if (CREDENTIAL_KEY.test(key)) { state.credentialsRemoved += 1; return undefined; }
    if (input === null || typeof input === 'boolean') return input;
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input)) harnessFail('HARNESS_INPUT_INVALID', 'publication numbers must be safe integers');
      return Object.is(input, -0) ? 0 : input;
    }
    if (typeof input === 'string') {
      scalarText(input, 'text');
      if (PARTNER_KEY.test(key) && REDACTED_IDENTIFIER.test(input)) return input;
      if (PARTNER_KEY.test(key)) { state.partnerIdentifiersHashed += 1; return `sha256:${canonicalDigest(input, 'ogvcs.benchmark/partner-identifier/v1')}`; }
      return input;
    }
    if (typeof input !== 'object') harnessFail('HARNESS_INPUT_INVALID', 'publication input contains non-JSON data');
    if (ancestors.has(input)) harnessFail('HARNESS_INPUT_INVALID', 'publication input contains a cycle');
    ancestors.add(input);
    const source = snapshot(input);
    let output;
    if (source.kind === 'array') {
      output = [];
      for (const child of source.values) {
        const value = visit(child, '', depth + 1);
        if (value !== undefined) output.push(value);
      }
    } else {
      output = {};
      for (const [name, child] of source.values) {
        const redacted = visit(child, name, depth + 1);
        if (redacted !== undefined) Object.defineProperty(output, name, { configurable: true, enumerable: true, value: redacted, writable: true });
      }
    }
    ancestors.delete(input);
    return output;
  }
  const output = visit(value);
  canonicalJson(output, { maxBytes: 1_048_576, maxNodes: MAX_NODES, maxDepth: MAX_DEPTH, maxWorkingMemoryBytes: 8_388_608 });
  return deepFreeze({ value: output, credentialsRemoved: state.credentialsRemoved, partnerIdentifiersHashed: state.partnerIdentifiersHashed });
}
