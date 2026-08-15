import { createHash } from 'node:crypto';

const DOMAIN_PATTERN = /^[a-z0-9][a-z0-9./_-]{0,126}$/;

/**
 * Serialize the JSON data model with lexicographically ordered object keys.
 *
 * Numbers are intentionally restricted to finite safe integers. Fixture
 * contracts represent large exact values as integers within that range; this
 * avoids platform/runtime-specific rounding from becoming part of an ID.
 * Object keys are sorted by JavaScript's specified UTF-16 code-unit ordering.
 * Strings are preserved exactly; callers that model paths
 * must normalize them before canonicalization.
 */
export function canonicalStringify(value) {
  const ancestors = new Set();

  function encode(current, path) {
    if (current === null) return 'null';

    switch (typeof current) {
      case 'boolean':
        return current ? 'true' : 'false';
      case 'string':
        return JSON.stringify(current);
      case 'number':
        if (!Number.isSafeInteger(current)) {
          throw new TypeError(`Canonical JSON requires a safe integer at ${path}`);
        }
        return Object.is(current, -0) ? '0' : String(current);
      case 'object':
        break;
      default:
        throw new TypeError(`Unsupported canonical JSON value at ${path}`);
    }

    if (ancestors.has(current)) {
      throw new TypeError(`Circular canonical JSON value at ${path}`);
    }
    ancestors.add(current);

    try {
      if (Array.isArray(current)) {
        return `[${current.map((item, index) => encode(item, `${path}[${index}]`)).join(',')}]`;
      }

      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError(`Canonical JSON requires a plain object at ${path}`);
      }

      const keys = Object.keys(current).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(current[key], `${path}.${key}`)}`).join(',')}}`;
    } finally {
      ancestors.delete(current);
    }
  }

  return encode(value, '$');
}

/** Return the canonical UTF-8 representation of a JSON value. */
export function canonicalBytes(value) {
  return Buffer.from(canonicalStringify(value), 'utf8');
}

/**
 * Return a domain-separated SHA-256 digest in lowercase hexadecimal form.
 * The preimage is `domain || NUL || canonical-json`.
 */
export function canonicalDigest(value, domain = 'ogvcs.fixture/canonical/v1') {
  assertDomain(domain);
  return createHash('sha256')
    .update(domain, 'ascii')
    .update(Buffer.from([0]))
    .update(canonicalBytes(value))
    .digest('hex');
}

/** Recursively clone a JSON value while rejecting unsupported data. */
export function canonicalClone(value) {
  return JSON.parse(canonicalStringify(value));
}

function assertDomain(domain) {
  if (typeof domain !== 'string' || !DOMAIN_PATTERN.test(domain)) {
    throw new TypeError('Digest domain must be a lowercase ASCII identifier of 1-127 characters');
  }
}
