import { encodeCanonical } from './cbor.js';
import { fail } from './errors.js';
import { FROZEN_KIND_NAMES, isKindNameAuthority } from './assignment-authority.js';

const PROFILE_TOKEN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const PROFILE_NAMESPACE = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:-[a-z0-9]+)*)+$/;
const FILE_ID = /^fid:([0-9a-f]{32})$/;

export const KIND_NAMES = FROZEN_KIND_NAMES;

function kindAuthority(value) {
  if (!isKindNameAuthority(value)) {
    fail('SCHEMA_FIELD_INVALID', { layer: 1, stage: 'configured-resource-preflight' });
  }
  return value;
}

function hexBytes(text) { return Uint8Array.from(text.match(/../g), pair => Number.parseInt(pair, 16)); }
export function toHex(value) { return Buffer.from(value).toString('hex'); }
export function equalBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

function mapShape(value, keys) {
  if (!(value instanceof Map) || value.size !== keys.length || keys.some(k => !value.has(k))) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
}
function u32(value) {
  if ((typeof value !== 'number' || !Number.isSafeInteger(value)) && typeof value !== 'bigint') fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  const n = BigInt(value);
  if (n < 1n || n > 0xffff_ffffn) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return Number(n);
}
function digestBytes(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
  return value.slice();
}

export class Digest {
  #bytes;

  constructor(algorithm, value) {
    if (algorithm !== 1) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.algorithm = 1;
    this.#bytes = digestBytes(value);
    Object.freeze(this);
  }
  get bytes() { return this.#bytes.slice(); }
  static fromMap(value) { mapShape(value, [0, 1]); return new Digest(value.get(0), value.get(1)); }
  toMap() { return new Map([[0, 1], [1, this.#bytes.slice()]]); }
}

export class ProfileRef {
  constructor(namespace, id, major) {
    if (typeof namespace !== 'string' || !PROFILE_NAMESPACE.test(namespace) || Buffer.byteLength(namespace) > 253 ||
        typeof id !== 'string' || !PROFILE_TOKEN.test(id) || Buffer.byteLength(id) > 63) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    this.namespace = namespace; this.id = id; this.major = u32(major); Object.freeze(this);
  }
  static parse(text) {
    if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 328) {
      fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    const match = /^([^/@]+)\/([^/@]+)@([1-9][0-9]*)$/.exec(text);
    if (!match || match[3].length > 10) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    let major;
    try { major = BigInt(match[3]); } catch { fail('SCHEMA_FIELD_INVALID', { layer: 2 }); }
    return new ProfileRef(match[1], match[2], major);
  }
  static fromMap(value) { mapShape(value, [0, 1, 2]); return new ProfileRef(value.get(0), value.get(1), value.get(2)); }
  toMap() { return new Map([[0, this.namespace], [1, this.id], [2, this.major]]); }
  toString() { return `${this.namespace}/${this.id}@${this.major}`; }
  canonicalBytes() { return encodeCanonical(this.toMap()); }
}

export class ObjectRef {
  #digest;

  constructor(kind, digest, registry = KIND_NAMES, { allowUnknownKind = false } = {}) {
    registry = kindAuthority(registry);
    if (!Number.isInteger(kind) || kind < 1 || kind > 65535) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    if (!registry.has(kind) && !allowUnknownKind) fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
    this.format = 1;
    this.kind = kind;
    this.algorithm = 1;
    this.#digest = digestBytes(digest);
    this.kindName = registry.get(kind);
    if (this.kindName !== undefined && (typeof this.kindName !== 'string' || !PROFILE_TOKEN.test(this.kindName))) {
      fail('REGISTRY_INVALID', { layer: 3 });
    }
    Object.freeze(this);
  }
  get digest() { return this.#digest.slice(); }
  static parse(text, registry = KIND_NAMES) {
    registry = kindAuthority(registry);
    // The longest valid form is 144 ASCII bytes with a 63-byte kind token.
    // Reject before split so hostile colon-dense input cannot amplify memory.
    if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 144) {
      fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    }
    const parts = text.split(':');
    if (parts[0] !== 'ogvcs' || parts[1] !== 'v1') fail('OBJECT_REFERENCE_FORMAT_UNSUPPORTED', { layer: 2 });
    const entry = [...registry].find(([, name]) => name === parts[2]);
    if (!entry) fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
    if (parts[3] !== 'sha256') fail('OBJECT_REFERENCE_FORMAT_UNSUPPORTED', { layer: 2 });
    if (parts.length !== 5 || !/^[0-9a-f]{64}$/.test(parts[4])) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    return new ObjectRef(entry[0], hexBytes(parts[4]), registry);
  }
  static fromMap(value, registry = KIND_NAMES, { allowUnknownKind = false } = {}) {
    registry = kindAuthority(registry);
    mapShape(value, [0, 1, 2, 3]);
    if (value.get(0) !== 1) fail('OBJECT_REFERENCE_FORMAT_UNSUPPORTED', { layer: 2 });
    if (value.get(2) !== 1) fail('OBJECT_REFERENCE_FORMAT_UNSUPPORTED', { layer: 2 });
    const kind = value.get(1);
    if (allowUnknownKind && Number.isInteger(kind) && kind > 0 && kind <= 65535 && !registry.has(kind)) {
      return new ObjectRef(kind, value.get(3), registry, { allowUnknownKind: true });
    }
    return new ObjectRef(kind, value.get(3), registry);
  }
  toMap() { return new Map([[0, 1], [1, this.kind], [2, 1], [3, this.#digest.slice()]]); }
  toString() {
    if (!this.kindName) fail('OBJECT_KIND_UNSUPPORTED', { layer: 2 });
    return `ogvcs:v1:${this.kindName}:sha256:${toHex(this.#digest)}`;
  }
}

export class FileId {
  #bytes;

  constructor(value) {
    if (!(value instanceof Uint8Array) || value.length !== 16) fail('SCHEMA_FIELD_INVALID', { layer: 2 });
    if (value.every(byte => byte === 0)) fail('FILEID_ZERO', { layer: 2 });
    this.#bytes = value.slice();
    Object.freeze(this);
  }
  get bytes() { return this.#bytes.slice(); }
  static parse(text) { const match = typeof text === 'string' && FILE_ID.exec(text); if (!match) fail('SCHEMA_FIELD_INVALID', { layer: 2 }); return new FileId(hexBytes(match[1])); }
  toString() { return `fid:${toHex(this.#bytes)}`; }
}

export const profileGrammar = Object.freeze({ token: PROFILE_TOKEN, namespace: PROFILE_NAMESPACE });
