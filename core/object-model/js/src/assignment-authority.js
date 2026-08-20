import { fail } from './errors.js';

const KIND_NAME_AUTHORITIES = new WeakSet();
const LOGICAL_TYPE_AUTHORITIES = new WeakSet();
const TOKEN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

function readOnlyMap(entries) {
  const map = new Map(entries);
  const view = {
    get size() { return map.size; },
    get(key) { return map.get(key); },
    has(key) { return map.has(key); },
    entries() { return map.entries(); },
    keys() { return map.keys(); },
    values() { return map.values(); },
    forEach(callback, thisArg) {
      map.forEach((value, key) => callback.call(thisArg, value, key, view));
    },
    [Symbol.iterator]() { return map[Symbol.iterator](); }
  };
  return Object.freeze(view);
}

/** Internal factory: callers receive a view only after registry validation. */
export function createKindNameAuthority(entries) {
  const checked = [];
  const codes = new Set();
  const tokens = new Set();
  for (const [code, token] of entries) {
    if (!Number.isInteger(code) || code < 1 || code > 65_535 || codes.has(code) ||
        typeof token !== 'string' || !TOKEN.test(token) || Buffer.byteLength(token, 'utf8') > 63 ||
        tokens.has(token)) {
      fail('REGISTRY_INVALID', { layer: 3, stage: 'registry-semantics' });
    }
    codes.add(code); tokens.add(token); checked.push([code, token]);
  }
  const view = readOnlyMap(checked);
  KIND_NAME_AUTHORITIES.add(view);
  return view;
}

export function isKindNameAuthority(value) {
  try { return value !== null && typeof value === 'object' && KIND_NAME_AUTHORITIES.has(value); }
  catch { return false; }
}

/** Internal factory for logical-record identity assignment authority. */
export function createLogicalTypeAuthority(codes) {
  const set = new Set();
  for (const code of codes) {
    if (!Number.isInteger(code) || code < 1 || code > 65_535 || set.has(code)) {
      fail('REGISTRY_INVALID', { layer: 3, stage: 'registry-semantics' });
    }
    set.add(code);
  }
  const view = Object.freeze({
    get size() { return set.size; },
    has(code) { return set.has(code); },
    values() { return set.values(); },
    [Symbol.iterator]() { return set[Symbol.iterator](); }
  });
  LOGICAL_TYPE_AUTHORITIES.add(view);
  return view;
}

export function isLogicalTypeAuthority(value) {
  try { return value !== null && typeof value === 'object' && LOGICAL_TYPE_AUTHORITIES.has(value); }
  catch { return false; }
}

export const FROZEN_KIND_NAMES = createKindNameAuthority([
  [1, 'chunk'], [2, 'content-manifest'], [3, 'tree'], [4, 'change-set'],
  [5, 'asset-group-set'], [6, 'repository-descriptor'], [7, 'snapshot'],
  [8, 'shelf-revision'], [9, 'provenance'], [10, 'attestation'], [11, 'conflict-set']
]);

export const FROZEN_LOGICAL_TYPES = createLogicalTypeAuthority([1, 2, 3, 4, 5, 6, 7, 8, 9]);
