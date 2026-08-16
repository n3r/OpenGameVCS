import { createHash } from 'node:crypto';

import { pathContract } from './contract.mjs';
import { PathFilesystemError, errorDecision, pathFail } from './errors.mjs';
import { findPathCollisions, isUnicodeScalarString, validateRepositoryPath } from './path.mjs';

const ENTRY_MODES = Object.freeze({ directory: 'directory', regular: 'regular-file', executable: 'executable-file', symlink: 'symlink' });
const SAFE_DIAGNOSTIC_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new TypeError('value outside canonical plan domain');
}

function canonicalArraySha256(values) {
  const hash = createHash('sha256');
  hash.update('[');
  for (let index = 0; index < values.length; index += 1) {
    if (index > 0) hash.update(',');
    hash.update(canonicalJson(values[index]));
  }
  hash.update(']\n');
  return hash.digest('hex');
}

function safeSymlinkTarget(target, linkPath) {
  if (!isUnicodeScalarString(target) || target.length === 0 || target.startsWith('/') || /^[A-Za-z]:/u.test(target) || target.includes('\\') || target.includes('\0') || target.normalize('NFC') !== target || Buffer.byteLength(target, 'utf8') > 4096) return false;
  let depth = linkPath.split('/').length - 1;
  for (const segment of target.split('/')) {
    if (segment === '' || segment === '.') return false;
    if (segment === '..') { depth -= 1; if (depth < 0) return false; } else depth += 1;
  }
  return true;
}

export function preflightMaterialization(request, options = {}) {
  if (!exactKeys(request, ['schemaVersion', 'caseMode', 'profile', 'platform', 'capabilities', 'entries']) || request.schemaVersion !== 'ogvcs.path/preflight-request/v1'
    || !exactKeys(request.capabilities, ['atomicReplace', 'executableBit', 'symlink'])
    || Object.values(request.capabilities).some((value) => typeof value !== 'boolean')) pathFail('PATH_INPUT_INVALID');
  const profile = pathContract.profiles.find(({ profile: value }) => value === request.profile);
  if (profile === undefined) pathFail('PATH_PROFILE_UNKNOWN');
  if (!profile.platforms.includes(request.platform)) pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'platform-profile' });
  if (request.capabilities?.atomicReplace !== true) pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'atomic-replace' });
  const maximum = options.maxEntries ?? 100_000;
  if (!Array.isArray(request.entries) || !Number.isSafeInteger(maximum) || maximum < 0 || request.entries.length > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'entries' });
  for (let index = 0; index < request.entries.length; index += 1) {
    const entry = request.entries[index];
    const keys = entry?.kind === 'symlink' ? ['id', 'path', 'kind', 'mode', 'symlinkTarget'] : ['id', 'path', 'kind', 'mode'];
    if (!exactKeys(entry, keys) || typeof entry.id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(entry.id)) pathFail('ENTRY_INVALID', undefined, { entry: index });
  }
  findPathCollisions(request.entries.map((entry, index) => ({ id: entry?.id ?? String(index), path: entry?.path })), { caseMode: request.caseMode, profile: request.profile, maxPaths: maximum });
  const byPath = new Map(); const normalized = [];
  let symlinks = 0; let executable = 0;
  for (let index = 0; index < request.entries.length; index += 1) {
    const entry = request.entries[index];
    if (!Object.hasOwn(ENTRY_MODES, entry.kind) || entry.mode !== ENTRY_MODES[entry.kind]) pathFail('ENTRY_INVALID', undefined, { entry: index });
    const path = validateRepositoryPath(entry.path, { profile: request.profile }).canonical;
    if (entry.kind === 'symlink') {
      symlinks += 1;
      if (request.capabilities?.symlink !== true) pathFail('CAPABILITY_UNAVAILABLE', undefined, { capability: 'symlink', entry: index });
      if (!safeSymlinkTarget(entry.symlinkTarget, path)) pathFail('SYMLINK_FORBIDDEN', undefined, { entry: index });
    } else if (entry.symlinkTarget !== undefined) pathFail('ENTRY_INVALID', undefined, { entry: index });
    if (entry.kind === 'executable') executable += 1;
    byPath.set(path, { kind: entry.kind, index });
    normalized.push(Object.freeze({ id: entry.id, kind: entry.kind, mode: entry.mode, path, ...(entry.symlinkTarget === undefined ? {} : { symlinkTarget: entry.symlinkTarget }) }));
  }
  for (let index = 0; index < normalized.length; index += 1) {
    const parent = normalized[index].path.includes('/') ? normalized[index].path.slice(0, normalized[index].path.lastIndexOf('/')) : null;
    if (parent !== null && byPath.get(parent)?.kind !== 'directory') pathFail('ENTRY_INVALID', undefined, { entry: index, rule: 'parent-directory' });
  }
  const planSha256 = canonicalArraySha256(normalized);
  return Object.freeze({
    request: Object.freeze({ caseMode: request.caseMode, profile: request.profile, platform: request.platform }),
    entries: Object.freeze(normalized),
    summary: Object.freeze({ entries: normalized.length, executable, symlinks, nativeExecutableBits: request.capabilities.executableBit === true ? executable : 0, planSha256 }),
  });
}

export function evaluatePreflight(request, options = {}) {
  try { return Object.freeze({ accepted: true, summary: preflightMaterialization(request, options).summary }); }
  catch (error) { if (!(error instanceof PathFilesystemError)) throw error; return errorDecision(error); }
}
