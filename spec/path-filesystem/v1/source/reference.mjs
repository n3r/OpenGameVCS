import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const encoder = new TextEncoder();
const SAFE_DIAGNOSTIC_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

export const CORE_LIMITS = Object.freeze({
  segmentUtf8Bytes: 255,
  joinedUtf8Bytes: 4096,
  depth: 256,
});

export function canonicalJson(value) {
  const seen = new Set();
  const encode = (current) => {
    if (current === null || typeof current === 'boolean') return JSON.stringify(current);
    if (typeof current === 'string') {
      assertUnicodeScalarString(current, 'canonical JSON string');
      return JSON.stringify(current);
    }
    if (typeof current === 'number') {
      if (!Number.isSafeInteger(current)) throw new TypeError('canonical JSON numbers must be safe integers');
      return String(current);
    }
    if (Array.isArray(current)) {
      if (seen.has(current)) throw new TypeError('canonical JSON cannot contain a cycle');
      seen.add(current);
      const encoded = `[${current.map(encode).join(',')}]`;
      seen.delete(current);
      return encoded;
    }
    if (current !== null && typeof current === 'object' && Object.getPrototypeOf(current) === Object.prototype) {
      if (seen.has(current)) throw new TypeError('canonical JSON cannot contain a cycle');
      seen.add(current);
      const encoded = `{${Object.keys(current).sort().map((key) => `${JSON.stringify(key)}:${encode(current[key])}`).join(',')}}`;
      seen.delete(current);
      return encoded;
    }
    throw new TypeError('canonical JSON contains an unsupported value');
  };
  return encode(value);
}

export function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function assertUnicodeScalarString(value, label = 'value') {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`);
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError(`${label} contains an unpaired surrogate`);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError(`${label} contains an unpaired surrogate`);
    }
  }
}

export function parseCaseFolding(text) {
  const mappings = new Map();
  for (const line of text.split('\n')) {
    const body = line.split('#', 1)[0].trim();
    if (!body) continue;
    const match = /^([0-9A-F]{4,6});\s*([CFST]);\s*([0-9A-F ]+);$/u.exec(body);
    if (!match) throw new Error(`invalid CaseFolding line: ${line}`);
    const [, sourceHex, status, mappingHex] = match;
    if (status !== 'C' && status !== 'F') continue;
    const source = Number.parseInt(sourceHex, 16);
    const mapping = mappingHex.trim().split(/ +/u).map((part) => Number.parseInt(part, 16));
    if (mappings.has(source)) throw new Error(`duplicate full case-fold mapping U+${sourceHex}`);
    mappings.set(source, Object.freeze(mapping));
  }
  return mappings;
}

export const CASE_FOLDING_SOURCE = readFileSync(resolve(ROOT, 'data/CaseFolding-16.0.0.txt'), 'utf8');
export const CASE_FOLDING = parseCaseFolding(CASE_FOLDING_SOURCE);

export function caseFoldV1(value) {
  assertUnicodeScalarString(value, 'case-fold input');
  let result = '';
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0);
    const mapping = CASE_FOLDING.get(codePoint);
    result += mapping === undefined ? scalar : String.fromCodePoint(...mapping);
  }
  return result;
}

export function utf8Length(value) {
  return encoder.encode(value).length;
}

const WINDOWS_FORBIDDEN = /[<>:"\\|?*]/u;
const OPERATIONAL_CONTROL = /[\u0000-\u001f\u007f]/u;
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
  'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³',
]);

function fail(code, detail = {}) {
  return Object.keys(detail).length === 0 ? { accepted: false, error: code } : { accepted: false, error: code, detail };
}

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

export function pathSegments(input) {
  if (Array.isArray(input)) return [...input];
  if (typeof input !== 'string') return null;
  if (input.length === 0 || input.startsWith('/')) return null;
  return input.split('/');
}

function windowsDevice(segment) {
  const basename = segment.split('.', 1)[0].toUpperCase();
  return WINDOWS_DEVICE_NAMES.has(basename);
}

function profileByRef(profiles, profileRef) {
  return profiles.find((profile) => profile.profile === profileRef);
}

export function validatePath(input, profileRef, profiles) {
  const profile = profileByRef(profiles, profileRef);
  if (profile === undefined) return fail('PATH_PROFILE_UNKNOWN');
  const segments = pathSegments(input);
  if (segments === null || segments.length === 0) return fail('PATH_INPUT_INVALID');
  if (segments.length > CORE_LIMITS.depth || segments.length > profile.limits.depth) {
    return fail('PATH_LIMIT_EXCEEDED', { resource: 'depth' });
  }
  let joinedUtf8 = Math.max(0, segments.length - 1);
  let joinedUtf16 = Math.max(0, segments.length - 1);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    try {
      assertUnicodeScalarString(segment, 'path segment');
    } catch {
      return fail('PATH_INPUT_INVALID', { segment: index });
    }
    if (segment.length === 0 || segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\\') || segment.includes('\0')) {
      return fail('PATH_INPUT_INVALID', { segment: index });
    }
    if (segment.normalize('NFC') !== segment) return fail('PATH_NOT_NFC', { segment: index });
    const bytes = utf8Length(segment);
    if (bytes > CORE_LIMITS.segmentUtf8Bytes || bytes > profile.limits.segmentUtf8Bytes || segment.length > profile.limits.segmentUtf16Units) {
      return fail('PATH_LIMIT_EXCEEDED', { resource: 'segment', segment: index });
    }
    joinedUtf8 += bytes;
    joinedUtf16 += segment.length;
    if (OPERATIONAL_CONTROL.test(segment)) return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'control', segment: index });
    if (segment === '.ogvcs') return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'workspace-reserved', segment: index });
    if (profile.rules.windowsNames) {
      if (WINDOWS_FORBIDDEN.test(segment)) return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-character', segment: index });
      if (/[. ]$/u.test(segment)) return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-trailing', segment: index });
      if (windowsDevice(segment)) return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-device', segment: index });
    } else if (profile.rules.macosColon && segment.includes(':')) {
      return fail('PATH_PLATFORM_FORBIDDEN', { rule: 'macos-colon', segment: index });
    }
  }
  if (joinedUtf8 > CORE_LIMITS.joinedUtf8Bytes || joinedUtf8 > profile.limits.joinedUtf8Bytes || joinedUtf16 > profile.limits.joinedUtf16Units) {
    return fail('PATH_LIMIT_EXCEEDED', { resource: 'joined-path' });
  }
  return {
    accepted: true,
    canonical: segments.join('/'),
    segments,
    measures: { depth: segments.length, joinedUtf8Bytes: joinedUtf8, joinedUtf16Units: joinedUtf16 },
  };
}

function encodeKeySegments(segments) {
  return segments.map((segment) => {
    const bytes = Buffer.from(segment, 'utf8');
    return `${bytes.length.toString(16).padStart(4, '0')}:${bytes.toString('hex')}`;
  }).join('/');
}

export function collisionKeys(input, caseMode, profileRef, profiles) {
  const validated = validatePath(input, profileRef, profiles);
  if (!validated.accepted) return validated;
  if (caseMode !== 'case-sensitive' && caseMode !== 'case-folded') return fail('CASE_MODE_INVALID');
  const repositorySegments = caseMode === 'case-folded' ? validated.segments.map(caseFoldV1) : validated.segments;
  const profile = profileByRef(profiles, profileRef);
  const platformSegments = profile.rules.platformCaseFold ? validated.segments.map(caseFoldV1) : validated.segments;
  return {
    ...validated,
    repositoryKey: `ogvcs-path-key-v1:${caseMode}:${encodeKeySegments(repositorySegments)}`,
    platformKey: `ogvcs-platform-key-v1:${profileRef}:${encodeKeySegments(platformSegments)}`,
  };
}

export function detectCollisions(items, caseMode, profileRef, profiles) {
  if (!Array.isArray(items)) return fail('PATH_INPUT_INVALID');
  const repository = new Map();
  const platform = new Map();
  const normalized = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const id = item?.id ?? String(index);
    if (typeof id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(id)) return fail('PATH_INPUT_INVALID', { item: index });
    const keys = collisionKeys(item?.path, caseMode, profileRef, profiles);
    if (!keys.accepted) return keys;
    const priorRepository = repository.get(keys.repositoryKey);
    if (priorRepository !== undefined) {
      return fail('PATH_COLLISION', { class: 'repository', first: priorRepository, second: id });
    }
    const priorPlatform = platform.get(keys.platformKey);
    if (priorPlatform !== undefined) {
      return fail('PATH_COLLISION', { class: 'platform', first: priorPlatform, second: id });
    }
    repository.set(keys.repositoryKey, id);
    platform.set(keys.platformKey, id);
    normalized.push({ id, path: keys.canonical, repositoryKey: keys.repositoryKey, platformKey: keys.platformKey });
  }
  return { accepted: true, items: normalized };
}

function validateSymlinkTarget(target, linkPath) {
  if (typeof target !== 'string' || target.length === 0 || target.startsWith('/') || /^[A-Za-z]:/u.test(target) || target.includes('\\') || target.includes('\0')) return false;
  try { assertUnicodeScalarString(target, 'symlink target'); } catch { return false; }
  if (target.normalize('NFC') !== target || utf8Length(target) > 4096) return false;
  let depth = linkPath.split('/').length - 1;
  for (const segment of target.split('/')) {
    if (segment === '' || segment === '.') return false;
    if (segment === '..') {
      depth -= 1;
      if (depth < 0) return false;
    } else {
      depth += 1;
    }
  }
  return true;
}

const ENTRY_MODES = Object.freeze({
  directory: 'directory',
  regular: 'regular-file',
  executable: 'executable-file',
  symlink: 'symlink',
});

export function preflightMaterialization(request, profiles) {
  if (!exactKeys(request, ['schemaVersion', 'caseMode', 'profile', 'platform', 'capabilities', 'entries']) || request.schemaVersion !== 'ogvcs.path/preflight-request/v1'
    || !exactKeys(request.capabilities, ['atomicReplace', 'executableBit', 'symlink'])
    || Object.values(request.capabilities).some((value) => typeof value !== 'boolean')) return fail('PATH_INPUT_INVALID');
  const { caseMode, profile: profileRef, platform, capabilities, entries } = request;
  const profile = profileByRef(profiles, profileRef);
  if (profile === undefined) return fail('PATH_PROFILE_UNKNOWN');
  if (!profile.platforms.includes(platform)) return fail('CAPABILITY_UNAVAILABLE', { capability: 'platform-profile' });
  if (capabilities?.atomicReplace !== true) return fail('CAPABILITY_UNAVAILABLE', { capability: 'atomic-replace' });
  if (!Array.isArray(entries) || entries.length > 100_000) return fail('LIMIT_EXCEEDED', { resource: 'entries' });
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const keys = entry?.kind === 'symlink' ? ['id', 'path', 'kind', 'mode', 'symlinkTarget'] : ['id', 'path', 'kind', 'mode'];
    if (!exactKeys(entry, keys) || typeof entry.id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(entry.id)) return fail('ENTRY_INVALID', { entry: index });
  }
  const collision = detectCollisions(entries.map((entry, index) => ({ id: entry?.id ?? String(index), path: entry?.path })), caseMode, profileRef, profiles);
  if (!collision.accepted) return collision;
  const byPath = new Map();
  const normalized = [];
  let symlinks = 0;
  let executable = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const kind = entry.kind;
    if (!Object.hasOwn(ENTRY_MODES, kind) || entry.mode !== ENTRY_MODES[kind]) return fail('ENTRY_INVALID', { entry: index });
    const pathResult = validatePath(entry.path, profileRef, profiles);
    if (!pathResult.accepted) return { ...pathResult, entry: index };
    const canonical = pathResult.canonical;
    if (kind === 'symlink') {
      symlinks += 1;
      if (capabilities?.symlink !== true) return fail('CAPABILITY_UNAVAILABLE', { capability: 'symlink', entry: index });
      if (!validateSymlinkTarget(entry.symlinkTarget, canonical)) return fail('SYMLINK_FORBIDDEN', { entry: index });
    } else if (entry.symlinkTarget !== undefined) {
      return fail('ENTRY_INVALID', { entry: index });
    }
    if (kind === 'executable') executable += 1;
    byPath.set(canonical, { kind, index });
    normalized.push({
      id: entry.id,
      kind: entry.kind,
      mode: entry.mode,
      path: canonical,
      ...(entry.symlinkTarget === undefined ? {} : { symlinkTarget: entry.symlinkTarget }),
    });
  }
  for (let index = 0; index < normalized.length; index += 1) {
    const parent = normalized[index].path.includes('/') ? normalized[index].path.slice(0, normalized[index].path.lastIndexOf('/')) : null;
    if (parent !== null && byPath.get(parent)?.kind !== 'directory') return fail('ENTRY_INVALID', { entry: index, rule: 'parent-directory' });
  }
  return {
    accepted: true,
    summary: {
      entries: entries.length,
      executable,
      symlinks,
      nativeExecutableBits: capabilities?.executableBit === true ? executable : 0,
      planSha256: sha256(canonicalBytes(normalized)),
    },
  };
}

export function planRenames(request, profiles) {
  if (request === null || typeof request !== 'object' || !Array.isArray(request.renames) || request.renames.length > 100_000) {
    return fail('PATH_INPUT_INVALID');
  }
  const sourceItems = [];
  const destinations = [];
  const normalized = [];
  for (let index = 0; index < request.renames.length; index += 1) {
    const rename = request.renames[index];
    const from = collisionKeys(rename?.from, request.caseMode, request.profile, profiles);
    const to = collisionKeys(rename?.to, request.caseMode, request.profile, profiles);
    if (!from.accepted) return { ...from, rename: index };
    if (!to.accepted) return { ...to, rename: index };
    if (typeof rename.fileId !== 'string' || !/^[0-9a-f]{32}$/u.test(rename.fileId)) return fail('ENTRY_INVALID', { rename: index });
    sourceItems.push({ id: String(index), path: from.canonical });
    destinations.push({ id: String(index), path: to.canonical });
    normalized.push({ fileId: rename.fileId, from: from.canonical, to: to.canonical });
  }
  const sourceCollision = detectCollisions(sourceItems, request.caseMode, request.profile, profiles);
  if (!sourceCollision.accepted) return { ...sourceCollision, error: 'RENAME_CONFLICT' };
  const collision = detectCollisions(destinations, request.caseMode, request.profile, profiles);
  if (!collision.accepted) return { ...collision, error: 'RENAME_CONFLICT' };
  const ordered = normalized.map((rename, index) => ({ ...rename, index })).sort((left, right) => Buffer.compare(Buffer.from(left.from), Buffer.from(right.from)));
  const transaction = sha256(canonicalBytes(ordered.map(({ index: _index, ...rename }) => rename))).slice(0, 24);
  const stage = ordered.map((rename, index) => ({
    from: rename.from,
    to: `.ogvcs/rename/${transaction}-${index.toString().padStart(6, '0')}`,
    fileId: rename.fileId,
    phase: 'stage',
  }));
  const temporaryBySource = new Map(stage.map((step) => [step.from, step.to]));
  const publish = [...normalized].sort((left, right) => Buffer.compare(Buffer.from(left.to), Buffer.from(right.to))).map((rename) => ({
    from: temporaryBySource.get(rename.from),
    to: rename.to,
    fileId: rename.fileId,
    phase: 'publish',
  }));
  return { accepted: true, caseMode: request.caseMode, profile: request.profile, transaction, steps: [...stage, ...publish] };
}

export function initialWatcherState(adapter = 'portable-sequence') {
  return {
    schemaVersion: 'ogvcs.path/watcher-state/v1', adapter, cursor: null,
    generation: 0, session: null, authoritativeClean: false,
    reconciliationRequired: true, reason: 'initial-scan',
  };
}

export function watcherTransition(state, event) {
  if (state?.schemaVersion !== 'ogvcs.path/watcher-state/v1' || event === null || typeof event !== 'object') return fail('WATCH_STATE_INVALID');
  const next = structuredClone(state);
  if (event.type === 'reconcile') {
    if (typeof event.cursor !== 'string' || event.cursor.length === 0 || event.cursor.length > 4096 || !Number.isSafeInteger(event.generation) || event.generation !== state.generation + 1) return fail('WATCH_STATE_INVALID');
    next.cursor = event.cursor; next.generation = event.generation; next.session = null;
    next.authoritativeClean = true; next.reconciliationRequired = false; next.reason = null;
    return { accepted: true, state: next };
  }
  if (event.type === 'start') {
    if (typeof event.session !== 'string' || event.session.length === 0 || state.session !== null) return fail('WATCH_STATE_INVALID');
    next.session = event.session; next.authoritativeClean = false;
    return { accepted: true, state: next };
  }
  if (event.type === 'batch') {
    if (state.session === null || event.session !== state.session) return fail('WATCH_STATE_INVALID');
    if (event.overflow === true) {
      next.authoritativeClean = false; next.reconciliationRequired = true; next.reason = 'overflow';
      return { accepted: false, error: 'WATCH_OVERFLOW', state: next };
    }
    if (event.fromCursor !== state.cursor) {
      next.authoritativeClean = false; next.reconciliationRequired = true; next.reason = 'cursor-gap';
      return { accepted: false, error: 'WATCH_GAP', state: next };
    }
    if (typeof event.toCursor !== 'string' || event.toCursor.length === 0 || event.toCursor.length > 4096) return fail('WATCH_STATE_INVALID');
    next.cursor = event.toCursor;
    if (event.indexUpdated !== true) {
      next.authoritativeClean = false; next.reconciliationRequired = true; next.reason = 'adapter-error';
    } else {
      next.authoritativeClean = !state.reconciliationRequired;
    }
    return { accepted: true, state: next };
  }
  if (event.type === 'stop') {
    if (state.session === null || event.session !== state.session || state.authoritativeClean !== true || state.reconciliationRequired) return fail('RECONCILIATION_REQUIRED');
    next.session = null;
    return { accepted: true, state: next };
  }
  if (event.type === 'restart') {
    if (state.session !== null) {
      next.session = null; next.authoritativeClean = false; next.reconciliationRequired = true; next.reason = 'unclean-shutdown';
      return { accepted: false, error: 'WATCH_UNCLEAN_SHUTDOWN', state: next };
    }
    return { accepted: true, state: next };
  }
  return fail('WATCH_STATE_INVALID');
}
