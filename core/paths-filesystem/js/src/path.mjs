import { pathContract } from './contract.mjs';
import { PathFilesystemError, errorDecision, pathFail } from './errors.mjs';

const encoder = new TextEncoder();
const CORE_LIMITS = Object.freeze({ segmentUtf8Bytes: 255, joinedUtf8Bytes: 4096, depth: 256 });
const WINDOWS_FORBIDDEN = /[<>:"\\|?*]/u;
const OPERATIONAL_CONTROL = /[\u0000-\u001f\u007f]/u;
const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`),
  'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³',
]);
const SAFE_DIAGNOSTIC_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

function parseCaseFolding(text) {
  const mappings = new Map();
  for (const line of text.split('\n')) {
    const body = line.split('#', 1)[0].trim();
    if (!body) continue;
    const match = /^([0-9A-F]{4,6});\s*([CFST]);\s*([0-9A-F ]+);$/u.exec(body);
    if (!match) throw new Error('packaged Unicode case-fold table is malformed');
    if (match[2] !== 'C' && match[2] !== 'F') continue;
    const source = Number.parseInt(match[1], 16);
    if (mappings.has(source)) throw new Error('packaged Unicode case-fold table repeats a full mapping');
    mappings.set(source, Object.freeze(match[3].trim().split(/ +/u).map((part) => Number.parseInt(part, 16))));
  }
  if (mappings.size !== 1557) throw new Error('packaged Unicode case-fold mapping count differs from v1');
  return mappings;
}
const CASE_FOLDING = parseCaseFolding(pathContract.caseFoldingText);

export function isUnicodeScalarString(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function assertScalar(value, code = 'PATH_INPUT_INVALID') {
  if (!isUnicodeScalarString(value)) pathFail(code);
}

function utf8Length(value) { return encoder.encode(value).length; }
function profileByRef(profileRef) { return pathContract.profiles.find(({ profile }) => profile === profileRef); }
function segmentsFor(input, profile) {
  if (Array.isArray(input)) {
    if (input.length > CORE_LIMITS.depth || input.length > profile.limits.depth) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'depth' });
    return [...input];
  }
  if (typeof input !== 'string' || input.length === 0 || input.startsWith('/')) pathFail('PATH_INPUT_INVALID');
  if (input.length > profile.limits.joinedUtf16Units) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'joined-path' });
  return input.split('/');
}
function deviceName(segment) { return WINDOWS_DEVICE_NAMES.has(segment.split('.', 1)[0].toUpperCase()); }

export function caseFold(value) {
  assertScalar(value);
  let result = '';
  for (const scalar of value) {
    const mapping = CASE_FOLDING.get(scalar.codePointAt(0));
    result += mapping === undefined ? scalar : String.fromCodePoint(...mapping);
  }
  return result;
}

export function validateRepositoryPath(input, options = {}) {
  const profileRef = options.profile ?? 'path.opengamevcs/portable@1';
  const profile = profileByRef(profileRef);
  if (profile === undefined) pathFail('PATH_PROFILE_UNKNOWN');
  const segments = segmentsFor(input, profile);
  if (segments.length === 0) pathFail('PATH_INPUT_INVALID');
  if (segments.length > CORE_LIMITS.depth || segments.length > profile.limits.depth) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'depth' });
  let joinedUtf8Bytes = segments.length - 1;
  let joinedUtf16Units = segments.length - 1;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    assertScalar(segment);
    if (segment.length === 0 || segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\\') || segment.includes('\0')) pathFail('PATH_INPUT_INVALID', undefined, { segment: index });
    if (segment.length > profile.limits.segmentUtf16Units || segment.length > CORE_LIMITS.segmentUtf8Bytes) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'segment', segment: index });
    if (segment.normalize('NFC') !== segment) pathFail('PATH_NOT_NFC', undefined, { segment: index });
    const bytes = utf8Length(segment);
    if (bytes > CORE_LIMITS.segmentUtf8Bytes || bytes > profile.limits.segmentUtf8Bytes) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'segment', segment: index });
    joinedUtf8Bytes += bytes;
    joinedUtf16Units += segment.length;
    if (OPERATIONAL_CONTROL.test(segment)) pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'control', segment: index });
    if (caseFold(segment) === '.ogvcs') pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'workspace-reserved', segment: index });
    if (profile.rules.windowsNames) {
      if (WINDOWS_FORBIDDEN.test(segment)) pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'windows-character', segment: index });
      if (/[. ]$/u.test(segment)) pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'windows-trailing', segment: index });
      if (deviceName(segment)) pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'windows-device', segment: index });
    } else if (profile.rules.macosColon && segment.includes(':')) {
      pathFail('PATH_PLATFORM_FORBIDDEN', undefined, { rule: 'macos-colon', segment: index });
    }
  }
  if (joinedUtf8Bytes > CORE_LIMITS.joinedUtf8Bytes || joinedUtf8Bytes > profile.limits.joinedUtf8Bytes || joinedUtf16Units > profile.limits.joinedUtf16Units) pathFail('PATH_LIMIT_EXCEEDED', undefined, { resource: 'joined-path' });
  return Object.freeze({
    canonical: segments.join('/'), segments: Object.freeze(segments),
    measures: Object.freeze({ depth: segments.length, joinedUtf8Bytes, joinedUtf16Units }),
    profile: profileRef,
  });
}

function encodedKey(segments) {
  return segments.map((segment) => {
    const bytes = Buffer.from(segment, 'utf8');
    return `${bytes.length.toString(16).padStart(4, '0')}:${bytes.toString('hex')}`;
  }).join('/');
}

export function pathCollisionKeys(input, options = {}) {
  const profileRef = options.profile ?? 'path.opengamevcs/portable@1';
  const caseMode = options.caseMode ?? 'case-sensitive';
  if (caseMode !== 'case-sensitive' && caseMode !== 'case-folded') pathFail('CASE_MODE_INVALID');
  const result = validateRepositoryPath(input, { profile: profileRef });
  const profile = profileByRef(profileRef);
  const repository = caseMode === 'case-folded' ? result.segments.map(caseFold) : result.segments;
  const platform = profile.rules.platformCaseFold ? result.segments.map(caseFold) : result.segments;
  return Object.freeze({
    ...result,
    repositoryKey: `ogvcs-path-key-v1:${caseMode}:${encodedKey(repository)}`,
    platformKey: `ogvcs-platform-key-v1:${profileRef}:${encodedKey(platform)}`,
  });
}

export function findPathCollisions(items, options = {}) {
  if (!Array.isArray(items)) pathFail('PATH_INPUT_INVALID');
  const maximum = options.maxPaths ?? 100_000;
  if (!Number.isSafeInteger(maximum) || maximum < 0 || items.length > maximum) pathFail('LIMIT_EXCEEDED', undefined, { resource: 'paths' });
  const repository = new Map(); const platform = new Map(); const normalized = [];
  for (let index = 0; index < items.length; index += 1) {
    const id = items[index]?.id ?? String(index);
    if (typeof id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(id)) pathFail('PATH_INPUT_INVALID', undefined, { item: index });
    const keys = pathCollisionKeys(items[index]?.path, options);
    if (repository.has(keys.repositoryKey)) pathFail('PATH_COLLISION', undefined, { class: 'repository', first: repository.get(keys.repositoryKey), second: id });
    if (platform.has(keys.platformKey)) pathFail('PATH_COLLISION', undefined, { class: 'platform', first: platform.get(keys.platformKey), second: id });
    repository.set(keys.repositoryKey, id); platform.set(keys.platformKey, id);
    normalized.push(Object.freeze({ id, path: keys.canonical, repositoryKey: keys.repositoryKey, platformKey: keys.platformKey }));
  }
  return Object.freeze({ items: Object.freeze(normalized) });
}

export function evaluatePath(input, options = {}) {
  try {
    const result = pathCollisionKeys(input, options);
    return Object.freeze({ accepted: true, canonical: result.canonical, segments: result.segments, measures: result.measures, repositoryKey: result.repositoryKey, platformKey: result.platformKey });
  } catch (error) {
    if (!(error instanceof PathFilesystemError)) throw error;
    return errorDecision(error);
  }
}

export function evaluateCollisions(items, options = {}) {
  try {
    return Object.freeze({ accepted: true, ...findPathCollisions(items, options) });
  } catch (error) {
    if (!(error instanceof PathFilesystemError)) throw error;
    return errorDecision(error);
  }
}
