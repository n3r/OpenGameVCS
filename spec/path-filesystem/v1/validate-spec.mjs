#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE_ROOT = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(process.env.OGVCS_PATH_CONTRACT_ROOT ?? SOURCE_ROOT);
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_NODES = 200_000;
const EXPECTED = Object.freeze({
  contractVersion: '1.0.0', artifacts: 27, registries: 4, schemas: 7,
  pathCases: 25, foldCases: 7, collisionCases: 7, preflightCases: 12,
  renameCases: 6, watcherCases: 6, errors: 23, profiles: 4,
});
const EXPECTED_REGISTRY_SHA256 = Object.freeze({
  'case-modes.json': 'b519d4fee0624baf16551b2347647e04a7c4fe611b4242383b787ab9a573035f',
  'errors.json': '04d38c93ba868b9fa5123746b57e0262c054dd4495c5b61b5fea1c1ef0019b18',
  'operation-outcomes.json': '7c88e7a9bd2ca2b5b968a058c22cfb8f4d615b5ce6bafad30fee44dfe8e892fa',
  'platform-profiles.json': '2491968352ce8d79fb4405549ad21b06a1dcfe42d44b7d2bafb3029af344d10a',
});
const STATIC_ARTIFACTS = Object.freeze([
  'LICENSE', 'README.md', 'THIRD_PARTY_NOTICES.md',
  'data/CaseFolding-16.0.0.txt', 'data/UNICODE-LICENSE.txt',
  'docs/path-contract.md', 'docs/versioning-and-operations.md',
  'docs/watcher-contract.md', 'docs/workspace-safety.md', 'package.json',
]);
const EXPECTED_SCHEMA_FILES = new Set([
  'conformance-report.schema.json', 'path-result.schema.json',
  'preflight-request.schema.json', 'preflight-result.schema.json',
  'registry.schema.json', 'rename-plan.schema.json', 'watcher-state.schema.json',
]);
const EXPECTED_VECTOR_FILES = new Set([
  'collision-cases.json', 'fold-cases.json', 'path-cases.json',
  'preflight-cases.json', 'rename-cases.json', 'watcher-cases.json',
]);
const EXPECTED_CASE_FOLDING_SHA256 = '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb';
const EXPECTED_UNICODE_LICENSE_SHA256 = 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96';
const EXPECTED_MIT_SHA256 = '6f0f22f485ae8614870468a48f2c084eaf800fe02c5a2c4d9a91d34bc7f58eb4';
const encoder = new TextEncoder();
const SAFE_DIAGNOSTIC_ID = /^[A-Za-z0-9._:-]{1,256}$/u;

function fail(message) { throw new Error(`path-contract-v1: ${message}`); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  fail('value outside the canonical JSON domain');
}
const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`, 'utf8');

function inspectTree(value, label) {
  const stack = [{ value, depth: 0 }];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    nodes += 1;
    if (nodes > MAX_NODES) fail(`${label} exceeds the node ceiling`);
    if (current.depth > MAX_DEPTH) fail(`${label} exceeds the nesting ceiling`);
    if (typeof current.value === 'string' && Buffer.byteLength(current.value, 'utf8') > 65_536) fail(`${label} contains an oversized string`);
    if (Array.isArray(current.value)) {
      for (const child of current.value) stack.push({ value: child, depth: current.depth + 1 });
    } else if (current.value && typeof current.value === 'object') {
      for (const [key, child] of Object.entries(current.value)) {
        if (Buffer.byteLength(key, 'utf8') > 256) fail(`${label} contains an oversized key`);
        stack.push({ value: child, depth: current.depth + 1 });
      }
    } else if (current.value !== null && !['boolean', 'number', 'string'].includes(typeof current.value)) fail(`${label} contains an unsupported value`);
  }
}

async function boundedFile(relative, maximum = MAX_JSON_BYTES) {
  const path = resolve(ROOT, relative);
  const metadata = await lstat(path).catch(() => null);
  if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink() || metadata.size > maximum) fail(`${relative} is not a bounded regular file`);
  return readFile(path);
}

async function loadCanonical(relative) {
  const bytes = await boundedFile(relative);
  let value;
  try { value = JSON.parse(bytes); } catch { fail(`${relative} is invalid JSON`); }
  inspectTree(value, relative);
  if (!bytes.equals(canonicalBytes(value))) fail(`${relative} is not canonical JSON`);
  return { bytes, value };
}

async function jsonFiles(directory) {
  const entries = await readdir(resolve(ROOT, directory), { withFileTypes: true });
  return entries.filter((entry) => entry.isFile() && entry.name.endsWith('.json')).map(({ name }) => name).sort();
}

function exactSet(actual, expected, label) {
  if (actual.size !== expected.size || [...expected].some((value) => !actual.has(value))) fail(`${label} differs from the frozen inventory`);
}

function hasExactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function parseCaseFolding(text) {
  const mappings = new Map();
  for (const line of text.split('\n')) {
    const body = line.split('#', 1)[0].trim();
    if (!body) continue;
    const match = /^([0-9A-F]{4,6});\s*([CFST]);\s*([0-9A-F ]+);$/u.exec(body);
    if (!match) fail('CaseFolding.txt contains a malformed assignment');
    if (match[2] !== 'C' && match[2] !== 'F') continue;
    const codepoint = Number.parseInt(match[1], 16);
    if (mappings.has(codepoint)) fail('CaseFolding.txt repeats a C/F source assignment');
    mappings.set(codepoint, match[3].trim().split(/ +/u).map((part) => Number.parseInt(part, 16)));
  }
  if (mappings.size !== 1557) fail('CaseFolding.txt C/F assignment count differs from Unicode 16.0.0');
  return mappings;
}

function scalarText(value) {
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

function caseFold(value, mappings) {
  if (!scalarText(value)) fail('fold vector contains non-scalar text');
  let result = '';
  for (const scalar of value) {
    const mapped = mappings.get(scalar.codePointAt(0));
    result += mapped === undefined ? scalar : String.fromCodePoint(...mapped);
  }
  return result;
}

const windowsNames = new Set(['CON', 'PRN', 'AUX', 'NUL', ...Array.from({ length: 9 }, (_, index) => `COM${index + 1}`), ...Array.from({ length: 9 }, (_, index) => `LPT${index + 1}`), 'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³']);
const decision = (error, detail) => ({ accepted: false, error, ...(detail === undefined || Object.keys(detail).length === 0 ? {} : { detail }) });
const utf8Length = (value) => encoder.encode(value).length;

function segmentsFor(input) {
  if (Array.isArray(input)) return [...input];
  if (typeof input !== 'string' || input.length === 0 || input.startsWith('/')) return null;
  return input.split('/');
}

function validatePath(input, profile) {
  const segments = segmentsFor(input);
  if (segments === null || segments.length === 0) return decision('PATH_INPUT_INVALID');
  if (segments.length > 256 || segments.length > profile.limits.depth) return decision('PATH_LIMIT_EXCEEDED', { resource: 'depth' });
  let joinedUtf8Bytes = segments.length - 1;
  let joinedUtf16Units = segments.length - 1;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (!scalarText(segment) || segment.length === 0 || segment === '.' || segment === '..' || segment.includes('/') || segment.includes('\\') || segment.includes('\0')) return decision('PATH_INPUT_INVALID', { segment: index });
    if (segment.normalize('NFC') !== segment) return decision('PATH_NOT_NFC', { segment: index });
    const bytes = utf8Length(segment);
    if (bytes > 255 || bytes > profile.limits.segmentUtf8Bytes || segment.length > profile.limits.segmentUtf16Units) return decision('PATH_LIMIT_EXCEEDED', { resource: 'segment', segment: index });
    joinedUtf8Bytes += bytes; joinedUtf16Units += segment.length;
    if (/[\u0000-\u001f\u007f]/u.test(segment)) return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'control', segment: index });
    if (caseFold(segment, mappings) === '.ogvcs') return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'workspace-reserved', segment: index });
    if (profile.rules.windowsNames) {
      if (/[<>:"\\|?*]/u.test(segment)) return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-character', segment: index });
      if (/[. ]$/u.test(segment)) return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-trailing', segment: index });
      if (windowsNames.has(segment.split('.', 1)[0].toUpperCase())) return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'windows-device', segment: index });
    } else if (profile.rules.macosColon && segment.includes(':')) return decision('PATH_PLATFORM_FORBIDDEN', { rule: 'macos-colon', segment: index });
  }
  if (joinedUtf8Bytes > 4096 || joinedUtf8Bytes > profile.limits.joinedUtf8Bytes || joinedUtf16Units > profile.limits.joinedUtf16Units) return decision('PATH_LIMIT_EXCEEDED', { resource: 'joined-path' });
  return { accepted: true, canonical: segments.join('/'), segments, measures: { depth: segments.length, joinedUtf8Bytes, joinedUtf16Units } };
}

function encodeSegments(segments) {
  return segments.map((segment) => {
    const bytes = Buffer.from(segment, 'utf8');
    return `${bytes.length.toString(16).padStart(4, '0')}:${bytes.toString('hex')}`;
  }).join('/');
}

function keys(input, caseMode, profileRef, profiles, mappings) {
  if (!['case-sensitive', 'case-folded'].includes(caseMode)) return decision('CASE_MODE_INVALID');
  const profile = profiles.get(profileRef);
  if (profile === undefined) return decision('PATH_PROFILE_UNKNOWN');
  const validated = validatePath(input, profile);
  if (!validated.accepted) return validated;
  const repository = caseMode === 'case-folded' ? validated.segments.map((segment) => caseFold(segment, mappings)) : validated.segments;
  const platform = profile.rules.platformCaseFold ? validated.segments.map((segment) => caseFold(segment, mappings)) : validated.segments;
  return {
    ...validated,
    repositoryKey: `ogvcs-path-key-v1:${caseMode}:${encodeSegments(repository)}`,
    platformKey: `ogvcs-platform-key-v1:${profileRef}:${encodeSegments(platform)}`,
  };
}

function collisions(items, caseMode, profileRef, profiles, mappings) {
  const repository = new Map(); const platform = new Map(); const normalized = [];
  for (let index = 0; index < items.length; index += 1) {
    const id = items[index].id ?? String(index);
    if (typeof id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(id)) return decision('PATH_INPUT_INVALID', { item: index });
    const result = keys(items[index].path, caseMode, profileRef, profiles, mappings);
    if (!result.accepted) return result;
    if (repository.has(result.repositoryKey)) return decision('PATH_COLLISION', { class: 'repository', first: repository.get(result.repositoryKey), second: id });
    if (platform.has(result.platformKey)) return decision('PATH_COLLISION', { class: 'platform', first: platform.get(result.platformKey), second: id });
    repository.set(result.repositoryKey, id); platform.set(result.platformKey, id);
    normalized.push({ id, path: result.canonical, repositoryKey: result.repositoryKey, platformKey: result.platformKey });
  }
  return { accepted: true, items: normalized };
}

function safeSymlinkTarget(target, linkPath) {
  if (typeof target !== 'string' || target.length === 0 || target.startsWith('/') || /^[A-Za-z]:/u.test(target) || target.includes('\\') || target.includes('\0') || target.normalize('NFC') !== target || utf8Length(target) > 4096) return false;
  let depth = linkPath.split('/').length - 1;
  for (const segment of target.split('/')) {
    if (segment === '' || segment === '.') return false;
    if (segment === '..') { depth -= 1; if (depth < 0) return false; } else depth += 1;
  }
  return true;
}

function preflight(testCase, profiles, mappings) {
  if (!hasExactKeys(testCase, ['schemaVersion', 'caseMode', 'profile', 'platform', 'capabilities', 'entries']) || testCase.schemaVersion !== 'ogvcs.path/preflight-request/v1'
    || !hasExactKeys(testCase.capabilities, ['atomicReplace', 'executableBit', 'symlink'])
    || Object.values(testCase.capabilities).some((value) => typeof value !== 'boolean')) return decision('PATH_INPUT_INVALID');
  const profile = profiles.get(testCase.profile);
  if (profile === undefined) return decision('PATH_PROFILE_UNKNOWN');
  if (!profile.platforms.includes(testCase.platform)) return decision('CAPABILITY_UNAVAILABLE', { capability: 'platform-profile' });
  if (testCase.capabilities?.atomicReplace !== true) return decision('CAPABILITY_UNAVAILABLE', { capability: 'atomic-replace' });
  for (let index = 0; index < testCase.entries.length; index += 1) {
    const entry = testCase.entries[index];
    const expectedKeys = entry?.kind === 'symlink' ? ['id', 'path', 'kind', 'mode', 'symlinkTarget'] : ['id', 'path', 'kind', 'mode'];
    if (!hasExactKeys(entry, expectedKeys) || typeof entry.id !== 'string' || !SAFE_DIAGNOSTIC_ID.test(entry.id)) return decision('ENTRY_INVALID', { entry: index });
  }
  const collision = collisions(testCase.entries.map((entry, index) => ({ id: entry?.id ?? String(index), path: entry?.path })), testCase.caseMode, testCase.profile, profiles, mappings);
  if (!collision.accepted) return collision;
  const modes = { directory: 'directory', regular: 'regular-file', executable: 'executable-file', symlink: 'symlink' };
  const byPath = new Map(); const normalized = [];
  let executable = 0; let symlinks = 0;
  for (let index = 0; index < testCase.entries.length; index += 1) {
    const entry = testCase.entries[index];
    if (!Object.hasOwn(modes, entry.kind) || entry.mode !== modes[entry.kind]) return decision('ENTRY_INVALID', { entry: index });
    const path = validatePath(entry.path, profile);
    if (!path.accepted) return path;
    if (entry.kind === 'symlink') {
      symlinks += 1;
      if (testCase.capabilities?.symlink !== true) return decision('CAPABILITY_UNAVAILABLE', { capability: 'symlink', entry: index });
      if (!safeSymlinkTarget(entry.symlinkTarget, path.canonical)) return decision('SYMLINK_FORBIDDEN', { entry: index });
    } else if (entry.symlinkTarget !== undefined) return decision('ENTRY_INVALID', { entry: index });
    if (entry.kind === 'executable') executable += 1;
    byPath.set(path.canonical, { kind: entry.kind });
    normalized.push({ id: entry.id, kind: entry.kind, mode: entry.mode, path: path.canonical, ...(entry.symlinkTarget === undefined ? {} : { symlinkTarget: entry.symlinkTarget }) });
  }
  for (let index = 0; index < normalized.length; index += 1) {
    const parent = normalized[index].path.includes('/') ? normalized[index].path.slice(0, normalized[index].path.lastIndexOf('/')) : null;
    if (parent !== null && byPath.get(parent)?.kind !== 'directory') return decision('ENTRY_INVALID', { entry: index, rule: 'parent-directory' });
  }
  const planSha256 = sha256(Buffer.from(`${canonicalJson({
    capabilities: testCase.capabilities,
    caseMode: testCase.caseMode,
    entries: normalized,
    platform: testCase.platform,
    profile: testCase.profile,
  })}\n`, 'utf8'));
  return { accepted: true, summary: { entries: normalized.length, executable, symlinks, nativeExecutableBits: testCase.capabilities.executableBit === true ? executable : 0, planSha256 } };
}

function renames(testCase, profiles, mappings) {
  const sources = []; const destinations = []; const normalized = [];
  for (let index = 0; index < testCase.renames.length; index += 1) {
    const item = testCase.renames[index];
    const from = keys(item?.from, testCase.caseMode, testCase.profile, profiles, mappings);
    if (!from.accepted) return from;
    const to = keys(item?.to, testCase.caseMode, testCase.profile, profiles, mappings);
    if (!to.accepted) return to;
    if (typeof item.fileId !== 'string' || !/^[0-9a-f]{32}$/u.test(item.fileId)) return decision('ENTRY_INVALID', { rename: index });
    sources.push({ id: String(index), path: from.canonical }); destinations.push({ id: String(index), path: to.canonical }); normalized.push({ fileId: item.fileId, from: from.canonical, to: to.canonical });
  }
  const sourceCollision = collisions(sources, testCase.caseMode, testCase.profile, profiles, mappings);
  if (!sourceCollision.accepted) return sourceCollision.error === 'PATH_COLLISION' ? decision('RENAME_CONFLICT', sourceCollision.detail) : sourceCollision;
  const collision = collisions(destinations, testCase.caseMode, testCase.profile, profiles, mappings);
  if (!collision.accepted) return collision.error === 'PATH_COLLISION' ? decision('RENAME_CONFLICT', collision.detail) : collision;
  const compare = (left, right) => Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
  const ordered = normalized.map((item, index) => ({ ...item, index })).sort((left, right) => compare(left.from, right.from));
  const transaction = sha256(Buffer.from(`${canonicalJson(ordered.map(({ index: _index, ...item }) => item))}\n`, 'utf8')).slice(0, 24);
  const staged = ordered.map((item, index) => ({ from: item.from, to: `.ogvcs/rename/${transaction}-${String(index).padStart(6, '0')}`, fileId: item.fileId, phase: 'stage' }));
  const temp = new Map(staged.map(({ from, to }) => [from, to]));
  const publish = [...normalized].sort((left, right) => compare(left.to, right.to)).map((item) => ({ from: temp.get(item.from), to: item.to, fileId: item.fileId, phase: 'publish' }));
  return { accepted: true, caseMode: testCase.caseMode, profile: testCase.profile, transaction, steps: [...staged, ...publish] };
}

function initialWatcher() { return { schemaVersion: 'ogvcs.path/watcher-state/v1', adapter: 'portable-sequence', cursor: null, generation: 0, session: null, authoritativeClean: false, reconciliationRequired: true, reason: 'initial-scan' }; }
function watcherTransition(state, event) {
  const next = { ...state };
  if (event.type === 'reconcile') {
    if (typeof event.cursor !== 'string' || event.cursor.length === 0 || event.generation !== state.generation + 1) return decision('WATCH_STATE_INVALID');
    return { accepted: true, state: { ...next, cursor: event.cursor, generation: event.generation, session: null, authoritativeClean: true, reconciliationRequired: false, reason: null } };
  }
  if (event.type === 'start') {
    if (typeof event.session !== 'string' || event.session.length === 0 || state.session !== null) return decision('WATCH_STATE_INVALID');
    return { accepted: true, state: { ...next, session: event.session, authoritativeClean: false } };
  }
  if (event.type === 'batch') {
    if (state.session === null || event.session !== state.session) return decision('WATCH_STATE_INVALID');
    if (event.overflow === true) return { ...decision('WATCH_OVERFLOW'), state: { ...next, authoritativeClean: false, reconciliationRequired: true, reason: 'overflow' } };
    if (event.fromCursor !== state.cursor) return { ...decision('WATCH_GAP'), state: { ...next, authoritativeClean: false, reconciliationRequired: true, reason: 'cursor-gap' } };
    if (typeof event.toCursor !== 'string' || event.toCursor.length === 0) return decision('WATCH_STATE_INVALID');
    return event.indexUpdated === true
      ? { accepted: true, state: { ...next, cursor: event.toCursor, authoritativeClean: !state.reconciliationRequired } }
      : { accepted: true, state: { ...next, cursor: event.toCursor, authoritativeClean: false, reconciliationRequired: true, reason: 'adapter-error' } };
  }
  if (event.type === 'stop') {
    if (state.session === null || event.session !== state.session || state.authoritativeClean !== true || state.reconciliationRequired) return decision('RECONCILIATION_REQUIRED');
    return event.resumeSupported === true
      ? { accepted: true, state: { ...next, session: null } }
      : { accepted: true, state: { ...next, session: null, authoritativeClean: false, reconciliationRequired: true, reason: 'unsupported-resume' } };
  }
  if (event.type === 'restart') {
    if (state.session !== null) return { ...decision('WATCH_UNCLEAN_SHUTDOWN'), state: { ...next, session: null, authoritativeClean: false, reconciliationRequired: true, reason: 'unclean-shutdown' } };
    return { accepted: true, state: next };
  }
  return decision('WATCH_STATE_INVALID');
}

function watcher(testCase) {
  let state = initialWatcher(); const outcomes = [];
  for (const event of testCase.events) {
    const raw = watcherTransition(state, event);
    const result = raw.state === undefined ? { ...raw, state } : raw;
    outcomes.push(result);
    if (raw.state !== undefined) state = raw.state;
    if (!result.accepted) break;
  }
  return { outcomes, state };
}

const manifest = (await loadCanonical('manifest.json')).value;
if (manifest.schemaVersion !== 'ogvcs.path/contract-manifest/v1' || manifest.contractVersion !== EXPECTED.contractVersion) fail('manifest version differs');
for (const [name, expected] of Object.entries(EXPECTED)) {
  if (name === 'contractVersion') continue;
  if (manifest.counts?.[name] !== expected) fail(`manifest count ${name} differs`);
}

const packageBytes = await boundedFile('package.json');
let packageDocument;
try { packageDocument = JSON.parse(packageBytes); } catch { fail('package.json is invalid JSON'); }
inspectTree(packageDocument, 'package.json');
if (packageDocument.name !== '@opengamevcs/path-contract-v1' || packageDocument.version !== EXPECTED.contractVersion || packageDocument.license !== 'MIT' || packageDocument.type !== 'module') fail('package identity differs');
if (sha256(await boundedFile('LICENSE', 4096)) !== EXPECTED_MIT_SHA256) fail('MIT license differs');

const registryFiles = await jsonFiles('registries');
const schemaFiles = await jsonFiles('schemas');
const vectorFiles = await jsonFiles('vectors');
exactSet(new Set(registryFiles), new Set(Object.keys(EXPECTED_REGISTRY_SHA256)), 'registry inventory');
exactSet(new Set(schemaFiles), EXPECTED_SCHEMA_FILES, 'schema inventory');
exactSet(new Set(vectorFiles), EXPECTED_VECTOR_FILES, 'vector inventory');

const artifacts = [...STATIC_ARTIFACTS, ...registryFiles.map((name) => `registries/${name}`), ...schemaFiles.map((name) => `schemas/${name}`), ...vectorFiles.map((name) => `vectors/${name}`)].sort();
exactSet(new Set(manifest.artifacts.map(({ path }) => path)), new Set(artifacts), 'manifest artifact inventory');
if (new Set(manifest.artifacts.map(({ path }) => path)).size !== manifest.artifacts.length) fail('manifest repeats an artifact');
for (const record of manifest.artifacts) {
  const bytes = await boundedFile(record.path, 16 * 1024 * 1024);
  if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256) fail(`artifact binding differs: ${record.path}`);
}

const registries = new Map();
for (const name of registryFiles) {
  const loaded = await loadCanonical(`registries/${name}`);
  if (sha256(loaded.bytes) !== EXPECTED_REGISTRY_SHA256[name]) fail(`frozen registry assignment differs: ${name}`);
  const document = loaded.value;
  if (document.schemaVersion !== 'ogvcs.path/registry/v1' || document.version !== 1 || !Array.isArray(document.entries) || document.entries.length === 0) fail(`registry envelope differs: ${name}`);
  const expectedRegistry = name.slice(0, -5);
  if (document.registry !== expectedRegistry || registries.has(document.registry)) fail(`registry basename binding differs: ${name}`);
  const codes = document.entries.map(({ code }) => code);
  const names = document.entries.map(({ name: entryName }) => entryName);
  if (codes.some((code) => !Number.isInteger(code) || code <= 0) || new Set(codes).size !== codes.length || new Set(names).size !== names.length || names.some((entryName) => typeof entryName !== 'string' || entryName.length === 0)) fail(`registry assignments are invalid: ${name}`);
  registries.set(document.registry, document);
}
if (registries.get('case-modes').entries.map(({ name }) => name).join(',') !== 'case-sensitive,case-folded') fail('case-mode assignments differ');
if (registries.get('errors').entries.length !== 23 || registries.get('errors').entries.some(({ name }) => !/^[A-Z][A-Z0-9_]*$/u.test(name))) fail('error assignments differ');
const profiles = new Map(registries.get('platform-profiles').entries.map((entry) => [entry.profile, entry]));
exactSet(new Set(profiles.keys()), new Set(['path.opengamevcs/portable@1', 'path.opengamevcs/windows@1', 'path.opengamevcs/macos@1', 'path.opengamevcs/linux@1']), 'profile assignments');
for (const profile of profiles.values()) {
  if (profile.state !== 'ratified' || profile.owner !== 'OGVCS-004' || profile.limits.depth > 256 || profile.limits.segmentUtf8Bytes > 255 || profile.limits.joinedUtf8Bytes > 4096) fail(`profile is outside the v1 contract: ${profile.profile}`);
}

const registryRecords = manifest.artifacts.filter(({ path }) => path.startsWith('registries/'));
const vectorRecords = manifest.artifacts.filter(({ path }) => path.startsWith('vectors/'));
if (sha256(canonicalBytes(registryRecords)) !== manifest.registrySetSha256) fail('registry-set digest differs');
if (sha256(canonicalBytes(vectorRecords)) !== manifest.vectorSetSha256) fail('vector-set digest differs');

for (const name of schemaFiles) {
  const schema = (await loadCanonical(`schemas/${name}`)).value;
  if (schema.$schema !== 'https://json-schema.org/draft/2020-12/schema' || schema.$id !== `https://opengamevcs.dev/schemas/path/v1/${name}`) fail(`schema identity differs: ${name}`);
  if (schema.type === 'object' && schema.additionalProperties !== false) fail(`top-level schema is not closed: ${name}`);
}
const preflightSchema = (await loadCanonical('schemas/preflight-request.schema.json')).value;
if (preflightSchema.properties.entries.maxItems !== 100_000 || preflightSchema.properties.entries.items.additionalProperties !== false) fail('preflight schema bounds/closure differ');
const watcherSchema = (await loadCanonical('schemas/watcher-state.schema.json')).value;
if (watcherSchema.additionalProperties !== false || watcherSchema.properties.reason.oneOf[1].enum.length !== 7
  || !watcherSchema.properties.reason.oneOf[1].enum.includes('unsupported-resume')) fail('watcher schema differs');

const caseFoldingBytes = await boundedFile('data/CaseFolding-16.0.0.txt', 256 * 1024);
const unicodeLicenseBytes = await boundedFile('data/UNICODE-LICENSE.txt', 16 * 1024);
if (sha256(caseFoldingBytes) !== EXPECTED_CASE_FOLDING_SHA256 || sha256(unicodeLicenseBytes) !== EXPECTED_UNICODE_LICENSE_SHA256) fail('Unicode source/license digest differs');
if (manifest.unicode.version !== '16.0.0' || manifest.unicode.caseFoldingSha256 !== EXPECTED_CASE_FOLDING_SHA256 || manifest.unicode.licenseSha256 !== EXPECTED_UNICODE_LICENSE_SHA256 || manifest.unicode.mapping !== 'full-default-C-and-F-without-T-or-post-fold-normalization') fail('Unicode manifest binding differs');
const mappings = parseCaseFolding(caseFoldingBytes.toString('utf8'));

const sourceHash = createHash('sha256');
for (const relative of ['scripts/generate.mjs', 'source/contract.mjs', 'source/reference.mjs', 'source/schemas.mjs']) {
  sourceHash.update(`${relative}\0`, 'utf8'); sourceHash.update(await boundedFile(relative, 1024 * 1024));
}
if (sourceHash.digest('hex') !== manifest.generatorSha256) fail('generator provenance digest differs');

const vectorDocuments = new Map();
for (const name of vectorFiles) vectorDocuments.set(name, (await loadCanonical(`vectors/${name}`)).value);
for (const testCase of vectorDocuments.get('fold-cases.json').cases) {
  if (caseFold(testCase.input, mappings) !== testCase.expected) fail(`independent fold result differs: ${testCase.id}`);
}
for (const testCase of vectorDocuments.get('path-cases.json').cases) {
  const profile = profiles.get(testCase.profile);
  const actual = profile === undefined ? decision('PATH_PROFILE_UNKNOWN') : keys(testCase.input, testCase.caseMode, testCase.profile, profiles, mappings);
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) fail(`independent path result differs: ${testCase.id}`);
}
for (const testCase of vectorDocuments.get('collision-cases.json').cases) {
  const actual = collisions(testCase.paths.map((path, index) => ({ id: String(index), path })), testCase.caseMode, testCase.profile, profiles, mappings);
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) fail(`independent collision result differs: ${testCase.id}`);
}
for (const testCase of vectorDocuments.get('preflight-cases.json').cases) {
  const { id: _id, expected: _expected, ...request } = testCase;
  const actual = preflight(request, profiles, mappings);
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) fail(`independent preflight result differs: ${testCase.id}`);
}
for (const testCase of vectorDocuments.get('rename-cases.json').cases) {
  const actual = renames(testCase, profiles, mappings);
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) fail(`independent rename result differs: ${testCase.id}`);
}
for (const testCase of vectorDocuments.get('watcher-cases.json').cases) {
  const actual = watcher(testCase);
  if (canonicalJson(actual) !== canonicalJson(testCase.expected)) fail(`independent watcher result differs: ${testCase.id}`);
}

process.stdout.write(`${JSON.stringify({
  schemaVersion: manifest.schemaVersion,
  contractVersion: manifest.contractVersion,
  artifacts: manifest.counts.artifacts,
  registries: manifest.counts.registries,
  schemas: manifest.counts.schemas,
  vectors: manifest.counts.pathCases + manifest.counts.foldCases + manifest.counts.collisionCases + manifest.counts.preflightCases + manifest.counts.renameCases + manifest.counts.watcherCases,
  errors: manifest.counts.errors,
  profiles: manifest.counts.profiles,
  registrySetSha256: manifest.registrySetSha256,
  vectorSetSha256: manifest.vectorSetSha256,
  result: 'valid',
})}\n`);
