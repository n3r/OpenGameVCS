import assert from 'node:assert/strict';
import test from 'node:test';

import { caseFold, evaluateCollisions, evaluatePath, loadContractJson } from '../src/index.mjs';
import { evaluatePreflight, preflightMaterialization } from '../src/preflight.mjs';
import { evaluateRenames } from '../src/rename.mjs';
import { evaluateWatcherCase } from '../src/watcher.mjs';

test('all 63 language-neutral vectors reproduce exact decisions', () => {
  let executed = 0;
  for (const value of loadContractJson('vectors/path-cases.json').cases) {
    assert.deepEqual(evaluatePath(value.input, { caseMode: value.caseMode, profile: value.profile }), value.expected, value.id); executed += 1;
  }
  for (const value of loadContractJson('vectors/fold-cases.json').cases) { assert.equal(caseFold(value.input), value.expected, value.id); executed += 1; }
  for (const value of loadContractJson('vectors/collision-cases.json').cases) {
    assert.deepEqual(evaluateCollisions(value.paths.map((path, index) => ({ id: String(index), path })), { caseMode: value.caseMode, profile: value.profile }), value.expected, value.id); executed += 1;
  }
  for (const value of loadContractJson('vectors/preflight-cases.json').cases) {
    const { id, expected, ...request } = value;
    assert.deepEqual(evaluatePreflight(request), expected, id); executed += 1;
  }
  for (const value of loadContractJson('vectors/rename-cases.json').cases) { assert.deepEqual(evaluateRenames(value), value.expected, value.id); executed += 1; }
  for (const value of loadContractJson('vectors/watcher-cases.json').cases) { assert.deepEqual(evaluateWatcherCase(value), value.expected, value.id); executed += 1; }
  assert.equal(executed, 63);
});

test('case folding is frozen, locale-independent, and does not repair input', () => {
  assert.equal(caseFold('Straße'), 'strasse');
  assert.equal(caseFold('İstanbul'), 'i\u0307stanbul');
  assert.equal(evaluatePath('Cafe\u0301/file', { caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1' }).error, 'PATH_NOT_NFC');
  assert.equal(evaluatePath('Café/file', { caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1' }).accepted, true);
});

test('preflight rejects non-scalar symlink targets before platform mutation', () => {
  const result = evaluatePreflight({
    schemaVersion: 'ogvcs.path/preflight-request/v1',
    caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/linux@1',
    platform: 'linux',
    capabilities: { atomicReplace: true, executableBit: true, symlink: true },
    entries: [{ id: 'link', path: 'current', kind: 'symlink', mode: 'symlink', symlinkTarget: '\ud800' }],
  });
  assert.equal(result.error, 'SYMLINK_FORBIDDEN');
});

test('preflight plan identity binds case, profile, platform, capabilities, and entries', () => {
  const request = {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/portable@1', platform: 'linux',
    capabilities: { atomicReplace: true, executableBit: true, symlink: true },
    entries: [{ id: 'asset', path: 'Asset', kind: 'regular', mode: 'regular-file' }],
  };
  const base = preflightMaterialization(request).summary.planSha256;
  const variants = [
    { ...request, caseMode: 'case-folded' },
    { ...request, profile: 'path.opengamevcs/linux@1' },
    { ...request, platform: 'macos' },
    { ...request, capabilities: { ...request.capabilities, executableBit: false } },
    { ...request, entries: [{ ...request.entries[0], path: 'Other' }] },
  ];
  for (const variant of variants) assert.notEqual(preflightMaterialization(variant).summary.planSha256, base);
});

test('resolved sidecar groups enter one complete-set plan without redefining group semantics', () => {
  const base = {
    schemaVersion: 'ogvcs.path/preflight-request/v1', caseMode: 'case-sensitive',
    profile: 'path.opengamevcs/portable@1', platform: 'linux',
    capabilities: { atomicReplace: true, executableBit: true, symlink: true },
  };
  const asset = { id: 'asset', path: 'Assets/Hero.prefab', kind: 'regular', mode: 'regular-file' };
  const sidecar = { id: 'sidecar', path: 'Assets/Hero.prefab.meta', kind: 'regular', mode: 'regular-file' };
  const grouped = preflightMaterialization({ ...base, entries: [
    { id: 'assets', path: 'Assets', kind: 'directory', mode: 'directory' }, asset, sidecar,
  ] });
  const incomplete = preflightMaterialization({ ...base, entries: [
    { id: 'assets', path: 'Assets', kind: 'directory', mode: 'directory' }, asset,
  ] });
  assert.equal(grouped.summary.entries, 3);
  assert.notEqual(grouped.summary.planSha256, incomplete.summary.planSha256);
});

test('seeded path properties preserve canonical values, fold idempotence, and bounds', () => {
  let state = 0x9e3779b9;
  const next = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  const alphabet = ['a', 'B', '7', '_', '-', 'é', 'ß', 'Σ', 'Ж', '猫'];
  for (let sample = 0; sample < 2_000; sample += 1) {
    const depth = 1 + (next() % 8); const segments = [];
    for (let segment = 0; segment < depth; segment += 1) {
      const length = 1 + (next() % 16); let value = '';
      for (let index = 0; index < length; index += 1) value += alphabet[next() % alphabet.length];
      segments.push(value.normalize('NFC'));
    }
    const input = segments.join('/');
    const result = evaluatePath(input, { caseMode: 'case-folded', profile: 'path.opengamevcs/portable@1' });
    assert.equal(result.accepted, true);
    assert.equal(result.canonical, input);
    const folded = caseFold(input);
    assert.equal(caseFold(folded), folded);
  }
  assert.equal(evaluatePath(Array.from({ length: 257 }, () => 'a'), { profile: 'path.opengamevcs/portable@1' }).error, 'PATH_LIMIT_EXCEEDED');
  assert.equal(evaluatePath(`${'a'.repeat(255)}/é`, { profile: 'path.opengamevcs/portable@1' }).accepted, true);
  assert.equal(evaluatePath(`${'a'.repeat(256)}/é`, { profile: 'path.opengamevcs/portable@1' }).error, 'PATH_LIMIT_EXCEEDED');
});

test('large caller inputs stop at configured bounds before scanning entries', () => {
  let visited = 0;
  const items = new Proxy(Array.from({ length: 2 }), { get(target, key, receiver) { if (key === '0') visited += 1; return Reflect.get(target, key, receiver); } });
  const result = evaluateCollisions(items, { maxPaths: 1, caseMode: 'case-sensitive', profile: 'path.opengamevcs/linux@1' });
  assert.equal(result.error, 'LIMIT_EXCEEDED');
  assert.equal(visited, 0);

  let segmentReads = 0;
  const oversizedPath = new Proxy(Array.from({ length: 257 }, () => 'a'), {
    get(target, key, receiver) {
      if (key === '0') segmentReads += 1;
      return Reflect.get(target, key, receiver);
    },
  });
  assert.equal(evaluatePath(oversizedPath, { profile: 'path.opengamevcs/linux@1' }).error, 'PATH_LIMIT_EXCEEDED');
  assert.equal(segmentReads, 0);
  assert.equal(evaluatePath('a'.repeat(5000), { profile: 'path.opengamevcs/linux@1' }).error, 'PATH_LIMIT_EXCEEDED');
});

test('contract loader serves only manifest-bound JSON inside the packed authority', () => {
  assert.throws(() => loadContractJson('../package.json'));
  assert.throws(() => loadContractJson('README.md'));
});
