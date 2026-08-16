import assert from 'node:assert/strict';
import test from 'node:test';

import { caseFold, evaluateCollisions, evaluatePath, loadContractJson } from '../src/index.mjs';
import { evaluatePreflight } from '../src/preflight.mjs';
import { evaluateRenames } from '../src/rename.mjs';
import { evaluateWatcherCase } from '../src/watcher.mjs';

test('all 62 language-neutral vectors reproduce exact decisions', () => {
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
  assert.equal(executed, 62);
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
