import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { canonicalStringify, generateFixture, verifyFixture } from '../src/index.mjs';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));
const profiles = ['code-heavy', 'unreal-like', 'unity-like', 'large-binary', 'global-studio'];

for (const profile of profiles) {
  test(`${profile} golden request has portable byte-identical digests`, async (t) => {
    const root = await mkdtemp(path.join(os.tmpdir(), `ogvcs-golden-${profile}-`));
    t.after(() => rm(root, { force: true, recursive: true }));
    const requestPath = path.join(packageRoot, 'goldens', profile, 'request.json');
    const expectedPath = path.join(packageRoot, 'goldens', profile, 'expected.json');
    const requestText = await readFile(requestPath, 'utf8');
    const request = JSON.parse(requestText);
    const expected = JSON.parse(await readFile(expectedPath, 'utf8'));
    assert.equal(requestText, `${canonicalStringify(request)}\n`, 'golden request itself is canonical');

    const firstRoot = path.join(root, 'first');
    const secondRoot = path.join(root, 'second');
    await mkdir(firstRoot);
    await mkdir(secondRoot);
    await generateFixture(request, { cwd: firstRoot });
    await generateFixture(request, { cwd: secondRoot });

    const first = JSON.parse(await readFile(path.join(firstRoot, 'fixture', 'manifest.json'), 'utf8'));
    const second = JSON.parse(await readFile(path.join(secondRoot, 'fixture', 'manifest.json'), 'utf8'));
    const actual = {
      counts: first.counts,
      digests: first.digests,
      manifestDigest: first.manifestDigest,
      profile: first.profile,
      requestDigest: first.requestDigest,
    };
    assert.deepEqual(actual, expected);
    assert.equal(canonicalStringify(first), canonicalStringify(second));
    assert.deepEqual(await verifyFixture('fixture', { cwd: firstRoot, deep: true }),
      await verifyFixture('fixture', { cwd: secondRoot, deep: true }));
  });
}
