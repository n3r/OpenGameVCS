#!/usr/bin/env node

import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  canonicalStringify,
  createRequest,
  generateFixture,
  listProfiles,
  verifyFixture,
} from '../src/index.mjs';

const write = process.argv.length === 3 && process.argv[2] === '--write';
if (!write && process.argv.length !== 2) {
  throw new Error('Usage: update-goldens.mjs [--write]');
}

const packageDirectory = fileURLToPath(new URL('../', import.meta.url));
const goldenDirectory = path.join(packageDirectory, 'goldens');
const versions = new Map(listProfiles().map((profile) => [profile.id, profile.version]));
const profileDirectories = (await readdir(goldenDirectory, { withFileTypes: true }))
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();
const scratch = await mkdtemp(path.join(os.tmpdir(), 'ogvcs-update-goldens-'));
const differences = [];

try {
  for (const profileId of profileDirectories) {
    const currentVersion = versions.get(profileId);
    if (!currentVersion) throw new Error(`Golden directory has no built-in profile: ${profileId}`);
    const directory = path.join(goldenDirectory, profileId);
    const previous = JSON.parse(await readFile(path.join(directory, 'request.json'), 'utf8'));
    const request = createRequest({
      destination: 'fixture',
      extensions: previous.extensions,
      profile: { id: profileId, version: currentVersion },
      scale: previous.scale,
      seed: `golden-${profileId}-profile-${currentVersion}`,
    });
    const profileScratch = path.join(scratch, profileId);
    await mkdir(profileScratch);
    const generated = await generateFixture(request, { cwd: profileScratch });
    const verification = await verifyFixture('fixture', { cwd: profileScratch, deep: true });
    if (!verification.verified) throw new Error(`${profileId} did not deep-verify`);
    const manifest = JSON.parse(await readFile(
      path.join(profileScratch, 'fixture', 'manifest.json'),
      'utf8',
    ));
    const expected = {
      counts: manifest.counts,
      digests: manifest.digests,
      manifestDigest: generated.manifestDigest,
      profile: manifest.profile,
      requestDigest: generated.requestDigest,
    };
    await reconcile(path.join(directory, 'request.json'), `${canonicalStringify(request)}\n`);
    await reconcile(path.join(directory, 'expected.json'), `${canonicalStringify(expected)}\n`);
  }
} finally {
  await rm(scratch, { force: true, recursive: true });
}

if (!write && differences.length > 0) {
  throw new Error(`Golden outputs are stale: ${differences.join(', ')}; run with --write`);
}
process.stdout.write(`${canonicalStringify({
  mode: write ? 'updated' : 'checked',
  profiles: profileDirectories,
})}\n`);

async function reconcile(filePath, expectedText) {
  const actualText = await readFile(filePath, 'utf8').catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (actualText === expectedText) return;
  differences.push(path.relative(packageDirectory, filePath));
  if (write) await writeFile(filePath, expectedText);
}
