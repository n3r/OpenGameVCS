#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalStringify, generateFixture, verifyFixture } from '../src/index.mjs';

const packageDirectory = fileURLToPath(new URL('../', import.meta.url));
const outputFlag = process.argv.indexOf('--output');
if (outputFlag !== -1 && (outputFlag !== process.argv.length - 2 || !process.argv[outputFlag + 1])) {
  throw new Error('Usage: golden-summary.mjs [--output <path>]');
}
if (outputFlag === -1 && process.argv.length !== 2) {
  throw new Error('Usage: golden-summary.mjs [--output <path>]');
}

const scratch = await mkdtemp(path.join(os.tmpdir(), 'ogvcs-golden-summary-'));
try {
  const profileDirectories = (await readdir(path.join(packageDirectory, 'goldens'), {
    withFileTypes: true,
  }))
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const profiles = [];
  for (const profileDirectory of profileDirectories) {
    const request = JSON.parse(await readFile(
      path.join(packageDirectory, 'goldens', profileDirectory, 'request.json'),
      'utf8',
    ));
    const profileScratch = path.join(scratch, profileDirectory);
    await mkdir(profileScratch);
    const generated = await generateFixture(request, { cwd: profileScratch });
    const fixtureDirectory = path.join(profileScratch, ...request.destination.split('/'));
    const manifest = JSON.parse(await readFile(path.join(fixtureDirectory, 'manifest.json'), 'utf8'));
    const verification = await verifyFixture(request.destination, { cwd: profileScratch, deep: true });
    if (!verification.verified) {
      throw new Error(`${profileDirectory} failed deep verification`);
    }
    profiles.push({
      artifactDigests: {
        inventory: await sha256File(path.join(fixtureDirectory, manifest.inventory.path)),
        operations: await sha256File(path.join(fixtureDirectory, 'operations.ndjson')),
        scenario: await sha256File(path.join(fixtureDirectory, manifest.operationScenario.path)),
      },
      counts: manifest.counts,
      digests: manifest.digests,
      manifestDigest: generated.manifestDigest,
      profile: manifest.profile,
      requestDigest: generated.requestDigest,
    });
  }

  const document = `${canonicalStringify({
    profiles,
    schemaVersion: 'ogvcs.fixture/golden-conformance-summary/v1',
  })}\n`;
  if (outputFlag === -1) process.stdout.write(document);
  else await writeFile(path.resolve(process.argv[outputFlag + 1]), document, { flag: 'wx' });
} finally {
  await rm(scratch, { force: true, recursive: true });
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}
