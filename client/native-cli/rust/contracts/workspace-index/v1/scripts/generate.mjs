#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CHECK = process.argv.slice(2).includes('--check');
if (process.argv.length > 3 || (process.argv.length === 3 && !CHECK)) {
  throw new Error('usage: node scripts/generate.mjs [--check]');
}

const CONTRACT_VERSION = '0.1.0-rc.4';
const ARTIFACTS = [
  'README.md',
  'contract.json',
  'scripts/generate.mjs',
  'validate.mjs',
  'vectors/retention-hmac.json',
  'vectors/status-cursor-hmac.json',
].sort();
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');

const records = [];
for (const path of ARTIFACTS) {
  const bytes = await readFile(resolve(ROOT, path));
  records.push({ path, bytes: bytes.length, sha256: sha256(bytes) });
}
const manifest = {
  schema: 'ogvcs.workspace-index/private-contract-manifest/v1',
  contractVersion: CONTRACT_VERSION,
  artifactSetSha256: sha256(canonicalBytes(records)),
  counts: { artifacts: records.length, vectors: 2 },
  artifacts: records,
};
const expected = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
const destination = resolve(ROOT, 'manifest.json');
if (CHECK) {
  const actual = await readFile(destination).catch(() => null);
  if (actual === null || !actual.equals(expected)) {
    process.stderr.write('manifest.json: generated content differs\n');
    process.exitCode = 1;
  }
} else {
  await writeFile(destination, expected);
}
