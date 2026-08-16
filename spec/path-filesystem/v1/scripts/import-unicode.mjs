#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EXPECTED = Object.freeze({
  caseFolding: '6f1f9c588eb4a5c718d9e8f93b782685e5c7fec872cf05e8e6878053599e09bb',
  license: 'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96',
});

function usage() {
  throw new Error('usage: node scripts/import-unicode.mjs <CaseFolding-16.0.0.txt> <unicode-license.txt>');
}

if (process.argv.length !== 4) usage();
const [caseSource, licenseSource] = process.argv.slice(2).map((value) => resolve(value));

async function digest(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

if (await digest(caseSource) !== EXPECTED.caseFolding) {
  throw new Error('Unicode CaseFolding-16.0.0.txt digest does not match the frozen authority');
}
if (await digest(licenseSource) !== EXPECTED.license) {
  throw new Error('Unicode license digest does not match the frozen authority');
}

const destination = resolve(ROOT, 'data');
await mkdir(destination, { recursive: true });
await copyFile(caseSource, resolve(destination, 'CaseFolding-16.0.0.txt'));
await copyFile(licenseSource, resolve(destination, 'UNICODE-LICENSE.txt'));
