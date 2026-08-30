#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const reportPaths = process.argv.slice(2);
if (reportPaths.length < 2) {
  throw new Error('usage: compare-bounded-reports.mjs <reference.json> <candidate.json> [...]');
}
const [referencePath, ...candidatePaths] = reportPaths;
const reference = JSON.parse(await readFile(referencePath));
for (const candidatePath of candidatePaths) {
  const candidate = JSON.parse(await readFile(candidatePath));
  assert.deepEqual(candidate, reference, `${candidatePath} differs from ${referencePath}`);
}
process.stdout.write(
  `matched ${reference.cases.length} bounded cases across ${reportPaths.length} reports\n`
);
