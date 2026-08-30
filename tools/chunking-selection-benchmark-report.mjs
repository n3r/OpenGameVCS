#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildChunkingSelectionReport, canonicalJson } from './chunking-selection-benchmark-common.mjs';

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--output' || argv[1].length === 0) {
    throw new Error('usage: node tools/chunking-selection-benchmark-report.mjs --output <report.json>');
  }
  return resolve(process.cwd(), argv[1]);
}

export { buildChunkingSelectionReport } from './chunking-selection-benchmark-common.mjs';

async function main() {
  const output = parseArguments(process.argv.slice(2));
  const report = await buildChunkingSelectionReport();
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonicalJson(report)}\n`, 'utf8');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await main();
}
