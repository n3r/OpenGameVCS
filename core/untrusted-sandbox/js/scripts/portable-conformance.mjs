#!/usr/bin/env node

import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  readGitSourceEvidence,
  runPrivatePortableConformance,
} from '../src/internal/conformance-evidence.mjs';
import { canonicalJson } from '../src/internal/reference-contract.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== '--output' || args[2] !== '--source-revision') {
  throw new Error('usage: node scripts/portable-conformance.mjs --output <report.json> --source-revision <40-hex>');
}
if (Number.parseInt(process.versions.node.split('.')[0], 10) !== 24) throw new Error('portable conformance requires Node 24');
const output = resolve(args[1]);
const sourceRevision = args[3];
const platform = process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : process.platform;
const source = await readGitSourceEvidence({ repositoryRoot, sourceRevision });
const report = await runPrivatePortableConformance({ platform, sourceFiles: source.sourceFiles, sourceRevision });
await writeFile(output, Buffer.from(`${canonicalJson(report)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
process.stdout.write(`${canonicalJson({ outcome: report.outcome, output, platform, sourceRevision })}\n`);
if (report.outcome !== 'passed') process.exitCode = 1;
