#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import {
  comparePortableConformanceReports,
  readGitSourceEvidence,
} from '../core/untrusted-sandbox/js/src/internal/conformance-evidence.mjs';
import { canonicalJson } from '../core/untrusted-sandbox/js/src/internal/reference-contract.mjs';

const repositoryRoot = resolve(import.meta.dirname, '..');
const args = process.argv.slice(2);
if (args.length !== 10
    || args[0] !== '--linux'
    || args[2] !== '--macos'
    || args[4] !== '--windows'
    || args[6] !== '--source-revision'
    || args[8] !== '--output') throw new Error('usage: node tools/compare-untrusted-sandbox-conformance.mjs --linux <report> --macos <report> --windows <report> --source-revision <40-hex> --output <comparison>');
const paths = [args[1], args[3], args[5]].map((path) => resolve(path));
const reports = await Promise.all(paths.map((path) => readFile(path, 'utf8').then(JSON.parse)));
const expectedSource = await readGitSourceEvidence({ repositoryRoot, sourceRevision: args[7] });
const comparison = comparePortableConformanceReports(reports, expectedSource);
const output = resolve(args[9]);
await writeFile(output, Buffer.from(`${canonicalJson(comparison)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
process.stdout.write(`${canonicalJson({ output, result: comparison.result, sourceRevision: comparison.sourceRevision })}\n`);
