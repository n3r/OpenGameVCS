#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import { comparePortableConformanceReports } from '../core/untrusted-sandbox/js/src/internal/conformance-evidence.mjs';
import { canonicalJson } from '../core/untrusted-sandbox/js/src/internal/reference-contract.mjs';

const args = process.argv.slice(2);
if (args.length !== 8
  || args[0] !== '--linux'
  || args[2] !== '--macos'
  || args[4] !== '--windows'
  || args[6] !== '--output') throw new Error('usage: node tools/compare-untrusted-sandbox-conformance.mjs --linux <report> --macos <report> --windows <report> --output <comparison>');
const paths = [args[1], args[3], args[5]].map((path) => resolve(path));
const reports = await Promise.all(paths.map((path) => readFile(path, 'utf8').then(JSON.parse)));
const comparison = comparePortableConformanceReports(reports);
const output = resolve(args[7]);
await writeFile(output, Buffer.from(`${canonicalJson(comparison)}\n`, 'utf8'), { flag: 'wx', mode: 0o600 });
process.stdout.write(`${canonicalJson({ output, result: comparison.result, sourceRevision: comparison.sourceRevision })}\n`);
