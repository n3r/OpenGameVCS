#!/usr/bin/env node

import { resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { canonicalJson } from '../foundation/benchmark-fault-harness/src/canonical.mjs';
import { runBenchmarkReport } from '../foundation/benchmark-fault-harness/src/report.mjs';

const parsed = parseArgs({ options: { output: { type: 'string' }, profile: { type: 'string', default: 'presubmit' } }, strict: true });
if (!parsed.values.output) throw new Error('usage: node tools/benchmark-fault-conformance-report.mjs --output <directory> [--profile <name>]');
const report = await runBenchmarkReport({ output: resolve(parsed.values.output), contractRoot: resolve(import.meta.dirname, '../spec/benchmark-fault/v1'), harnessProfile: parsed.values.profile });
process.stdout.write(`${canonicalJson(report)}\n`);
