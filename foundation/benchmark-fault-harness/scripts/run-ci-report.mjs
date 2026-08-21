#!/usr/bin/env node

import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/canonical.mjs';
import { asHarnessError } from '../src/errors.mjs';
import { runBenchmarkReport } from '../src/report.mjs';

const parsed = parseArgs({ options: { output: { type: 'string' }, profile: { type: 'string' }, contract: { type: 'string' }, help: { type: 'boolean', short: 'h', default: false } }, strict: true });
if (parsed.values.help) {
  process.stdout.write('Usage: run-ci-report --output <directory> [--profile local-smoke|presubmit|nightly] [--contract <directory>]\n');
} else {
  try {
    if (!parsed.values.output) throw new TypeError('--output is required');
    let contractRoot = parsed.values.contract && resolve(parsed.values.contract);
    if (!contractRoot) {
      const sourceContract = fileURLToPath(new URL('../../../spec/benchmark-fault/v1/', import.meta.url));
      try { await access(new URL('manifest.json', new URL('../../../spec/benchmark-fault/v1/', import.meta.url))); contractRoot = sourceContract; } catch { /* packed install resolves its declared dependency */ }
    }
    const report = await runBenchmarkReport({ output: resolve(parsed.values.output), harnessProfile: parsed.values.profile, ...(contractRoot ? { contractRoot } : {}) });
    process.stdout.write(`${canonicalJson(report)}\n`);
  } catch (error) {
    const failure = asHarnessError(error, 'HARNESS_INPUT_INVALID');
    process.stderr.write(`${canonicalJson({ ok: false, code: failure.code, message: failure.message })}\n`);
    process.exitCode = 1;
  }
}
