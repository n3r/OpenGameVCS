#!/usr/bin/env node

import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runBenchmarkReport } from '../src/report.mjs';

const scratch = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-ci-'));
try {
  const sourceContract = fileURLToPath(new URL('../../../spec/benchmark-fault/v1/', import.meta.url));
  let contractRoot;
  try { await access(join(sourceContract, 'manifest.json')); contractRoot = sourceContract; } catch { /* packed install resolves its declared contract dependency */ }
  const report = await runBenchmarkReport({ output: join(scratch, 'report'), harnessProfile: 'presubmit', ...(contractRoot ? { contractRoot } : {}) });
  if (report.overallStatus !== 'passed' || report.counts.corpora !== 5 || report.counts.samples !== 1_320 || report.results.conformanceFailed !== 0 || report.results.faultFailures !== 0 || report.results.brokenMisses !== 0 || report.results.securityMisses !== 0 || report.exactScaleExecuted !== false) throw new Error('bounded presubmit report is incomplete or failed');
  process.stdout.write(`${JSON.stringify({ profile: report.profile, samples: report.counts.samples, semanticResultsSha256: report.semanticResultsSha256, passed: true })}\n`);
} finally { await rm(scratch, { recursive: true, force: true }); }
