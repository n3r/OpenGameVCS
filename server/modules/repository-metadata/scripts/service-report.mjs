#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cases = [
  'canonical-file-graph',
  'authorization-binding-and-poisoning',
  'cas-100-racers',
  'file-id-race-and-tombstone',
  'rollback-outbox-idempotency',
  'migration-repeat-checksum-downgrade',
  'consistency-token-primary-and-lag',
];

function report(status, rows, detail) {
  return {
    schemaVersion: 'ogvcs.repository-metadata/service-report/v1',
    exactScaleExecuted: false,
    status,
    rows: rows.map((id) => ({ id, status })),
    ...(detail ? { detail } : {}),
  };
}

if (process.argv.includes('--check')) {
  process.stdout.write(`${JSON.stringify(report('declared', cases))}\n`);
  process.exit(0);
}

if (!process.env.OGVCS_METADATA_DATABASE_URL) {
  process.stdout.write(`${JSON.stringify(report('skipped', cases, 'OGVCS_METADATA_DATABASE_URL is unset'))}\n`);
  process.exit(0);
}

const execution = spawnSync(
  'cargo',
  ['test', '--test', 'postgres_integration', '--', '--nocapture', '--test-threads=1'],
  { cwd: root, encoding: 'utf8', env: process.env },
);
if (execution.error) {
  process.stderr.write(`${execution.error.message}\n`);
  process.exit(1);
}
process.stdout.write(execution.stdout);
process.stderr.write(execution.stderr);
const passed = new Set(
  execution.stdout
    .split(/\r?\n/u)
    .filter((line) => line.startsWith('OGVCS_METADATA_REPORT '))
    .map((line) => line.slice('OGVCS_METADATA_REPORT '.length)),
);
const rows = cases.map((id) => ({ id, status: passed.has(id) ? 'passed' : 'failed' }));
process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ogvcs.repository-metadata/service-report/v1',
  exactScaleExecuted: false,
  status: execution.status === 0 && rows.every((row) => row.status === 'passed') ? 'passed' : 'failed',
  rows,
})}\n`);
process.exit(execution.status ?? 1);
