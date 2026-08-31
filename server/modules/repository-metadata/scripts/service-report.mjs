#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cases = [
  'migration-v1-v5-upgrade-preserves-unpublished-history',
  'canonical-file-graph',
  'authorization-binding-and-poisoning',
  'authorized-view-item-projections',
  'publication-index-and-lifetime-binding',
  'immutable-settings-object-read',
  'outbox-lease-ack-release',
  'project-repository-list-cursors',
  'cas-100-racers',
  'file-id-race-and-tombstone',
  'rollback-outbox-idempotency',
  'migration-repeat-checksum-downgrade',
  'consistency-token-primary-and-lag',
  'bounded-ancestry-file-path-history',
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

function reportedCases(output) {
  return new Set(
    [...output.matchAll(/OGVCS_METADATA_REPORT ([a-z0-9]+(?:-[a-z0-9]+)*)/gu)]
      .map((match) => match[1]),
  );
}

if (process.argv.includes('--check')) {
  const harnessPrefixed = reportedCases(`test production_reference_postgres_report ... OGVCS_METADATA_REPORT ${cases[0]}\n`);
  if (!harnessPrefixed.has(cases[0])) throw new Error('report marker parser does not accept the Rust test-harness prefix');
  process.stdout.write(`${JSON.stringify(report('declared', cases))}\n`);
  process.exit(0);
}

if (!process.env.OGVCS_METADATA_DATABASE_URL) {
  process.stdout.write(`${JSON.stringify(report('skipped', cases, 'OGVCS_METADATA_DATABASE_URL is unset'))}\n`);
  process.exit(0);
}

const execution = spawnSync(
  'cargo',
  ['test', '--locked', '--features', 'legacy-test-adapter', '--test', 'postgres_integration', '--', '--nocapture', '--test-threads=1'],
  { cwd: root, encoding: 'utf8', env: process.env },
);
if (execution.error) {
  process.stderr.write(`${execution.error.message}\n`);
  process.exit(1);
}
process.stderr.write(execution.stdout);
process.stderr.write(execution.stderr);
const passed = reportedCases(execution.stdout);
const rows = cases.map((id) => ({ id, status: passed.has(id) ? 'passed' : 'failed' }));
const succeeded = execution.status === 0 && rows.every((row) => row.status === 'passed');
process.stdout.write(`${JSON.stringify({
  schemaVersion: 'ogvcs.repository-metadata/service-report/v1',
  exactScaleExecuted: false,
  status: succeeded ? 'passed' : 'failed',
  rows,
})}\n`);
process.exit(succeeded ? 0 : (execution.status || 1));
