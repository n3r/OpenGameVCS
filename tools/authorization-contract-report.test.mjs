import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const REPOSITORY = resolve(import.meta.dirname, '..');
const RUNNER = join(REPOSITORY, 'tools/run-packed-authorization-conformance.mjs');
const COMPARATOR = join(REPOSITORY, 'tools/compare-authorization-contract-reports.mjs');

function run(file, args) {
  return new Promise((resolvePromise) => {
    execFile(process.execPath, [file, ...args], { cwd: REPOSITORY, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolvePromise({ code: error?.code ?? 0, stdout, stderr });
    });
  });
}

test('packed conformance retains both exact packages and equal reference/adapter reports', { timeout: 180_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-authz-report-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const result = await run(RUNNER, ['--output', root]);
  assert.equal(result.code, 0, result.stderr || result.stdout);
  const evidence = JSON.parse(result.stdout);
  assert.equal(evidence.packages.length, 2);
  assert.deepEqual(evidence.packages.map(({ name }) => name).sort(), ['@opengamevcs/authorization-contract', '@opengamevcs/authorization-contract-v1']);
  assert.equal(evidence.reports.length, 2);
  for (const entry of [...evidence.packages, ...evidence.reports]) assert.match(entry.sha256, /^[0-9a-f]{64}$/);
  const reference = join(root, 'reference-report.json');
  const external = join(root, 'external-adapter-report.json');
  const compared = await run(COMPARATOR, [reference, external]);
  assert.equal(compared.code, 0, compared.stderr || compared.stdout);
  assert.deepEqual(JSON.parse(compared.stdout), {
    schemaVersion: 'ogvcs.authorization/comparison/v1', reports: 2,
    adapters: ['external-adapter', 'reference-fixture'], contractVersion: '1.0.0',
    manifestSha256: evidence.manifestSha256,
    registrySetSha256: evidence.registrySetSha256, resultsSha256: evidence.resultsSha256,
    packages: evidence.packages
      .map(({ name, version, sha256 }) => ({ name, version, sha256 }))
      .sort((left, right) => left.name.localeCompare(right.name)),
    vectors: 30, result: 'equal',
  });

  const changed = join(root, 'changed-report.json');
  const report = JSON.parse(await readFile(external, 'utf8'));
  report.rows[0].actualCode = 'DENY_CONTEXT_INCOMPLETE';
  await writeFile(changed, `${JSON.stringify(report)}\n`);
  const rejected = await run(COMPARATOR, [reference, changed]);
  assert.notEqual(rejected.code, 0);
  assert.match(rejected.stderr, /invalid authorization conformance row|row digest differs/);

  const packagePath = join(root, 'packages', evidence.packages[0].filename);
  await writeFile(packagePath, 'tampered package');
  const packageRejected = await run(COMPARATOR, [reference, external]);
  assert.notEqual(packageRejected.code, 0);
  assert.match(packageRejected.stderr, /packed package digest differs/);
});
