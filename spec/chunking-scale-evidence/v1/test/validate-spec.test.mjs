import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '../../../..');
const CONTRACT = join(ROOT, 'spec/chunking-scale-evidence/v1');
const GENERATE = join(CONTRACT, 'source/generate.mjs');
const VALIDATE = join(CONTRACT, 'validate-spec.mjs');
const run = (path, env = {}) => spawnSync(process.execPath, [path, ...(path === GENERATE ? ['--check'] : [])], { cwd: ROOT, env: { ...process.env, ...env }, encoding: 'utf8' });

test('generated OGVCS-007 exact-scale authority is current and independently valid', () => {
  const generated = run(GENERATE);
  assert.equal(generated.status, 0, generated.stderr);
  const validated = run(VALIDATE);
  assert.equal(validated.status, 0, validated.stderr);
  assert.equal(JSON.parse(validated.stdout).verified, true);
});

test('independent validation rejects authority, threshold, artifact, and predecessor substitution', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-scale-contract-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(CONTRACT, directory, { recursive: true });
  const env = { OGVCS_CHUNK_SCALE_CONTRACT_ROOT: directory };
  const cases = [
    ['registries/exact-scale-authority.json', (row) => { row.profile.ordinaryDispatchAllowed = true; }],
    ['registries/exact-scale-authority.json', (row) => { row.profile.sourceRevisionBinding = 'git-bound'; }],
    ['registries/exact-scale-authority.json', (row) => { row.task.completionCondition = 'verified every referenced chunk'; }],
    ['thresholds/chunking-exact-scale-release-v1.json', (row) => { row.entries[4].value += 1; }],
    ['schemas/retained-publication.schema.json', (row) => { row.properties.artifacts.maxItems = 4; }],
    ['schemas/scale-report.schema.json', (row) => { row.additionalProperties = true; }],
    ['manifest.json', (row) => { row.predecessorPins.benchmark.manifestSha256 = '0'.repeat(64); }],
  ];
  for (const [path, mutate] of cases) {
    await cp(CONTRACT, directory, { recursive: true, force: true });
    const target = join(directory, path);
    const value = JSON.parse(await readFile(target));
    mutate(value);
    await writeFile(target, `${JSON.stringify(value)}\n`);
    const result = run(VALIDATE, env);
    assert.notEqual(result.status, 0, `${path} substitution was accepted`);
  }
});

test('generation check rejects missing or stale generated artifacts without writing them', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-scale-generate-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(CONTRACT, directory, { recursive: true });
  const path = join(directory, 'registries/exact-scale-authority.json');
  await writeFile(path, '{}\n');
  const result = run(GENERATE, { OGVCS_CHUNK_SCALE_CONTRACT_ROOT: directory });
  assert.notEqual(result.status, 0);
  assert.equal(await readFile(path, 'utf8'), '{}\n');
});
