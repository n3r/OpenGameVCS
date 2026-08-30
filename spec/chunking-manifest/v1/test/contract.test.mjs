import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, cp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const ROOT = resolve(import.meta.dirname, '..');
function run(script, args = [], env = {}) { return spawnSync(process.execPath, [resolve(ROOT, script), ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, ...env } }); }

test('generated contract is current and independently validates', () => {
  const generation = run('scripts/generate.mjs', ['--check']);
  assert.equal(generation.status, 0, generation.stderr);
  const validation = run('validate-spec.mjs');
  assert.equal(validation.status, 0, validation.stderr);
  const result = JSON.parse(validation.stdout);
  assert.equal(result.profile, 'chunking.opengamevcs/gear-fastcdc-1m@1');
  assert.match(result.tableSha256, /^[0-9a-f]{64}$/u);
});

test('independent validator rejects a changed golden boundary', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-contract-'));
  await cp(ROOT, temporary, { recursive: true });
  const path = join(temporary, 'vectors/golden.json');
  const vector = JSON.parse(await readFile(path, 'utf8'));
  vector.cases.find(({ caseId }) => caseId === 'counter-a-six-mib').expected.boundaries[0] += 1;
  await writeFile(path, `${JSON.stringify(vector)}\n`);
  const validation = run('validate-spec.mjs', [], { OGVCS_CHUNK_CONTRACT_ROOT: temporary });
  assert.notEqual(validation.status, 0);
});

test('independent validator rejects stale manifest count schema', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-contract-'));
  await cp(ROOT, temporary, { recursive: true });
  const path = join(temporary, 'schemas/manifest.schema.json');
  const schema = JSON.parse(await readFile(path, 'utf8'));
  schema.properties.counts.properties.schemas.const = 5;
  await writeFile(path, `${JSON.stringify(schema)}\n`);
  const validation = run('validate-spec.mjs', [], { OGVCS_CHUNK_CONTRACT_ROOT: temporary });
  assert.notEqual(validation.status, 0);
  assert.match(validation.stderr, /count authority/u);
});

test('independent validator rejects coordinated portable-gzip authority drift', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'ogvcs-chunk-contract-'));
  await cp(ROOT, temporary, { recursive: true });
  const workloadPath = join(temporary, 'vectors/selection-benchmark-workloads.json');
  const schemaPath = join(temporary, 'schemas/selection-benchmark-workloads.schema.json');
  const workloads = JSON.parse(await readFile(workloadPath, 'utf8'));
  const compressed = workloads.workloads.find(({ workloadId }) => workloadId === 'already-compressed');
  compressed.baseRecipe.encoder = 'native-zlib';
  compressed.candidateRecipe.encoder = 'native-zlib';
  const schema = JSON.parse(await readFile(schemaPath, 'utf8'));
  schema.$defs.recipe.allOf[0].then.properties.encoder.const = 'native-zlib';
  await Promise.all([
    writeFile(workloadPath, `${JSON.stringify(workloads)}\n`),
    writeFile(schemaPath, `${JSON.stringify(schema)}\n`),
  ]);
  const validation = run('validate-spec.mjs', [], { OGVCS_CHUNK_CONTRACT_ROOT: temporary });
  assert.notEqual(validation.status, 0);
  assert.match(validation.stderr, /portable gzip encoder/u);
});
