import assert from 'node:assert/strict';
import { cp, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

import { loadBenchmarkContract } from '../../../../foundation/benchmark-fault-harness/src/contract.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const workspace = fileURLToPath(new URL('../../../../', import.meta.url));

test('generated contract loads and authenticates every authority set', async () => {
  const contract = await loadBenchmarkContract({ root, cache: false });
  assert.equal(contract.manifest.counts.tasks, 12);
  assert.deepEqual(contract.registries.tasks.entries.slice(0, 11).map(({ id }) => id), ['setup', 'status', 'sync', 'submit', 'lock', 'merge', 'ci', 'verify', 'backup', 'restore', 'export']);
  assert.equal(contract.registries.tasks.entries[11]?.id, 'chunking-verify');
  assert.equal(contract.manifest.counts.faultPoints, 12);
  assert.equal(contract.vectors.conformance.cases.length, contract.manifest.counts.scenarios);
  const directoryUrl = pathToFileURL(root.slice(0, -1));
  const fromDirectoryUrl = await loadBenchmarkContract({ root: directoryUrl, cache: false });
  assert.equal(fromDirectoryUrl.manifestSha256, contract.manifestSha256);
});

test('contract loader rejects a digest-preserving-path tamper', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-contract-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(root, directory, { recursive: true });
  const target = join(directory, 'registries', 'tasks.json');
  const text = await readFile(target, 'utf8');
  await writeFile(target, text.replace('setup', 'setux'), 'utf8');
  await assert.rejects(() => loadBenchmarkContract({ root: directory, cache: false }), /authentication failed/u);
});

test('independent validator rejects regenerated task and corpus-version drift from source model changes', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-benchmark-contract-independent-'));
  const sandbox = join(directory, 'workspace');
  const sandboxSpecRoot = join(sandbox, 'spec/benchmark-fault/v1');
  t.after(() => rm(directory, { recursive: true, force: true }));

  await mkdir(join(sandbox, 'spec/benchmark-fault'), { recursive: true });
  await cp(root, sandboxSpecRoot, { recursive: true });
  await symlink(join(workspace, 'node_modules'), join(sandbox, 'node_modules'));
  await symlink(join(workspace, 'foundation'), join(sandbox, 'foundation'));
  await symlink(join(workspace, 'core'), join(sandbox, 'core'));
  for (const name of ['authorization', 'chunking-manifest', 'path-filesystem', 'protocols', 'repository-format']) {
    await symlink(join(workspace, 'spec', name), join(sandbox, 'spec', name));
  }

  const modelPath = join(sandboxSpecRoot, 'source/model.mjs');
  const model = await readFile(modelPath, 'utf8');
  const mutated = model
    .replace("export const CHUNKING_TASK_ID = 'chunking-verify';", "export const CHUNKING_TASK_ID = 'chunking-verify-mutated';")
    .replace("export const FIXTURE_PROFILE_VERSION = '2.0.0';", "export const FIXTURE_PROFILE_VERSION = '2.0.1';");
  assert.notEqual(mutated, model);
  await writeFile(modelPath, mutated, 'utf8');

  const generate = spawnSync(process.execPath, ['source/generate.mjs'], { cwd: sandboxSpecRoot, encoding: 'utf8' });
  assert.equal(generate.status, 0, generate.stderr);

  const validate = spawnSync(process.execPath, ['validate-spec.mjs'], { cwd: sandboxSpecRoot, encoding: 'utf8' });
  assert.notEqual(validate.status, 0);
  assert.match(`${validate.stdout}\n${validate.stderr}`, /task registry differs|task registry bodies drifted|corpus authority branches drifted/u);
});
