import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { loadBenchmarkContract } from '../../../../foundation/benchmark-fault-harness/src/contract.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

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
