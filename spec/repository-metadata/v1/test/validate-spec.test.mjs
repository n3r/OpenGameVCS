import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { validateMetadataOperationSemantics, validateRepositoryMetadataContract } from '../validate-spec.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));

test('generated metadata contract authenticates and covers every OGVCS-006 requirement', async () => {
  const result = await validateRepositoryMetadataContract(root);
  assert.equal(result.operations, 22);
  assert.equal(result.errors, 11);
  assert.equal(result.vectors, 10);
});

test('contract validation rejects a generated registry tamper', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-metadata-contract-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await cp(root, directory, { recursive: true });
  const target = join(directory, 'registries', 'domain-errors.json');
  const source = await readFile(target, 'utf8');
  await writeFile(target, source.replace('OBJECT_INVALID', 'OBJECT_INVALIX'), 'utf8');
  await assert.rejects(() => validateRepositoryMetadataContract(directory), /authentication failed/u);
});

test('domain errors do not claim frozen OGVCS-041 assignments', async () => {
  const registry = JSON.parse(await readFile(join(root, 'registries', 'domain-errors.json')));
  assert.ok(registry.entries.every(({ protocolBinding }) => protocolBinding === 'unassigned'));
  assert.ok(registry.entries.every(({ code }) => code >= 1001));
});

test('semantic validation enforces profile family, sorted features, and UTF-8 path bytes', async () => {
  const vectorDocument = JSON.parse(await readFile(join(root, 'vectors', 'contract.json')));
  const create = vectorDocument.cases.find(({ id }) => id === 'repository-settings-portable').input;
  await validateMetadataOperationSemantics('repository.create', create, root);
  await assert.rejects(
    () => validateMetadataOperationSemantics('repository.create', { ...create, settings: { ...create.settings, requiredFeatures: [2, 1] } }, root),
    /sorted and unique/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('repository.create', { ...create, settings: { ...create.settings, pathProfile: 'content-policy.test/opaque@1' } }, root),
    /registered path profile/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('history.path-page', { path: ['界'.repeat(86)] }, root),
    /segment UTF-8 bytes/u,
  );
});
