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
  const manifest = JSON.parse(await readFile(join(root, 'manifest.json')));
  assert.equal(manifest.contractVersion, '0.2.0');
  assert.equal(manifest.counts.schemas, 8);
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

test('semantic validation enforces profile, path, metadata-kind, and persistence bounds', async () => {
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
    () => validateMetadataOperationSemantics('repository.create', {
      ...create,
      rootSnapshot: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`,
    }, root),
    /rootSnapshot must be snapshot/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('repository.create', {
      ...create,
      defaultReference: '💾'.repeat(129),
    }, root),
    /reference name/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('history.path-page', {
      path: ['界'.repeat(86)],
      snapshot: create.rootSnapshot,
    }, root),
    /segment UTF-8 bytes/u,
  );
  for (const segment of ['a\\b', '.ogvcs', '\u0001']) {
    await assert.rejects(
      () => validateMetadataOperationSemantics('history.path-page', {
        path: [segment],
        snapshot: create.rootSnapshot,
      }, root),
      /path segment is invalid/u,
    );
  }
  await validateMetadataOperationSemantics('history.path-page', {
    path: ['\u0085'],
    snapshot: create.rootSnapshot,
  }, root);
  await validateMetadataOperationSemantics('reference.read', { referenceName: '💾'.repeat(128) }, root);
  await validateMetadataOperationSemantics('reference.read', { referenceName: '\u0085' }, root);
  await assert.rejects(
    () => validateMetadataOperationSemantics('reference.read', { referenceName: 'main\0hidden' }, root),
    /reference name/u,
  );
  await validateMetadataOperationSemantics('object.get', {
    objectRef: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`,
  }, root);
  for (const kind of ['chunk', 'shelf-revision']) {
    await assert.rejects(
      () => validateMetadataOperationSemantics('object.get', {
        objectRef: `ogvcs:v1:${kind}:sha256:${'01'.repeat(32)}`,
      }, root),
      /not repository metadata/u,
    );
  }
  await assert.rejects(
    () => validateMetadataOperationSemantics('tree.page', {
      snapshot: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`,
      tree: `ogvcs:v1:tree:sha256:${'02'.repeat(32)}`,
    }, root),
    /snapshot must be snapshot/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('tree.page', {
      snapshot: `ogvcs:v1:snapshot:sha256:${'01'.repeat(32)}`,
      tree: `ogvcs:v1:snapshot:sha256:${'02'.repeat(32)}`,
    }, root),
    /tree must be tree/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('history.ancestry-page', {
      snapshot: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`,
    }, root),
    /snapshot must be snapshot/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('reference.compare-and-swap', {
      referenceName: 'main',
      expected: { state: 'present', target: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}` },
      desired: null,
    }, root),
    /expected.target must be snapshot/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('reference.compare-and-swap', {
      referenceName: 'main',
      expected: { state: 'absent' },
      desired: `ogvcs:v1:tree:sha256:${'01'.repeat(32)}`,
    }, root),
    /desired must be snapshot/u,
  );
  await validateMetadataOperationSemantics('file-id.register', {
    origin: 'create',
    allocationReceipt: `far1.${'A'.repeat(43)}`,
    ownerId: 'draft-1',
  }, root);
  await assert.rejects(
    () => validateMetadataOperationSemantics('file-id.register', { origin: 'copy' }, root),
    /lacks an allocation receipt/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('file-id.register', {
      origin: 'restore',
      allocationReceipt: `far1.${'A'.repeat(43)}`,
    }, root),
    /cannot counterfeit/u,
  );
  await assert.rejects(
    () => validateMetadataOperationSemantics('file-id.register-import', {
      ownerId: '💾'.repeat(65),
    }, root),
    /persisted identifier/u,
  );
});
