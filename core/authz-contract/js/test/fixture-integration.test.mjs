import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createRequest, generateFixture, verifyFixture } from '@opengamevcs/fixture-generator';

import { authorizationRequestFromFixtureOperation } from '../src/index.mjs';

test('OGVCS-001 OperationScenario v2 records map through the public authorization request contract', { timeout: 30_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-authz-fixture-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const destination = 'fixture';
  const request = createRequest({
    destination,
    extensions: { 'generation.large-file-mode': 'virtual', 'generation.materialization': 'full' },
    profile: { id: 'global-studio', version: '2.0.0' },
    scale: { historyOperationCount: 18, largeFileBytes: 0, maxDepth: 5, pathCount: 8 },
    seed: 'authorization-contract-v1',
  });
  await generateFixture(request, { cwd: root });
  const verified = await verifyFixture(destination, { cwd: root });
  assert.equal(verified.verified, true);
  const lines = (await readFile(join(root, destination, 'operations.ndjson'), 'utf8')).trim().split('\n');
  assert.equal(lines.length, 18);
  const mapped = lines.map((line) => authorizationRequestFromFixtureOperation(JSON.parse(line), {
    tenant: 'tenant-alpha', repository: 'game-main', authorityEpoch: 3, policyGeneration: 7,
  }));
  assert.deepEqual(new Set(mapped.map(({ permission }) => permission)), new Set(['submit', 'metadata.read', 'lock.create', 'review', 'content.materialize']));
  assert.equal(mapped.every(({ tenant, repository }) => tenant === 'tenant-alpha' && repository === 'game-main'), true);
  assert.equal(mapped.every(({ resource }) => resource.path?.normalize('NFC') === resource.path), true);
});
