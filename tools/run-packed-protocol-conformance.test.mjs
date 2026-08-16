import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runPackedProtocolConformance } from './run-packed-protocol-conformance.mjs';

test('packed protocol artifacts install, regenerate, and run fully offline', { timeout: 120_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-packed-evidence-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }));
  const evidence = await runPackedProtocolConformance(root);
  assert.equal(evidence.schemaVersion, 'ogvcs.protocol/packed-evidence/v1');
  assert.equal(evidence.adapterIsolation, 'node-permission-isolated-package-staged-authority-v1');
  assert.equal(evidence.contractVersion, '1.0.0-rc.1');
  assert.equal(evidence.license, 'MIT');
  assert.match(evidence.licenseSha256, /^[0-9a-f]{64}$/u);
  assert.equal(evidence.scenarios, 360);
  assert.equal(evidence.result, 'pass');
  assert.equal(evidence.packages.length, 6);
  assert.equal(evidence.packages.every(({ bytes, sha256 }) => bytes > 0 && /^[0-9a-f]{64}$/u.test(sha256)), true);
  assert.deepEqual(evidence.reports.map(({ adapterId }) => adapterId), [
    'ogvcs.protocol/reference-js@1',
    'ogvcs.protocol/independent-js@1',
  ]);
  const sourceManifest = JSON.parse(await readFile(join(root, 'offline-source/offline-source-manifest.json')));
  assert.equal(sourceManifest.license, 'MIT');
  assert.equal(sourceManifest.sourceSetSha256, evidence.sourceSetSha256);
  assert.equal(sourceManifest.files.some(({ path }) => path.endsWith('/LICENSE')), true);
  assert.equal(sourceManifest.files.some(({ path }) => path === 'core/authz-contract/js/package.json'), true);
  assert.equal(sourceManifest.files.some(({ path }) => path === 'core/authz-contract/js/src/index.mjs'), true);
});
