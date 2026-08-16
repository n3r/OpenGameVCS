import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { buildProtocolConformanceEvidence } from './protocol-conformance-report.mjs';

test('source protocol evidence runs both independent adapters over every bounded case', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-source-evidence-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }));
  const evidence = await buildProtocolConformanceEvidence(root);
  assert.equal(evidence.schemaVersion, 'ogvcs.protocol/conformance-evidence/v1');
  assert.equal(evidence.adapterIsolation, 'node-permission-isolated-package-staged-authority-v1');
  assert.equal(evidence.contractVersion, '1.0.0-rc.1');
  assert.equal(evidence.license, 'MIT');
  assert.match(evidence.licenseSha256, /^[0-9a-f]{64}$/u);
  assert.equal(evidence.scenarios, 360);
  assert.equal(evidence.result, 'pass');
  assert.deepEqual(evidence.reports.map(({ adapterId }) => adapterId), [
    'ogvcs.protocol/reference-js@1',
    'ogvcs.protocol/independent-js@1',
  ]);
  assert.equal(evidence.reports[0].reportDigest, evidence.reports[1].reportDigest);
  const reports = await Promise.all(evidence.reports.map(async ({ filename }) => JSON.parse(await readFile(join(root, filename)))));
  assert.equal(reports[0].failed, 0);
  assert.equal(reports[1].failed, 0);
  assert.deepEqual(reports[0].results, reports[1].results);
  const deniedReplay = reports[0].results.find(({ id }) => id === 'idempotency-response-loss-replay-authorization-revoked');
  assert.deepEqual({ code: deniedReplay?.code, mutationCount: deniedReplay?.mutationCount, preMutation: deniedReplay?.preMutation, result: deniedReplay?.result }, {
    code: 'AUTHORIZATION_DENIED', mutationCount: 1, preMutation: false, result: 'reject',
  });
});
