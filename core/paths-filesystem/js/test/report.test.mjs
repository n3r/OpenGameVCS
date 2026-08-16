import assert from 'node:assert/strict';
import test from 'node:test';

import { buildConformanceReport } from '../src/report.mjs';

test('conformance report executes every pure vector and bounded native proof', async () => {
  const report = await buildConformanceReport();
  assert.equal(report.total, 72);
  assert.equal(report.passed, 72);
  assert.equal(report.failed, 0);
  assert.equal(report.results.filter(({ category }) => category !== 'native-filesystem').length, 62);
  assert.match(report.resultsSha256, /^[0-9a-f]{64}$/u);
});
