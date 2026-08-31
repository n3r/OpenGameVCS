import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowPath = new URL('../.github/workflows/object-transfer.yml', import.meta.url);

test('object transfer workflow pins the bounded three-host JavaScript contract/runtime lane', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  assert.match(workflow, /^name: Object transfer bounded conformance$/mu);
  assert.match(workflow, /runner: ubuntu-latest, label: Linux/u);
  assert.match(workflow, /runner: macos-latest, label: macOS/u);
  assert.match(workflow, /runner: windows-latest, label: Windows/u);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 1);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    1,
  );
  assert.equal(
    workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length,
    1,
  );
  assert.match(workflow, /npm ci --ignore-scripts --no-audit --no-fund/u);
  assert.match(workflow, /npm run test:transfer:spec/u);
  assert.match(workflow, /npm run test:transfer$/mu);
  assert.match(workflow, /npm run test:packed --workspace @opengamevcs\/chunking-manifest/u);
  assert.match(workflow, /npm run test:roadmap/u);
  assert.match(workflow, /core\/chunking-manifest\/\*\*/u);
  assert.match(workflow, /spec\/chunking-manifest\/v1\/\*\*/u);
  assert.match(workflow, /spec\/object-transfer\/v1\/\*\*/u);
  assert.match(workflow, /core\/object-transfer\/\*\*/u);
  assert.match(workflow, /tools\/object-transfer-workflow-policy\.test\.mjs/u);
  assert.doesNotMatch(workflow, /100.?GiB|1.?TiB|S3|scale|throughput benchmark/iu);
});
