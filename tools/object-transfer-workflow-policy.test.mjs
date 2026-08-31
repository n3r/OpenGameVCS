import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowPath = new URL('../.github/workflows/object-transfer.yml', import.meta.url);
const releaseScalePath = new URL('../.github/workflows/object-transfer-release-scale.yml', import.meta.url);
const provenancePath = new URL('./object-transfer-minio-provenance.json', import.meta.url);

test('object transfer workflow pins the bounded three-host JavaScript contract/runtime lane', async () => {
  const workflow = await readFile(workflowPath, 'utf8');
  const provenance = JSON.parse(await readFile(provenancePath, 'utf8'));
  assert.match(workflow, /^name: Object transfer bounded conformance$/mu);
  assert.match(workflow, /runner: ubuntu-latest, label: Linux/u);
  assert.match(workflow, /runner: macos-latest, label: macOS/u);
  assert.match(workflow, /runner: windows-latest, label: Windows/u);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 2);
  assert.equal(
    workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length,
    2,
  );
  assert.equal(
    workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length,
    2,
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
  assert.match(workflow, /s3-compatible:\n    name: Pinned MinIO shared backend conformance \(Linux\)\n    runs-on: ubuntu-latest/u);
  assert.match(workflow, /OGVCS_S3_CONFORMANCE_ENDPOINT: http:\/\/127\.0\.0\.1:9000/u);
  assert.match(workflow, new RegExp(provenance.release, 'u'));
  assert.match(workflow, new RegExp(provenance.artifactSha256, 'u'));
  assert.match(workflow, new RegExp(provenance.downloadUrl.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'u'));
  assert.equal(provenance.platform, 'linux-amd64');
  assert.match(provenance.sourceReleaseUrl, /^https:\/\/github\.com\/minio\/minio\/releases\/tag\/RELEASE\./u);
  assert.doesNotMatch(workflow, /107374182400|RUN-EXACT-100-GIB/u);
  assert.doesNotMatch(
    workflow,
    /^\s*-\s*run:\s+.*object-transfer-release-scale\.mjs/mu,
  );
  assert.doesNotMatch(workflow, /MINIO_ROOT_PASSWORD[^\n]*(echo|print)|set -x/iu);
});

test('exact 100-GiB execution is isolated behind a manual self-hosted confirmation gate', async () => {
  const workflow = await readFile(releaseScalePath, 'utf8');
  assert.match(workflow, /^name: Object transfer exact release scale$/mu);
  assert.match(workflow, /^  workflow_dispatch:$/mu);
  assert.doesNotMatch(workflow, /^  (pull_request|push|schedule):/mu);
  assert.match(workflow, /if: inputs\.confirmation == 'RUN-EXACT-100-GIB'/u);
  assert.match(workflow, /runs-on: \[self-hosted, ogvcs-exact-scale\]/u);
  assert.match(workflow, /node-version: 24/u);
  assert.match(workflow, /--logical-bytes 107374182400/u);
  assert.match(workflow, /--chunk-bytes 8388608/u);
  assert.match(workflow, /tools\/object-transfer-release-scale\.mjs/u);
  assert.equal(workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length, 1);
  assert.equal(workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length, 1);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 1);
});
