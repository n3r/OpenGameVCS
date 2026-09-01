import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/untrusted-sandbox.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);

test('untrusted sandbox workflow pins portable protocol and live Linux isolation lanes', async () => {
  const [workflow, rootPackage] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
  ]);
  assert.match(workflow, /^name: Untrusted parser sandbox boundary$/mu);
  assert.match(workflow, /os: \[ubuntu-latest, macos-latest, windows-latest\]/u);
  assert.match(workflow, /linux-reference-conformance:\n    name: Linux reference isolation and hostile canaries\n    runs-on: ubuntu-latest/u);
  assert.equal(workflow.match(/node-version: 24/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/gu)?.length, 2);
  assert.equal(workflow.match(/actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/gu)?.length, 1);
  assert.match(workflow, /cc -static -O2 -std=c17 -Wall -Wextra -Werror core\/untrusted-sandbox\/js\/linux\/output_shim\.c/u);
  assert.match(workflow, /docker build --pull=false --network=none/u);
  assert.match(workflow, /npm run test:linux --workspace @opengamevcs\/untrusted-sandbox/u);
  assert.match(workflow, /OGVCS_DOCKER_BINARY: \/usr\/bin\/docker/u);
  assert.match(workflow, /untrusted-sandbox-linux-reference\.json/u);
  assert.doesNotMatch(workflow, /Retain Linux reference evidence\n        if: always\(\)/u);
  assert.match(workflow, /timeout-minutes: 20/u);
  assert.doesNotMatch(workflow, /continue-on-error|privileged|--network=(?:host|bridge)|--cap-add|--security-opt[= ]seccomp=unconfined/iu);
  assert.match(rootPackage.scripts['test:sandbox'], /untrusted-sandbox-workflow-policy\.test\.mjs/u);
});
