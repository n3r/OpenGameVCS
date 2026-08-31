import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const workflowUrl = new URL('../.github/workflows/identity-policy-audit.yml', import.meta.url);
const packageUrl = new URL('../package.json', import.meta.url);

test('identity-policy workflow is pinned, three-host, Node 24, and bounded', async () => {
  const [workflow, rootPackage] = await Promise.all([
    readFile(workflowUrl, 'utf8'),
    readFile(packageUrl, 'utf8').then(JSON.parse),
  ]);
  assert.match(workflow, /matrix:\s*\n\s*os: \[ubuntu-latest, macos-latest, windows-latest\]/u);
  assert.match(workflow, /node-version: 24/u);
  assert.doesNotMatch(workflow, /node-version: (?:20|22)(?:\D|$)/u);
  assert.match(workflow, /actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\.0\.1/u);
  assert.match(workflow, /actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7\.0\.0/u);
  assert.match(workflow, /npm run test:identity:spec/u);
  assert.match(workflow, /npm run test:identity/u);
  assert.match(workflow, /core\/paths-filesystem\/rust\/scripts\/sync-contract\.mjs --check/u);
  assert.match(workflow, /cargo test --manifest-path core\/paths-filesystem\/rust\/Cargo\.toml --locked --offline/u);
  assert.match(workflow, /cargo clippy --manifest-path core\/paths-filesystem\/rust\/Cargo\.toml --locked --offline --all-targets -- -D warnings/u);
  assert.match(workflow, /--test postgres_live -- --nocapture/u);
  assert.match(workflow, /--test aggregate_postgres_live -- --nocapture/u);
  assert.match(workflow, /- "core\/paths-filesystem\/rust\/\*\*"/u);
  assert.doesNotMatch(workflow, /(?:test:scale|exact[-_: ]scale|100\s*(?:GiB|GB)|1\s*TiB|1,?000,?000)/iu);
  assert.doesNotMatch(workflow, /^\s*schedule:/mu);
  assert.match(rootPackage.scripts['test:identity'], /identity-policy-workflow-policy\.test\.mjs/u);
  assert.match(rootPackage.scripts['test:identity'], /core\/paths-filesystem\/rust\/scripts\/sync-contract\.mjs --check/u);
  assert.match(rootPackage.scripts['test:identity:rust'], /cargo \+1\.82\.0 test/u);
  assert.match(rootPackage.scripts['test:identity:postgres'], /--test postgres_live -- --nocapture/u);
  assert.match(rootPackage.scripts['test:identity:postgres'], /--test aggregate_postgres_live -- --nocapture/u);
});
