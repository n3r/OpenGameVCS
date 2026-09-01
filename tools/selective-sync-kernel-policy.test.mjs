import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const read = (path) => readFile(new URL(path, root), 'utf8');

test('private kernel stays unwired, unbranded, bounded, and Todo', async () => {
  const [contract, manifest, rust, packageValue, prd] = await Promise.all([
    read('spec/selective-sync/v1/contract.json').then(JSON.parse),
    read('spec/selective-sync/v1/manifest.json').then(JSON.parse),
    read('core/selective-sync/rust/src/lib.rs'),
    read('package.json').then(JSON.parse),
    read('prd/todo/OGVCS-013-selective-sync-materialization.md'),
  ]);
  assert.equal(contract.state, 'private-untrusted-selection-candidate');
  assert.deepEqual(contract.networkRoutes, []);
  assert.equal(Object.values(contract.publicClaims).every((value) => value === false), true);
  assert.deepEqual(manifest.networkRoutes, []);
  assert.equal(Object.values(manifest.publicClaims).every((value) => value === false), true);
  assert.equal(contract.limits.metadataRecordsMaximum, 100_000);
  assert.equal(contract.limits.rulesMaximum, 4_096);
  assert.equal(contract.limits.ruleBytesMaximum, 4_114);
  assert.equal(contract.limits.inputRecordBytesMaximum, 4_185);
  assert.equal(contract.limits.outputRecordBytesMaximum, 4_154);
  assert.equal(contract.limits.sinkFragmentBytesMaximum, 4_154);
  assert.equal(contract.limits.collisionKeyBytesMaximum, 32_768);
  assert.equal(contract.limits.collisionKeyBytesTotalMaximum, 67_108_864);
  assert.match(rust, /pub const METADATA_RECORDS_MAXIMUM: u64 = 100_000;/u);
  assert.match(rust, /pub const RULES_MAXIMUM: usize = 4_096;/u);
  assert.match(rust, /pub const RULE_BYTES_MAXIMUM: usize = 4_114;/u);
  assert.match(rust, /pub const INPUT_RECORD_BYTES_MAXIMUM: usize = 4_185;/u);
  assert.match(rust, /pub const OUTPUT_RECORD_BYTES_MAXIMUM: usize = 4_154;/u);
  assert.match(rust, /pub const SINK_FRAGMENT_BYTES_MAXIMUM: usize = 4_154;/u);
  assert.match(rust, /pub const COLLISION_KEY_BYTES_MAXIMUM: usize = 32_768;/u);
  assert.match(rust, /pub const COLLISION_KEY_BYTES_TOTAL_MAXIMUM: u64 = 67_108_864;/u);
  const outputEncoder = rust.slice(rust.indexOf('fn encode_output_record('), rust.indexOf('\nfn append_content('));
  assert.doesNotMatch(outputEncoder, /entry_digest/u);
  assert.doesNotMatch(rust, /Vec<MetadataRecord>|AuthorizationContext|TransactionAuthorized|TcpListener|std::fs|reqwest|object fetch|cache hit/iu);
  assert.equal(packageValue.scripts['test:selective'].includes('selective-sync-kernel-policy.test.mjs'), true);
  assert.match(prd, /^\*\*Status:\*\* Todo  $/mu);
  assert.match(prd, /## Completion evidence\n\n- Implementation changes:\n- Test and benchmark results:/u);
});

test('ordinary selective gates contain no million-path or production route work', async () => {
  const [packageValue, specPackage, rustReadme] = await Promise.all([
    read('package.json').then(JSON.parse),
    read('spec/selective-sync/v1/package.json').then(JSON.parse),
    read('core/selective-sync/rust/README.md'),
  ]);
  for (const script of [packageValue.scripts['test:selective'], packageValue.scripts['test:selective:spec'], specPackage.scripts.test]) {
    assert.doesNotMatch(script, /1_?000_?000|million|workflow_dispatch|route|server/iu);
  }
  assert.match(rustReadme, /one-million-path latency\n?target/u);
});
