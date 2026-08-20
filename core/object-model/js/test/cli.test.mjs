import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';

import { CLI_EXIT, runCli } from '../src/cli.js';

const SPEC = resolve(import.meta.dirname, '../../../../spec/repository-format/v1');
const VECTORS = join(SPEC, 'vectors');
const json = async path => JSON.parse(await readFile(path, 'utf8'));

async function invoke(args) {
  let output = '';
  const exitCode = await runCli(args, { cwd: VECTORS, stdout: { write(value) { output += value; } } });
  return { exitCode, output, value: output.startsWith('{') ? JSON.parse(output) : undefined };
}

test('CLI discovers the exact bundled registry set without content-bearing output', async () => {
  const listed = await invoke(['registry', 'list']);
  assert.equal(listed.exitCode, CLI_EXIT.success);
  assert.equal(listed.value.ok, true);
  assert.equal(listed.value.result.counts.objectKinds, 11);
  assert.match(listed.value.result.registrySetDigest, /^[0-9a-f]{64}$/);

  const profiles = await invoke(['registry', 'profiles']);
  assert.equal(profiles.exitCode, CLI_EXIT.success);
  assert.ok(profiles.value.result.profiles.some(item => item.profile === 'path.test/opaque@1'));
  assert.deepEqual(Object.keys(profiles.value.result), ['profiles']);

  const profile = await invoke(['registry', 'profile', 'path.test/opaque@1', '--operation', 'conformance']);
  assert.equal(profile.exitCode, CLI_EXIT.success);
  assert.equal(profile.value.result.state, 'conformance-only');
});

test('CLI inspects, identifies, and verifies a metadata object', async () => {
  const index = await json(join(VECTORS, 'objects/index.json'));
  const vector = index.objects.find(item => item.name === 'tree');
  const expectedBytes = (await readFile(join(VECTORS, vector.payloadPath))).length;
  const inspected = await invoke(['inspect', vector.payloadPath]);
  assert.equal(inspected.exitCode, CLI_EXIT.success);
  assert.deepEqual({
    bytes: inspected.value.result.bytes,
    highestLayer: inspected.value.result.highestLayer,
    kind: inspected.value.result.kind,
    kindToken: inspected.value.result.kindToken,
    knownSchema: inspected.value.result.knownSchema,
    objectRef: inspected.value.result.objectRef
  }, {
    bytes: expectedBytes,
    highestLayer: 2,
    kind: 3,
    kindToken: 'tree',
    knownSchema: true,
    objectRef: `ogvcs:v1:tree:sha256:${vector.objectId}`
  });

  const identified = await invoke(['id', vector.payloadPath, '--kind', 'tree']);
  assert.equal(identified.exitCode, CLI_EXIT.success);
  assert.equal(identified.value.result.objectRef, inspected.value.result.objectRef);

  const verified = await invoke(['verify', 'object', vector.payloadPath, '--ref', inspected.value.result.objectRef,
    '--operation', 'conformance']);
  assert.equal(verified.exitCode, CLI_EXIT.success);
  assert.equal(verified.value.result.highestLayer, 3);
  assert.equal(verified.value.result.status, 'valid');

  for (const args of [
    ['inspect', vector.payloadPath, '--max-memory-bytes', '1'],
    ['id', vector.payloadPath, '--kind', 'tree', '--max-memory-bytes', '1'],
    ['verify', 'object', vector.payloadPath, '--ref', inspected.value.result.objectRef,
      '--operation', 'conformance', '--max-memory-bytes', '1']
  ]) {
    const limited = await invoke(args);
    assert.equal(limited.exitCode, CLI_EXIT.resource);
    assert.equal(limited.value.error.code, 'LIMIT_MEMORY');
    assert.equal(limited.value.error.layer, 1);
    assert.equal(limited.value.error.stage, 'configured-resource-preflight');
  }
});

test('CLI inspect remains a structural layer-two boundary for unknown required features', async () => {
  const inspected = await invoke(['inspect', 'registries/unknown-required-feature.cbor']);
  assert.equal(inspected.exitCode, CLI_EXIT.success);
  assert.equal(inspected.value.result.highestLayer, 2);
  assert.equal(inspected.value.result.knownSchema, true);
  assert.equal(inspected.value.result.requiredFeatureCount, 1);
  assert.match(inspected.value.result.objectRef, /^ogvcs:v1:provenance:sha256:[0-9a-f]{64}$/);
});

test('CLI verifies a canonical tree through the bounded raw-file path', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-cli-tree-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const descriptor = 'ogvcs:v1:repository-descriptor:sha256:dce2c6b4bedb2f231d7aef5ee499e1c7d2afd0b0150c66df36522d1a53042545';
  const verified = await invoke(['tree', 'verify', 'objects/03-tree.cbor', '--descriptor', descriptor,
    '--scratch', directory, '--operation', 'conformance', '--max-memory-bytes', '1048576']);
  assert.equal(verified.exitCode, CLI_EXIT.success);
  assert.equal(verified.value.command, 'tree verify');
  assert.equal(verified.value.result.kind, 3);
  assert.equal(verified.value.result.entryCount, 4);
  assert.equal(verified.value.result.highestLayer, 3);
  assert.equal(verified.value.result.status, 'valid');
  assert.equal(verified.value.result.objectRef,
    'ogvcs:v1:tree:sha256:9458b24239ce71b75b1c6ab857883d66a6eab3f0f6f4e9afab15371af1d4bf19');

  const usage = await invoke(['tree', 'verify', 'objects/03-tree.cbor', '--descriptor', descriptor]);
  assert.equal(usage.exitCode, CLI_EXIT.usage);
});

test('CLI verifies supplied closure through the bounded regular-file path and returns stable typed failures', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ogvcs-cli-bundle-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }));
  const valid = await invoke([
    'bundle', 'verify', 'logical-bundles/valid-supplied-closure.cborseq', '--scratch', directory,
    '--operation', 'conformance', '--max-memory-bytes', '16777216', '--max-scratch-bytes', '16777216'
  ]);
  assert.equal(valid.exitCode, CLI_EXIT.success);
  assert.equal(valid.value.result.highestLayer, 3);
  assert.equal(valid.value.result.objectCount, 2);
  assert.equal(valid.value.result.format, 'logical-bundle-v1');
  assert.equal(valid.value.result.claim, 'supplied-closure');
  assert.equal(valid.value.result.status, 'valid');
  assert.ok(valid.value.result.metrics.peakScratchBytes > 0);
  assert.ok(valid.value.result.metrics.processMaxRssBytes > 0);

  const invalid = await invoke([
    'bundle', 'verify', 'logical-bundles/invalid-closure-missing.cborseq', '--scratch', directory,
    '--operation', 'conformance', '--max-scratch-bytes', '16777216'
  ]);
  assert.equal(invalid.exitCode, CLI_EXIT.invalid);
  assert.equal(invalid.value.ok, false);
  assert.equal(invalid.value.error.code, 'BUNDLE_CLOSURE_MISSING');
  assert.equal(invalid.value.error.stage, 'closure-and-reference-resolution');
  assert.equal(invalid.output.includes('message'), false);

  const missingScratch = await invoke(['bundle', 'verify', 'logical-bundles/valid-supplied-closure.cborseq']);
  assert.equal(missingScratch.exitCode, CLI_EXIT.usage);
  const usage = await invoke(['verify']);
  assert.equal(usage.exitCode, CLI_EXIT.usage);
  assert.equal(usage.value.error.code, 'CLI_USAGE');
});
