import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  canonicalBytes,
  canonicalDigest,
  canonicalStringify,
} from '../src/canonical.mjs';
import {
  DeterministicPrng,
  deriveBytes,
  deriveUint64,
  deterministicInt,
} from '../src/prng.mjs';
import {
  deterministicChunks,
  deterministicId,
  digestDeterministicContent,
  normalizeLogicalPath,
} from '../src/content.mjs';
import { getProfile, listProfiles, resolveProfile } from '../src/profiles.mjs';

const schemasDirectory = fileURLToPath(new URL('../schemas/', import.meta.url));

test('canonical JSON orders keys and has a fixed domain-separated digest', () => {
  const first = { z: 3, a: [true, null, { b: 'x', a: -0 }] };
  const second = { a: [true, null, { a: 0, b: 'x' }], z: 3 };
  const expected = '{"a":[true,null,{"a":0,"b":"x"}],"z":3}';

  assert.equal(canonicalStringify(first), expected);
  assert.deepEqual(canonicalBytes(first), Buffer.from(expected));
  assert.equal(canonicalStringify(second), expected);
  assert.equal(
    canonicalDigest({ b: 2, a: 1 }),
    '07b8661f3a2a091709f41bd55c6eed1814b955693784e41a055fe278e0a21fe7',
  );
});

test('canonical JSON rejects ambiguous or runtime-specific values', () => {
  assert.throws(() => canonicalStringify({ value: 1.5 }), /safe integer/);
  assert.throws(() => canonicalStringify({ value: Number.MAX_SAFE_INTEGER + 1 }), /safe integer/);
  assert.throws(() => canonicalStringify({ value: undefined }), /Unsupported/);
  assert.throws(() => canonicalStringify(new Date(0)), /plain object/);
  const circular = {};
  circular.self = circular;
  assert.throws(() => canonicalStringify(circular), /Circular/);
});

test('counter-mode PRNG has stable vectors and arbitrary-offset reconstruction', () => {
  const expected = '7f400a2c4d153e4c85f726da49252fd22ab63a959315bbca410499d67b333495e9ac8dab467ab79901abcf61f7bc94df';
  assert.equal(deriveBytes('seed-1', 'paths', 48).toString('hex'), expected);
  assert.equal(deriveUint64('seed-1', 'paths', 7), 9_246_012_025_260_669_015n);
  assert.equal(deterministicInt('seed-1', 'paths', 97, 7), 71);

  const whole = deriveBytes('resume-seed', 'large-file', 4097, 17);
  const parts = Buffer.concat([
    deriveBytes('resume-seed', 'large-file', 1000, 17),
    deriveBytes('resume-seed', 'large-file', 1234, 1017),
    deriveBytes('resume-seed', 'large-file', 1863, 2251),
  ]);
  assert.deepEqual(parts, whole);

  const root = new DeterministicPrng('seed-1', 'root');
  assert.deepEqual(root.derive('items').bytesAt(9, 32), root.derive('items').bytesAt(9, 32));
  assert.notDeepEqual(root.derive('items').bytesAt(9, 32), root.derive('history').bytesAt(9, 32));
});

test('deterministic integer enforces safe bounds', () => {
  for (let index = 0; index < 1_000; index += 1) {
    const value = deterministicInt('bounds', 'draw', 7, index);
    assert.ok(value >= 0 && value < 7);
  }
  assert.throws(() => deterministicInt('x', 'y', 0), /positive safe integer/);
  assert.throws(() => deriveBytes('x', 'y', -1), /non-negative safe integer/);
  assert.throws(() => deriveUint64('x', 'y', Number.MAX_SAFE_INTEGER), /too large/);
});

test('content stream is independent of chunk size and supports exact range resume', () => {
  for (const compressionClass of ['incompressible', 'mixed', 'compressible', 'zero']) {
    const options = { seed: 'content-seed', stream: 'asset/v3', size: 200_003, compressionClass };
    const smallChunks = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 997 })]);
    const largeChunks = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 65_537 })]);
    const resumed = Buffer.concat([...deterministicChunks({ ...options, chunkSize: 7_919, start: 91_117 })]);
    assert.deepEqual(smallChunks, largeChunks, compressionClass);
    assert.deepEqual(resumed, smallChunks.subarray(91_117), compressionClass);
  }
});

test('streaming content digest has a fixed golden value', () => {
  assert.deepEqual(
    digestDeterministicContent({
      seed: 'seed-1',
      stream: 'asset',
      size: 100_000,
      chunkSize: 3_333,
      compressionClass: 'mixed',
    }),
    {
      algorithm: 'sha256',
      digest: 'd365cd3de8d04d3cc258d6ccb80d26174fdf8322c92b2b75d8019d2290477224',
      bytes: 100_000,
      contentAlgorithm: 'ogvcs.fixture/content-aes-256-ctr/v2',
    },
  );
  assert.throws(() => [...deterministicChunks({ size: 0 })], /seed/);
});

test('logical paths are normalized to safe relative NFC POSIX paths', () => {
  assert.equal(normalizeLogicalPath('Assets/Cafe\u0301/item.asset'), 'Assets/Caf\u00e9/item.asset');
  assert.equal(deterministicId('seed', 'file', 'Assets/Cafe\u0301/item.asset').length, 32);
  assert.throws(() => deterministicId('seed', 'bad:namespace', 'a/b'));
  for (const invalid of ['', '/absolute', '../escape', 'a/../b', 'a//b', 'C:/drive', 'a\\b', 'a\u0000b']) {
    assert.throws(() => normalizeLogicalPath(invalid));
  }
});

test('all five built-in profiles are stable, synthetic and defensively copied', () => {
  assert.deepEqual(
    listProfiles().map(({ id }) => id),
    ['code-heavy', 'global-studio', 'large-binary', 'unity-like', 'unreal-like'],
  );

  for (const { id, digest } of listProfiles()) {
    assert.match(digest, /^[0-9a-f]{64}$/);
    const profile = getProfile(id);
    assert.equal(profile.name, id);
    assert.equal(profile.license, 'NOASSERTION');
    assert.equal(profile.provenance.classification, 'fully-synthetic');
    assert.equal(profile.provenance.externalSourceIdentifiersAllowed, false);
    profile.features.push('caller-mutation');
    assert.ok(!getProfile(id).features.includes('caller-mutation'));
  }
});

test('profile resolution validates bounded scale and named feature overrides', () => {
  const resolved = resolveProfile('large-binary', {
    scale: { pathCount: 1_000_000, largeFileBytes: 107_374_182_400 },
    featureFlags: { duplication: false },
  });
  assert.equal(resolved.name, 'large-binary');
  assert.equal(resolved.defaults.largeFileBytes, 10_737_418_240);
  assert.equal(resolved.scale.pathCount, 1_000_000);
  assert.equal(resolved.scale.largeFileBytes, 107_374_182_400);
  assert.equal(resolved.featureFlags.duplication, false);
  assert.equal(resolved.featureFlags['edit-locality'], true);
  assert.match(resolved.resolvedDigest, /^[0-9a-f]{64}$/);
  const unityNegativeCases = resolveProfile('unity-like', {
    featureFlags: { 'negative-cases': true },
  });
  const unityWithoutNegativeCases = resolveProfile('unity-like', {
    featureFlags: { 'negative-cases': false },
  });
  assert.ok(unityNegativeCases.features.includes('negative-cases'));
  assert.notEqual(unityNegativeCases.resolvedDigest, unityWithoutNegativeCases.resolvedDigest);
  assert.throws(() => resolveProfile('large-binary', { scale: { pathCount: 0 } }), /pathCount/);
  assert.throws(() => resolveProfile('large-binary', { scale: { unknown: 1 } }), /Unknown scale/);
  assert.throws(() => resolveProfile('large-binary', { featureFlags: { unknown: true } }), /Unknown featureFlags/);
});

test('the nine public schemas are valid JSON with unique stable identifiers and strict roots', async () => {
  const names = (await readdir(schemasDirectory)).filter((name) => name.endsWith('.schema.json')).sort();
  assert.deepEqual(names, [
    'FixtureManifest.schema.json',
    'FixtureRequest.schema.json',
    'GenerationCheckpoint.schema.json',
    'GroupRelationships.schema.json',
    'InventoryRecord.schema.json',
    'LargeFileDescriptor.schema.json',
    'OperationScenario.schema.json',
    'VerificationResult.schema.json',
    'WorkloadProfile.schema.json',
  ]);

  const identifiers = new Set();
  for (const name of names) {
    const schema = JSON.parse(await readFile(`${schemasDirectory}/${name}`, 'utf8'));
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.match(schema.$id, /^https:\/\/schemas\.opengamevcs\.org\/fixture\/v[12]\//);
    assert.ok(['array', 'object'].includes(schema.type));
    if (schema.type === 'object') {
      assert.equal(schema.additionalProperties, false);
      assert.ok(Array.isArray(schema.required) && schema.required.length > 0);
    } else {
      assert.ok(schema.items, `${name} array root must constrain its items`);
    }
    assert.ok(!identifiers.has(schema.$id), `duplicate schema id: ${schema.$id}`);
    identifiers.add(schema.$id);
  }
});
