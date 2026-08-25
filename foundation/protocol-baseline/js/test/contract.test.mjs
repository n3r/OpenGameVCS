import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  canonicalJson, clearProtocolContractCacheForTest, loadProtocolContract, PROTOCOL_LIMITS_BY_NAME,
} from '../src/index.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'ogvcs-protocol-contract-'));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 50 }));
  await Promise.all(['schemas', 'registries', 'vectors'].map((name) => mkdir(join(root, name))));
  const documents = {
    'schemas/ping.schema.json': {
      $id: 'https://schemas.opengamevcs.org/protocol/v1/ping.schema.json',
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object', additionalProperties: false,
      properties: { schemaVersion: { const: 'ogvcs.protocol/ping/v1' }, value: { type: 'string', maxLength: 8 } },
      required: ['schemaVersion', 'value'],
    },
    'vectors/smoke.json': { schemaVersion: 'ogvcs.protocol/vectors/v1', cases: [] },
  };
  const pingBytes = Buffer.from(canonicalJson(documents['schemas/ping.schema.json']));
  documents['registries/schemas.json'] = {
    schemaVersion: 'ogvcs.protocol/registry/v1', registry: 'schemas', version: 1, license: 'MIT',
    entries: [{ code: 1, id: documents['schemas/ping.schema.json'].$id, message: 'ping', path: 'schemas/ping.schema.json', sha256: sha256(pingBytes), state: 'candidate' }],
  };
  documents['registries/limits.json'] = {
    schemaVersion: 'ogvcs.protocol/registry/v1', registry: 'limits', version: 1, license: 'MIT',
    entries: Object.entries(PROTOCOL_LIMITS_BY_NAME).map(([name, value], index) => ({ code: index + 1, name, value, unit: 'test-unit', enforcement: 'test-boundary', ...(name === 'maxErrorParameters' ? { configuredMinimum: 0 } : {}) })),
  };
  const artifacts = [];
  for (const [path, value] of Object.entries(documents)) {
    const bytes = Buffer.from(canonicalJson(value));
    await writeFile(join(root, path), bytes);
    artifacts.push({ path, bytes: bytes.length, mediaType: 'application/json', sha256: sha256(bytes) });
  }
  artifacts.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const setDigest = (records) => sha256(Buffer.from(canonicalJson(records.map(({ path, sha256: digest }) => ({ path, sha256: digest }))))) ;
  const registryEntries = artifacts.filter(({ path }) => path.startsWith('registries/'));
  const schemaEntries = artifacts.filter(({ path }) => path.startsWith('schemas/'));
  const vectorEntries = artifacts.filter(({ path }) => path.startsWith('vectors/'));
  const manifest = {
    schemaVersion: 'ogvcs.protocol/contract-manifest/v1', contractVersion: '1.0.0-rc.1', packageName: '@opengamevcs/protocol-contract-v1', license: 'MIT',
    registrySetSha256: setDigest(registryEntries), negotiationRegistrySetSha256: setDigest(registryEntries), schemaSetSha256: setDigest(schemaEntries), vectorSetSha256: setDigest(vectorEntries),
    counts: { artifacts: artifacts.length, schemas: schemaEntries.length, registries: registryEntries.length, scenarios: 0 }, artifacts,
  };
  await writeFile(join(root, 'manifest.json'), canonicalJson(manifest));
  return { root, documents, manifest };
}

test('manifest loader authenticates every declared artifact and builds schema indexes', async (t) => {
  const { root } = await fixture(t);
  const contract = await loadProtocolContract({ root, cache: false });
  assert.match(contract.manifestSha256, /^[0-9a-f]{64}$/u);
  assert.equal(contract.registries.limits.registry, 'limits');
  assert.equal(contract.vectors.smoke.cases.length, 0);
  assert.equal(contract.validator.schema('ping.schema.json'), contract.schemas['ping.schema.json']);
  assert.equal(contract.validator.validate({ schemaVersion: 'ogvcs.protocol/ping/v1', value: 'pong' }, 'ogvcs.protocol/ping/v1').value, 'pong');
});

test('manifest loader rejects digest drift, undeclared growth, noncanonical assets and reduced ceilings', async (t) => {
  const { root, documents } = await fixture(t);
  await writeFile(join(root, 'vectors/smoke.json'), canonicalJson({ ...documents['vectors/smoke.json'], changed: true }));
  await assert.rejects(() => loadProtocolContract({ root, cache: false }), /digest or length mismatch/u);

  const second = await fixture(t);
  await writeFile(join(second.root, 'registries/limits.json'), ` ${canonicalJson(second.documents['registries/limits.json'])}`);
  await assert.rejects(() => loadProtocolContract({ root: second.root, cache: false }), /canonical/u);

  const third = await fixture(t);
  await assert.rejects(() => loadProtocolContract({ root: third.root, cache: false, maxContractBytes: 64 }), (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED');
});

test('cached contracts do not bypass a later reduced receiver ceiling', async (t) => {
  const { root } = await fixture(t);
  await loadProtocolContract({ root });
  await assert.rejects(() => loadProtocolContract({ root, maxAssetBytes: 32 }), /bounded regular file/u);
});

test('loader discards raw assets and reserves retained decoded graphs under working memory', async (t) => {
  const { root } = await fixture(t);
  const contract = await loadProtocolContract({ root, cache: false });
  assert.ok(contract.workingMemoryBytes > contract.totalBytes);
  await assert.doesNotReject(() => loadProtocolContract({ root, cache: false, maxWorkingMemoryBytes: contract.workingMemoryBytes }));
  await assert.rejects(
    () => loadProtocolContract({ root, cache: false, maxWorkingMemoryBytes: contract.workingMemoryBytes - 1 }),
    /working-memory|remaining working memory/u,
  );
});

test('contract cache is raced against each caller cancellation boundary', async (t) => {
  clearProtocolContractCacheForTest();
  const { root } = await fixture(t);
  const first = loadProtocolContract({ root });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(() => loadProtocolContract({ root, signal: controller.signal }), (error) => error.code === 'PROTOCOL_CANCELLED');
  const loaded = await first;
  const warm = new AbortController();
  warm.abort();
  await assert.rejects(() => loadProtocolContract({ root, signal: warm.signal }), (error) => error.code === 'PROTOCOL_CANCELLED');
  assert.equal(loaded.manifest.packageName, '@opengamevcs/protocol-contract-v1');
});

test('declared contract bytes fail before an over-limit artifact is opened', async (t) => {
  const { root, manifest } = await fixture(t);
  const target = manifest.artifacts.find(({ path }) => path === 'vectors/smoke.json');
  target.bytes = 4096;
  await writeFile(join(root, 'manifest.json'), canonicalJson(manifest));
  await rm(join(root, target.path));
  const manifestBytes = Buffer.byteLength(canonicalJson(manifest));
  await assert.rejects(
    () => loadProtocolContract({ root, cache: false, maxContractBytes: manifestBytes + 4095 }),
    (error) => error.code === 'PROTOCOL_LIMIT_EXCEEDED',
  );
});
