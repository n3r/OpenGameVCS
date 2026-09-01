#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalDigest, canonicalJson } from '../../../../foundation/benchmark-fault-harness/src/index.mjs';
import { AUTHORITY, CONTRACT_VERSION, OWNER, REPORT_SCHEMA, RETAINED_PUBLICATION_SCHEMA, THRESHOLD } from './model.mjs';

const SOURCE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const CONTRACT_ROOT = resolve(process.env.OGVCS_CHUNK_SCALE_CONTRACT_ROOT ?? join(SOURCE_ROOT, 'spec/chunking-scale-evidence/v1'));
const CHECK = process.argv.includes('--check');
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bytesFor = (value) => Buffer.from(`${canonicalJson(value)}\n`);

async function predecessor(path) {
  const bytes = await readFile(join(SOURCE_ROOT, path));
  return { path, sha256: sha256(bytes), value: JSON.parse(bytes) };
}

const artifacts = new Map([
  ['registries/exact-scale-authority.json', AUTHORITY],
  ['schemas/retained-publication.schema.json', RETAINED_PUBLICATION_SCHEMA],
  ['schemas/scale-report.schema.json', REPORT_SCHEMA],
  ['thresholds/chunking-exact-scale-release-v1.json', THRESHOLD],
]);
const records = [...artifacts].map(([path, value]) => {
  const bytes = bytesFor(value);
  return { path, mediaType: path.startsWith('schemas/') ? 'application/schema+json' : 'application/json', bytes: bytes.byteLength, sha256: sha256(bytes) };
});
const [benchmark, chunking, generatorBytes, modelBytes] = await Promise.all([
  predecessor('spec/benchmark-fault/v1/manifest.json'),
  predecessor('spec/chunking-manifest/v1/manifest.json'),
  readFile(fileURLToPath(import.meta.url)),
  readFile(new URL('./model.mjs', import.meta.url)),
]);
const manifest = {
  schemaVersion: 'ogvcs.chunking-manifest/exact-scale-contract-manifest/v1',
  contractVersion: CONTRACT_VERSION,
  owner: OWNER,
  artifacts: records,
  artifactSetSha256: canonicalDigest(records, 'ogvcs.chunking-manifest/exact-scale-artifact-set/v1'),
  authoritySetSha256: canonicalDigest({ authority: AUTHORITY, threshold: THRESHOLD }, 'ogvcs.chunking-manifest/exact-scale-authority-set/v1'),
  predecessorPins: {
    benchmark: { contractVersion: benchmark.value.contractVersion, manifestPath: benchmark.path, manifestSha256: benchmark.sha256 },
    chunking: { contractVersion: chunking.value.contractVersion, manifestPath: chunking.path, manifestSha256: chunking.sha256, profile: chunking.value.profile, tableSha256: chunking.value.tableSha256 },
  },
  generatedBy: { generatorSha256: sha256(generatorBytes), modelSha256: sha256(modelBytes) },
  counts: { artifacts: records.length, assertions: AUTHORITY.task.assertions.length, thresholds: THRESHOLD.entries.length },
};
artifacts.set('manifest.json', manifest);

for (const [path, value] of artifacts) {
  const bytes = bytesFor(value);
  const target = join(CONTRACT_ROOT, path);
  if (CHECK) {
    const actual = await readFile(target).catch(() => null);
    if (!actual?.equals(bytes)) throw new Error(`generated exact-scale authority differs: ${path}`);
  } else {
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes);
  }
}
process.stdout.write(`${canonicalJson({ artifactSetSha256: manifest.artifactSetSha256, artifacts: records.length, contractVersion: CONTRACT_VERSION, thresholds: THRESHOLD.entries.length })}\n`);
