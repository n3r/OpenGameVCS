import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { validateSandboxManifest } from '../scripts/generate.mjs';
import { validateSandboxContract, validateSandboxDocuments } from '../validate-spec.mjs';
test('closed OGVCS-045 candidate contract is authenticated by independent checks', async () => { const value = await validateSandboxContract(); assert.ok(value.vectors >= 10); });
test('manifest rejects even one-byte tampering', async () => { const bytes = await readFile(new URL('../manifest.json', import.meta.url)); const tampered = Buffer.from(bytes); tampered[0] ^= 1; await assert.rejects(validateSandboxManifest({ manifestBytes: tampered })); });

test('independent semantics reject reauthenticated required-set and constraint drift', async () => {
  const documents = Object.fromEntries(await Promise.all([
    ['job', '../schemas/ParserJob.schema.json'],
    ['output', '../schemas/ParserOutput.schema.json'],
    ['result', '../schemas/ParserResult.schema.json'],
    ['vectors', '../vectors/canaries.json'],
  ].map(async ([key, path]) => [key, JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'))])));
  const mutations = [
    (copy) => { copy.job.required = copy.job.required.filter((key) => key !== 'toolDigest'); },
    (copy) => { copy.output.properties.outputs.items.required = []; },
    (copy) => { copy.output.properties.outputs.items.properties.digest.pattern = '^.*$'; },
    (copy) => { copy.result.oneOf[0].properties.outputDigest = { type: 'null' }; },
    (copy) => { copy.result.properties.status.enum.push('failed'); },
  ];
  assert.doesNotThrow(() => validateSandboxDocuments(structuredClone(documents)));
  for (const mutate of mutations) {
    const copy = structuredClone(documents); mutate(copy);
    assert.throws(() => validateSandboxDocuments(copy), /semantic constraints differ/u);
  }
});

test('independent semantics reject reauthenticated canary deletion or substitution', async () => {
  const documents = Object.fromEntries(await Promise.all([
    ['job', '../schemas/ParserJob.schema.json'],
    ['output', '../schemas/ParserOutput.schema.json'],
    ['result', '../schemas/ParserResult.schema.json'],
    ['vectors', '../vectors/canaries.json'],
  ].map(async ([key, path]) => [key, JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'))])));
  const deleted = structuredClone(documents); deleted.vectors.cases.pop();
  assert.throws(() => validateSandboxDocuments(deleted), /canary semantics differ/u);
  const substituted = structuredClone(documents); substituted.vectors.cases[0].expectedCode = 'SANDBOX_UNAVAILABLE';
  assert.throws(() => validateSandboxDocuments(substituted), /canary semantics differ/u);
});
