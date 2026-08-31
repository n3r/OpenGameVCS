import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('.', import.meta.url).pathname;
const readJson = (relative) => JSON.parse(readFileSync(join(root, relative), 'utf8'));
const version = '0.1.0-rc.1';

const packageJson = readJson('package.json');
assert.equal(packageJson.version, version);

const exitRegistry = readJson('registries/exit-classes.json');
assert.equal(exitRegistry.contractVersion, version);
assert.deepEqual(exitRegistry.classes, [
  { name: 'success', exitCode: 0 },
  { name: 'input', exitCode: 2 },
  { name: 'workspace', exitCode: 3 },
  { name: 'unsupported', exitCode: 4 },
  { name: 'cancelled', exitCode: 5 },
  { name: 'interaction-required', exitCode: 6 },
  { name: 'unavailable', exitCode: 7 },
  { name: 'internal', exitCode: 70 }
]);

for (const file of [
  'schemas/CliResult.schema.json',
  'schemas/ConfigResolution.schema.json',
  'schemas/InitializationRecord.schema.json',
  'schemas/WorkspaceMetadata.schema.json',
  'schemas/DiagnosticPreview.schema.json'
]) {
  const schema = readJson(file);
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.type, 'object');
  assert.equal(schema.additionalProperties, false);
}

const result = readJson('schemas/CliResult.schema.json');
assert.equal(result.properties.schema.const, 'ogvcs.cli-workspace/result/v1');
assert.equal(result.properties.contractVersion.const, version);
assert.deepEqual(result.properties.exitClass.enum, exitRegistry.classes.map(({ name }) => name));

const workspace = readJson('schemas/WorkspaceMetadata.schema.json');
assert.equal(workspace.properties.binding.properties.verification.const, 'unverified-local-declaration');
assert.equal('repositoryHint' in workspace.properties.binding.properties, false);

const initialization = readJson('schemas/InitializationRecord.schema.json');
assert.deepEqual(initialization.properties.state.enum, ['initializing', 'complete']);

const vectors = readJson('vectors/contract-v1.json');
assert.equal(vectors.contractVersion, version);
assert.deepEqual(vectors.cases.map(({ id }) => id), [
  'config-precedence-source-report',
  'secret-like-config-rejected',
  'raw-declaration-rejected',
  'cancel-after-control-publish',
  'noninteractive-provider-unavailable',
  'diagnostic-redaction'
]);

console.log('OGVCS CLI/workspace local-only contract v1: valid');
