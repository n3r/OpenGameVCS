import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const readBytes = (relative) => readFileSync(join(root, relative));
const readJson = (relative) => JSON.parse(readBytes(relative).toString('utf8'));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const version = '0.2.0-rc.2';
const schemaFiles = [
  'CliResult.schema.json',
  'CapabilitySelection.schema.json',
  'ConfigResolution.schema.json',
  'DiagnosticPreview.schema.json',
  'InitializationRecord.schema.json',
  'IntentReport.schema.json',
  'ProgressEvent.schema.json',
  'RemovalRecord.schema.json',
  'StagingState.schema.json',
  'VerifiedDiagnosticPreview.schema.json',
  'VerifiedWorkspaceMetadata.schema.json',
  'VerifiedWorkspaceReport.schema.json',
  'WorkspaceMetadata.schema.json',
  'WorkspaceJournal.schema.json',
  'WorkspaceReport.schema.json',
];

const packageJson = readJson('package.json');
assert.equal(packageJson.version, version);
assert.equal(packageJson.scripts.check, 'node scripts/generate.mjs --check && node validate-spec.mjs');
assert.equal(packageJson.scripts.test, packageJson.scripts.check);

const manifest = readJson('manifest.json');
assert.equal(manifest.schema, 'ogvcs.cli-workspace/contract-manifest/v1');
assert.equal(manifest.contractVersion, version);
assert.deepEqual(manifest.artifacts.map(({ path }) => path), [...manifest.artifacts.map(({ path }) => path)].sort());
assert.equal(new Set(manifest.artifacts.map(({ path }) => path)).size, manifest.artifacts.length);
for (const record of manifest.artifacts) {
  assert.match(record.path, /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/-]+$/u);
  const bytes = readBytes(record.path);
  assert.equal(record.bytes, bytes.length, `${record.path}: byte length`);
  assert.equal(record.sha256, sha256(bytes), `${record.path}: sha256`);
}
assert.equal(manifest.artifactSetSha256, sha256(canonicalBytes(manifest.artifacts)));
const digestSet = (prefix) => sha256(canonicalBytes(manifest.artifacts.filter(({ path }) => path.startsWith(prefix))));
assert.equal(manifest.registrySetSha256, digestSet('registries/'));
assert.equal(manifest.schemaSetSha256, digestSet('schemas/'));
assert.equal(manifest.vectorSetSha256, digestSet('vectors/'));
assert.equal(manifest.generatorSha256, sha256(readBytes('scripts/generate.mjs')));
assert.deepEqual(manifest.counts, { artifacts: 22, registries: 1, schemas: 15, vectors: 1 });

const schemas = new Map(schemaFiles.map((file) => [file, readJson(`schemas/${file}`)]));
assert.equal(new Set([...schemas.values()].map((schema) => schema.$id)).size, schemas.size);
for (const [file, schema] of schemas) {
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema', file);
  assert.equal(schema.type, 'object', file);
  assert.equal(schema.additionalProperties, false, file);
}

function resolveReference(reference, document) {
  assert.match(reference, /^#\/(?:[^/]+\/)*[^/]+$/u);
  return reference.slice(2).split('/').reduce((value, segment) => value[segment.replaceAll('~1', '/').replaceAll('~0', '~')], document);
}

function validateInstance(value, schema, document = schema, path = '$') {
  if (schema.$ref !== undefined) {
    if (schema.$ref.startsWith('#/')) {
      return validateInstance(value, resolveReference(schema.$ref, document), document, path);
    }
    const referenced = schemas.get(schema.$ref);
    assert(referenced !== undefined, `${path}: unknown schema reference ${schema.$ref}`);
    return validateInstance(value, referenced, referenced, path);
  }
  if (schema.oneOf !== undefined) {
    let matches = 0;
    for (const candidate of schema.oneOf) {
      try {
        validateInstance(value, candidate, document, path);
        matches += 1;
      } catch {
        // A oneOf candidate is expected to reject nonmatching variants.
      }
    }
    assert.equal(matches, 1, `${path}: oneOf`);
  }
  if (schema.const !== undefined) assert.deepEqual(value, schema.const, `${path}: const`);
  if (schema.enum !== undefined) assert(schema.enum.some((candidate) => JSON.stringify(candidate) === JSON.stringify(value)), `${path}: enum`);
  if (Array.isArray(schema.type)) {
    const matches = schema.type.some((type) => type === 'null'
      ? value === null
      : type === 'integer'
        ? Number.isInteger(value)
        : typeof value === type);
    assert(matches, `${path}: ${schema.type.join('|')}`);
    if (value === null) return;
    schema = { ...schema, type: schema.type.find((type) => type !== 'null') };
  }
  if (schema.type === 'object') {
    assert(value !== null && typeof value === 'object' && !Array.isArray(value), `${path}: object`);
    for (const required of schema.required ?? []) assert(Object.hasOwn(value, required), `${path}: missing ${required}`);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) assert(Object.hasOwn(schema.properties ?? {}, key), `${path}: unexpected ${key}`);
    }
    for (const [key, child] of Object.entries(schema.properties ?? {})) {
      if (Object.hasOwn(value, key)) validateInstance(value[key], child, document, `${path}.${key}`);
    }
  } else if (schema.type === 'array') {
    assert(Array.isArray(value), `${path}: array`);
    if (schema.minItems !== undefined) assert(value.length >= schema.minItems, `${path}: minItems`);
    if (schema.maxItems !== undefined) assert(value.length <= schema.maxItems, `${path}: maxItems`);
    if (schema.items !== undefined) value.forEach((item, index) => validateInstance(item, schema.items, document, `${path}[${index}]`));
  } else if (schema.type === 'string') {
    assert.equal(typeof value, 'string', `${path}: string`);
    if (schema.minLength !== undefined) assert(value.length >= schema.minLength, `${path}: minLength`);
    if (schema.maxLength !== undefined) assert(value.length <= schema.maxLength, `${path}: maxLength`);
    if (schema.pattern !== undefined) assert(new RegExp(schema.pattern, 'u').test(value), `${path}: pattern`);
  } else if (schema.type === 'boolean') {
    assert.equal(typeof value, 'boolean', `${path}: boolean`);
  } else if (schema.type === 'integer') {
    assert(Number.isInteger(value), `${path}: integer`);
    if (schema.minimum !== undefined) assert(value >= schema.minimum, `${path}: minimum`);
  }
}

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
  { name: 'internal', exitCode: 70 },
]);
assert.deepEqual(schemas.get('CliResult.schema.json').properties.exitClass.enum, exitRegistry.classes.map(({ name }) => name));
assert.equal(schemas.get('WorkspaceMetadata.schema.json').properties.binding.properties.verification.const, 'unverified-local-declaration');
assert.equal(schemas.get('WorkspaceReport.schema.json').properties.schema.const, 'ogvcs.cli-workspace/workspace-report/v1');
assert.deepEqual(schemas.get('InitializationRecord.schema.json').properties.state.enum, ['initializing', 'complete']);
assert.equal(schemas.get('VerifiedWorkspaceMetadata.schema.json').properties.binding.properties.verification.const, 'public-service-verified');
assert.equal(schemas.get('VerifiedWorkspaceMetadata.schema.json').properties.binding.properties.repositoryIdHex.pattern, '^[0-9a-f]{12}[1-8][0-9a-f]{3}[89ab][0-9a-f]{15}$');
assert.equal(schemas.get('VerifiedWorkspaceReport.schema.json').properties.schema.const, 'ogvcs.cli-workspace/verified-workspace-report/v2');
assert.equal(schemas.get('CapabilitySelection.schema.json').properties.authorizationRegistrySha256.const, '293f9ab0be023a9ded33326d04a8314080bda56e7c70dd18d0cca38b70bed9cc');
assert.equal(schemas.get('CapabilitySelection.schema.json').properties.pathRegistrySha256.const, 'bbabdd95d78cfe0dd9751ab67ccbd9dfa5565bf8c049468aea3129bec787bd42');
assert.equal(schemas.get('IntentReport.schema.json').properties.uploadsStarted.const, false);
assert.equal(schemas.get('IntentReport.schema.json').properties.submitStarted.const, false);
assert.equal(schemas.get('IntentReport.schema.json').properties.remoteDurableState.const, 'unchanged');
const stagedIntent = schemas.get('StagingState.schema.json').properties.intents.items;
assert(stagedIntent.required.includes('allocationReceipt'));
assert(stagedIntent.required.includes('allocationIdempotencyKeySha256'));
assert.equal(stagedIntent.properties.allocationReceipt.pattern, '^far1\\.[A-Za-z0-9_-]{43}$');

const vectors = readJson('vectors/contract-v1.json');
assert.equal(vectors.contractVersion, version);
assert.deepEqual(vectors.schemaExamples.map(({ schemaFile }) => schemaFile), schemaFiles);
for (const example of vectors.schemaExamples) {
  const schema = schemas.get(example.schemaFile);
  validateInstance(example.value, schema);
  assert.throws(() => validateInstance({ ...example.value, unexpected: true }, schema));
}
const stagingExample = vectors.schemaExamples.find(({ schemaFile }) => schemaFile === 'StagingState.schema.json').value;
const stagingWithoutReceipt = structuredClone(stagingExample);
stagingWithoutReceipt.intents[0].allocationReceipt = null;
assert.throws(() => validateInstance(stagingWithoutReceipt, schemas.get('StagingState.schema.json')));

const expectedIds = [
  'config-precedence-source-report',
  'secret-like-config-rejected',
  'raw-declaration-rejected',
  'cancel-after-control-publish',
  'noninteractive-provider-unavailable',
  'diagnostic-redaction',
];
assert.deepEqual(vectors.cases.map(({ id }) => id), expectedIds);
const byId = new Map(vectors.cases.map((entry) => [entry.id, entry]));

const config = byId.get('config-precedence-source-report');
const sourceLayers = [
  ['flag', config.input.flags],
  ['environment', config.input.environment],
  ['workspace', config.input.workspace],
  ['user-profile', config.input.userProfile],
  ['system-default', config.input.systemDefault],
];
const resolved = Object.fromEntries(['endpoint', 'profile', 'output'].map((field) => {
  const [source, layer] = sourceLayers.find(([, candidate]) => candidate[field] !== undefined);
  return [field, { value: layer[field], source }];
}));
assert.deepEqual(resolved, {
  endpoint: config.expected.endpoint,
  profile: config.expected.profile,
  output: config.expected.output,
});
assert.equal(config.expected.code, 'CONFIG_RESOLVED');

const secret = byId.get('secret-like-config-rejected');
const secretNeedles = ['token', 'secret', 'credential', 'password', 'authorization', 'cookie', 'key'];
const containsSecretKey = (value) => value !== null && typeof value === 'object' && Object.entries(value).some(([key, child]) => secretNeedles.some((needle) => key.toLowerCase().includes(needle)) || containsSecretKey(child));
assert.equal(containsSecretKey(secret.input.configuration), true);
assert.deepEqual({ exitClass: 'input', code: 'CONFIG_INVALID' }, { exitClass: secret.expected.exitClass, code: secret.expected.code });
assert(!'A configuration source is invalid.'.includes(secret.expected.forbidden));

const raw = byId.get('raw-declaration-rejected');
const validDigest = (value) => /^[0-9a-f]{64}$/u.test(value);
assert.equal(Object.values(raw.input).every(validDigest), false);
assert.deepEqual(raw.expected, { exitClass: 'input', code: 'INPUT_INVALID', workspacePublished: false });

const cancelled = byId.get('cancel-after-control-publish');
assert.equal(cancelled.input.cancellationPoint, 'after-control-publish');
assert.deepEqual(cancelled.expected, {
  exitClass: 'cancelled', code: 'OPERATION_CANCELLED', workspacePublished: true,
  markerState: 'initializing', remoteDurableState: 'unchanged', nextOperation: 'workspace recover',
});

const authentication = byId.get('noninteractive-provider-unavailable');
const authenticationResult = authentication.input.nonInteractive && authentication.input.providerStatus !== 'available'
  ? { exitClass: 'interaction-required', code: 'AUTHENTICATION_REQUIRED', credentialStatus: 'unavailable', prompted: false }
  : { exitClass: 'success', code: 'AUTHENTICATION_AVAILABLE', credentialStatus: 'available', prompted: false };
assert.deepEqual(authenticationResult, authentication.expected);

const diagnostic = byId.get('diagnostic-redaction');
const diagnosticValue = {
  schema: 'ogvcs.cli-workspace/diagnostic-preview/v1',
  contractVersion: version,
  preview: true,
  written: false,
  workspaceState: 'ready',
  workspaceRootDigest: sha256(Buffer.from(diagnostic.input.root)),
  workspaceIdDigest: sha256(Buffer.from(diagnostic.input.workspaceId)),
  endpointDigest: sha256(Buffer.from(diagnostic.input.endpoint)),
  endpointScheme: diagnostic.input.endpoint.startsWith('https://') ? 'https' : 'http',
  configSources: { endpoint: 'flag', profile: 'flag', output: 'system-default' },
  credentialStatus: diagnostic.input.credentialStatus,
  redactionPolicy: 'v1-no-paths-identities-or-secrets',
};
validateInstance(diagnosticValue, schemas.get('DiagnosticPreview.schema.json'));
assert.equal(diagnosticValue.schema, diagnostic.expected.schema);
assert.equal(diagnosticValue.endpointScheme, diagnostic.expected.endpointScheme);
assert.equal(diagnosticValue.credentialStatus, diagnostic.expected.credentialStatus);
assert.equal(diagnosticValue.redactionPolicy, diagnostic.expected.redactionPolicy);
const renderedDiagnostic = JSON.stringify(diagnosticValue);
for (const field of ['root', 'workspaceId', 'endpoint', 'profile', 'repositoryDeclarationDigest', 'branchDeclarationDigest', 'baselineDeclarationDigest', 'specDeclarationDigest']) {
  const forbidden = diagnostic.input[field];
  assert(!renderedDiagnostic.includes(forbidden), `diagnostic exposed ${field}`);
}

console.log(JSON.stringify({
  schema: 'ogvcs.cli-workspace/validation-report/v1',
  contractVersion: version,
  artifactSetSha256: manifest.artifactSetSha256,
  schemas: schemas.size,
  vectors: vectors.cases.length,
}));
