#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const FORMAT = join('spec', 'repository-format', 'v1');
const VECTOR_RELATIVE = join(FORMAT, 'vectors');
const MAX_JSON_BYTES = 16_777_216;
const EXPECTED = Object.freeze({ artifacts: 1236, obligations: 148, scenarios: 235, stableErrors: 81 });
const VALIDATION_STAGES = Object.freeze([
  'configured-resource-preflight', 'canonical-framing', 'sequence-shape-and-order',
  'declared-identity', 'transcript-authentication', 'known-schema',
  'closure-and-reference-resolution', 'declared-accounting', 'registry-semantics',
  'repository-semantics'
]);
const REGISTRY_FILES = Object.freeze([
  'object-kinds.json', 'hash-algorithms.json', 'common-fields.json', 'kind-fields.json',
  'entry-kinds.json', 'entry-modes.json', 'required-features.json', 'extensions.json',
  'profiles.json', 'logical-record-types.json', 'semantic-enums.json', 'limits.json'
]);
const REQUIREMENT_IDS = Object.freeze([
  'OGVCS-002-FR-09', 'OGVCS-002-FR-11', 'OGVCS-002-AC-03', 'OGVCS-002-AC-04', 'OGVCS-002-AC-06',
  'OGVCS-002-AC-07', 'OGVCS-002-AC-08', 'OGVCS-002-AC-09', 'OGVCS-002-AC-10',
  'OGVCS-002-AC-11'
]);
const REGISTRY_RECIPE_SCENARIOS = Object.freeze([
  'registry-conformance-mode', 'registry-conformance-production', 'registry-deprecated-read',
  'registry-deprecated-write', 'registry-duplicate', 'registry-invalid-entry',
  'registry-ratified-read-write', 'registry-reassigned', 'registry-reserved',
  'registry-unknown-profile'
]);
const CONFIGURED_RESOURCE_RECIPES = Object.freeze({
  'error-limit-memory': {
    api: 'verify-logical-bundle-stream',
    limits: { maxMemoryBytes: 1 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'error-limit-scratch': {
    api: 'verify-logical-bundle-stream',
    limits: { maxMemoryBytes: 67_108_864, maxScratchBytes: 0 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  },
  'error-limit-time': {
    api: 'verify-logical-bundle-stream',
    limits: { maxTimeMs: 0 },
    source: 'logical-bundles/valid-supplied-closure.cborseq'
  }
});
function fixtureAdapterRecipe(id, expectedCode, adapter, materialization = 'full') {
  return {
    adapter: {
      allocation: 'incrementing-nonzero-128-bit',
      persistLedger: 'memory',
      targetConsumption: 'always-available',
      ...adapter
    },
    expectedCode,
    generatorRequest: {
      destination: `fixture-adapter/${id}`,
      extensions: {
        'generation.large-file-mode': 'virtual',
        'generation.materialization': materialization
      },
      profile: { id: 'code-heavy', version: '2.0.0' },
      scale: { historyOperationCount: 8, largeFileBytes: 0, maxDepth: 5, pathCount: 6 },
      seed: `ogvcs-002-${id}`
    },
    schema: 'ogvcs.repository-format.v1.fixture-adapter-invocation.v1'
  };
}
const FIXTURE_ADAPTER_RECIPES = Object.freeze({
  'error-fixture-content-unavailable': fixtureAdapterRecipe('error-fixture-content-unavailable',
    'FIXTURE_CONTENT_UNAVAILABLE', {}, 'index-only'),
  'error-fixture-mapping-missing': fixtureAdapterRecipe('error-fixture-mapping-missing',
    'FIXTURE_MAPPING_MISSING', { persistLedger: 'omit' }),
  'error-fixture-native-binding-missing': fixtureAdapterRecipe('error-fixture-native-binding-missing',
    'FIXTURE_NATIVE_BINDING_MISSING', { requireNativeHistoryBindings: true }),
  'error-fixture-schema-unsupported': fixtureAdapterRecipe('error-fixture-schema-unsupported',
    'FIXTURE_SCHEMA_UNSUPPORTED', { postGenerationMutation: { type: 'request-profile-version', value: '1.0.0' } }),
  'error-fixture-semantic-invalid': fixtureAdapterRecipe('error-fixture-semantic-invalid',
    'FIXTURE_SEMANTIC_INVALID', { verifierResult: 'semantic-invalid' })
});
const REQUIRED_OBLIGATIONS = Object.freeze([
  ...['create', 'modify', 'copy', 'move', 'rename', 'delete', 'restore', 'group-create',
    'group-update', 'group-delete', 'merge-resolution'].map(name => `transition:${name}`),
  'transition:exact-replay', 'transition:result-mismatch',
  'history:parents-0', 'history:parents-1', 'history:parents-2', 'history:parents-8',
  'history:second-root', 'history:missing-parent', 'history:duplicate-parent', 'history:cycle',
  'history:cross-repository', 'history:parents-9',
  'fileid:zero', 'fileid:duplicate', 'fileid:create-reuse', 'fileid:copy-reuse',
  'fileid:source-forgery', 'fileid:move-rename', 'fileid:copy', 'fileid:delete-recreate',
  'fileid:restore-ancestry', 'fileid:restore-invalid-ancestry', 'fileid:restore-forgery',
  'fileid:cross-repository', 'fileid:import-retry', 'fileid:import-conflict',
  'fileid:import-native-collision', 'fileid:concurrent-loser-state',
  'tree:empty', 'tree:unicode', 'tree:all-entry-kinds', 'tree:all-modes', 'tree:million-entries',
  'group:create', 'group:update', 'group:delete', 'group:cardinality', 'group:external-key',
  ...['content', 'divergent-move', 'delete-modify', 'type', 'mode', 'policy', 'group',
    'path-collision'].map(kind => `conflict:kind-${kind}`),
  ...['base', 'left', 'right', 'delete', 'custom'].map(choice => `conflict:choice-${choice}`),
  'conflict:resolved', 'conflict:unresolved', 'conflict:custom-driver',
  'shelf:revision-chain', 'provenance:acyclic', 'provenance:cycle',
  'provenance:snapshot-cycle', 'attestation:unsigned', 'attestation:signed',
  'attestation:signature-shape',
  'manifest:empty', 'manifest:repeated-chunk', 'manifest:multi-chunk',
  'manifest:corrupt-chunk', 'manifest:chunk-length', 'manifest:length-sum-mismatch',
  'manifest:logical-ceiling', 'manifest:unknown-profile', 'manifest:one-tib',
  'manifest:annotation-invariance',
  ...['header', 'object', 'logical-record', 'root', 'trailer'].map(kind => `bundle:item-${kind}`),
  'bundle:zero-sections', 'bundle:logical-preservation', 'bundle:multi-root-sort',
  'bundle:sort', 'bundle:count', 'bundle:ordinal', 'bundle:mode', 'bundle:budget',
  'bundle:declared-accounting',
  'bundle:object-id', 'bundle:record-id', 'bundle:root-invalid', 'bundle:trailer',
  'bundle:eof', 'bundle:duplicate', 'bundle:closure-missing', 'bundle:closure-extra',
  'bundle:wrong-kind', 'bundle:forbidden-claim', 'bundle:every-edge-family',
  'bundle:every-root-family',
  ...Array.from({ length: 11 }, (_, index) => `bundle:edge-object-kind-${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `bundle:logical-type-${index + 1}`),
  'bundle:root-kind-object', 'bundle:root-kind-logical-record',
  'mutation:single-bit', 'hash:tamper', 'truncation:every-prefix', 'malformed:complete',
  'limits:all', 'registry:duplicate', 'registry:reassigned', 'registry:invalid-entry',
  'registry:reserved', 'registry:ratified', 'registry:deprecated-read',
  'registry:deprecated-write', 'registry:conformance', 'registry:conformance-production',
  'registry:unknown-profile', 'registry:unknown-feature', 'registry:unknown-feature-forward',
  'registry:unknown-extension-preserve'
].sort());
const OPERATIONS = new Set([
  'adapt-fixture', 'allocate-file-id', 'canonical-scan', 'import-file-id', 'replay-change-set',
  'validate-abstract-reference-graph', 'validate-bundle', 'validate-bundle-claim',
  'validate-object', 'validate-repository'
]);
const RESOURCE_DOMAIN = Buffer.from('OpenGameVCS resource summary\0', 'ascii');
const REGISTRY_DOMAIN = Buffer.from('OpenGameVCS registry set\0', 'ascii');

function fail(message) { throw new Error(`reference-vector audit failed: ${message}`); }
function same(left, right) { return JSON.stringify(stableValue(left)) === JSON.stringify(stableValue(right)); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function u16(value) { const out = Buffer.alloc(2); out.writeUInt16BE(value); return out; }
function u32(value) { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, stableValue(value[key])]));
  }
  return value;
}

function stableJson(value) { return `${JSON.stringify(stableValue(value), null, 2)}\n`; }

function safePath(value) {
  return typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.includes('\0') &&
    !value.startsWith('/') && value.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}

function expectedMediaType(path) {
  if (path.startsWith('scenarios/graphs/') && path.endsWith('.json')) {
    return 'application/vnd.opengamevcs.abstract-reference-graph+json';
  }
  if (path.endsWith('.cbor')) return 'application/cbor';
  if (path.endsWith('.cborseq')) return 'application/cbor-seq';
  if (path.endsWith('.bin')) return 'application/octet-stream';
  if (path.endsWith('.md')) return 'text/markdown';
  if (path.endsWith('.json')) return 'application/json';
  fail(`unrouted media type for ${path}`);
}

async function boundedJson(path, requireCanonical = false) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_JSON_BYTES) {
    fail(`unsafe or oversized JSON file ${path}`);
  }
  const bytes = await readFile(path);
  if (bytes.includes(0x0d) || bytes[0] === 0xef) fail(`noncanonical JSON bytes in ${path}`);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { fail(`invalid JSON in ${path}`); }
  if (requireCanonical && stableJson(value) !== bytes.toString('utf8')) {
    fail(`noncanonical JSON serialization in ${path}`);
  }
  return value;
}

async function canonicalJson(path) { return boundedJson(path, true); }

async function filesBelow(root, prefix = '') {
  const directory = prefix === '' ? root : join(root, ...prefix.split('/'));
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const files = [];
  for (const entry of entries) {
    const child = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (!safePath(child) || entry.isSymbolicLink()) fail(`unsafe vector filesystem entry ${child}`);
    if (entry.isDirectory()) files.push(...await filesBelow(root, child));
    else if (entry.isFile()) files.push(child);
    else fail(`unsupported vector filesystem entry ${child}`);
  }
  return files;
}

function recordMap(records, label, orderKey = 'path') {
  if (!Array.isArray(records)) fail(`${label} is not an array`);
  const map = new Map();
  let previous;
  for (const record of records) {
    const orderValue = record?.[orderKey];
    if (!safePath(record?.path) ||
        typeof orderValue !== 'string' ||
        (previous !== undefined && orderValue.localeCompare(previous, 'en') <= 0) ||
        map.has(record.path)) {
      fail(`${label} paths are not sorted and unique`);
    }
    previous = orderValue;
    map.set(record.path, record);
  }
  return map;
}

async function verifyArtifact(vectorRoot, inventory, record, label) {
  if (!record || !safePath(record.path)) fail(`${label} has an unsafe artifact path`);
  const expected = inventory.get(record.path);
  if (!expected || !same(expected, record)) fail(`${label} does not match the top-level inventory`);
  const bytes = await readFile(join(vectorRoot, ...record.path.split('/')));
  if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256 ||
      record.mediaType !== expectedMediaType(record.path)) fail(`${label} bytes or media type differ`);
  return bytes;
}

async function verifySeedAndPreimages(vectorRoot, inventory) {
  const objectDomain = Buffer.from('OpenGameVCS object\0', 'ascii');
  const logicalDomain = Buffer.from('OpenGameVCS logical record\0', 'ascii');
  const conflictDomain = Buffer.from('OpenGameVCS conflict\0', 'ascii');
  const objectIndex = await canonicalJson(join(vectorRoot, 'objects', 'index.json'));
  const logicalIndex = await canonicalJson(join(vectorRoot, 'logical-records', 'index.json'));
  const conflictIndex = await canonicalJson(join(vectorRoot, 'conflicts', 'index.json'));
  if (objectIndex.schema !== 'ogvcs.repository-format.v1.object-vectors.v1' ||
      !Array.isArray(objectIndex.objects) || objectIndex.objects.length !== 11 ||
      logicalIndex.schema !== 'ogvcs.repository-format.v1.logical-record-vectors.v1' ||
      !Array.isArray(logicalIndex.records) || logicalIndex.records.length !== 9 ||
      conflictIndex.schema !== 'ogvcs.repository-format.v1.conflict-preimages.v1' ||
      !Array.isArray(conflictIndex.combinations) || conflictIndex.combinations.length !== 8) {
    fail('identity preimage index shape changed');
  }
  for (const row of objectIndex.objects) {
    const payloadRecord = inventory.get(row.payloadPath);
    const payload = await verifyArtifact(vectorRoot, inventory, payloadRecord, `object preimage ${row.name}`);
    const preimage = Buffer.concat([objectDomain, u16(1), u16(row.kind), payload]);
    if (row.objectDomainHex !== objectDomain.toString('hex') || row.formatVersionUint16beHex !== '0001' ||
        row.kindUint16beHex !== u16(row.kind).toString('hex') || row.objectId !== sha256(preimage) ||
        row.preimageRecipe !== 'objectDomainHex || formatVersionUint16beHex || kindUint16beHex || exact payloadPath bytes' ||
        row.preimageHex !== (payload.length <= 256 ? preimage.toString('hex') : null)) {
      fail(`object preimage or identity differs for ${row.name}`);
    }
  }
  for (const row of logicalIndex.records) {
    const payload = await verifyArtifact(vectorRoot, inventory, inventory.get(row.payloadPath),
      `logical-record preimage ${row.type}`);
    const preimage = Buffer.concat([logicalDomain, u16(1), u16(row.type), payload]);
    if (row.logicalDomainHex !== logicalDomain.toString('hex') || row.formatVersionUint16beHex !== '0001' ||
        row.typeUint16beHex !== u16(row.type).toString('hex') || row.identity !== sha256(preimage) ||
        row.preimageHex !== preimage.toString('hex')) {
      fail(`logical-record preimage or identity differs for type ${row.type}`);
    }
  }
  for (let mask = 0; mask < conflictIndex.combinations.length; mask += 1) {
    const row = conflictIndex.combinations[mask];
    const bits = mask.toString(2).padStart(3, '0');
    const payload = await verifyArtifact(vectorRoot, inventory, inventory.get(row.keyedPayloadPath),
      `conflict preimage ${bits}`);
    const preimage = Buffer.concat([conflictDomain, u16(1), payload]);
    if (row.keyedPayloadPath !== `conflicts/${bits}-keyed-preimage.cbor` ||
        row.basePresent !== Boolean(mask & 4) || row.leftPresent !== Boolean(mask & 2) ||
        row.rightPresent !== Boolean(mask & 1) || row.domainHex !== conflictDomain.toString('hex') ||
        row.formatVersionUint16beHex !== '0001' || row.conflictId !== sha256(preimage)) {
      fail(`conflict preimage or identity differs for ${bits}`);
    }
  }
  if (conflictIndex.conflictIdRecipe !== 'SHA-256(domainHex || 0001 || exact keyedPayloadPath bytes)') {
    fail('conflict identity recipe changed');
  }

  const seed = await canonicalJson(join(vectorRoot, 'seed.json'));
  const first = objectIndex.objects[0];
  const payload = await readFile(join(vectorRoot, ...first.payloadPath.split('/')));
  const seedPreimage = Buffer.concat([objectDomain, u16(1), u16(1), payload]);
  if (seed.schema !== 'ogvcs.repository-format.v1.hand-auditable-seed.v1' ||
      !same(seed.independentlyReproducible, {
        formatVersionUint16beHex: '0001',
        formula: 'SHA-256(objectDomainHex || formatVersionUint16beHex || kindUint16beHex || payloadHex)',
        kindUint16beHex: '0001',
        objectDomainAscii: 'OpenGameVCS object\\0',
        objectDomainHex: objectDomain.toString('hex'),
        objectId: sha256(seedPreimage),
        payloadAsciiEscaped: 'OpenGameVCS\\n',
        payloadHex: payload.toString('hex'),
        preimageHex: seedPreimage.toString('hex')
      }) || first.kind !== 1 || first.objectId !== seed.independentlyReproducible.objectId) {
    fail('hand-auditable seed or preimage invariant differs');
  }
}

function resourceDigest(summary) {
  const fields = ['bytes', 'items', 'traversalEdges', 'indexEntries', 'peakMemoryBytes', 'scratchBytes'];
  for (const field of fields) {
    if (!Number.isSafeInteger(summary[field]) || summary[field] < 0) fail(`invalid resource counter ${field}`);
  }
  return sha256(Buffer.concat([RESOURCE_DOMAIN, u16(1), ...fields.map(field => u64(summary[field]))]));
}

function artifactBytes(inventory, path) {
  const record = inventory.get(path);
  if (!record) fail(`scenario references an uninventoried artifact ${path}`);
  return record.bytes;
}

async function registryDigest(root) {
  const hash = createHash('sha256');
  hash.update(REGISTRY_DOMAIN);
  hash.update(u16(1));
  const records = [];
  for (const file of REGISTRY_FILES) {
    const pathText = `registries/${file}`;
    const bytes = await readFile(join(root, FORMAT, 'registries', file));
    hash.update(u32(Buffer.byteLength(pathText)));
    hash.update(pathText, 'utf8');
    hash.update(u64(bytes.length));
    hash.update(bytes);
    records.push({ bytes: bytes.length, path: pathText, sha256: sha256(bytes) });
  }
  return { digest: hash.digest('hex'), records };
}

function permitsSite(error, stage, layer) {
  return error?.sites?.some(site => site.stage === stage && site.layers.includes(layer)) === true;
}

async function verifyScenarios(root, vectorRoot, inventory, manifest, registrySet, errors) {
  const index = await canonicalJson(join(vectorRoot, 'scenarios', 'index.json'));
  if (!Array.isArray(index.cases) || index.cases.length !== EXPECTED.scenarios) fail('scenario index count changed');
  const byId = new Map();
  for (const row of index.cases) {
    if (byId.has(row.scenarioId)) fail(`duplicate scenario ${row.scenarioId}`);
    byId.set(row.scenarioId, row);
  }
  const manifestScenarios = recordMap(manifest.scenarios, 'manifest scenarios', 'scenarioId');
  if (manifestScenarios.size !== index.cases.length) fail('manifest scenario count differs from index');
  const configuredResourceSeen = new Set();
  const fixtureAdapterSeen = new Set();
  const rejectionStagesSeen = new Set();

  for (const row of index.cases) {
    const listed = manifestScenarios.get(row.artifact);
    if (!listed || listed.scenarioId !== row.scenarioId) fail(`scenario route missing for ${row.scenarioId}`);
    const bytes = await verifyArtifact(vectorRoot, inventory, inventory.get(row.artifact), `scenario ${row.scenarioId}`);
    if (sha256(bytes) !== listed.sha256) fail(`scenario manifest digest differs for ${row.scenarioId}`);
    const scenario = await canonicalJson(join(vectorRoot, ...row.artifact.split('/')));
    if (scenario.schemaVersion !== 'ogvcs.repository-format/validation-scenario/v1' ||
        scenario.scenarioId !== row.scenarioId || scenario.operation !== row.operation ||
        !OPERATIONS.has(scenario.operation) || scenario.failurePrecedence !== 'errors-v1-layer-stage-code-offset-subject') {
      fail(`scenario envelope mismatch for ${row.scenarioId}`);
    }
    const implementationScope = scenario.implementationScope ?? ['javascript', 'rust'];
    if (!Array.isArray(implementationScope) || implementationScope.length === 0 ||
        new Set(implementationScope).size !== implementationScope.length ||
        implementationScope.some(value => !['javascript', 'rust'].includes(value)) ||
        !same(scenario.implementationScope, row.implementationScope)) {
      fail(`scenario implementation scope mismatch for ${row.scenarioId}`);
    }
    if (!Array.isArray(scenario.requirementIds) || !same(scenario.requirementIds, row.requirementIds) ||
        new Set(scenario.requirementIds).size !== scenario.requirementIds.length) {
      fail(`scenario requirement routing mismatch for ${row.scenarioId}`);
    }
    if (scenario.context?.registrySnapshot?.registrySetSha256 !== registrySet ||
        scenario.context?.asOf !== 'immediately-before-candidate-snapshot') {
      fail(`scenario registry or temporal context mismatch for ${row.scenarioId}`);
    }
    for (const input of scenario.inputs ?? []) await verifyArtifact(vectorRoot, inventory, input, `${row.scenarioId} input`);
    for (const entry of scenario.context?.objectLookup ?? []) {
      await verifyArtifact(vectorRoot, inventory, entry.artifact, `${row.scenarioId} lookup`);
    }

    const definitionPath = scenario.resources?.recipe?.parameters?.definition;
    const definitionHash = scenario.resources?.recipe?.parameters?.definitionSha256;
    if (!safePath(definitionPath) || inventory.get(definitionPath)?.sha256 !== definitionHash) {
      fail(`scenario definition binding mismatch for ${row.scenarioId}`);
    }
    const definition = await canonicalJson(join(vectorRoot, ...definitionPath.split('/')));
    if (definition.expectedRootState?.scenarioId !== row.scenarioId ||
        definition.registrySetSha256 !== registrySet || definition.failurePrecedence !== scenario.failurePrecedence ||
        definition.operation !== scenario.operation ||
        !same(definition.implementationScope, scenario.implementationScope)) fail(`scenario definition mismatch for ${row.scenarioId}`);

    const definitionInput = scenario.inputs.find(input => input.path === definitionPath);
    if (!definitionInput) fail(`scenario omits its definition input for ${row.scenarioId}`);
    const expectedResourceRecipe = CONFIGURED_RESOURCE_RECIPES[row.scenarioId];
    if (expectedResourceRecipe) {
      if (row.materialization !== 'executable-configured-resource-constructor' ||
          !same(definition.exactConstructorValues?.configuredResource, expectedResourceRecipe) ||
          !scenario.inputs.some(input => input.path === expectedResourceRecipe.source)) {
        fail(`configured resource recipe differs for ${row.scenarioId}`);
      }
      configuredResourceSeen.add(row.scenarioId);
    } else if (row.materialization === 'executable-configured-resource-constructor') {
      fail(`unexpected configured resource constructor ${row.scenarioId}`);
    }
    const expectedFixtureAdapter = FIXTURE_ADAPTER_RECIPES[row.scenarioId];
    if (expectedFixtureAdapter) {
      if (scenario.operation !== 'adapt-fixture' ||
          row.materialization !== 'executable-fixture-adapter-constructor' ||
          !same(scenario.implementationScope, ['javascript']) ||
          !same(definition.exactConstructorValues?.fixtureAdapter, expectedFixtureAdapter)) {
        fail(`fixture adapter recipe differs for ${row.scenarioId}`);
      }
      fixtureAdapterSeen.add(row.scenarioId);
    } else if (scenario.operation === 'adapt-fixture' ||
        row.materialization === 'executable-fixture-adapter-constructor') {
      fail(`unexpected fixture adapter constructor ${row.scenarioId}`);
    }
    const logical = definition.suppliedResourceCatalogue?.logicalRecordArtifacts ?? [];
    const summary = scenario.resources.summary;
    const suppliedPaths = new Set([
      ...scenario.inputs.map(item => item.path),
      ...(scenario.context.objectLookup ?? []).map(item => item.artifact.path),
      ...logical
    ]);
    const expectedBytes = [...suppliedPaths].reduce((sum, path) => sum + artifactBytes(inventory, path), 0);
    if (summary.bytes !== expectedBytes || summary.items !== (scenario.context.objectLookup?.length ?? 0) + logical.length ||
        summary.traversalEdges !== 0 || summary.indexEntries !== 0 || summary.peakMemoryBytes !== 0 ||
        summary.scratchBytes !== 0 || summary.summarySha256 !== resourceDigest(summary)) {
      fail(`scenario resource summary mismatch for ${row.scenarioId}`);
    }

    if (row.expected.result === 'reject') {
      if (scenario.expected.result !== 'reject' || scenario.expected.code !== row.code ||
          scenario.expected.layer !== row.expected.layer || scenario.expected.stage !== row.expected.stage ||
          !permitsSite(errors.get(row.code), scenario.expected.stage, scenario.expected.layer)) {
        fail(`scenario rejection mismatch for ${row.scenarioId}`);
      }
      rejectionStagesSeen.add(scenario.expected.stage);
    } else {
      if (scenario.expected.result !== 'accept' || scenario.expected.highestLayer !== row.expected.highestLayer ||
          scenario.expected.output.summarySha256 !== summary.summarySha256) fail(`scenario acceptance mismatch for ${row.scenarioId}`);
      await verifyArtifact(vectorRoot, inventory, scenario.expected.output.artifact, `${row.scenarioId} output`);
      const output = await canonicalJson(join(vectorRoot, ...scenario.expected.output.artifact.path.split('/')));
      const { schema, ...rootState } = output;
      if (schema !== 'ogvcs.repository-format.v1.scenario-output.v1' ||
          !same(rootState, definition.expectedRootState)) {
        fail(`scenario output differs from its definition for ${row.scenarioId}`);
      }
    }
    const expectedLayer = scenario.expected.result === 'reject'
      ? scenario.expected.layer : scenario.expected.highestLayer;
    if (definition.validation?.requestedLayer !== expectedLayer) {
      fail(`scenario definition layer differs for ${row.scenarioId}`);
    }
  }
  if (!same([...configuredResourceSeen].sort(), Object.keys(CONFIGURED_RESOURCE_RECIPES).sort())) {
    fail('configured resource scenario set changed');
  }
  if (!same([...fixtureAdapterSeen].sort(), Object.keys(FIXTURE_ADAPTER_RECIPES).sort())) {
    fail('fixture adapter scenario set changed');
  }
  if (!same([...rejectionStagesSeen].sort(), [...VALIDATION_STAGES].sort())) {
    fail('rejecting scenarios do not execute every frozen validation stage');
  }
  return { index, byId };
}

async function verifyCoverage(vectorRoot, scenarioIndex, errors) {
  const coverage = await canonicalJson(join(vectorRoot, 'coverage-matrix.json'));
  const rows = scenarioIndex.cases;
  if (REQUIRED_OBLIGATIONS.length !== EXPECTED.obligations) fail('independent obligation contract count differs');
  const expectedObligations = REQUIRED_OBLIGATIONS.map(obligation => ({
    obligation,
    scenarios: rows.filter(row => row.obligationTags.includes(obligation)).map(row => row.scenarioId)
  }));
  const expectedRequirements = REQUIREMENT_IDS.map(requirementId => ({
    requirementId,
    scenarios: rows.filter(row => row.requirementIds.includes(requirementId)).map(row => row.scenarioId)
  }));
  const expectedErrors = [...errors].map(code => ({
    code,
    scenarios: rows.filter(row => row.code === code).map(row => row.scenarioId)
  }));
  const materialization = Object.fromEntries([...new Set(rows.map(row => row.materialization))].sort().map(kind => [
    kind, rows.filter(row => row.materialization === kind).length
  ]));
  if (!same(coverage.obligations, expectedObligations) ||
      !same(coverage.requirementIds, expectedRequirements) || !same(coverage.stableErrors, expectedErrors) ||
      !same(coverage.totals, {
        materialization,
        obligations: EXPECTED.obligations,
        scenarios: EXPECTED.scenarios,
        stableErrors: EXPECTED.stableErrors
      })) fail('coverage matrix is not derivable from the scenario index and error catalogue');
  for (const row of coverage.stableErrors) if (row.scenarios.length === 0) fail(`stable error lacks a scenario: ${row.code}`);
}

async function verifyLimits(root, vectorRoot, scenarios) {
  const registry = await boundedJson(join(root, FORMAT, 'registries', 'limits.json'));
  const summary = await canonicalJson(join(vectorRoot, 'limits.json'));
  const constructors = await canonicalJson(join(vectorRoot, 'limits', 'virtual-constructors.json'));
  if (registry.entries.length !== 25 || summary.cases.length !== 25 || constructors.cases.length !== 50) {
    fail('hard-limit corpus cardinality changed');
  }
  const byName = new Map(summary.cases.map(row => [row.name, row]));
  const variants = new Map();
  for (const item of constructors.cases) {
    const key = `${item.case}/${item.variant}`;
    if (variants.has(key) || item.algorithm?.id !== 'ogvcs.virtual-boundary-constructor' ||
        item.algorithm.version !== 1 || typeof item.emitter !== 'string' || item.emitter.length === 0 ||
        item.summary?.digestHex !== sha256(stableJson(item.summary.input))) fail(`invalid virtual limit constructor ${key}`);
    variants.set(key, item);
  }
  for (const limit of registry.entries) {
    const row = byName.get(limit.name);
    if (!row || row.unit !== limit.unit || row.maximum.value !== limit.value ||
        row.maximumPlusOne.value !== limit.value + 1 || row.maximumPlusOne.expected.code !== limit.errorCode) {
      fail(`limit summary differs from registry for ${limit.name}`);
    }
    for (const [variant, value, expected] of [
      ['maximum', limit.value, row.maximum.expected],
      ['maximum-plus-one', limit.value + 1, row.maximumPlusOne.expected]
    ]) {
      const item = variants.get(`${limit.name}/${variant}`);
      if (!item || item.valueDecimal !== String(value) || !same(item.expected, expected) ||
          item.summary.input.valueDecimal !== String(value) || item.summary.input.variant !== variant) {
        fail(`limit constructor differs for ${limit.name}/${variant}`);
      }
      const suffix = variant === 'maximum' ? 'max' : 'max-plus-one';
      const scenarioId = `limit-${limit.name}-${suffix}`;
      const scenario = scenarios.get(scenarioId);
      const expectedMatches = scenario && scenario.expected.result === item.expected.result &&
        (item.expected.result === 'accept'
          ? scenario.expected.highestLayer === item.expected.highestLayer
          : scenario.expected.code === item.expected.code && scenario.expected.layer === item.expected.layer &&
            scenario.expected.stage === item.expected.stage);
      if (!expectedMatches ||
          scenario.materialization !== 'executable-virtual-limit-constructor') {
        fail(`limit scenario differs from executable constructor for ${limit.name}/${variant}`);
      }
      const definition = await canonicalJson(join(
        vectorRoot, 'scenarios', 'definitions', `${scenarioId}.json`
      ));
      if (!same(definition.exactConstructorValues?.virtualLimit, {
        case: limit.name,
        recipe: 'limits/virtual-constructors.json',
        variant
      })) {
        fail(`limit scenario omits executable constructor binding for ${limit.name}/${variant}`);
      }
    }
  }
}

async function verifyMutationRecipes(vectorRoot, inventory) {
  const mutation = await canonicalJson(join(vectorRoot, 'mutations', 'single-bit.json'));
  let cases = 0;
  for (const source of mutation.sources) {
    if (artifactBytes(inventory, source.source) !== source.byteLength) fail(`mutation source length differs for ${source.source}`);
    cases += source.byteLength * 8;
  }
  for (const item of mutation.bundleItemShapes) {
    if (item.byteOffset + item.byteLength > artifactBytes(inventory, item.source)) fail('bundle item mutation range exceeds source');
    cases += item.byteLength * 8;
  }
  if (mutation.wholeSequence.byteLength !== artifactBytes(inventory, mutation.wholeSequence.source)) {
    fail('whole bundle mutation length differs');
  }
  cases += mutation.wholeSequence.byteLength * 8;
  if (cases !== mutation.totalCases || cases !== 58_520) fail('single-bit mutation cardinality differs');

  const truncation = await canonicalJson(join(vectorRoot, 'mutations', 'truncation.json'));
  let prefixes = 0;
  for (const source of truncation.sources) {
    const byteOffset = source.byteOffset ?? 0;
    if (!Number.isSafeInteger(byteOffset) || byteOffset < 0 ||
        byteOffset + source.byteLength > artifactBytes(inventory, source.source) ||
        source.prefixes.fromInclusive !== 0 || source.prefixes.toInclusive !== source.byteLength - 1) {
      fail(`truncation source range differs for ${source.source}`);
    }
    prefixes += source.byteLength;
  }
  const whole = truncation.wholeSequence;
  if (whole.byteLength !== artifactBytes(inventory, whole.source)) fail('whole bundle truncation length differs');
  let cursor = 0;
  for (const range of whole.ranges) {
    if (range.fromInclusive !== cursor || range.toInclusive < range.fromInclusive) fail('bundle truncation ranges are not contiguous');
    prefixes += range.toInclusive - range.fromInclusive + 1;
    cursor = range.toInclusive + 1;
  }
  if (cursor !== whole.byteLength || prefixes !== 7_303) fail('truncation prefix cardinality differs');
  const malformed = await canonicalJson(join(vectorRoot, 'malformed', 'index.json'));
  for (const [scenarioId, path, totalCases] of [
    ['malformed-complete-corpus', 'malformed/index.json', malformed.explicitCases.length],
    ['mutation-systematic-single-bit', 'mutations/single-bit.json', cases],
    ['truncation-every-prefix', 'mutations/truncation.json', prefixes]
  ]) {
    const scenario = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', `${scenarioId}.json`));
    const definition = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', `${scenarioId}.json`));
    if (!scenario.inputs.some(input => input.path === path) ||
        !same(definition.exactConstructorValues?.enumeratedRecipe, { path, totalCases }) ||
        scenario.expected.result !== 'accept' || scenario.expected.highestLayer !== 1) {
      fail(`enumerated scenario is not bound to its executable recipe: ${scenarioId}`);
    }
  }
  return { mutationCases: cases, truncationPrefixes: prefixes };
}

async function verifyRegistryRecipes(vectorRoot, scenarios) {
  const index = await canonicalJson(join(vectorRoot, 'registries', 'index.json'));
  const recipes = index.cases.filter(item => REGISTRY_RECIPE_SCENARIOS.includes(item.scenarioId));
  const ids = recipes.map(item => item.scenarioId).sort((left, right) => left.localeCompare(right, 'en'));
  if (!same(ids, [...REGISTRY_RECIPE_SCENARIOS].sort((left, right) => left.localeCompare(right, 'en'))) ||
      new Set(ids).size !== ids.length) fail('registry scenario recipe set differs');
  for (const recipe of recipes) {
    const row = scenarios.get(recipe.scenarioId);
    const outcomeMatches = row && row.expected.result === recipe.expected.result &&
      (recipe.expected.result === 'accept'
        ? row.expected.highestLayer === recipe.expected.highestLayer
        : row.expected.code === recipe.expected.code && row.expected.layer === recipe.expected.layer &&
          row.expected.stage === recipe.expected.stage);
    if (!row || row.materialization !== 'executable-enumerated-registry-recipe' ||
        !outcomeMatches) fail(`registry scenario outcome differs from recipe: ${recipe.scenarioId}`);
    const scenario = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', `${recipe.scenarioId}.json`));
    const definition = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', `${recipe.scenarioId}.json`));
    if (!scenario.inputs.some(input => input.path === 'registries/index.json') ||
        !same(definition.exactConstructorValues?.registryCase, {
          path: 'registries/index.json', scenarioId: recipe.scenarioId
        })) fail(`registry scenario omits executable recipe binding: ${recipe.scenarioId}`);
    if (recipe.operation === 'validate-registry-set') {
      if (recipe.sourceRegistryDirectory !== '../registries' ||
          !['append-copy', 'append-entry', 'replace-entry-field'].includes(recipe.mutation?.action) ||
          !REGISTRY_FILES.includes(recipe.mutation?.file)) {
        fail(`invalid registry-set mutation recipe: ${recipe.scenarioId}`);
      }
    } else if (recipe.snapshot !== 'old' || typeof recipe.profile !== 'string' ||
        !['conformance', 'new-write', 'production-write', 'read', 'read-or-new-write', 'read-or-write'].includes(recipe.operation)) {
      fail(`invalid registry lifecycle recipe: ${recipe.scenarioId}`);
    }
  }
}

async function verifyScaleDefinitions(vectorRoot) {
  const manifestCase = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', 'manifest-one-tib.json'));
  const manifest = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', 'manifest-one-tib.json'));
  const treeCase = await canonicalJson(join(vectorRoot, 'scenarios', 'cases', 'tree-million-entries.json'));
  const tree = await canonicalJson(join(vectorRoot, 'scenarios', 'definitions', 'tree-million-entries.json'));
  if (!same(manifestCase.requirementIds, ['OGVCS-002-AC-09', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02']) ||
      !same(treeCase.requirementIds, ['OGVCS-002-AC-02', 'OGVCS-002-FR-09', 'OGVCS-002-NFR-02'])) {
    fail('scale cases do not route their acceptance requirements');
  }
  const manifestPlan = manifest.exactConstructorValues.scalePlan;
  const seed = Buffer.from(manifestPlan.recurrence.seed, 'hex');
  const block = createHash('sha256').update(seed).update(Buffer.from([0x43]))
    .update("repeated-chunk-v1", 'ascii').digest();
  const chunk = Buffer.alloc(1_048_576);
  for (let offset = 0; offset < chunk.length; offset += block.length) block.copy(chunk, offset);
  const objectDigest = createHash('sha256').update('OpenGameVCS object\0', 'ascii')
    .update(u16(1)).update(u16(1)).update(chunk).digest('hex');
  const fixed = manifestPlan.fixedFields;
  if (seed.length !== 32 || block.toString('hex') !== fixed.repeatedBlockSha256 ||
      sha256(chunk) !== fixed.rawChunkSha256 ||
      fixed.chunkObjectRef !== `ogvcs:v1:chunk:sha256:${objectDigest}` ||
      fixed.chunkBytes !== '1048576' || fixed.chunkCount !== '1048576' ||
      fixed.logicalBytes !== '1099511627776') fail('1 TiB manifest recurrence is not self-consistent');
  const treePlan = tree.exactConstructorValues.scalePlan;
  if (treePlan.streamCardinality !== '1000000' || treePlan.recurrence.seed !== tree.seedHex ||
      manifestPlan.recurrence.seed !== manifest.seedHex || tree.seedHex !== treeCase.resources.recipe.seed ||
      manifest.seedHex !== manifestCase.resources.recipe.seed) {
    fail('scale recurrence cardinality or seed differs');
  }
}

async function verifyExpectations(vectorRoot, inventory) {
  const expectations = await canonicalJson(join(vectorRoot, 'expectations.json'));
  const paths = expectations.artifacts.map(record => record.path);
  const expected = [...inventory.keys()].filter(path => path !== 'expectations.json');
  if (!same(paths, expected) || new Set(paths).size !== paths.length) fail('artifact expectations do not route the inventory exactly once');
}

function parseArguments(argv) {
  if (argv.length === 0) return DEFAULT_ROOT;
  if (argv.length === 2 && argv[0] === '--root') return resolve(argv[1]);
  fail('usage: node tools/verify-reference-vectors.mjs [--root REPOSITORY]');
}

async function main() {
  const root = parseArguments(process.argv.slice(2));
  const vectorRoot = join(root, VECTOR_RELATIVE);
  const manifest = await canonicalJson(join(vectorRoot, 'manifest.json'));
  if (manifest.manifestVersion !== 'ogvcs.repository-format/vector-manifest/v1' ||
      manifest.generator?.implementation !== 'node tools/reference-vector-generator/generate.mjs' ||
      manifest.generator.version !== '2.0.0') fail('vector manifest identity differs');
  const generatorBytes = await readFile(join(root, 'tools', 'reference-vector-generator', 'generate.mjs'));
  if (sha256(generatorBytes) !== manifest.generator.sourceSha256) fail('vector generator provenance digest differs');

  const inventory = recordMap(manifest.artifacts, 'artifact inventory');
  if (inventory.size !== EXPECTED.artifacts) fail('artifact inventory count changed');
  const actualFiles = (await filesBelow(vectorRoot))
    .filter(path => path !== 'manifest.json')
    .sort((left, right) => left.localeCompare(right, 'en'));
  if (!same(actualFiles, [...inventory.keys()])) fail('artifact inventory does not match the vector tree');
  for (const record of inventory.values()) await verifyArtifact(vectorRoot, inventory, record, `inventory ${record.path}`);

  const errorsDocument = await boundedJson(join(root, FORMAT, 'errors.json'));
  const errorCodes = errorsDocument.errors.map(item => item.code);
  if (errorCodes.length !== EXPECTED.stableErrors || new Set(errorCodes).size !== errorCodes.length) {
    fail('stable error catalogue count or uniqueness changed');
  }
  const errors = new Map();
  for (const error of errorsDocument.errors) {
    if (!Array.isArray(error.sites) || error.sites.length === 0) fail(`stable error lacks validation sites: ${error.code}`);
    const pairs = new Set();
    for (const site of error.sites) {
      if (!VALIDATION_STAGES.includes(site.stage) || !Array.isArray(site.layers) || site.layers.length === 0 ||
          site.layers.some(layer => !Number.isInteger(layer) || layer < 1 || layer > 3)) {
        fail(`stable error has invalid validation site: ${error.code}`);
      }
      for (const layer of site.layers) {
        const pair = `${site.stage}\0${layer}`;
        if (pairs.has(pair)) fail(`stable error repeats validation site: ${error.code}`);
        pairs.add(pair);
      }
    }
    errors.set(error.code, error);
  }
  const registry = await registryDigest(root);
  const snapshot = await canonicalJson(join(vectorRoot, 'registries', 'live-snapshot.json'));
  if (snapshot.registrySetSha256 !== registry.digest || !same(snapshot.registries, registry.records)) {
    fail('live registry snapshot does not match normative registry bytes');
  }
  await verifySeedAndPreimages(vectorRoot, inventory);
  const scenarios = await verifyScenarios(root, vectorRoot, inventory, manifest, registry.digest, errors);
  await verifyCoverage(vectorRoot, scenarios.index, new Set(errorCodes));
  await verifyLimits(root, vectorRoot, scenarios.byId);
  const recipes = await verifyMutationRecipes(vectorRoot, inventory);
  await verifyRegistryRecipes(vectorRoot, scenarios.byId);
  await verifyScaleDefinitions(vectorRoot);
  await verifyExpectations(vectorRoot, inventory);
  process.stdout.write(`${JSON.stringify({
    artifacts: inventory.size,
    obligations: EXPECTED.obligations,
    registrySetSha256: registry.digest,
    scenarios: scenarios.byId.size,
    schema: 'ogvcs.repository-format.vector-audit/v1',
    stableErrors: errorCodes.length,
    validationStages: VALIDATION_STAGES.length,
    ...recipes
  })}\n`);
}

await main();
