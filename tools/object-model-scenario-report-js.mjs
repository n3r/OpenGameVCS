#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

function moduleTarget(configured, fallback) {
  if (configured === undefined) return fallback;
  if (isAbsolute(configured) || configured.startsWith('./') || configured.startsWith('../')) {
    return pathToFileURL(resolve(configured)).href;
  }
  return configured;
}

const { createRequest, generateFixture } = await import(moduleTarget(
  process.env.OGVCS_FIXTURE_GENERATOR_JS_MODULE,
  '@opengamevcs/fixture-generator'
));

const {
  OgvcsError,
  Digest,
  ObjectRef,
  ProfileRef,
  RegistrySnapshot,
  RepositoryObjectLookup,
  adaptFixture,
  allocateFileId,
  createDiskFileIdIndex,
  createBundleTranscriptHashWriter,
  decodeCanonical,
  decodeSequence,
  decodeMetadata,
  encodeCanonical,
  encodeLogicalBundle,
  encodeMetadata,
  evaluateHardLimit,
  expandTree,
  hashLogicalRecord,
  hashObject,
  loadRegistryDirectory,
  profileDecision,
  REGISTRY_FILES,
  registryFromEvolutionSnapshot,
  scanMetadata,
  toHex,
  validateAbstractReferenceGraph,
  validateAssetGroups,
  validateBundleClaim,
  validateConflictSet,
  validateFileIdAllocation,
  validateImportRequest,
  validateLifetimeAndImports,
  validateLogicalRecord,
  validateKnownSchema,
  validateProvenanceGraph,
  validateRepositoryCandidate,
  validateRegistrySet,
  validateShelfRevision,
  validateSnapshotGraph,
  replayChangeSet,
  visitLogicalBundle,
  writeContentManifest,
  writeOrderedLogicalBundle,
  writeOrderedTree,
  writeSortedTree,
  verifyLogicalBundle,
  verifyLogicalBundleStream,
  verifyManifest,
  verifyTreeFile
} = await import(moduleTarget(
  process.env.OGVCS_OBJECT_MODEL_JS_MODULE,
  new URL('../core/object-model/js/src/index.js', import.meta.url).href
));

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC = resolve(process.env.OGVCS_FORMAT_ROOT ?? resolve(ROOT, 'spec/repository-format/v1'));
const VECTORS = resolve(process.env.OGVCS_VECTOR_ROOT ?? resolve(SPEC, 'vectors'));
const DEFINITION_SUFFIX = '/scenarios/definitions/';
const byteCache = new Map();

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value) { return createHash('sha256').update(value).digest('hex'); }
async function bytes(relative) {
  if (!byteCache.has(relative)) byteCache.set(relative, new Uint8Array(await readFile(resolve(VECTORS, relative))));
  return byteCache.get(relative);
}
async function json(relative) { return JSON.parse(await readFile(resolve(VECTORS, relative), 'utf8')); }
async function specJson(relative) { return JSON.parse(await readFile(resolve(SPEC, relative), 'utf8')); }
function hexBytes(value) { return new Uint8Array(Buffer.from(value, 'hex')); }

async function lookupFor(scenario, registry, overrides = {}) {
  const entries = [];
  for (const item of scenario.context.objectLookup) entries.push([item.ref, await bytes(item.artifact.path)]);
  for (const mutation of overrides.lookupMutations ?? []) {
    if (mutation?.action !== 'replace-payload-preserve-reference' ||
        typeof mutation.reference !== 'string' || typeof mutation.sourceArtifact !== 'string') {
      throw new Error(`${scenario.scenarioId}: invalid route lookup mutation`);
    }
    const index = entries.findIndex(([reference]) => reference === mutation.reference);
    if (index < 0) throw new Error(`${scenario.scenarioId}: lookup mutation reference is not supplied`);
    entries[index] = [mutation.reference, await bytes(mutation.sourceArtifact)];
  }
  return new RepositoryObjectLookup(entries, {
    mode: overrides.mode ?? scenario.context.mode,
    registry,
    semanticProfiles: true
  });
}

function repositoryContext(scenario, lookup) {
  return {
    descriptor: scenario.context.repositoryDescriptor,
    designatedRoot: scenario.context.designatedRoot,
    importMappings: scenario.context.importMappings,
    lifetimeRecords: scenario.context.lifetimeRecords,
    lookup,
    caseMode: scenario.context.caseMode,
    verifyContent: true,
    workingLifetimeAdditions: scenario.context.workingLifetimeAdditions
  };
}

function stateFingerprint(state) {
  return encodeCanonical(new Map([
    [0, [...(state.entries?.values?.() ?? [])]],
    [1, [...(state.groups?.values?.() ?? [])]]
  ]));
}

function assertStateUnchanged(state, fingerprint, scenarioId) {
  assert.deepEqual(stateFingerprint(state), fingerprint,
    `${scenarioId}: replay mutated its caller-owned base state`);
}

function groupsForState(reference, lookup) {
  if (reference === undefined || reference === null || reference === 'empty') return new Map();
  const set = lookup.resolve(reference, 5).value;
  return new Map((set.get(17) ?? []).map(group => [toHex(group.get(0)), group]));
}

function materializeReplayBase(baseState, scenario, lookup, descriptor) {
  if (!baseState || typeof baseState !== 'object') {
    throw new Error(`${scenario.scenarioId}: replay route is missing baseState`);
  }
  const tree = expandTree(baseState.tree, lookup, descriptor, {
    caseMode: scenario.context.caseMode,
    verifyContent: true
  });
  return Object.freeze({
    entries: tree.entries,
    fileIds: tree.fileIds,
    groups: groupsForState(baseState.groups, lookup)
  });
}

function replayBaseFromCandidate(scenario, lookup) {
  const candidate = lookup.resolve(scenario.context.candidateSnapshot, 7).value;
  const changeSetReference = candidate.get(19);
  const changeSet = lookup.resolve(changeSetReference, 4).value;
  const conflictSet = candidate.has(28)
    ? lookup.resolve(candidate.get(28), 11).value
    : undefined;
  if (!changeSet.has(17)) {
    return { candidate, changeSetReference, conflictSet, base: Object.freeze({
      entries: new Map(), fileIds: new Map(), groups: new Map()
    }) };
  }
  const baseSnapshot = lookup.resolve(changeSet.get(17), 7).value;
  return {
    candidate,
    changeSetReference,
    conflictSet,
    base: materializeReplayBase({ tree: baseSnapshot.get(18), groups: baseSnapshot.get(20) },
      scenario, lookup, scenario.context.repositoryDescriptor)
  };
}

function primaryInput(scenario) {
  return scenario.inputs.find(input => !input.path.includes(DEFINITION_SUFFIX.slice(1)));
}

function primaryReference(scenario, input) {
  return scenario.context.objectLookup.find(entry => entry.artifact.path === input?.path)?.ref;
}

async function executeMutationRecipe(registry) {
  const [recipe, objectIndex, logicalIndex] = await Promise.all([
    json('mutations/single-bit.json'), json('objects/index.json'), json('logical-records/index.json')
  ]);
  let executed = 0;
  const sources = [
    ...objectIndex.objects.map(item => ({ category: item.kind === 1 ? 'raw-object' : 'metadata-object',
      declared: item.objectId, kind: item.kind, path: item.payloadPath })),
    ...logicalIndex.records.map(item => ({ category: 'logical-record', declared: item.identity,
      path: item.payloadPath, type: item.type }))
  ];
  assert.equal(sources.length, recipe.sources.length);
  for (const [sourceIndex, declared] of recipe.sources.entries()) {
    const source = sources[sourceIndex];
    const original = await bytes(source.path);
    assert.equal(original.length, declared.byteLength);
    for (let offset = 0; offset < original.length; offset += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        const changed = original.slice(); changed[offset] ^= 1 << bit;
        let identity;
        try {
          if (source.category === 'raw-object') identity = toHex(hashObject(source.kind, changed).digest);
          else if (source.category === 'metadata-object') {
            const decoded = decodeMetadata(changed, { semantic: false });
            if (decoded.kind !== source.kind) throw new OgvcsError('OBJECT_REFERENCE_KIND_MISMATCH', {
              layer: 2, stage: 'known-schema'
            });
            identity = toHex(hashObject(source.kind, changed).digest);
          } else {
            const value = decodeCanonical(changed);
            const validated = validateLogicalRecord(value, { registry, operation: 'conformance' });
            identity = toHex(hashLogicalRecord(validated.type, changed).bytes);
          }
        } catch (error) {
          if (!(error instanceof OgvcsError)) throw error;
        }
        if (identity === source.declared) throw new Error(`mutation preserved identity: ${source.path}:${offset}:${bit}`);
        executed += 1;
      }
    }
  }
  const bundle = await bytes(recipe.wholeSequence.source);
  for (const range of [
    ...recipe.bundleItemShapes.map(item => ({ offset: item.byteOffset, length: item.byteLength })),
    { offset: 0, length: bundle.length }
  ]) {
    for (let relative = 0; relative < range.length; relative += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        const changed = bundle.slice(); changed[range.offset + relative] ^= 1 << bit;
        let rejected = false;
        try { verifyLogicalBundle(changed, { registry, operation: 'conformance' }); }
        catch (error) { if (!(error instanceof OgvcsError)) throw error; rejected = true; }
        if (!rejected) throw new Error(`bundle mutation validated: ${range.offset + relative}:${bit}`);
        executed += 1;
      }
    }
  }
  assert.equal(executed, recipe.totalCases);
  return { executed, highestLayer: 1 };
}

async function executeTruncationRecipe(registry) {
  const recipe = await json('mutations/truncation.json');
  let executed = 0;
  for (const source of recipe.sources) {
    const complete = await bytes(source.source);
    const item = complete.subarray(source.byteOffset ?? 0, (source.byteOffset ?? 0) + source.byteLength);
    for (let prefix = source.prefixes.fromInclusive; prefix <= source.prefixes.toInclusive; prefix += 1) {
      assert.throws(() => decodeCanonical(item.subarray(0, prefix)), error => error instanceof OgvcsError &&
        error.code === source.expected.code && error.layer === source.expected.layer &&
        (source.expected.stage === undefined || error.stage === source.expected.stage));
      executed += 1;
    }
  }
  const sequence = await bytes(recipe.wholeSequence.source);
  for (const range of recipe.wholeSequence.ranges) {
    for (let prefix = range.fromInclusive; prefix <= range.toInclusive; prefix += 1) {
      assert.throws(() => verifyLogicalBundle(sequence.subarray(0, prefix), {
        registry, operation: 'conformance'
      }), error =>
        error instanceof OgvcsError && error.code === range.expected.code && error.layer === range.expected.layer &&
        (range.expected.stage === undefined || error.stage === range.expected.stage));
      executed += 1;
    }
  }
  assert.equal(executed, recipe.totalCases);
  return { executed, highestLayer: 1 };
}

async function executeMalformedRecipe() {
  const index = await json('malformed/index.json');
  let executed = 0;
  for (const item of index.explicitCases) {
    const payload = await bytes(item.artifact);
    assert.throws(() => decodeCanonical(payload), error => error instanceof OgvcsError &&
      error.code === item.expected.code && error.layer === item.expected.layer &&
      (item.expected.stage === undefined || error.stage === item.expected.stage));
    executed += 1;
  }
  return { executed, highestLayer: 1 };
}

function registryOperations(value) {
  if (value === 'read-or-production-write') return ['read', 'production-write'];
  return [value];
}

async function executeRegistryRecipe(scenarioId) {
  const index = await json('registries/index.json');
  const recipe = index.cases.find(item => item.scenarioId === scenarioId);
  if (!recipe) throw new Error(`${scenarioId}: missing registry recipe`);
  if (recipe.operation === 'validate-registry-set') {
    const documents = Object.fromEntries(await Promise.all(REGISTRY_FILES.map(async file =>
      [file, await specJson(`registries/${file}`)])));
    const mutation = recipe.mutation;
    const entries = documents[mutation.file]?.entries;
    if (!Array.isArray(entries)) throw new Error(`${scenarioId}: invalid registry mutation file`);
    if (mutation.action === 'append-entry') entries.push(structuredClone(mutation.entry));
    else if (mutation.action === 'append-copy') {
      const source = entries.find(entry => Object.entries(mutation.selector).every(([key, value]) => entry[key] === value));
      if (!source) throw new Error(`${scenarioId}: mutation selector did not match`);
      entries.push(structuredClone(source));
    } else if (mutation.action === 'replace-entry-field') {
      const target = entries.find(entry => Object.entries(mutation.selector).every(([key, value]) => entry[key] === value));
      if (!target) throw new Error(`${scenarioId}: mutation selector did not match`);
      target[mutation.field] = structuredClone(mutation.value);
    } else throw new Error(`${scenarioId}: unknown registry mutation action`);
    validateRegistrySet(documents);
    return { highestLayer: 3 };
  }
  const snapshot = registryFromEvolutionSnapshot(await json(`registries/${recipe.snapshot}-snapshot.json`));
  for (const operation of registryOperations(recipe.operation)) profileDecision(snapshot, recipe.profile, operation);
  return { highestLayer: 3 };
}

function operationFailure(code, layer, stage) {
  throw new OgvcsError(code, { layer, ...(stage === undefined ? {} : { stage }) });
}

function profileMap(text) { return ProfileRef.parse(text).toMap(); }

function pathProfileAdapter(recipe) {
  if (!recipe) return { adapter: undefined, assertComplete() {} };
  const invocations = [...(recipe.invocations ?? [])];
  let index = 0;
  const adapter = Object.freeze({
    profile: recipe.profile,
    caseMode: recipe.caseMode,
    validate(request) {
      const expected = invocations[index++];
      if (!expected) throw new Error('unexpected path-profile invocation');
      assert.equal(request.profile, recipe.profile);
      assert.equal(request.caseMode, recipe.caseMode);
      assert.deepEqual(request.segments, expected.segments);
      return structuredClone(expected.decision);
    }
  });
  return {
    adapter,
    assertComplete() { assert.equal(index, invocations.length, 'missing path-profile invocation'); }
  };
}

function rawPathProfileAdapter(request) {
  return Object.freeze({
    profile: request.adapter.profile,
    ...(Object.hasOwn(request.adapter, 'caseMode') ? { caseMode: request.adapter.caseMode } : {}),
    validate(actual) {
      assert.equal(actual.profile, request.profile);
      assert.equal(actual.caseMode, request.caseMode);
      assert.deepEqual(actual.segments, request.segments);
      return structuredClone(request.adapter.decision);
    }
  });
}

function treeEntry(value) {
  return new Map([
    [0, value.name], [1, value.kind], [2, hexBytes(value.fileId)], [3, value.mode],
    [4, ObjectRef.parse(value.target).toMap()], [5, BigInt(value.logicalSize)],
    [6, profileMap(value.contentPolicy)]
  ]);
}

async function executeManifestWriter(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'write-content-manifest' || request.registry !== 'bundled') {
    throw new Error(`${scenario.scenarioId}: invalid manifest writer recipe`);
  }
  const authority = await lifecycleRegistry(registry, request.registryFixture);
  const chunks = Array.isArray(request.chunkArtifacts)
    ? await Promise.all(request.chunkArtifacts.map(bytes))
    : [await bytes(request.chunkArtifact)];
  if (chunks.length !== 1 && chunks.length !== request.parts.length) {
    throw new Error(`${scenario.scenarioId}: manifest provider occurrence count mismatch`);
  }
  const staged = [];
  await writeContentManifest({
    registry: authority,
    operation: request.operation,
    chunkProfile: ProfileRef.parse(request.chunkProfile),
    logicalLength: BigInt(request.logicalLength),
    partCount: Number(request.declaredParts),
    maxItems: request.maxItems,
    requiredFeatures: request.requiredFeatures ?? [],
    parts: request.parts.map(part => new Map([
      [0, ObjectRef.parse(part.chunk).toMap()], [1, BigInt(part.length)]
    ])),
    wholeFileDigest: new Map([[0, 1], [1, hexBytes(request.wholeFileSha256)]]),
    chunkProvider: async (_reference, { index }) => chunks[chunks.length === 1 ? 0 : index],
    verifyContent: true,
    sink: async value => { staged.push(value.slice()); }
  });
  return { highestLayer: 3 };
}

async function executeTreeWriter(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'write-tree' || request.registry !== 'bundled') {
    throw new Error(`${scenario.scenarioId}: invalid tree writer recipe`);
  }
  const authority = await lifecycleRegistry(registry, request.registryFixture);
  const staged = [];
  const common = {
    registry: authority,
    operation: request.operation,
    descriptor: ObjectRef.parse(request.descriptor),
    entryCount: Number(request.entryCount),
    maxItems: request.maxItems,
    requiredFeatures: request.requiredFeatures ?? [],
    entries: request.entries.map(treeEntry),
    sink: async value => { staged.push(value.slice()); }
  };
  if (request.ordering === 'ordered') await writeOrderedTree(common);
  else if (request.ordering === 'sorted') {
    const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-scenario-tree-'));
    try { await writeSortedTree({ ...common, scratchDirectory }); }
    finally { await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }); }
  } else throw new Error(`${scenario.scenarioId}: invalid tree ordering`);
  return { highestLayer: 3 };
}

async function executeLogicalBundleWriter(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'write-logical-bundle' || request.registry !== 'bundled' ||
      !Array.isArray(request.writerSurfaces) || !Array.isArray(request.objectMutations)) {
    throw new Error(`${scenario.scenarioId}: invalid logical-bundle writer recipe`);
  }
  const authority = await lifecycleRegistry(registry, request.registryFixture);
  const { values } = decodeSequence(await bytes(request.source), { maxValueBytes: 536_871_424 });
  const source = values.filter(item => item.get(1) === 2);
  const objects = await Promise.all([...request.objectMutations]
    .sort((left, right) => left.outputOrdinal - right.outputOrdinal)
    .map(async mutation => {
      let original;
      let payload;
      if (mutation.sourceArtifact !== undefined) {
        payload = await bytes(mutation.sourceArtifact);
        original = new ObjectRef(mutation.kind, new Uint8Array(32), authority.kindNames);
      } else {
        const item = source[mutation.sourceOrdinal];
        if (!(item instanceof Map)) throw new Error(`${scenario.scenarioId}: missing source object`);
        original = ObjectRef.fromMap(item.get(3), authority.kindNames);
        payload = item.get(4).slice();
      }
      const kind = mutation.replaceKind ?? mutation.kind ?? original.kind;
      const digest = mutation.replaceDeclaredDigest === undefined
        ? original.digest : hexBytes(mutation.replaceDeclaredDigest);
      const ref = mutation.allowUnknownKind === true
        ? new ObjectRef(kind, digest, authority.kindNames, { allowUnknownKind: true })
        : new ObjectRef(kind, digest, authority.kindNames);
      return { ref, payload };
    }));
  const logicalRecords = await Promise.all([...(request.logicalRecordInputs ?? [])]
    .sort((left, right) => left.outputOrdinal - right.outputOrdinal)
    .map(async input => decodeCanonical(await bytes(input.sourceArtifact), {
      maxBytes: 67_108_864, maxValueBytes: 67_108_864
    })));
  const roots = [...(request.rootInputs ?? [])].map(input => {
    if (input.kind !== 1) {
      throw new Error(`${scenario.scenarioId}: unsupported logical root carrier`);
    }
    return {
      kind: 1,
      identity: ObjectRef.parse(input.identity, authority.kindNames),
      role: ProfileRef.parse(input.roleProfile)
    };
  });
  const failures = [];
  for (const surface of request.writerSurfaces) {
    try {
      if (surface === 'bundle-memory-encoder') {
        encodeLogicalBundle({ objects, logicalRecords, roots }, {
          registry: authority, operation: request.operation, maxMemoryBytes: request.maxMemoryBytes,
          declaredTraversalEdges: request.plan.budget.traversalEdges,
          declaredIndexEntries: request.plan.budget.indexEntries
        });
      } else if (surface === 'bundle-ordered') {
        const staged = [];
        await writeOrderedLogicalBundle({
          plan: request.plan, objects, logicalRecords, roots,
          sink: async value => { staged.push(value.slice()); }, registry: authority,
          operation: request.operation, maxMemoryBytes: request.maxMemoryBytes
        });
      } else throw new Error(`${scenario.scenarioId}: unknown writer surface ${surface}`);
    } catch (error) {
      if (!(error instanceof OgvcsError)) throw error;
      failures.push(error);
    }
  }
  if (failures.length !== request.writerSurfaces.length ||
      failures.some(error => error.code !== failures[0].code || error.layer !== failures[0].layer ||
        error.stage !== failures[0].stage)) {
    throw new Error(`${scenario.scenarioId}: writer surfaces did not reject identically: ${
      failures.map(error => `${error.code}@${error.layer}/${error.stage}`).join(', ')}`);
  }
  throw failures[0];
}

async function executePathProfileDecision(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'validate-path-profile-decision') {
    throw new Error(`${scenario.scenarioId}: invalid path-profile recipe`);
  }
  const lookup = await lookupFor(scenario, registry);
  const tree = scenario.context.objectLookup.map(item => item.ref)
    .find(reference => ObjectRef.parse(reference).kind === 3);
  if (!tree) throw new Error(`${scenario.scenarioId}: missing tree carrier`);
  expandTree(tree, lookup, scenario.context.repositoryDescriptor, {
    caseMode: request.caseMode,
    validatePathProfile: rawPathProfileAdapter(request),
    verifyContent: false
  });
  return { highestLayer: 3 };
}

async function scenarioLookupEntries(scenario) {
  return Promise.all(scenario.context.objectLookup.map(async item =>
    [item.ref, await bytes(item.artifact.path)]));
}

function referenceOfKind(scenario, kind) {
  return scenario.context.objectLookup.map(item => item.ref)
    .find(reference => ObjectRef.parse(reference).kind === kind);
}

async function boundedLookup(scenario, registry, maxMemoryBytes, entries) {
  return new RepositoryObjectLookup(entries ?? await scenarioLookupEntries(scenario), {
    registry,
    mode: scenario.context.mode,
    semanticProfiles: true,
    maxMemoryBytes
  });
}

async function minimumSuccessfulCeiling(callback) {
  let low = 0;
  let high = 67_108_864;
  const succeeds = async ceiling => {
    try { await callback(ceiling); return true; }
    catch (error) {
      if (error instanceof OgvcsError && error.code === 'LIMIT_MEMORY') return false;
      throw error;
    }
  };
  if (!await succeeds(high)) throw new Error('resource fixture does not succeed at the hard ordinary ceiling');
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (await succeeds(middle)) high = middle;
    else low = middle + 1;
  }
  return low;
}

async function observeResourceRoute({
  route, recoveryKind, failRoute, recoverRoute, unchanged,
  allowedCodes = ['LIMIT_MEMORY', 'LIMIT_TIME'], extraEvidence = {}
}) {
  let failure;
  try { await failRoute(); }
  catch (error) { failure = error; }
  if (!(failure instanceof OgvcsError) || !allowedCodes.includes(failure.code)) {
    throw failure ?? new Error(`${route}: reduced resource route unexpectedly accepted`);
  }
  await unchanged();
  await recoverRoute();
  await unchanged();
  return Object.freeze({
    failure,
    evidence: Object.freeze({
      ...extraEvidence,
      noPartialState: true,
      recoveryKind,
      route,
      succeeded: true
    })
  });
}

function throwResourceEvidence(request, observations, extraEvidence = {}) {
  assert.deepEqual(observations.map(item => item.evidence.route), request.routes,
    'resource proof did not execute every declared route in order');
  const [first] = observations;
  assert.ok(first, 'resource proof did not execute a route');
  for (const observation of observations) {
    assert.equal(observation.failure.code, first.failure.code);
    assert.equal(observation.failure.layer, first.failure.layer);
    assert.equal(observation.failure.stage, first.failure.stage);
  }
  const evidence = Object.freeze({
    ...extraEvidence,
    noPartialState: true,
    routeEvidence: Object.freeze(observations.map(item => item.evidence))
  });
  assert.deepEqual(evidence, request.evidenceRequired,
    'observed resource evidence does not match the authenticated recipe');
  first.failure.resourceEvidence = evidence;
  throw first.failure;
}

async function executeResourceReservation(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'validate-resource-reservation' ||
      request.evidenceRequired?.noPartialState !== true ||
      !Array.isArray(request.evidenceRequired?.routeEvidence) ||
      !Array.isArray(request.routes) ||
      (request.memoryCeiling?.derivation !== 'one-byte-below-conservative-retained-cost-v1' &&
       request.memoryCeiling?.derivation !==
         'one-byte-below-reader-current-entry-and-fileid-index-composite-v1' &&
       request.timeCeiling?.derivation !== 'one-checkpoint-before-final-bounded-mapping-v1' &&
       !(request.configuredLimit?.field === 'maxEdges' ||
         request.configuredLimit?.field === 'maxScratchBytes'))) {
    throw new Error(`${scenario.scenarioId}: invalid resource reservation recipe`);
  }
  if (request.cluster === 'tree-stream-transaction-composite-memory') {
    const authority = await lifecycleRegistry(registry, request.registryFixture);
    const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-tree-index-resource-'));
    const runNames = async () => (await readdir(scratchDirectory))
      .filter(name => name.endsWith('.run')).sort();
    const newIndex = () => createDiskFileIdIndex({
      scratchDirectory, maxMemoryBytes: 1_048_576, maxRunBytes: 262_144,
      maxOpenRuns: 4, maxScratchBytes: 1_048_576
    });
    const verify = (source, ceiling, index) => verifyTreeFile(resolve(VECTORS, source), {
      descriptor: ObjectRef.parse(referenceOfKind(scenario, 6)),
      fileIdIndex: index,
      // A one-byte reader buffer makes the derived minimum expose the exact
      // remaining FileID-index admission instead of varying with file size.
      readChunkBytes: 1,
      maxMemoryBytes: ceiling,
      operation: request.operation,
      registry: authority
    });
    try {
      const minimum = await minimumSuccessfulCeiling(async ceiling => {
        const probe = await newIndex();
        try { return await verify(request.recovery.source, ceiling, probe); }
        finally { await probe.abort().catch(() => {}); }
      });
      const index = await newIndex();
      const before = await runNames();
      let failure;
      try { await verify(request.failure.source, minimum, index); }
      catch (error) { failure = error; }
      if (!(failure instanceof OgvcsError) || failure.code !== 'LIMIT_MEMORY') {
        throw failure ?? new Error(`${scenario.scenarioId}: composite attempt unexpectedly accepted`);
      }
      assert.deepEqual(await runNames(), before,
        `${scenario.scenarioId}: failed index attempt published scratch state`);
      const recovered = await verify(request.recovery.source, minimum, index);
      assert.equal(recovered.summary.entryCount, 1,
        `${scenario.scenarioId}: fitting recovery did not validate one entry`);
      assert.deepEqual(await runNames(), before,
        `${scenario.scenarioId}: recovered index retained scratch state`);
      const evidence = Object.freeze({
        noPartialState: true,
        routeEvidence: Object.freeze([Object.freeze({
          compositeMemoryBounded: true,
          indexInstanceReused: true,
          noPartialState: true,
          recoveryKind: 'same-authority-instance',
          route: 'verify-tree-file-stream',
          scratchIndexReusableAfterAbort: true,
          succeeded: true,
          targetUnchanged: true
        })])
      });
      assert.deepEqual(evidence, request.evidenceRequired);
      failure.resourceEvidence = evidence;
      throw failure;
    } finally {
      await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    }
  }
  const entries = await scenarioLookupEntries(scenario);
  if (request.cluster === 'replay-base') {
    const changeSet = request.changeSet;
    const baseLookup = await boundedLookup(scenario, registry, 67_108_864, entries);
    const expanded = expandTree(request.baseState.tree, baseLookup, referenceOfKind(scenario, 6), {
      caseMode: scenario.context.caseMode, verifyContent: false
    });
    const base = { entries: expanded.entries, groups: new Map() };
    const before = encodeCanonical([...base.entries.values()]);
    const invoke = lookup => replayChangeSet(changeSet, base, {
      lookup,
      descriptor: referenceOfKind(scenario, 6), caseMode: scenario.context.caseMode,
      lifetimeRecords: [], importMappings: [], workingLifetimeAdditions: []
    });
    const minimum = await minimumSuccessfulCeiling(async ceiling =>
      invoke(await boundedLookup(scenario, registry, ceiling, entries)));
    const lookup = await boundedLookup(scenario, registry, minimum, entries);
    lookup.reserveDerived(1);
    const observation = await observeResourceRoute({
      route: 'replay-change-set', recoveryKind: 'same-authority-instance',
      failRoute: () => invoke(lookup),
      recoverRoute: () => { lookup.releaseDerived(1); return invoke(lookup); },
      unchanged: () => {
      assert.ok(base.entries.size > 0);
      assert.equal(base.groups.size, 0);
      assert.deepEqual(encodeCanonical([...base.entries.values()]), before);
      }
    });
    throwResourceEvidence(request, [observation]);
  } else if (request.cluster === 'fileid-lifetime-import-indexes') {
    const contextFor = lookup => ({
      lookup,
      descriptor: referenceOfKind(scenario, 6),
      caseMode: scenario.context.caseMode,
      lifetimeRecords: [], importMappings: [], allocations: [], restorations: [],
      workingLifetimeAdditions: [], entries: new Map()
    });
    const minimum = await minimumSuccessfulCeiling(async ceiling => validateLifetimeAndImports(
      contextFor(new RepositoryObjectLookup([], {
        registry, mode: scenario.context.mode, semanticProfiles: true, maxMemoryBytes: ceiling
      }))));
    const lookup = new RepositoryObjectLookup([], {
      registry, mode: scenario.context.mode, semanticProfiles: true, maxMemoryBytes: minimum
    });
    lookup.reserveDerived(1);
    const observation = await observeResourceRoute({
      route: 'validate-lifetime-and-imports', recoveryKind: 'same-authority-instance',
      failRoute: () => validateLifetimeAndImports(contextFor(lookup)),
      recoverRoute: () => { lookup.releaseDerived(1); return validateLifetimeAndImports(contextFor(lookup)); },
      unchanged: () => undefined
    });
    throwResourceEvidence(request, [observation]);
  } else if (request.cluster === 'fileid-import-many-mappings-deadline') {
    const changeSet = referenceOfKind(scenario, 4);
    const descriptor = referenceOfKind(scenario, 6);
    const working = Array.from({ length: 64 }, (_, index) => ({
      descriptor,
      fileId: (index + 1).toString(16).padStart(32, '0'),
      origin: 'native-create',
      firstChangeSet: changeSet,
      firstOperation: 0
    }));
    const importRequest = {
      schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
      operation: 'import-file-id', importerProfile: 'importer.test/fixture-adapter@1',
      sourceNamespaceDigest: '71'.repeat(32), sourceIdentityDigest: '72'.repeat(32),
      requestedFileId: 'ff'.repeat(16)
    };
    const invoke = async now => validateImportRequest(importRequest, {
      lookup: new RepositoryObjectLookup(entries, {
        registry, mode: scenario.context.mode, semanticProfiles: true,
        maxTimeMs: 1, now
      }),
      descriptor, caseMode: scenario.context.caseMode, lifetimeRecords: [],
      importMappings: [], workingLifetimeAdditions: working
    });
    let checkpoints = 0;
    await invoke(() => { checkpoints += 1; return 0; });
    assert.ok(checkpoints > 2, 'deadline fixture did not exercise bounded checkpoints');
    let calls = 0;
    const before = JSON.stringify({ importRequest, working });
    const observation = await observeResourceRoute({
      route: 'validate-import-request', recoveryKind: 'fresh-operation-after-deadline',
      failRoute: () => invoke(() => (++calls >= checkpoints - 1 ? 2 : 0)),
      recoverRoute: () => invoke(() => 0),
      unchanged: () => assert.equal(JSON.stringify({ importRequest, working }), before)
    });
    throwResourceEvidence(request, [observation]);
  } else if (request.cluster === 'graph-workspace-indexes') {
    const snapshot = referenceOfKind(scenario, 7);
    const runGraph = lookup => validateSnapshotGraph(snapshot, {
        lookup,
        descriptor: referenceOfKind(scenario, 6),
        designatedRoot: snapshot,
        caseMode: scenario.context.caseMode
      });
    const minimum = await minimumSuccessfulCeiling(async ceiling =>
      runGraph(await boundedLookup(scenario, registry, ceiling, entries)));
    const lookup = await boundedLookup(scenario, registry, minimum, entries);
    lookup.reserveDerived(1);
    const observation = await observeResourceRoute({
      route: 'validate-snapshot-graph', recoveryKind: 'same-authority-instance',
      failRoute: () => runGraph(lookup),
      recoverRoute: () => { lookup.releaseDerived(1); return runGraph(lookup); },
      unchanged: () => undefined
    });
    throwResourceEvidence(request, [observation]);
  } else if (request.cluster === 'conflict-group-indexes') {
    const conflictFixture = request.conflictFixture ?? Object.freeze({
      scenario: 'conflict-choice-base',
      reference: 'ogvcs:v1:conflict-set:sha256:562aa353fa3bfcf681e7e4a218f66c9f3c1157c490508cb81f4320f271be25cf'
    });
    const conflictScenario = await json(`scenarios/cases/${conflictFixture.scenario}.json`);
    const conflictEntries = await scenarioLookupEntries(conflictScenario);
    const conflict = conflictFixture.reference;
    const descriptor = conflictScenario.context.repositoryDescriptor;
    const runConflict = lookup => validateConflictSet(conflict, lookup, descriptor);
    const conflictMinimum = await minimumSuccessfulCeiling(async ceiling =>
      runConflict(await boundedLookup(conflictScenario, registry, ceiling, conflictEntries)));
    const conflictLookup = await boundedLookup(
      conflictScenario, registry, conflictMinimum, conflictEntries);
    conflictLookup.reserveDerived(1);
    const conflictObservation = await observeResourceRoute({
      route: 'validate-conflict-set', recoveryKind: 'same-authority-instance',
      failRoute: () => runConflict(conflictLookup),
      recoverRoute: () => { conflictLookup.releaseDerived(1); return runConflict(conflictLookup); },
      unchanged: () => undefined
    });
    const set = decodeMetadata(await bytes('objects/05-asset-group-set.cbor'), { semantic: false }).value;
    const groups = new Map(set.get(17).map(group => [Buffer.from(group.get(0)).toString('hex'), group]));
    const fileIds = new Set(set.get(17).flatMap(group => group.get(3)
      .map(member => `fid:${Buffer.from(member.get(0)).toString('hex')}`)));
    const invoke = maxMemoryBytes => validateAssetGroups(groups, fileIds, {
      registry, mode: scenario.context.mode, maxMemoryBytes
    });
    const groupMinimum = await minimumSuccessfulCeiling(invoke);
    const groupObservation = await observeResourceRoute({
      route: 'validate-asset-groups', recoveryKind: 'stateless-reinvoke',
      failRoute: () => invoke(groupMinimum - 1),
      recoverRoute: () => invoke(groupMinimum),
      unchanged: () => assert.equal(groups.size, set.get(17).length)
    });
    throwResourceEvidence(request, [conflictObservation, groupObservation]);
  } else if (request.cluster === 'many-invalid-error-selection') {
    const malformed = new Map([[0, 1], [1, 3], [2, []], [16, ObjectRef.parse(
      referenceOfKind(scenario, 6)).toMap()], [17, []]]);
    for (let field = 100; field < 164; field += 1) malformed.set(field, field);
    const malformedBefore = encodeCanonical(malformed);
    const validTree = decodeMetadata(await bytes('objects/03-tree.cbor'), { semantic: false }).value;
    let retained = 0;
    for (const [reference, payload] of entries) {
      retained += payload.length * (ObjectRef.parse(reference).kind === 1 ? 4 : 16) + 512;
    }
    const invoke = async ceiling => (await boundedLookup(scenario, registry, ceiling, entries)).validateAll();
    const lookupMinimum = await minimumSuccessfulCeiling(invoke);
    const lookupObservation = await observeResourceRoute({
      route: 'repository-object-lookup-validate-all', recoveryKind: 'stateless-reinvoke',
      failRoute: () => invoke(Math.min(retained, lookupMinimum - 1)),
      recoverRoute: () => invoke(lookupMinimum),
      unchanged: () => undefined
    });
    const schemaMinimum = await minimumSuccessfulCeiling(async ceiling =>
      validateKnownSchema(validTree, 3, { semantic: false, maxWorkingBytes: ceiling }));
    const schemaObservation = await observeResourceRoute({
      route: 'validate-known-schema', recoveryKind: 'stateless-reinvoke',
      failRoute: () => validateKnownSchema(malformed, 3, {
        semantic: false, maxWorkingBytes: schemaMinimum - 1
      }),
      recoverRoute: () => {
        let recovered;
        try {
          validateKnownSchema(malformed, 3, { semantic: false, maxWorkingBytes: schemaMinimum });
        } catch (error) {
          recovered = error;
        }
        assert.ok(recovered instanceof OgvcsError);
        assert.equal(recovered.code, 'SCHEMA_FIELD_UNKNOWN');
        assert.equal(recovered.layer, 2);
        assert.equal(recovered.stage, 'known-schema');
        // A valid value at the same bound proves the configured workspace was
        // released rather than merely replacing one terminal failure.
        validateKnownSchema(validTree, 3, { semantic: false, maxWorkingBytes: schemaMinimum });
      },
      unchanged: () => assert.deepEqual(encodeCanonical(malformed), malformedBefore)
    });
    throwResourceEvidence(request, [lookupObservation, schemaObservation]);
  } else if (request.cluster === 'lookup-edge-counter-rollback' ||
      request.cluster === 'lookup-scratch-counter-rollback') {
    if (request.assertCounterBaselineAfterFailure !== true ||
        request.assertCounterBaselineAfterRecovery !== true ||
        request.configuredLimit?.value !== (request.cluster === 'lookup-edge-counter-rollback' ? 1 : 64)) {
      throw new Error(`${scenario.scenarioId}: invalid counter rollback recipe`);
    }
    const field = request.configuredLimit.field;
    const expectedField = request.cluster === 'lookup-edge-counter-rollback'
      ? 'maxEdges' : 'maxScratchBytes';
    if (field !== expectedField) throw new Error(`${scenario.scenarioId}: invalid configured counter`);
    const lookup = new RepositoryObjectLookup(entries, {
      registry, mode: scenario.context.mode, semanticProfiles: true,
      [field]: request.configuredLimit.value
    });
    const baseline = lookup.guardSummary;
    const descriptor = referenceOfKind(scenario, 6);
    const route = request.routes[0];
    const recovery = request.recovery;
    const observation = await observeResourceRoute({
      route,
      recoveryKind: 'same-authority-instance',
      allowedCodes: [request.cluster === 'lookup-edge-counter-rollback'
        ? 'LIMIT_COUNT' : 'LIMIT_SCRATCH'],
      extraEvidence: { counterBaselineRestored: true },
      failRoute: () => expandTree(request.failureTree, lookup, descriptor, {
          caseMode: scenario.context.caseMode, verifyContent: false
        }),
      recoverRoute: () => {
        if (recovery?.api === 'verify-manifest') return verifyManifest(recovery.reference, lookup);
        if (recovery?.api === 'expand-tree') {
          return expandTree(recovery.recoveryTree, lookup,
            descriptor, {
              caseMode: scenario.context.caseMode, verifyContent: false
            });
        }
        throw new Error(`${scenario.scenarioId}: invalid counter recovery route`);
      },
      unchanged: () => assert.deepEqual(lookup.guardSummary, baseline,
        'operation counter baseline was not restored')
    });
    throwResourceEvidence(request, [observation]);
  } else throw new Error(`${scenario.scenarioId}: unsupported resource cluster ${request.cluster}`);
  throw new Error(`${scenario.scenarioId}: resource proof returned without its expected failure`);
}

async function executeTreeGroupsMemory(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'validate-tree-groups-memory' ||
      request.memoryCeiling?.derivation !==
        'one-byte-below-simultaneous-retained-tree-group-membership-and-collision-index' ||
      !Array.isArray(request.routes) || request.evidenceRequired?.eachComponentAloneFit !== true) {
    throw new Error(`${scenario.scenarioId}: invalid tree/groups memory recipe`);
  }
  const entries = await scenarioLookupEntries(scenario);
  const runCompositeWithLookup = lookup => validateRepositoryCandidate(
    scenario.context.candidateSnapshot, repositoryContext(scenario, lookup));
  const runComposite = async ceiling => runCompositeWithLookup(
    await boundedLookup(scenario, registry, ceiling, entries));
  const runTree = async ceiling => {
    const lookup = await boundedLookup(scenario, registry, ceiling, entries);
    const snapshot = lookup.resolve(scenario.context.candidateSnapshot, 7).value;
    return expandTree(snapshot.get(18), lookup, scenario.context.repositoryDescriptor, {
      caseMode: scenario.context.caseMode, verifyContent: false
    });
  };
  const runGroups = async ceiling => {
    const lookup = await boundedLookup(scenario, registry, ceiling, entries);
    const snapshot = lookup.resolve(scenario.context.candidateSnapshot, 7).value;
    const set = lookup.resolve(ObjectRef.fromMap(snapshot.get(20)), 5).value;
    const groups = new Map(set.get(17).map(group => [Buffer.from(group.get(0)).toString('hex'), group]));
    const fileIds = new Set(set.get(17).flatMap(group => group.get(3)
      .map(member => `fid:${Buffer.from(member.get(0)).toString('hex')}`)));
    return validateAssetGroups(groups, fileIds, { lookup });
  };
  const minimum = await minimumSuccessfulCeiling(runComposite);
  const reduced = minimum - 1;
  const before = entries.map(([reference, payload]) => [reference, Buffer.from(payload).toString('hex')]);
  await runTree(reduced);
  await runGroups(reduced);
  const lookup = await boundedLookup(scenario, registry, minimum, entries);
  lookup.reserveDerived(1);
  const observation = await observeResourceRoute({
    route: 'validate-tree-groups-memory', recoveryKind: 'same-authority-instance',
    failRoute: () => runCompositeWithLookup(lookup),
    recoverRoute: () => { lookup.releaseDerived(1); return runCompositeWithLookup(lookup); },
    unchanged: () => assert.deepEqual(entries.map(([reference, payload]) =>
      [reference, Buffer.from(payload).toString('hex')]), before)
  });
  throwResourceEvidence(request, [observation], { eachComponentAloneFit: true });
}

async function executeTypedReferenceAuthority(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.case === 'arbitrary-kind-map-relabel') {
    ObjectRef.parse(request.text, new Map(request.kindMap));
  } else if (request.case === 'duplicate-kind-token') {
    const documents = structuredClone(Object.fromEntries(registry.documents));
    const mutation = request.registryMutation;
    const target = documents[mutation.file]?.entries?.find(entry =>
      Object.entries(mutation.selector).every(([key, value]) => entry[key] === value));
    if (!target || mutation.action !== 'replace-entry-field') {
      throw new Error(`${scenario.scenarioId}: invalid typed-reference registry mutation`);
    }
    target[mutation.field] = structuredClone(mutation.value);
    validateRegistrySet(documents);
  } else if (request.case === 'durable-text-overlength-colon-dense') {
    if (request.maximumBytes !== 144 || Buffer.byteLength(request.text, 'utf8') <= request.maximumBytes) {
      throw new Error(`${scenario.scenarioId}: invalid durable-reference bound recipe`);
    }
    ObjectRef.parse(request.text);
  } else throw new Error(`${scenario.scenarioId}: invalid typed-reference authority case`);
  return { highestLayer: 3 };
}

async function lifecycleRegistry(base, fixture) {
  if (!fixture) return base;
  const index = await json(fixture.path);
  const recipe = index.cases.find(item => item.scenarioId === fixture.scenarioId);
  if (!recipe?.snapshot) throw new Error(`${fixture.scenarioId}: missing registry lifecycle snapshot`);
  const evolution = await json(`registries/${recipe.snapshot}-snapshot.json`);
  const documents = structuredClone(Object.fromEntries(base.documents));
  documents['profiles.json'].entries.push(...(evolution.profiles?.entries ?? []).map(entry => ({
    ...entry, owner: entry.owner ?? 'OGVCS-002'
  })));
  const tuple = entry => `${entry.namespace}\0${entry.id}\0${String(entry.major).padStart(10, '0')}`;
  documents['profiles.json'].entries.sort((left, right) => tuple(left) < tuple(right) ? -1 : tuple(left) > tuple(right) ? 1 : 0);
  documents['extensions.json'].entries.push(...(evolution.extensions?.entries ?? []));
  documents['extensions.json'].entries.sort((left, right) => tuple(left) < tuple(right) ? -1 : tuple(left) > tuple(right) ? 1 : 0);
  const features = evolution.requiredFeatures?.entries ?? [];
  if (features.length > 0) {
    documents['required-features.json'].entries.push(...features);
    documents['required-features.json'].entries.sort((left, right) => left.code - right.code);
    const highest = Math.max(...features.map(entry => entry.code));
    documents['required-features.json'].unassigned = highest < 0xffff_ffff
      ? [{ from: highest + 1, to: 0xffff_ffff }]
      : [];
  }
  return validateRegistrySet(documents);
}

async function operationRegistry(request, base) {
  if (request.registry === undefined || request.registry === 'absent') return undefined;
  if (request.registry === 'partial' || request.registry === 'forged') {
    // Public construction deliberately produces an unbranded tooling view;
    // every semantic surface must reject it before touching its source.
    return new RegistrySnapshot({
      objectKinds: [...base.objectKinds.values()],
      logicalRecordTypes: [...base.logicalRecordTypes.values()],
      profiles: [...base.profiles.values()]
    });
  }
  if (request.registry !== 'bundled') throw new Error(`unknown registry selector: ${request.registry}`);
  return lifecycleRegistry(base, request.registryFixture);
}

function groupFixture(input) {
  const fileId = hexBytes(input.fileIds[0]);
  const group = new Map([
    [0, hexBytes(input.groupId)],
    [1, profileMap(input.groupProfile)],
    [2, fileId],
    [3, [new Map([[0, fileId], [1, profileMap(input.roleProfile)]])]],
    [4, [new Map([[0, profileMap(input.externalKeyProfile)], [1, hexBytes(input.externalKeyValueHex)]])]]
  ]);
  return { fileIds: new Set(input.fileIds.map(value => `fid:${value}`)), groups: new Map([[input.groupId, group]]) };
}

function codecOptions(request, authority) {
  return {
    ...(request.registry === 'absent' ? {} : { registry: authority }),
    ...(Object.hasOwn(request, 'operation') ? { operation: request.operation } : {}),
    ...(Object.hasOwn(request, 'semanticProfiles') ? { semantic: request.semanticProfiles } : {}),
    ...(request.semanticCallback ? { semanticValidator: () => undefined } : {})
  };
}

async function executeCodecSurface(request, authority, frozenRegistry) {
  const options = codecOptions(request, authority);
  const source = request.source;
  const layerTwo = request.registry === 'absent' && request.semanticProfiles === false &&
    !Object.hasOwn(request, 'operation');
  const semantic = request.registry === 'bundled' && request.semanticProfiles !== false &&
    ['read', 'conformance', 'production-write'].includes(request.operation);
  const configurationInvalid = !layerTwo && !semantic;
  if (request.surface === 'metadata-decoder') {
    const result = decodeMetadata(configurationInvalid ? new Uint8Array() : await bytes(source), options);
    return { highestLayer: result.highestLayer };
  }
  if (request.surface === 'tree-schema-decoder') {
    const value = configurationInvalid ? undefined : decodeCanonical(await bytes(source));
    validateKnownSchema(value, 3, options);
    return { highestLayer: 2 };
  }
  if (request.surface === 'tree-file') {
    const validSource = configurationInvalid ? undefined : decodeCanonical(await bytes(source));
    const result = await verifyTreeFile(resolve(VECTORS, source ?? 'malformed/nonminimal-unsigned.cbor'), {
      ...options,
      ...(request.repositoryDescriptor !== undefined
        ? { descriptor: ObjectRef.parse(request.repositoryDescriptor, authority?.kindNames) }
        : validSource instanceof Map ? { descriptor: validSource.get(16) } : {})
    });
    return { highestLayer: result.highestLayer ?? 3 };
  }
  const payload = configurationInvalid ? new Uint8Array() : await bytes(source);
  if (request.surface === 'bundle-memory-verifier') {
    const result = verifyLogicalBundle(payload, options);
    return { highestLayer: result.highestLayer };
  }
  if (request.surface === 'bundle-stream-verifier') {
    const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-operation-bundle-'));
    try {
      const result = await verifyLogicalBundleStream(payload, { ...options, scratchDirectory });
      return { highestLayer: result.highestLayer };
    } finally {
      await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    }
  }
  throw new Error(`unsupported codec surface: ${request.surface}`);
}

function bundleCarrier(payload) {
  const { values } = decodeSequence(payload);
  const header = values[0];
  if (!(header instanceof Map) || header.get(1) !== 1) throw new Error('invalid bundle carrier');
  const objects = [];
  const logicalRecords = [];
  const roots = [];
  for (const item of values.slice(1, -1)) {
    if (!(item instanceof Map)) throw new Error('invalid bundle carrier item');
    if (item.get(1) === 2) objects.push({ ref: ObjectRef.fromMap(item.get(3)), payload: item.get(4) });
    else if (item.get(1) === 3) logicalRecords.push(item.get(4));
    else if (item.get(1) === 4) roots.push({
      kind: item.get(3), identity: item.get(4), role: item.get(5)
    });
    else throw new Error('invalid bundle carrier item type');
  }
  return {
    objects,
    logicalRecords,
    roots,
    plan: {
      objectCount: header.get(3),
      logicalRecordCount: header.get(4),
      rootCount: header.get(5),
      budget: {
        sequenceBytes: header.get(6).get(0),
        largestItemBytes: header.get(6).get(1),
        traversalEdges: header.get(6).get(2),
        indexEntries: header.get(6).get(3)
      }
    }
  };
}

async function executeEmitterSurface(request, authority, frozenRegistry) {
  const options = {
    ...(request.registry === 'absent' ? {} : { registry: authority }),
    ...(Object.hasOwn(request, 'operation') ? { operation: request.operation } : {})
  };
  const configurationInvalid = request.registry !== 'bundled' ||
    !['conformance', 'production-write'].includes(request.operation);
  if (request.surface === 'metadata-encoder') {
    encodeMetadata(configurationInvalid ? undefined : decodeCanonical(await bytes(request.source)), options);
  } else if (request.surface === 'tree-ordered' || request.surface === 'tree-sorted') {
    const tree = configurationInvalid ? undefined : decodeCanonical(await bytes(request.source));
    const writer = request.surface === 'tree-ordered' ? writeOrderedTree : writeSortedTree;
    const scratchDirectory = request.surface === 'tree-sorted'
      ? await mkdtemp(join(tmpdir(), 'ogvcs-operation-tree-')) : undefined;
    try {
      await writer({
        ...options,
        ...(tree instanceof Map ? {
          descriptor: ObjectRef.fromMap(tree.get(16), authority?.kindNames),
          requiredFeatures: tree.get(2),
          ...(tree.has(3) ? { extensions: tree.get(3) } : {}),
          entries: tree.get(17),
          entryCount: tree.get(17).length
        } : {}),
        ...(scratchDirectory ? { scratchDirectory } : {}),
        sink: async () => undefined
      });
    } finally {
      if (scratchDirectory) {
        await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
      }
    }
  } else if (request.surface === 'content-manifest') {
    const manifest = configurationInvalid ? undefined : decodeCanonical(await bytes(request.source));
    await writeContentManifest({
      ...options,
      ...(manifest instanceof Map ? {
        requiredFeatures: manifest.get(2),
        ...(manifest.has(3) ? { extensions: manifest.get(3) } : {}),
        chunkProfile: ProfileRef.fromMap(manifest.get(18)),
        logicalLength: manifest.get(16),
        partCount: manifest.get(19).length,
        parts: manifest.get(19),
        wholeFileDigest: manifest.get(17)
      } : {}),
      sink: async () => undefined
    });
  } else if (request.surface === 'bundle-memory-encoder' || request.surface === 'bundle-ordered') {
    const carrier = configurationInvalid ? {} : bundleCarrier(await bytes(request.source));
    if (request.surface === 'bundle-memory-encoder') {
      encodeLogicalBundle(carrier, options);
      return { highestLayer: 3 };
    }
    await writeOrderedLogicalBundle({
      ...options,
      ...carrier,
      sink: async () => undefined
    });
  } else throw new Error(`unsupported emitter surface: ${request.surface}`);
  return { highestLayer: 3 };
}

async function executeRepositoryModeSurface(request, scenario, authority, frozenRegistry) {
  if (request.surface === 'logical-record-map-raw') {
    const value = decodeCanonical(await bytes(request.source));
    validateLogicalRecord(value, { semantic: false });
    return { highestLayer: 2 };
  }
  if (request.surface === 'repository-lookup-layer2') {
    new RepositoryObjectLookup([], {
      ...(request.limits ?? {}),
      ...(Object.hasOwn(request, 'mode') ? { mode: request.mode } : {}),
      ...(request.registry === 'absent' ? {} : { registry: authority }),
      semanticProfiles: request.semanticProfiles
    });
    return { highestLayer: 2 };
  }
  const configurationInvalid = request.registry !== 'bundled' ||
    !['conformance', 'production'].includes(request.mode) || request.semanticProfiles !== true;
  const entries = configurationInvalid ? {
    [Symbol.iterator]() { throw new Error('repository payload traversed before authority preflight'); }
  } : request.surface === 'repository-lookup-validate-all'
    ? await Promise.all(request.lookupOrder.map(async (reference, index) =>
      [reference, await bytes(request.sources[index])]))
    : await scenarioLookupEntries(scenario);
  const lookup = new RepositoryObjectLookup(entries, {
    ...(Object.hasOwn(request, 'mode') ? { mode: request.mode } : {}),
    ...(request.registry === 'absent' ? {} : { registry: authority }),
    ...(Object.hasOwn(request, 'semanticProfiles') ? { semanticProfiles: request.semanticProfiles } : {})
  });
  const context = {
    descriptor: request.repositoryDescriptor,
    designatedRoot: request.designatedRoot,
    importMappings: request.lifetimeContext?.importMappings ?? request.importContext?.importMappings ?? [],
    lifetimeRecords: request.lifetimeContext?.lifetimeRecords ?? request.importContext?.lifetimeRecords ?? [],
    lookup,
    caseMode: request.caseMode ?? scenario.context.caseMode,
    verifyContent: true,
    workingLifetimeAdditions: request.lifetimeContext?.workingLifetimeAdditions ??
      request.importContext?.workingLifetimeAdditions ?? []
  };
  if (request.surface === 'tree-expand') {
    expandTree(request.tree, lookup, request.repositoryDescriptor, {
      caseMode: request.caseMode,
      verifyContent: false
    });
    return { highestLayer: 3 };
  }
  if (request.surface === 'repository-candidate') {
    return validateRepositoryCandidate(request.candidateSnapshot, context);
  }
  if (request.surface === 'repository-lookup-validate-all') {
    return { highestLayer: lookup.validateAll().highestLayer };
  }
  if (request.surface === 'manifest-verify') {
    verifyManifest(request.manifest, lookup);
    return { highestLayer: 3 };
  }
  if (request.surface === 'import-request') {
    validateImportRequest({
      schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
      operation: 'import-file-id',
      ...request.importRequest
    }, context);
    return { highestLayer: 3 };
  }
  if (request.surface === 'import-request-raw' && Array.isArray(request.rawImportRequestOrders)) {
    let observed;
    for (const order of request.rawImportRequestOrders) {
      let outcome;
      try {
        validateImportRequest(Object.fromEntries(order), context);
        outcome = { accepted: true };
      } catch (error) {
        if (!(error instanceof OgvcsError)) throw error;
        outcome = { accepted: false, code: error.code, layer: error.layer, stage: error.stage };
      }
      if (observed === undefined) observed = outcome;
      else assert.deepEqual(outcome, observed,
        `${scenario.scenarioId}: raw import key order changed validation outcome`);
    }
    if (observed?.accepted === false) operationFailure(observed.code, observed.layer, observed.stage);
    return { highestLayer: 3 };
  }
  if (request.surface === 'import-request-context-raw' &&
      Array.isArray(request.rawLifetimeContextOrders)) {
    let observed;
    for (const rawContext of request.rawLifetimeContextOrders) {
      let outcome;
      try {
        validateImportRequest({
          schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
          operation: 'import-file-id',
          ...request.importRequest
        }, { ...context, ...rawContext });
        outcome = { accepted: true };
      } catch (error) {
        if (!(error instanceof OgvcsError)) throw error;
        outcome = { accepted: false, code: error.code, layer: error.layer, stage: error.stage };
      }
      if (observed === undefined) observed = outcome;
      else assert.deepEqual(outcome, observed,
        `${scenario.scenarioId}: raw import context order changed validation outcome`);
    }
    if (observed?.accepted === false) operationFailure(observed.code, observed.layer, observed.stage);
    return { highestLayer: 3 };
  }
  if (request.surface === 'lifetime-and-imports-raw' &&
      Array.isArray(request.rawLifetimeContextOrders)) {
    let observed;
    for (const rawContext of request.rawLifetimeContextOrders) {
      let outcome;
      try {
        validateLifetimeAndImports({ ...context, ...rawContext });
        outcome = { accepted: true };
      } catch (error) {
        if (!(error instanceof OgvcsError)) throw error;
        outcome = { accepted: false, code: error.code, layer: error.layer, stage: error.stage };
      }
      if (observed === undefined) observed = outcome;
      else assert.deepEqual(outcome, observed,
        `${scenario.scenarioId}: raw lifetime row order changed validation outcome`);
    }
    if (observed?.accepted === false) operationFailure(observed.code, observed.layer, observed.stage);
    return { highestLayer: 3 };
  }
  if (request.surface === 'asset-groups' && (request.groupInput || request.groupInputs)) {
    const fixtures = (request.groupInputs ?? [request.groupInput]).map(groupFixture);
    const groups = new Map();
    const fileIds = new Set();
    for (const fixture of fixtures) {
      for (const [key, value] of fixture.groups) groups.set(key, value);
      for (const value of fixture.fileIds) fileIds.add(value);
    }
    validateAssetGroups(groups, fileIds, {
      mode: request.mode, registry: authority
    });
    return { highestLayer: 3 };
  }
  if (request.surface === 'asset-groups-raw') {
    const first = groupFixture(request.firstGroupInput);
    const later = groupFixture(request.laterGroupInput);
    const firstGroup = [...first.groups.values()][0];
    let laterGroup = [...later.groups.values()][0];
    let callerTrapInvoked = false;
    if (request.malformedCarrier.kind === 'non-map-group') {
      laterGroup = request.malformedCarrier.value;
    } else if (request.malformedCarrier.kind === 'non-map-member') {
      laterGroup.set(3, [request.malformedCarrier.value]);
    } else if (request.malformedCarrier.kind === 'non-map-external-key') {
      laterGroup.set(4, [request.malformedCarrier.value]);
    } else if (request.malformedCarrier.kind === 'map-proxy-with-throwing-get-prototype-of') {
      laterGroup = new Proxy(laterGroup, {
        getPrototypeOf() {
          callerTrapInvoked = true;
          throw new Error(request.malformedCarrier.marker);
        }
      });
    } else if (request.malformedCarrier.kind ===
        'members-array-proxy-with-throwing-get-own-property-descriptor') {
      laterGroup.set(3, new Proxy(laterGroup.get(3), {
        getOwnPropertyDescriptor() {
          callerTrapInvoked = true;
          throw new Error(request.malformedCarrier.marker);
        }
      }));
    } else if (request.malformedCarrier.kind ===
        'external-keys-array-proxy-with-throwing-get-own-property-descriptor') {
      laterGroup.set(4, new Proxy(laterGroup.get(4) ?? [], {
        getOwnPropertyDescriptor() {
          callerTrapInvoked = true;
          throw new Error(request.malformedCarrier.marker);
        }
      }));
    } else if (request.malformedCarrier.kind ===
        'groups-map-proxy-with-throwing-get-prototype-of') {
      // The outer collection is wrapped after its ordinary contents are built
      // below, so the real public boundary receives the hostile carrier.
    } else if (request.malformedCarrier.kind ===
        'options-proxy-with-throwing-get-own-property-descriptor') {
      // The configured options authority is wrapped immediately before the
      // public call below. Its traps must remain completely unobserved.
    } else {
      throw new Error(`${scenario.scenarioId}: unsupported malformed group carrier`);
    }
    let groups = new Map([
      [request.firstGroupInput.groupId, firstGroup],
      [request.laterGroupInput.groupId, laterGroup]
    ]);
    if (request.malformedCarrier.kind === 'groups-map-proxy-with-throwing-get-prototype-of') {
      groups = new Proxy(groups, {
        getPrototypeOf() {
          callerTrapInvoked = true;
          throw new Error(request.malformedCarrier.marker);
        }
      });
    }
    const fileIds = new Set([...first.fileIds, ...later.fileIds]);
    let validationOptions = { mode: request.mode, registry: authority };
    if (request.malformedCarrier.kind ===
        'options-proxy-with-throwing-get-own-property-descriptor') {
      validationOptions = new Proxy(validationOptions, {
        getOwnPropertyDescriptor() {
          callerTrapInvoked = true;
          throw new Error(request.malformedCarrier.marker);
        }
      });
    }
    try {
      validateAssetGroups(groups, fileIds, validationOptions);
    } catch (error) {
      assert.equal(callerTrapInvoked, false,
        `${scenario.scenarioId}: public shape preflight invoked caller Proxy code`);
      throw error;
    }
    assert.equal(callerTrapInvoked, false);
    return { highestLayer: 3 };
  }
  throw new Error(`unsupported repository semantic surface: ${request.surface}`);
}

async function executeOperationMode(scenario, frozenRegistry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.api !== 'validate-operation-mode') throw new Error(`${scenario.scenarioId}: invalid operation mode recipe`);
  const authority = await operationRegistry(request, frozenRegistry);
  if (request.surface === 'bundle-visitor') {
    const result = await visitLogicalBundle(await bytes(request.source), {}, {
      ...(Object.hasOwn(request, 'mode') ? { mode: request.mode } : {})
    });
    return { highestLayer: 2, ...result };
  }
  if (['tree-file', 'tree-schema-decoder', 'metadata-decoder',
    'bundle-memory-verifier', 'bundle-stream-verifier'].includes(request.surface)) {
    return executeCodecSurface(request, authority, frozenRegistry);
  }
  if (['metadata-encoder', 'tree-ordered', 'tree-sorted', 'content-manifest',
    'bundle-ordered', 'bundle-memory-encoder'].includes(request.surface)) {
    return executeEmitterSurface(request, authority, frozenRegistry);
  }
  return executeRepositoryModeSurface(request, scenario, authority, frozenRegistry);
}

async function executeAllocate(scenario, input) {
  const request = await json(input.path);
  if (request.phase === 'finalize') {
    validateFileIdAllocation({
      candidateFileId: request.candidateFileId,
      operation: request.operation,
      retryLimit: request.retryLimit,
      schema: request.schema
    }, scenario.context);
  } else if (request.phase === 'generate') {
    const recipe = request.entropyRecipe;
    if (!recipe || typeof recipe !== 'object') throw new Error(`${scenario.scenarioId}: missing entropy recipe`);
    let calls = 0;
    const candidates = recipe.candidateFileIds ?? [];
    const consumed = new Set(recipe.isConsumed ?? []);
    await allocateFileId({
      maxAttempts: request.retryLimit,
      entropy: async () => {
        if (calls === recipe.failAtCall) { calls += 1; throw new Error(recipe.failure); }
        const index = calls++;
        const candidate = candidates[index] ?? (recipe.exhaustedBehavior === 'repeat-last-candidate' ? candidates.at(-1) : undefined);
        if (!candidate) throw new Error('entropy recipe exhausted');
        return hexBytes(candidate);
      },
      isConsumed: (_candidate, candidateHex) => consumed.has(candidateHex)
    });
  } else {
    throw new Error(`${scenario.scenarioId}: unknown allocation phase`);
  }
  return { highestLayer: 3 };
}

async function executeFixtureAdapterRecipe(scenario) {
  const definitionInput = scenario.inputs.find(item => item.path.startsWith('scenarios/definitions/'));
  const recipe = (await json(definitionInput.path)).exactConstructorValues?.fixtureAdapter;
  if (recipe?.schema !== 'ogvcs.repository-format.v1.fixture-adapter-invocation.v1' ||
      recipe.expectedCode !== scenario.expected.code ||
      recipe.adapter?.allocation !== 'incrementing-nonzero-128-bit' ||
      recipe.adapter?.targetConsumption !== 'always-available') {
    throw new Error(`${scenario.scenarioId}: invalid fixture adapter recipe`);
  }
  const cwd = await mkdtemp(join(tmpdir(), 'ogvcs-scenario-fixture-'));
  try {
    const request = createRequest(recipe.generatorRequest);
    await generateFixture(request, { cwd });
    const mutation = recipe.adapter.postGenerationMutation;
    if (mutation !== undefined) {
      if (mutation.type !== 'request-profile-version' || typeof mutation.value !== 'string') {
        throw new Error(`${scenario.scenarioId}: unknown fixture mutation`);
      }
      const requestPath = join(cwd, recipe.generatorRequest.destination, 'fixture-request.json');
      const changed = JSON.parse(await readFile(requestPath, 'utf8'));
      changed.profile.version = mutation.value;
      await writeFile(requestPath, `${JSON.stringify(changed, null, 2)}\n`, 'utf8');
    }
    let allocation = 0;
    let ledger;
    const options = {
      allocateId: async () => (++allocation).toString(16).padStart(32, '0'),
      cwd,
      isTargetFileIdConsumed: async () => false,
      ...(recipe.adapter.persistLedger === 'memory'
        ? { persistLedger: async value => { ledger = value; } }
        : recipe.adapter.persistLedger === 'omit' ? {} : (() => { throw new Error('invalid ledger recipe'); })()),
      ...(recipe.adapter.requireNativeHistoryBindings === true ? { requireNativeHistoryBindings: true } : {}),
      ...(recipe.adapter.verifierResult === 'semantic-invalid'
        ? { verifyFixture: async () => ({ mode: 'full', status: 'invalid', verified: false }) }
        : {})
    };
    await adaptFixture(recipe.generatorRequest.destination, options);
    void ledger;
    return { highestLayer: 3 };
  } finally {
    await rm(cwd, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
  }
}

async function executeRepositoryRoute(scenario, registry) {
  const input = scenario.inputs.find(item => item.path.startsWith('scenarios/operations/'));
  const request = await json(input.path);
  if (request.schema !== 'ogvcs.repository-format.v1.repository-route-input.v1' ||
      request.authorityContext !== 'scenario.context' || typeof request.api !== 'string') {
    throw new Error(`${scenario.scenarioId}: invalid repository route recipe`);
  }
  const lookup = await lookupFor(scenario, registry, {
    lookupMutations: request.lookupMutations
  });
  const context = repositoryContext(scenario, lookup);
  switch (request.api) {
    case 'expand-tree':
      expandTree(request.tree, lookup, request.repositoryDescriptor, {
        caseMode: request.caseMode,
        verifyContent: request.verifyContent
      });
      return { highestLayer: 3 };
    case 'verify-manifest':
      verifyManifest(request.manifest, lookup);
      return { highestLayer: 3 };
    case 'replay-change-set': {
      // Base materialization is harness setup, not part of the production
      // lifecycle decision exercised by replay. Authenticate it independently
      // under conformance so a deliberately conformance-only descriptor in the
      // replay carrier cannot preempt the route's missing-reference L2 pass.
      const baseLookup = await lookupFor(scenario, registry, { mode: 'conformance' });
      const base = materializeReplayBase(request.baseState, scenario, baseLookup,
        request.repositoryDescriptor);
      const before = stateFingerprint(base);
      try {
        replayChangeSet(request.changeSet, base, {
          ...context,
          descriptor: request.repositoryDescriptor,
          verifyContent: true
        });
      } finally {
        assertStateUnchanged(base, before, scenario.scenarioId);
      }
      return { highestLayer: 3 };
    }
    case 'validate-conflict-set':
      validateConflictSet(request.conflictSet, lookup, request.repositoryDescriptor);
      return { highestLayer: 3 };
    case 'validate-provenance-graph':
      validateProvenanceGraph(request.roots, lookup, { forbidden: request.forbidden });
      return { highestLayer: 3 };
    case 'validate-snapshot-graph':
      validateSnapshotGraph(request.candidateSnapshot, {
        ...context,
        descriptor: request.repositoryDescriptor ?? context.descriptor,
        verifyContent: true
      });
      return { highestLayer: 3 };
    case 'validate-lifetime-and-imports':
      validateLifetimeAndImports({
        ...context,
        descriptor: request.repositoryDescriptor ?? context.descriptor
      });
      return { highestLayer: 3 };
    case 'validate-import-request':
      validateImportRequest({
        schema: 'ogvcs.repository-format.v1.fileid-operation-input.v1',
        operation: 'import-file-id',
        ...request.importRequest
      }, {
        ...context,
        descriptor: request.repositoryDescriptor ?? context.descriptor
      });
      return { highestLayer: 3 };
    case 'validate-shelf-revision':
      validateShelfRevision(request.shelfRevision, {
        ...context,
        verifyContent: request.callerVerifyContent
      });
      return { highestLayer: 3 };
    case 'validate-repository-candidate':
      return validateRepositoryCandidate(request.candidateSnapshot, {
        ...context,
        verifyContent: request.callerVerifyContent
      });
    default:
      throw new Error(`${scenario.scenarioId}: unsupported repository route ${request.api}`);
  }
}

async function executeConcrete(row, scenario, registry, limitCases) {
  const input = primaryInput(scenario);
  if (row.materialization === 'executable-enumerated-registry-recipe') {
    return executeRegistryRecipe(row.scenarioId);
  }
  if (row.materialization === 'executable-virtual-limit-constructor') {
    const match = /^limit-(.+)-(max|max-plus-one)$/.exec(row.scenarioId);
    assert.ok(match);
    const variant = match[2] === 'max' ? 'maximum' : 'maximum-plus-one';
    const constructor = limitCases.get(`${match[1]}\0${variant}`);
    if (!constructor) throw new Error(`${row.scenarioId}: missing limit constructor`);
    const result = evaluateHardLimit(registry, constructor.case, constructor.valueDecimal);
    if (!result.accepted) throw new OgvcsError(result.code, {
      layer: result.layer, stage: result.stage
    });
    return { highestLayer: result.layer };
  }
  if (row.scenarioId === 'mutation-systematic-single-bit') return executeMutationRecipe(registry);
  if (row.scenarioId === 'truncation-every-prefix') return executeTruncationRecipe(registry);
  if (row.scenarioId === 'malformed-complete-corpus') return executeMalformedRecipe();
  if (row.operation === 'adapt-fixture') return executeFixtureAdapterRecipe(scenario);
  if (row.operation === 'validate-operation-mode') return executeOperationMode(scenario, registry);
  if (row.operation === 'write-content-manifest') return executeManifestWriter(scenario, registry);
  if (row.operation === 'write-tree') return executeTreeWriter(scenario, registry);
  if (row.operation === 'write-logical-bundle') return executeLogicalBundleWriter(scenario, registry);
  if (row.operation === 'validate-path-profile-decision') return executePathProfileDecision(scenario, registry);
  if (row.operation === 'validate-resource-reservation') return executeResourceReservation(scenario, registry);
  if (row.operation === 'validate-tree-groups-memory') return executeTreeGroupsMemory(scenario, registry);
  if (row.operation === 'validate-repository-route') return executeRepositoryRoute(scenario, registry);
  if (row.operation === 'validate-typed-reference-authority') {
    return executeTypedReferenceAuthority(scenario, registry);
  }
  if (row.materialization === 'executable-configured-resource-constructor') {
    const definitionInput = scenario.inputs.find(item => item.path.startsWith('scenarios/definitions/'));
    const recipe = (await json(definitionInput.path)).exactConstructorValues?.configuredResource;
    if (!recipe || recipe.source !== input.path || !recipe.limits || typeof recipe.limits !== 'object') {
      throw new Error(`${row.scenarioId}: invalid configured resource recipe`);
    }
    const payload = await bytes(recipe.source);
    if (recipe.api === 'visit-logical-bundle') {
      await visitLogicalBundle(payload, {}, recipe.limits);
      return { highestLayer: 1 };
    }
    if (recipe.api === 'create-bundle-transcript-hash-writer') {
      createBundleTranscriptHashWriter(recipe.limits).update(payload).finish();
      return { highestLayer: 1 };
    }
    if (recipe.api === 'verify-logical-bundle-stream') {
      const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-scenario-bundle-'));
      try {
        await verifyLogicalBundleStream(payload, {
          ...recipe.limits,
          operation: scenario.context.mode === 'production' ? 'production-write' : 'conformance',
          registry,
          scratchDirectory
        });
      } finally {
        await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
      }
      return { highestLayer: 2 };
    }
    throw new Error(`${row.scenarioId}: unsupported configured resource api ${recipe.api}`);
  }
  if (row.operation === 'validate-bundle-claim') {
    const request = await json(input.path);
    assert.equal(request.schema, 'ogvcs.repository-format.v1.bundle-claim-input.v1');
    assert.equal(request.operation, 'validate-bundle-claim');
    validateBundleClaim(request.claim);
    return { highestLayer: 3 };
  }
  if (row.operation === 'validate-bundle') {
    // The original bundle vectors are explicitly the supplied-closure L2
    // route. Lifecycle-aware bundle cases use validate-operation-mode.
    const result = verifyLogicalBundle(await bytes(input.path), { semantic: false });
    return { highestLayer: result.highestLayer };
  }
  if (row.operation === 'validate-abstract-reference-graph') {
    return validateAbstractReferenceGraph(await json(input.path));
  }
  if (row.operation === 'allocate-file-id') return executeAllocate(scenario, input);
  if (row.operation === 'canonical-scan' && input.mediaType === 'application/json') {
    const request = await json(input.path);
    if (request.api === 'canonical-scan' &&
        request.schema === 'ogvcs.repository-format.v1.canonical-scan-input.v1' &&
        request.surface === 'generic-cbor-item' && typeof request.source === 'string') {
      decodeCanonical(await bytes(request.source));
      return { highestLayer: 1 };
    }
  }

  const lookup = await lookupFor(scenario, registry);
  const context = repositoryContext(scenario, lookup);
  if (row.operation === 'import-file-id') {
    validateImportRequest(await json(input.path), context);
    return { highestLayer: 3 };
  }
  if (row.operation === 'validate-repository') {
    return validateRepositoryCandidate(scenario.context.candidateSnapshot, context);
  }
  if (row.operation === 'replay-change-set') {
    const { changeSetReference, conflictSet, base } = replayBaseFromCandidate(scenario, lookup);
    const before = stateFingerprint(base);
    try {
      replayChangeSet(changeSetReference, base, { ...context, conflictSet });
    } finally {
      assertStateUnchanged(base, before, scenario.scenarioId);
    }
    // Result-coherence scenarios additionally bind replay's output to the
    // carried candidate snapshot. The public replay route has already run;
    // candidate validation supplies the independently authenticated expected
    // tree/group state and conflict-set relationship.
    validateRepositoryCandidate(scenario.context.candidateSnapshot, context);
    return { highestLayer: 3 };
  }
  if (row.operation === 'canonical-scan') {
    const ref = primaryReference(scenario, input);
    if (ref) { lookup.resolve(ref); return { highestLayer: 1 }; }
    return scanMetadata(await bytes(input.path));
  }
  if (row.operation !== 'validate-object') throw new Error(`${row.scenarioId}: unsupported operation ${row.operation}`);

  if (!input || !input.mediaType.startsWith('application/cbor')) throw new Error(`${row.scenarioId}: no object input`);
  const ref = primaryReference(scenario, input);
  if (!ref) {
    const decoded = decodeMetadata(await bytes(input.path), {
      registry,
      operation: scenario.context.mode === 'production' ? 'production-write' : 'conformance'
    });
    return { highestLayer: decoded.highestLayer };
  }
  const parsed = ObjectRef.parse(ref);
  if (parsed.kind === 2) { verifyManifest(ref, lookup); return { highestLayer: 3 }; }
  if (parsed.kind === 3) {
    const pathAdapter = pathProfileAdapter(scenario.context.pathProfileValidator);
    expandTree(ref, lookup, scenario.context.repositoryDescriptor, {
      caseMode: scenario.context.caseMode,
      ...(pathAdapter.adapter === undefined ? {} : { validatePathProfile: pathAdapter.adapter })
    });
    pathAdapter.assertComplete();
    return { highestLayer: 3 };
  }
  if (parsed.kind === 8) { validateShelfRevision(ref, { ...context, descriptor: scenario.context.repositoryDescriptor }); return { highestLayer: 3 }; }
  if (parsed.kind === 11) { validateConflictSet(ref, lookup, scenario.context.repositoryDescriptor); return { highestLayer: 3 }; }
  lookup.resolve(ref, parsed.kind);
  return { highestLayer: 3 };
}

function outcomeFor(error, result) {
  if (error) {
    if (!(error instanceof OgvcsError)) throw error;
    return { code: error.code, layer: error.layer, stage: error.stage, result: 'reject',
      ...(error.resourceEvidence === undefined ? {} : { evidence: error.resourceEvidence }) };
  }
  return { highestLayer: result.highestLayer, result: 'accept',
    ...(result.evidence === undefined ? {} : { evidence: result.evidence }) };
}

function sameExpected(actual, expected) {
  return canonical(actual.evidence) === canonical(expected.evidence) &&
    actual.result === expected.result && (actual.result === 'accept'
    ? actual.highestLayer === expected.highestLayer
    : actual.code === expected.code && actual.layer === expected.layer &&
      (expected.stage === undefined || actual.stage === expected.stage));
}

export async function executeJavascriptScenarios() {
  const [index, limits, registry] = await Promise.all([
    json('scenarios/index.json'), json('limits/virtual-constructors.json'),
    loadRegistryDirectory(resolve(SPEC, 'registries'))
  ]);
  const limitCases = new Map(limits.cases.map(item => [`${item.case}\0${item.variant}`, item]));
  const rows = [];
  for (const row of index.cases) {
    const scenario = await json(row.artifact);
    const implementationScope = row.implementationScope ?? ['javascript', 'rust'];
    const executable = row.materialization !== 'virtual-constructor' &&
      (row.materialization !== 'virtual-constructor-shared-bundle-baseline' || row.scenarioId === 'bundle-export-claim');
    if (!executable) {
      rows.push({ implementationScope, materialization: row.materialization, operation: row.operation,
        reason: 'inventory-only-constructor', scenarioId: row.scenarioId, status: 'not-executed' });
      continue;
    }
    let error; let result;
    try { result = await executeConcrete(row, scenario, registry, limitCases); }
    catch (caught) { error = caught; }
    const actual = outcomeFor(error, result);
    rows.push({ actual, expected: row.expected.result === 'accept'
      ? { highestLayer: row.expected.highestLayer, result: 'accept',
        ...(row.expected.evidence === undefined ? {} : { evidence: row.expected.evidence }) }
      : { code: row.expected.code, layer: row.expected.layer,
        ...(row.expected.stage === undefined ? {} : { stage: row.expected.stage }), result: 'reject',
        ...(row.expected.evidence === undefined ? {} : { evidence: row.expected.evidence }) },
    implementationScope, materialization: row.materialization, operation: row.operation, scenarioId: row.scenarioId,
    status: sameExpected(actual, row.expected) ? 'passed' : 'failed' });
  }
  const failed = rows.filter(row => row.status === 'failed');
  const executed = rows.filter(row => row.status !== 'not-executed');
  const reportCore = {
    executed: executed.length,
    failed: failed.length,
    inventoryOnly: rows.length - executed.length,
    notApplicable: 0,
    rows,
    scenarios: rows.length
  };
  return Object.freeze({
    ...reportCore,
    resultsSha256: digest(canonical(rows)),
    schema: 'ogvcs.object-model.scenario-execution-report/v1'
  });
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length !== 2 || argv[0] !== '--output') throw new Error('usage: node tools/object-model-scenario-report-js.mjs --output <report.json>');
  const report = await executeJavascriptScenarios();
  if (report.failed !== 0) {
    const failures = report.rows.filter(row => row.status === 'failed').map(row =>
      `${row.scenarioId}(${canonical(row.actual)} != ${canonical(row.expected)})`).join(', ');
    throw new Error(`scenario execution failed: ${failures}`);
  }
  const output = resolve(process.cwd(), argv[1]);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonical(report)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonical(report)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
