#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
  ObjectRef,
  RepositoryObjectLookup,
  adaptFixture,
  allocateFileId,
  decodeCanonical,
  decodeMetadata,
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
  validateBundleClaim,
  validateConflictSet,
  validateFileIdAllocation,
  validateImportRequest,
  validateLogicalRecord,
  validateRepositoryCandidate,
  validateRegistrySet,
  validateShelfRevision,
  verifyLogicalBundle,
  verifyLogicalBundleStream,
  verifyManifest
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

async function lookupFor(scenario, registry) {
  const entries = [];
  for (const item of scenario.context.objectLookup) entries.push([item.ref, await bytes(item.artifact.path)]);
  return new RepositoryObjectLookup(entries, {
    mode: scenario.context.mode,
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
    verifyContent: true,
    workingLifetimeAdditions: scenario.context.workingLifetimeAdditions
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
            const decoded = decodeMetadata(changed, { registry, semantic: false });
            if (decoded.kind !== source.kind) throw new OgvcsError('OBJECT_REFERENCE_KIND_MISMATCH', {
              layer: 2, stage: 'known-schema'
            });
            identity = toHex(hashObject(source.kind, changed).digest);
          } else {
            const value = decodeCanonical(changed);
            const validated = validateLogicalRecord(value, { registry });
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
        try { verifyLogicalBundle(changed, { registry, mode: 'conformance' }); }
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
      assert.throws(() => verifyLogicalBundle(sequence.subarray(0, prefix), { registry }), error =>
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
  if (value === 'read-or-write') return ['read', 'new-write'];
  if (value === 'read-or-new-write') return ['read', 'new-write'];
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
  if (row.materialization === 'executable-configured-resource-constructor') {
    const definitionInput = scenario.inputs.find(item => item.path.startsWith('scenarios/definitions/'));
    const recipe = (await json(definitionInput.path)).exactConstructorValues?.configuredResource;
    if (recipe?.api !== 'verify-logical-bundle-stream' || recipe.source !== input.path ||
        !recipe.limits || typeof recipe.limits !== 'object') {
      throw new Error(`${row.scenarioId}: invalid configured resource recipe`);
    }
    const scratchDirectory = await mkdtemp(join(tmpdir(), 'ogvcs-scenario-bundle-'));
    try {
      await verifyLogicalBundleStream(await bytes(recipe.source), {
        ...recipe.limits,
        mode: scenario.context.mode,
        registry,
        scratchDirectory
      });
    } finally {
      await rm(scratchDirectory, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 });
    }
    return { highestLayer: 2 };
  }
  if (row.operation === 'validate-bundle-claim') {
    const request = await json(input.path);
    assert.equal(request.schema, 'ogvcs.repository-format.v1.bundle-claim-input.v1');
    assert.equal(request.operation, 'validate-bundle-claim');
    validateBundleClaim(request.claim);
    return { highestLayer: 3 };
  }
  if (row.operation === 'validate-bundle') {
    const result = verifyLogicalBundle(await bytes(input.path), { registry, mode: scenario.context.mode });
    return { highestLayer: result.highestLayer };
  }
  if (row.operation === 'validate-abstract-reference-graph') {
    return validateAbstractReferenceGraph(await json(input.path));
  }
  if (row.operation === 'allocate-file-id') return executeAllocate(scenario, input);

  const lookup = await lookupFor(scenario, registry);
  const context = repositoryContext(scenario, lookup);
  if (row.operation === 'import-file-id') {
    validateImportRequest(await json(input.path), context);
    return { highestLayer: 3 };
  }
  if (row.operation === 'validate-repository' || row.operation === 'replay-change-set') {
    return validateRepositoryCandidate(scenario.context.candidateSnapshot, context);
  }
  if (row.operation === 'canonical-scan') {
    const ref = primaryReference(scenario, input);
    if (ref) { lookup.resolve(ref); return { highestLayer: 1 }; }
    return scanMetadata(await bytes(input.path), { registry });
  }
  if (row.operation !== 'validate-object') throw new Error(`${row.scenarioId}: unsupported operation ${row.operation}`);

  if (!input || !input.mediaType.startsWith('application/cbor')) throw new Error(`${row.scenarioId}: no object input`);
  const ref = primaryReference(scenario, input);
  if (!ref) {
    const decoded = decodeMetadata(await bytes(input.path), { registry, operation: scenario.context.mode });
    return { highestLayer: decoded.highestLayer };
  }
  const parsed = ObjectRef.parse(ref);
  if (parsed.kind === 2) { verifyManifest(ref, lookup); return { highestLayer: 3 }; }
  if (parsed.kind === 3) { expandTree(ref, lookup, scenario.context.repositoryDescriptor); return { highestLayer: 3 }; }
  if (parsed.kind === 8) { validateShelfRevision(ref, { ...context, descriptor: scenario.context.repositoryDescriptor }); return { highestLayer: 3 }; }
  if (parsed.kind === 11) { validateConflictSet(ref, lookup, scenario.context.repositoryDescriptor); return { highestLayer: 3 }; }
  lookup.resolve(ref, parsed.kind);
  return { highestLayer: 3 };
}

function outcomeFor(error, result) {
  if (error) {
    if (!(error instanceof OgvcsError)) throw error;
    return { code: error.code, layer: error.layer, stage: error.stage, result: 'reject' };
  }
  return { highestLayer: result.highestLayer, result: 'accept' };
}

function sameExpected(actual, expected) {
  return actual.result === expected.result && (actual.result === 'accept'
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
      ? { highestLayer: row.expected.highestLayer, result: 'accept' }
      : { code: row.expected.code, layer: row.expected.layer,
        ...(row.expected.stage === undefined ? {} : { stage: row.expected.stage }), result: 'reject' },
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
    const failures = report.rows.filter(row => row.status === 'failed').map(row => row.scenarioId).join(', ');
    throw new Error(`scenario execution failed: ${failures}`);
  }
  const output = resolve(process.cwd(), argv[1]);
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${canonical(report)}\n`, { encoding: 'utf8', flag: 'wx' });
  process.stdout.write(`${canonical(report)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
