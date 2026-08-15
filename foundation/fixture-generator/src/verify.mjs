import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, opendir, realpath } from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest, canonicalStringify } from './canonical.mjs';
import { createChains } from './checkpoint.mjs';
import {
  GENERATOR_VERSION,
  MAX_CONTROL_DOCUMENT_BYTES,
  MAX_GROUP_RELATIONSHIP_BYTES,
  MAX_REQUEST_DOCUMENT_BYTES,
  TOOL_NAME,
  VERIFICATION_SCHEMA,
} from './constants.mjs';
import { readBoundedJson } from './io.mjs';
import { loadFixtureRequest, loadManifest } from './manifest.mjs';
import {
  computeDirectorySet,
  createGroups,
  createOperation,
  createPathRecord,
  historyShape,
  largeFileRecipe,
  scenarioEnvelope,
} from './model.mjs';
import {
  shouldMaterializeSmall,
  verifyLargeFile,
  verifySmallRecord,
} from './materialize.mjs';
import { getProfile, resolveProfile } from './profiles.mjs';
import { requestSettings } from './request.mjs';
import {
  assertSchemaDocument,
  assertSchemaFragment,
  portableRelativePathIssue,
} from './schema-validator.mjs';
import { invalidRequest } from './errors.mjs';
import { OWNER_FILENAME } from './safety.mjs';
import { planFixture } from './plan.mjs';
import { ResourceBudget } from './writer.mjs';

const MAX_NDJSON_LINE_BYTES = 64 * 1024;
const REQUIRED_TOP_LEVEL = Object.freeze([
  OWNER_FILENAME,
  'fixture-request.json',
  'groups.json',
  'inventory.ndjson',
  'manifest.json',
  'operations.ndjson',
  'scenario.json',
  'workload-profile.json',
]);

function resolvedProfileFor(request, profile) {
  return resolveProfile(profile.id, {
    featureFlags: Object.fromEntries(
      profile.features.map((name) => [name, request.featureFlags[name]]),
    ),
    scale: request.scale,
    version: profile.version,
  });
}

function addCheck(checks, code, status, details = {}) {
  const check = { code, status };
  for (const key of ['actual', 'expected', 'logicalPath', 'message']) {
    if (details[key] !== undefined) {
      check[key] = key === 'message' ? String(details[key]).slice(0, 2048) : details[key];
    }
  }
  checks.push(check);
}

function checkRuntime(budget, phase) {
  budget?.checkRuntime(`verification:${phase}`);
}

async function runCheck(checks, code, action, budget) {
  checkRuntime(budget, code);
  try {
    const details = await action();
    checkRuntime(budget, code);
    addCheck(checks, code, 'pass', details);
    return true;
  } catch (error) {
    if (error?.type === 'resource-limit') throw error;
    addCheck(checks, code, 'fail', { message: error.message });
    return false;
  }
}

function same(left, right) {
  return canonicalStringify(left) === canonicalStringify(right);
}

function assertExactKeys(value, expectedKeys, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (!same(actual, expected)) throw new Error(`${label} has unsupported or missing fields`);
}

function isContained(root, target) {
  const relative = path.relative(root, target);
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative);
}

/**
 * Resolve a fixture-relative artifact without permitting absolute paths,
 * traversal, native separators, control characters, non-NFC text, symlink
 * components, or a path outside the already-real fixture root.
 */
export async function resolveFixtureArtifact(directory, relativePath, label, options = {}) {
  checkRuntime(options.budget, 'artifact-path');
  if (
    typeof relativePath !== 'string'
    || relativePath.length === 0
    || relativePath.length > 4096
    || relativePath !== relativePath.normalize('NFC')
    || relativePath.includes('\\')
    || /[\u0000-\u001f\u007f]/u.test(relativePath)
    || relativePath.startsWith('/')
    || /^[A-Za-z]:/u.test(relativePath)
  ) {
    throw new Error(`${label} is not a portable relative artifact path`);
  }
  const segments = relativePath.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`${label} contains an empty, dot, or traversal segment`);
  }

  const root = await realpath(directory);
  const target = path.resolve(root, ...segments);
  if (!isContained(root, target)) throw new Error(`${label} escapes the fixture root`);

  let cursor = root;
  let metadata;
  for (let index = 0; index < segments.length; index += 1) {
    checkRuntime(options.budget, 'artifact-path');
    cursor = path.join(cursor, segments[index]);
    try {
      metadata = await lstat(cursor);
    } catch (error) {
      if (error.code === 'ENOENT' && options.allowMissing === true) return target;
      throw new Error(`${label} is missing: ${error.code ?? error.message}`);
    }
    if (metadata.isSymbolicLink()) throw new Error(`${label} traverses a symlink or junction`);
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      throw new Error(`${label} traverses a non-directory component`);
    }
  }

  if (options.kind === 'directory' && !metadata?.isDirectory()) {
    throw new Error(`${label} is not a directory`);
  }
  if ((options.kind ?? 'file') === 'file' && !metadata?.isFile()) {
    throw new Error(`${label} is not a regular file`);
  }
  const physical = await realpath(target);
  if (path.relative(root, physical) !== path.relative(root, target)) {
    throw new Error(`${label} resolves to an unexpected physical path`);
  }
  return target;
}

async function readBoundedNdjson(filePath, visitor, maximumRecords, budget) {
  const stream = createReadStream(filePath);
  const hash = createHash('sha256');
  let pending = Buffer.alloc(0);
  let count = 0;
  let offset = 0;
  try {
    for await (const chunk of stream) {
      checkRuntime(budget, 'ndjson-stream');
      hash.update(chunk);
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
      while (true) {
        checkRuntime(budget, 'ndjson-record');
        const newline = pending.indexOf(0x0a);
        if (newline < 0) break;
        if (newline === 0) throw new Error('NDJSON artifact contains an empty record');
        if (newline > MAX_NDJSON_LINE_BYTES) throw new Error('NDJSON record exceeds the safe line bound');
        if (count >= maximumRecords) throw new Error('NDJSON artifact contains too many records');
        const line = pending.subarray(0, newline).toString('utf8');
        pending = pending.subarray(newline + 1);
        let value;
        try {
          value = JSON.parse(line);
        } catch (error) {
          throw new Error(`malformed NDJSON record ${count}: ${error.message}`);
        }
        await visitor(value, { count, line: `${line}\n`, offset });
        offset += newline + 1;
        count += 1;
      }
      if (pending.length > MAX_NDJSON_LINE_BYTES) {
        throw new Error('NDJSON record exceeds the safe line bound');
      }
    }
  } finally {
    stream.destroy();
  }
  if (pending.length !== 0) throw new Error('NDJSON artifact has an unterminated record');
  return { count, digest: hash.digest('hex') };
}

async function traverseMaterializedFiles(root, budget) {
  const rootMetadata = await lstat(root).catch(() => null);
  if (!rootMetadata) return { directories: new Set(), files: new Set() };
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw new Error('files artifact is not a real directory');
  }
  const directories = new Set();
  const files = new Set();
  const remaining = [root];
  while (remaining.length > 0) {
    checkRuntime(budget, 'workspace-tree');
    const directory = remaining.pop();
    const handle = await opendir(directory);
    for await (const entry of handle) {
      checkRuntime(budget, 'workspace-tree');
      const child = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`materialized tree contains a symlink: ${entry.name}`);
      if (entry.isDirectory()) {
        directories.add(path.relative(root, child).split(path.sep).join('/'));
        remaining.push(child);
      } else if (entry.isFile()) {
        files.add(path.relative(root, child).split(path.sep).join('/'));
      } else {
        throw new Error(`materialized tree contains an unsupported file kind: ${entry.name}`);
      }
    }
  }
  return { directories, files };
}

function expectedMaterializedFiles(request) {
  const settings = requestSettings(request);
  const hasLarge = request.scale.largeFileBytes > 0;
  const smallPaths = request.scale.pathCount - (hasLarge ? 1 : 0);
  let smallFiles = 0;
  if (settings.materialization === 'full') smallFiles = smallPaths;
  if (settings.materialization === 'sampled') {
    const sampled = Math.min(request.scale.pathCount, settings.materializedPathLimit);
    smallFiles = sampled - (hasLarge && sampled > 0 ? 1 : 0);
  }
  const largeFiles = hasLarge && !['stream-verified', 'virtual'].includes(settings.largeFileMode) ? 1 : 0;
  return smallFiles + largeFiles;
}

function recordIsMaterialized(request, record) {
  if (record.content.algorithm === 'sha256') return shouldMaterializeSmall(request, record.index);
  return record.content.algorithm === 'sha256-recipe-v2'
    && !['stream-verified', 'virtual'].includes(requestSettings(request).largeFileMode);
}

async function verifyExecutableMode(directory, request, record, budget) {
  if (
    process.platform === 'win32'
    || record.content.algorithm !== 'sha256'
    || !shouldMaterializeSmall(request, record.index)
  ) return;
  const relativePath = `files/${record.logicalPath}`;
  const target = await resolveFixtureArtifact(
    directory,
    relativePath,
    'materialized inventory path',
    { budget },
  );
  const metadata = await lstat(target);
  const actual = metadata.mode & 0o777;
  const expected = record.mode === '100755' ? 0o755 : 0o644;
  if (actual !== expected) {
    throw new Error(`materialized mode ${actual.toString(8)} differs from ${expected.toString(8)}`);
  }
}

function* expectedScenarioChunks(request, profile, operationsDigest, budget) {
  checkRuntime(budget, 'scenario-envelope');
  const envelope = scenarioEnvelope(request, profile, [], operationsDigest);
  assertSchemaDocument('OperationScenario', envelope);
  const prefix = canonicalStringify({
    digest: envelope.digest,
    networkConditions: envelope.networkConditions,
  });
  yield `${prefix.slice(0, -1)},"operations":[`;
  for (let sequence = 0; sequence < request.scale.historyOperationCount; sequence += 1) {
    if (sequence % 1024 === 0) checkRuntime(budget, 'scenario-operation');
    if (sequence > 0) yield ',';
    yield canonicalStringify(createOperation(request, profile, sequence));
  }
  const suffix = canonicalStringify({
    extensions: envelope.extensions,
    participants: envelope.participants,
    profile: envelope.profile,
    scenarioId: envelope.scenarioId,
    schemaVersion: envelope.schemaVersion,
    seed: envelope.seed,
  });
  yield `],${suffix.slice(1)}\n`;
}

async function compareScenarioStream(filePath, expectedChunks, budget) {
  const stream = createReadStream(filePath);
  const iterator = stream[Symbol.asyncIterator]();
  const hash = createHash('sha256');
  let actual = Buffer.alloc(0);
  let actualOffset = 0;

  async function refill() {
    checkRuntime(budget, 'scenario-stream');
    const next = await iterator.next();
    if (next.done) return false;
    actual = next.value;
    actualOffset = 0;
    hash.update(actual);
    return true;
  }

  try {
    for (const expectedChunk of expectedChunks) {
      checkRuntime(budget, 'scenario-stream');
      const expected = Buffer.from(expectedChunk, 'utf8');
      let expectedOffset = 0;
      while (expectedOffset < expected.length) {
        if (actualOffset === actual.length && !(await refill())) {
          throw new Error('scenario artifact is truncated');
        }
        const length = Math.min(expected.length - expectedOffset, actual.length - actualOffset);
        if (!expected.subarray(expectedOffset, expectedOffset + length)
          .equals(actual.subarray(actualOffset, actualOffset + length))) {
          throw new Error('scenario artifact differs from the canonical operation scenario');
        }
        expectedOffset += length;
        actualOffset += length;
      }
    }
    if (actualOffset < actual.length || await refill()) {
      throw new Error('scenario artifact contains trailing bytes');
    }
    return hash.digest('hex');
  } finally {
    stream.destroy();
  }
}

function validateLargeDescriptor(descriptor, request, record) {
  assertSchemaDocument('LargeFileDescriptor', descriptor);
  assertExactKeys(
    descriptor,
    [
      'compressionClass', 'contentAlgorithm', 'descriptorDigest', 'logicalBytes',
      'logicalPath', 'physical', 'recipeDigest', 'representation', 'stream', 'versions',
    ],
    'large-file descriptor',
  );
  const { descriptorDigest, physical, ...recipe } = descriptor;
  if (!same(recipe, largeFileRecipe(request, record.logicalPath))) {
    throw new Error('large-file descriptor recipe differs from the canonical request');
  }
  if (!/^[0-9a-f]{64}$/u.test(descriptorDigest)) {
    throw new Error('large-file descriptor digest is malformed');
  }

  const mode = requestSettings(request).largeFileMode;
  if (physical?.mode !== mode) throw new Error('large-file physical mode differs from the request');
  if (mode === 'virtual') {
    assertExactKeys(physical, ['mode', 'physicalBytes'], 'virtual large-file representation');
    if (physical.physicalBytes !== 0) throw new Error('virtual large-file representation claims physical bytes');
    return;
  }
  if (mode === 'stream-verified') {
    assertExactKeys(
      physical,
      ['mode', 'physicalBytes', 'streamedLogicalBytes', 'versionDigests'],
      'stream-verified large-file representation',
    );
    const expectedStreamedLogicalBytes = request.scale.largeFileBytes * descriptor.versions.length;
    if (
      physical.physicalBytes !== 0
      || physical.streamedLogicalBytes !== expectedStreamedLogicalBytes
    ) {
      throw new Error('stream-verified large-file byte accounting is inconsistent');
    }
    validateVersionDigests(physical.versionDigests, descriptor.versions, request.scale.largeFileBytes);
    return;
  }
  if (mode === 'full') {
    assertExactKeys(
      physical,
      ['digest', 'logicalFileSize', 'mode', 'physicalBytes', 'versionDigests'],
      'full large-file representation',
    );
    if (
      physical.logicalFileSize !== request.scale.largeFileBytes
      || physical.physicalBytes !== request.scale.largeFileBytes
      || !/^[0-9a-f]{64}$/u.test(physical.digest)
    ) throw new Error('full large-file representation metadata is inconsistent');
    validateVersionDigests(physical.versionDigests, descriptor.versions, request.scale.largeFileBytes);
    return;
  }

  assertExactKeys(
    physical,
    ['extentPayloadBytes', 'extents', 'logicalFileSize', 'maximumAllocatedBytes', 'mode'],
    'sparse large-file representation',
  );
  if (
    physical.logicalFileSize !== request.scale.largeFileBytes
    || !Array.isArray(physical.extents)
    || physical.extents.length < 1
    || physical.extents.length > 3
  ) throw new Error('sparse large-file representation metadata is inconsistent');
  let describedBytes = 0;
  for (const extent of physical.extents) {
    assertExactKeys(extent, ['digest', 'length', 'offset'], 'sparse extent');
    if (
      !Number.isSafeInteger(extent.offset)
      || !Number.isSafeInteger(extent.length)
      || extent.offset < 0
      || extent.length < 1
      || extent.offset + extent.length > request.scale.largeFileBytes
      || !/^[0-9a-f]{64}$/u.test(extent.digest)
    ) throw new Error('sparse extent is outside the declared logical file');
    describedBytes += extent.length;
  }
  if (
    physical.extentPayloadBytes !== describedBytes
    || physical.maximumAllocatedBytes !== request.scale.largeFileBytes
  ) {
    throw new Error('sparse allocation accounting differs from its extents or logical size');
  }
}

function validateVersionDigests(versionDigests, versions, logicalBytes) {
  if (!Array.isArray(versionDigests) || versionDigests.length !== versions.length) {
    throw new Error('large-file version digest count differs from its recipe');
  }
  for (let index = 0; index < versionDigests.length; index += 1) {
    const entry = versionDigests[index];
    assertExactKeys(entry, ['algorithm', 'bytes', 'digest', 'version'], 'large-file version digest');
    if (
      entry.algorithm !== 'sha256'
      || entry.bytes !== logicalBytes
      || entry.version !== versions[index].version
      || !/^[0-9a-f]{64}$/u.test(entry.digest)
    ) throw new Error('large-file version digest is malformed or inconsistent');
  }
}

function manifestSemantics(manifest, request) {
  const settings = requestSettings(request);
  if (!same(manifest.profile.id, request.profile.id) || !same(manifest.profile.version, request.profile.version)) {
    throw new Error('manifest profile identity differs from the canonical request');
  }
  if (
    manifest.extensions['representation.large-file'] !== settings.largeFileMode
    || manifest.extensions['representation.paths'] !== settings.materialization
  ) throw new Error('manifest representation differs from the canonical request');
  const expectedLargeArtifact = request.scale.largeFileBytes > 0 ? 'large-file.json' : null;
  if (manifest.extensions['artifacts.large-file'] !== expectedLargeArtifact) {
    throw new Error('manifest large-file artifact declaration differs from the request');
  }
  if (
    request.scale.largeFileBytes === 0
    && manifest.extensions['large-file.descriptor-digest'] !== null
  ) throw new Error('manifest declares a descriptor digest without a large-file artifact');
}

function buildVerificationResult(manifest, checks, mode, verifiedItems, verifiedBytes) {
  const failed = checks.filter(({ status }) => status === 'fail').length;
  const skipped = checks.filter(({ status }) => status === 'skipped').length;
  const passed = checks.filter(({ status }) => status === 'pass').length;
  const result = {
    checks,
    manifestDigest: manifest.manifestDigest,
    mode,
    requestDigest: manifest.requestDigest,
    schemaVersion: VERIFICATION_SCHEMA,
    status: failed === 0 ? 'valid' : 'invalid',
    summary: {
      checks: checks.length,
      failed,
      passed,
      skipped,
      verifiedBytes,
      verifiedItems,
    },
    tool: { name: TOOL_NAME, version: GENERATOR_VERSION },
    verified: failed === 0,
  };
  assertSchemaDocument('VerificationResult', result);
  return result;
}

export async function verifyFixture(destination, options = {}) {
  const destinationIssue = portableRelativePathIssue(destination);
  if (destinationIssue !== null) {
    throw invalidRequest(`destination ${destinationIssue}`, {
      reason: destinationIssue,
      value: destination,
    });
  }
  const cwd = await realpath(options.cwd ?? process.cwd());
  const directory = path.resolve(cwd, ...destination.split('/'));
  return verifyFixtureDirectory(directory, options);
}

// This entry point is intentionally not re-exported from the package index. It
// lets the generator verify its already-resolved, private staging directory
// without weakening the portable-relative contract of the public API.
export async function verifyFixtureDirectory(directory, options = {}) {
  const startedAt = Date.now();
  let bootstrap;
  checkRuntime(options.budget, 'start');
  if (!options.budget) {
    // The fixed-size request sidecar is the bootstrap contract for standalone
    // verification. It lets us establish the fixture's deadline and memory
    // budget before allocating/parsing the much larger manifest.
    bootstrap = await loadFixtureRequest(directory);
    const plan = planFixture(bootstrap.request);
    const explicitMaximumMemoryBytes = bootstrap.request.resourceLimits?.maximumMemoryBytes;
    options = {
      ...options,
      budget: new ResourceBudget({
        deadline: bootstrap.request.resourceLimits?.maximumDurationSeconds === undefined
          ? undefined
          : startedAt + bootstrap.request.resourceLimits.maximumDurationSeconds * 1000,
        // A caller-specified ceiling is an absolute process-RSS contract. In
        // its absence, bound this invocation's incremental verifier work: a
        // long-lived library process may legitimately begin above the clean
        // process peak estimated for generation.
        maximumMemoryBytes: explicitMaximumMemoryBytes,
        maximumMemoryGrowthBytes: explicitMaximumMemoryBytes === undefined
          ? Number(plan.estimates.standaloneVerificationMemoryGrowthBytes)
          : undefined,
        maximumPhysicalBytes: bootstrap.request.resourceLimits?.maximumPhysicalBytes,
        testFailurePhase: options.env?.OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE,
      }),
    };
    checkRuntime(options.budget, 'start');
  }
  const { manifest, request } = await loadManifest(directory, {
    bootstrap,
    budget: options.budget,
  });
  const checks = [];
  const mode = options.deep ? 'full' : 'metadata';
  let verifiedBytes = 0;
  let verifiedItems = 0;
  const verifyCheck = (code, action) => runCheck(checks, code, action, options.budget);

  const manifestValid = await verifyCheck('MANIFEST_SCHEMA', async () => {
    assertSchemaDocument('FixtureManifest', manifest);
    manifestSemantics(manifest, request);
  });
  if (!manifestValid) {
    return buildVerificationResult(manifest, checks, mode, verifiedItems, verifiedBytes);
  }

  const profile = getProfile(request.profile.id, request.profile.version);
  const resolvedProfile = resolvedProfileFor(request, profile);
  const chains = createChains();
  const directories = new Set();
  const expectedPhysicalDirectories = new Set();
  const expectedPhysicalFiles = new Set();
  const validatedOperationShapes = new Set();
  let inventoryCount = 0;
  let operationCount = 0;
  let logicalBytes = 0;
  let largeRecord;

  await verifyCheck('MANIFEST_DIGEST', async () => ({ expected: manifest.manifestDigest }));
  await verifyCheck('REQUEST_DOCUMENT', async () => {
    const requestPath = await resolveFixtureArtifact(
      directory,
      'fixture-request.json',
      'stored fixture request',
      { budget: options.budget },
    );
    const stored = await readBoundedJson(requestPath, 'stored fixture request', {
      budget: options.budget,
      maximumBytes: MAX_REQUEST_DOCUMENT_BYTES,
      phase: 'verification-request',
    });
    assertSchemaDocument('FixtureRequest', stored);
    if (!same(stored, request)) throw new Error('stored request differs from manifest request');
  });
  await verifyCheck('PROFILE_DOCUMENT', async () => {
    const profilePath = await resolveFixtureArtifact(
      directory,
      'workload-profile.json',
      'stored workload profile',
      { budget: options.budget },
    );
    const stored = await readBoundedJson(profilePath, 'stored workload profile', {
      budget: options.budget,
      maximumBytes: MAX_CONTROL_DOCUMENT_BYTES,
      phase: 'verification-profile',
    });
    assertSchemaDocument('WorkloadProfile', stored);
    assertSchemaDocument('WorkloadProfile', profile);
    if (!same(stored, profile)) throw new Error('stored profile differs from the built-in profile');
    if (resolvedProfile.resolvedDigest !== manifest.profile.resolvedDigest) {
      throw new Error('resolved profile digest differs from manifest');
    }
    if (
      manifest.provenance.classification !== profile.provenance.classification
      || manifest.provenance.license !== profile.license
      || manifest.provenance.generatedArtifactsContainExternalIdentifiers !== false
      || manifest.provenance.generatorAlgorithm !== 'ogvcs-fixture-generator-v1'
      || manifest.provenance.requestMetadata !== 'caller-supplied-unattested'
    ) throw new Error('manifest provenance differs from the resolved profile contract');
  });

  const inventoryValid = await verifyCheck('INVENTORY_STREAM', async () => {
    const inventoryPath = await resolveFixtureArtifact(
      directory,
      manifest.inventory.path,
      'manifest inventory artifact',
      { budget: options.budget },
    );
    const parsed = await readBoundedNdjson(inventoryPath, async (record, context) => {
      assertSchemaDocument('InventoryRecord', record);
      const expected = createPathRecord(request, profile, context.count);
      const expectedLine = `${canonicalStringify(expected)}\n`;
      if (!same(record, expected) || context.line !== expectedLine) {
        throw new Error(`inventory record ${context.count} is not canonical deterministic output`);
      }
      const pathIdentity = {
        fileId: expected.fileId,
        group: expected.group ?? null,
        kind: expected.kind,
        logicalPath: expected.logicalPath,
        mode: expected.mode,
        role: expected.role,
      };
      chains.paths.update(`${canonicalStringify(pathIdentity)}\n`);
      chains.content.update(`${canonicalStringify({
        digest: expected.content.digest,
        logicalBytes: expected.content.logicalBytes,
        logicalPath: expected.logicalPath,
      })}\n`);
      chains.tree.update(expectedLine);
      computeDirectorySet(expected, directories);
      if (recordIsMaterialized(request, expected)) {
        expectedPhysicalFiles.add(expected.logicalPath);
        const segments = expected.logicalPath.split('/');
        for (let length = 1; length < segments.length; length += 1) {
          expectedPhysicalDirectories.add(segments.slice(0, length).join('/'));
        }
      }
      logicalBytes += expected.content.logicalBytes;
      inventoryCount += 1;
      verifiedItems += 1;
      if (context.count === 0 && expected.content.algorithm === 'sha256-recipe-v2') largeRecord = expected;
      if (options.deep) {
        await verifySmallRecord(directory, request, expected, options.budget);
        await verifyExecutableMode(directory, request, expected, options.budget);
        if (
          expected.content.algorithm === 'sha256'
          && shouldMaterializeSmall(request, expected.index)
        ) verifiedBytes += expected.content.logicalBytes;
      }
    }, request.scale.pathCount, options.budget);
    if (parsed.digest !== manifest.inventory.digest) {
      throw new Error('inventory artifact digest differs from manifest');
    }
    if (parsed.count !== request.scale.pathCount || inventoryCount !== request.scale.pathCount) {
      throw new Error(`inventory count ${inventoryCount} differs from ${request.scale.pathCount}`);
    }
    if (
      chains.paths.digest !== manifest.digests.paths
      || chains.content.digest !== manifest.digests.content
    ) throw new Error('inventory rolling digests differ from manifest');
  });

  const operationsValid = await verifyCheck('OPERATION_STREAM', async () => {
    const operationsPath = await resolveFixtureArtifact(
      directory,
      'operations.ndjson',
      'operation stream artifact',
      { budget: options.budget },
    );
    const parsed = await readBoundedNdjson(operationsPath, (operation, context) => {
      const expected = createOperation(request, profile, context.count);
      const expectedLine = `${canonicalStringify(expected)}\n`;
      if (!same(operation, expected) || context.line !== expectedLine) {
        throw new Error(`operation ${context.count} is not canonical deterministic output`);
      }
      const shape = `${expected.kind}:${Object.hasOwn(expected, 'relatedTarget')}:${Object.hasOwn(expected, 'networkCondition')}`;
      if (!validatedOperationShapes.has(shape)) {
        assertSchemaFragment('OperationScenario', '#/properties/operations/items', expected);
        validatedOperationShapes.add(shape);
      }
      chains.operations.update(expectedLine);
      operationCount += 1;
      verifiedItems += 1;
    }, request.scale.historyOperationCount, options.budget);
    if (parsed.count !== request.scale.historyOperationCount || operationCount !== request.scale.historyOperationCount) {
      throw new Error(`operation count ${operationCount} differs from request`);
    }
    if (chains.operations.digest !== manifest.digests.operations) {
      throw new Error('operation rolling digest differs from manifest');
    }
  });

  await verifyCheck('GROUP_RELATIONSHIPS', async () => {
    checkRuntime(options.budget, 'groups');
    const expected = createGroups(request, profile);
    const groupsPath = await resolveFixtureArtifact(
      directory,
      manifest.extensions['artifacts.groups'],
      'manifest group artifact',
      { budget: options.budget },
    );
    const stored = await readBoundedJson(groupsPath, 'group relationship artifact', {
      budget: options.budget,
      maximumBytes: MAX_GROUP_RELATIONSHIP_BYTES,
      phase: 'verification-groups',
    });
    assertSchemaDocument('GroupRelationships', stored);
    assertSchemaDocument('GroupRelationships', manifest.groups);
    assertSchemaDocument('GroupRelationships', expected);
    if (!same(expected, stored) || !same(expected, manifest.groups)) {
      throw new Error('group relationships differ from deterministic profile output');
    }
    if (canonicalDigest(expected, 'ogvcs.fixture/groups/v1') !== manifest.extensions['groups.digest']) {
      throw new Error('group relationship digest differs from manifest');
    }
  });

  await verifyCheck('SCENARIO_ARTIFACT', async () => {
    if (!operationsValid) throw new Error('operation stream prerequisite failed');
    const scenarioPath = await resolveFixtureArtifact(
      directory,
      manifest.operationScenario.path,
      'manifest scenario artifact',
      { budget: options.budget },
    );
    const actualDigest = await compareScenarioStream(
      scenarioPath,
      expectedScenarioChunks(request, profile, chains.operations.digest, options.budget),
      options.budget,
    );
    if (actualDigest !== manifest.operationScenario.digest) {
      throw new Error('scenario artifact digest differs from manifest');
    }
    const expectedEnvelope = scenarioEnvelope(request, profile, [], chains.operations.digest);
    if (expectedEnvelope.digest !== manifest.extensions['scenario.envelope-digest']) {
      throw new Error('scenario envelope digest differs from manifest');
    }
  });

  await verifyCheck('TREE_DIGEST', async () => {
    if (!inventoryValid || !operationsValid) throw new Error('prerequisite stream verification failed');
    const groupsDigest = canonicalDigest(manifest.groups, 'ogvcs.fixture/groups/v1');
    const expected = canonicalDigest({
      content: chains.content.snapshot(),
      groups: groupsDigest,
      paths: chains.paths.snapshot(),
      profile: resolvedProfile.resolvedDigest,
      treeRecords: chains.tree.snapshot(),
    }, 'ogvcs.fixture/tree/v1');
    if (expected !== manifest.digests.tree) throw new Error('tree digest differs from canonical inputs');
    if (logicalBytes !== manifest.logicalBytes) throw new Error('logical byte total differs from manifest');
    if (!same(historyShape(request, profile, options.budget), manifest.history)) {
      throw new Error('history shape differs from request');
    }
    if (
      manifest.counts.paths !== inventoryCount
      || manifest.counts.files !== inventoryCount
      || manifest.counts.operations !== operationCount
      || manifest.counts.directories !== directories.size
      || manifest.counts.groups !== manifest.groups.length
    ) throw new Error('manifest counts differ from verified artifacts');
  });

  await verifyCheck('LARGE_FILE_REPRESENTATION', async () => {
    if (!largeRecord) {
      if (
        manifest.extensions['artifacts.large-file'] !== null
        || manifest.extensions['large-file.descriptor-digest'] !== null
      ) throw new Error('unexpected large-file artifact');
      return { message: 'request contains no large mutable file' };
    }
    const descriptorPath = await resolveFixtureArtifact(
      directory,
      manifest.extensions['artifacts.large-file'],
      'manifest large-file descriptor',
      { budget: options.budget },
    );
    const descriptor = await readBoundedJson(descriptorPath, 'large-file descriptor', {
      budget: options.budget,
      maximumBytes: MAX_CONTROL_DOCUMENT_BYTES,
      phase: 'verification-large-descriptor',
    });
    validateLargeDescriptor(descriptor, request, largeRecord);
    if (descriptor.descriptorDigest !== manifest.extensions['large-file.descriptor-digest']) {
      throw new Error('large-file descriptor digest differs from manifest binding');
    }
    const result = await verifyLargeFile(directory, request, largeRecord, descriptor, {
      budget: options.budget,
      deep: options.deep,
    });
    verifiedBytes += result.bytes;
  });

  await verifyCheck('WORKSPACE_SAFETY', async () => {
    const expected = new Set(REQUIRED_TOP_LEVEL);
    if (request.scale.largeFileBytes > 0) expected.add('large-file.json');
    if (expectedMaterializedFiles(request) > 0) expected.add('files');

    const actual = new Set();
    const topLevel = await opendir(directory);
    for await (const entry of topLevel) {
      checkRuntime(options.budget, 'workspace-top-level');
      if (entry.isSymbolicLink()) throw new Error(`top-level artifact is a symlink: ${entry.name}`);
      if (entry.name === 'files') {
        if (!entry.isDirectory()) throw new Error('files artifact is not a directory');
      } else if (!entry.isFile()) {
        throw new Error(`top-level artifact is not a regular file: ${entry.name}`);
      }
      actual.add(entry.name);
    }
    if (!same([...actual].sort(), [...expected].sort())) {
      throw new Error('fixture contains missing, dangling, or unexpected top-level artifacts');
    }

    const filesRoot = await resolveFixtureArtifact(
      directory,
      'files',
      'materialized files root',
      {
        allowMissing: expectedMaterializedFiles(request) === 0,
        budget: options.budget,
        kind: 'directory',
      },
    );
    const tree = await traverseMaterializedFiles(filesRoot, options.budget);
    if (
      !same([...tree.files].sort(), [...expectedPhysicalFiles].sort())
      || !same([...tree.directories].sort(), [...expectedPhysicalDirectories].sort())
    ) {
      throw new Error('materialized tree paths or directory prefixes differ from the canonical request');
    }
  });

  checkRuntime(options.budget, 'complete');
  return buildVerificationResult(manifest, checks, mode, verifiedItems, verifiedBytes);
}
