import { createHash } from 'node:crypto';
import { lstat, mkdir, opendir, readFile, realpath, stat, truncate, unlink } from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest, canonicalStringify } from './canonical.mjs';
import { CONTENT_ALGORITHM as CONTENT_STREAM_ALGORITHM } from './content.mjs';
import {
  assertChainSnapshots,
  checkpointDocument,
  createChains,
  readCheckpoint,
} from './checkpoint.mjs';
import {
  GENERATOR_VERSION,
  MANIFEST_SCHEMA,
  MAX_CONTROL_DOCUMENT_BYTES,
  SCHEMA_VERSIONS,
  TOOL_NAME,
} from './constants.mjs';
import { integrityFailure, resourceLimit, unsafeDestination } from './errors.mjs';
import {
  atomicWriteCanonical,
  hashFile,
  readBoundedJson,
  readNdjson,
  syncDirectory,
} from './io.mjs';
import { addManifestDigest, loadManifest } from './manifest.mjs';
import {
  computeDirectorySet,
  contentIndexLine,
  createGroups,
  createOperation,
  createPathRecord,
  historyShape,
  scenarioEnvelope,
} from './model.mjs';
import {
  materializeLargeFile,
  materializeSmallRecord,
  shouldMaterializeSmall,
  verifyLargeFile,
  verifySmallRecord,
} from './materialize.mjs';
import { planFixture } from './plan.mjs';
import { resolveProfile } from './profiles.mjs';
import { requestSettings, resolveRequest } from './request.mjs';
import {
  assertWorkspaceArtifactAllowlist,
  prepareWorkspace,
  publishWorkspace,
  reconcileCompletedOwnedStage,
  removeOwnedAtomicTemporaryArtifacts,
  removeOwnedArtifacts,
} from './safety.mjs';
import { verifyFixtureDirectory } from './verify.mjs';
import { BufferedFileWriter, ResourceBudget } from './writer.mjs';

const GENERATED_ARTIFACTS = [
  'checkpoint.json',
  'fixture-request.json',
  'groups.json',
  'inventory.ndjson',
  'large-file.json',
  'manifest.json',
  'operations.ndjson',
  'scenario.json',
  'workload-profile.json',
  'files',
];

function progress(options, event) {
  options.onProgress?.({
    ...event,
    schemaVersion: 'ogvcs.fixture/progress/v1',
  });
}

function postCommitDiagnostic(error, phase) {
  return {
    code: typeof error?.code === 'string' ? error.code : 'POST_COMMIT_ERROR',
    phase,
  };
}

async function releaseCommittedWorkspace(releaseLock, diagnostics) {
  try {
    await releaseLock();
  } catch {
    // The release closure is retryable. A transient cleanup failure should not
    // leave a durable fixture needlessly locked, but repeated failure is still
    // reported without converting committed success into an error.
    try {
      await releaseLock();
    } catch (error) {
      diagnostics.push(postCommitDiagnostic(error, 'lock-release'));
    }
  }
}

async function releaseFailedWorkspace(releaseLock, primaryError) {
  try {
    await releaseLock();
  } catch (cleanupError) {
    primaryError.workspaceLockCleanup = postCommitDiagnostic(cleanupError, 'lock-release');
  }
}

function assertRuntimeLimits(runtime) {
  runtime.budget.checkRuntime(runtime.phase ?? 'generation');
}

function parseInjectedLimit(env, name) {
  const value = env?.[name];
  if (value === undefined) return undefined;
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw resourceLimit(`${name} must be a canonical non-negative integer`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throw resourceLimit(`${name} exceeds the safe integer range`);
  return number;
}

function resolvedProfileFor(request, profile) {
  return resolveProfile(profile.id, {
    featureFlags: Object.fromEntries(
      profile.features.map((name) => [name, request.featureFlags[name]]),
    ),
    scale: request.scale,
    version: profile.version,
  });
}

async function initializeStage(runtime) {
  await atomicWriteCanonical(path.join(runtime.stage, 'fixture-request.json'), runtime.request, {
    artifact: 'fixture-request.json',
    budget: runtime.budget,
  });
  await atomicWriteCanonical(path.join(runtime.stage, 'workload-profile.json'), runtime.profile, {
    artifact: 'workload-profile.json',
    budget: runtime.budget,
  });
}

function updatePathChains(chains, record) {
  const line = `${canonicalStringify(record)}\n`;
  const pathIdentity = {
    fileId: record.fileId,
    group: record.group ?? null,
    kind: record.kind,
    logicalPath: record.logicalPath,
    mode: record.mode,
    role: record.role,
  };
  chains.paths.update(`${canonicalStringify(pathIdentity)}\n`);
  chains.content.update(contentIndexLine(record));
  chains.tree.update(line);
  return line;
}

async function checkpoint(runtime, phase, nextItemIndex, state = 'generating') {
  assertRuntimeLimits(runtime);
  runtime.sequence += 1;
  const document = checkpointDocument({
    chains: runtime.chains,
    completedItems: runtime.completedPathCount + runtime.completedOperationCount,
    completedLogicalBytes: runtime.logicalBytes,
    nextItemIndex,
    phase,
    requestDigest: runtime.requestDigest,
    sequence: runtime.sequence,
    stageId: runtime.stageId,
    state,
  });
  await atomicWriteCanonical(path.join(runtime.stage, 'checkpoint.json'), document, {
    artifact: 'checkpoint.json',
    budget: runtime.budget,
  });
  assertRuntimeLimits(runtime);
  progress(runtime.options, {
    checkpoint: document.checkpointSequence,
    completed: nextItemIndex,
    phase,
    type: 'checkpoint',
  });
  const pauseAt = parseInjectedLimit(
    runtime.options.env,
    'OGVCS_FIXTURE_TEST_PAUSE_AT_CHECKPOINT',
  );
  if (pauseAt === document.checkpointSequence) {
    const pauseMs = parseInjectedLimit(
      runtime.options.env,
      'OGVCS_FIXTURE_TEST_PAUSE_MILLISECONDS',
    ) ?? 1_000;
    if (pauseMs > 30_000) throw resourceLimit('Test checkpoint pause cannot exceed 30000 milliseconds');
    await new Promise((resolve) => setTimeout(resolve, pauseMs));
  }
  const interruptAfter = parseInjectedLimit(
    runtime.options.env,
    'OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_CHECKPOINT',
  );
  if (interruptAfter === document.checkpointSequence) process.exit(99);
  return document;
}

async function ensureRegularArtifact(filePath) {
  const metadata = await lstat(filePath).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw integrityFailure('Generation artifact is missing or unsafe', { path: filePath });
  }
  return metadata;
}

async function registerExistingTopLevelArtifacts(runtime) {
  for (const artifact of ['.ogvcs-fixture-owner.json', ...GENERATED_ARTIFACTS]) {
    if (artifact === 'files') continue;
    const metadata = await lstat(path.join(runtime.stage, artifact)).catch((error) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (metadata?.isFile() && !metadata.isSymbolicLink()) {
      runtime.budget.setArtifactBytes(artifact, metadata.size);
    }
  }
}

function recordCanMaterialize(request, record) {
  if (record.content.algorithm === 'sha256') {
    return shouldMaterializeSmall(request, record.index);
  }
  return record.content.algorithm === 'sha256-recipe-v2'
    && ['full', 'sparse'].includes(requestSettings(request).largeFileMode);
}

async function assertCanonicalMaterializedTree(runtime) {
  const root = path.join(runtime.stage, 'files');
  const rootMetadata = await lstat(root).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!rootMetadata) return;
  if (!rootMetadata.isDirectory() || rootMetadata.isSymbolicLink()) {
    throw unsafeDestination('Materialized tree is not a real directory', { path: root });
  }

  const files = new Set();
  const directories = new Set();
  async function visit(directory, prefix = '') {
    const handle = await opendir(directory);
    for await (const entry of handle) {
      runtime.budget.checkRuntime('recovery-materialized-tree-scan');
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const target = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw unsafeDestination('Materialized tree contains a symbolic link', { path: target });
      }
      if (entry.isDirectory()) {
        directories.add(relative);
        await visit(target, relative);
      } else if (entry.isFile()) {
        files.add(relative);
      } else {
        throw unsafeDestination('Materialized tree contains an unsupported entry', { path: target });
      }
    }
  }
  await visit(root);

  for (
    let index = 0;
    index < runtime.request.scale.pathCount && (files.size > 0 || directories.size > 0);
    index += 1
  ) {
    if (index % 1024 === 0) runtime.budget.checkRuntime('recovery-materialized-tree-proof');
    const record = createPathRecord(runtime.request, runtime.profile, index);
    if (!recordCanMaterialize(runtime.request, record)) continue;
    files.delete(record.logicalPath);
    const segments = record.logicalPath.split('/');
    segments.pop();
    let prefix = '';
    for (const segment of segments) {
      prefix = prefix ? `${prefix}/${segment}` : segment;
      directories.delete(prefix);
    }
  }
  if (files.size > 0 || directories.size > 0) {
    throw unsafeDestination('Materialized tree contains paths not derived by the canonical request', {
      directories: [...directories].sort().slice(0, 8),
      files: [...files].sort().slice(0, 8),
    });
  }
}

async function recoverInventory(runtime, checkpointDocument) {
  const phase = checkpointDocument.extensions['generation.phase'];
  const limit = phase === 'paths'
    ? checkpointDocument.nextItemIndex
    : runtime.request.scale.pathCount;
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > runtime.request.scale.pathCount) {
    throw integrityFailure('Checkpoint path cursor is outside the request');
  }
  const inventoryPath = path.join(runtime.stage, 'inventory.ndjson');
  const metadata = await ensureRegularArtifact(inventoryPath);
  let logicalBytes = 0;
  let largeRecord;
  const parsed = await readNdjson(inventoryPath, async (record, context) => {
    runtime.budget.checkRuntime('recovery-inventory-record');
    const expected = createPathRecord(runtime.request, runtime.profile, context.count);
    if (canonicalStringify(record) !== canonicalStringify(expected)) {
      throw integrityFailure('Inventory record differs from deterministic request output', {
        index: context.count,
      });
    }
    updatePathChains(runtime.chains, expected);
    computeDirectorySet(expected, runtime.directories);
    logicalBytes += expected.content.logicalBytes;
    if (context.count === 0 && expected.content.algorithm === 'sha256-recipe-v2') largeRecord = expected;
    // During the path phase, materialized files are reconstructed from the
    // durable inventory cursor below. Skipping their pre-rebuild registration
    // keeps the physical ledger single-counted and makes an interrupted rebuild
    // idempotently resumable. Later phases own a complete files tree and verify
    // it in place.
    if (phase !== 'paths') {
      await verifySmallRecord(runtime.stage, runtime.request, expected, runtime.budget);
    }
  }, { maxRecords: limit });
  if (parsed.count !== limit) {
    throw integrityFailure('Inventory is shorter than its verified checkpoint', {
      actual: parsed.count,
      expected: limit,
    });
  }
  if (metadata.size > parsed.bytes) {
    await truncate(inventoryPath, parsed.bytes);
    if (phase !== 'paths') {
      throw integrityFailure('Inventory contains data written after a completed path phase');
    }
    progress(runtime.options, {
      completed: limit,
      phase: 'paths',
      type: 'discarded-uncheckpointed-tail',
    });
  }
  const settings = requestSettings(runtime.request);
  const rebuildSmallMaterialization = settings.materialization !== 'index-only';
  const discardUncheckpointedPhysicalLarge = largeRecord !== undefined
    && ['full', 'sparse'].includes(settings.largeFileMode);
  if (phase === 'paths' && largeRecord !== undefined) {
    // A descriptor is not checkpoint-owned until the operations handoff. A
    // crash after its atomic write but before that handoff must not make the
    // retry depend on an ahead-of-checkpoint artifact.
    await removeOwnedArtifacts(runtime.stage, runtime.requestDigest, ['large-file.json']);
    runtime.budget.removeArtifact('large-file.json');
  }
  if (phase === 'paths' && (rebuildSmallMaterialization || discardUncheckpointedPhysicalLarge)) {
    // A crash can occur after an uncheckpointed file is fsynced but before its
    // buffered inventory line is durable. Rebuild the path-phase files from
    // the verified checkpoint cursor so no ahead-of-checkpoint file can block
    // the resumed writer's exclusive create. A completed large-file handoff
    // always advances the checkpoint to operations, so this cannot discard a
    // checkpoint-owned large representation. Physical large-file modes also
    // use files/ when ordinary materialization is index-only, so their partial
    // exclusive-created file must be discarded before retry.
    await assertCanonicalMaterializedTree(runtime);
    await removeOwnedArtifacts(runtime.stage, runtime.requestDigest, ['files']);
    for (let index = 0; index < limit; index += 1) {
      runtime.budget.checkRuntime('recovery-materialization-rebuild');
      const record = createPathRecord(runtime.request, runtime.profile, index);
      await materializeSmallRecord(runtime.stage, runtime.request, record, runtime.budget);
    }
    progress(runtime.options, {
      completed: limit,
      phase: 'paths',
      type: 'reconciled-path-materialization',
    });
  }
  runtime.budget.setArtifactBytes('inventory.ndjson', parsed.bytes);
  runtime.completedPathCount = limit;
  runtime.logicalBytes = logicalBytes;
  runtime.largeRecord = largeRecord;
}

async function recoverOperations(runtime, checkpointDocument) {
  const phase = checkpointDocument.extensions['generation.phase'];
  const limit = phase === 'operations' ? checkpointDocument.nextItemIndex : runtime.request.scale.historyOperationCount;
  if (!Number.isSafeInteger(limit) || limit < 0 || limit > runtime.request.scale.historyOperationCount) {
    throw integrityFailure('Checkpoint operation cursor is outside the request');
  }
  if (limit === 0) {
    if (phase === 'operations') {
      // The large-file handoff checkpoint precedes creation of the operation
      // stream. Discard any ahead-of-checkpoint artifact so the resumed writer
      // can create the canonical empty/non-empty stream exclusively.
      await removeOwnedArtifacts(runtime.stage, runtime.requestDigest, ['operations.ndjson']);
      runtime.budget.removeArtifact('operations.ndjson');
      runtime.completedOperationCount = 0;
      return;
    }
    const operationsPath = path.join(runtime.stage, 'operations.ndjson');
    const metadata = await ensureRegularArtifact(operationsPath);
    if (metadata.size !== 0) {
      throw integrityFailure('Zero-operation checkpoint has a non-empty operation stream', {
        actualBytes: metadata.size,
      });
    }
    runtime.budget.setArtifactBytes('operations.ndjson', 0);
    runtime.completedOperationCount = 0;
    return;
  }
  const operationsPath = path.join(runtime.stage, 'operations.ndjson');
  const metadata = await ensureRegularArtifact(operationsPath);
  const parsed = await readNdjson(operationsPath, (operation, context) => {
    runtime.budget.checkRuntime('recovery-operation-record');
    const expected = createOperation(runtime.request, runtime.profile, context.count);
    const line = `${canonicalStringify(expected)}\n`;
    if (canonicalStringify(operation) !== canonicalStringify(expected)) {
      throw integrityFailure('Operation record differs from deterministic request output', {
        sequence: context.count,
      });
    }
    runtime.chains.operations.update(line);
  }, { maxRecords: limit });
  if (parsed.count !== limit) throw integrityFailure('Operation stream is shorter than its checkpoint');
  if (metadata.size > parsed.bytes) {
    await truncate(operationsPath, parsed.bytes);
    progress(runtime.options, {
      completed: limit,
      phase: 'operations',
      type: 'discarded-uncheckpointed-tail',
    });
  }
  runtime.budget.setArtifactBytes('operations.ndjson', parsed.bytes);
  runtime.completedOperationCount = limit;
}

async function recoverLarge(runtime, checkpointDocument) {
  const phase = checkpointDocument.extensions['generation.phase'];
  if (!runtime.largeRecord || phase === 'paths' || phase === 'large-file') return;
  const descriptor = await readBoundedJson(
    path.join(runtime.stage, 'large-file.json'),
    'large-file descriptor',
    {
      budget: runtime.budget,
      maximumBytes: MAX_CONTROL_DOCUMENT_BYTES,
      phase: 'recovery-large-descriptor',
    },
  );
  const descriptorMetadata = await stat(path.join(runtime.stage, 'large-file.json'));
  runtime.budget.setArtifactBytes('large-file.json', descriptorMetadata.size);
  await verifyLargeFile(runtime.stage, runtime.request, runtime.largeRecord, descriptor, {
    budget: runtime.budget,
    deep: true,
  });
  runtime.largeDescriptor = descriptor;
}

async function recoverControlArtifacts(runtime) {
  const controls = [
    ['fixture-request.json', 'stored fixture request', runtime.request],
    ['workload-profile.json', 'stored workload profile', runtime.profile],
  ];
  for (const [artifact, description, expected] of controls) {
    const actual = await readBoundedJson(
      path.join(runtime.stage, artifact),
      description,
      {
        budget: runtime.budget,
        maximumBytes: MAX_CONTROL_DOCUMENT_BYTES,
        phase: `recovery-${artifact}`,
      },
    );
    if (canonicalStringify(actual) !== canonicalStringify(expected)) {
      throw integrityFailure(`${description} differs from the canonical request`);
    }
  }
}

async function tryRecovery(runtime) {
  const document = await readCheckpoint(runtime.stage, runtime.requestDigest, runtime.stageId);
  runtime.sequence = document.checkpointSequence;
  await recoverControlArtifacts(runtime);
  await recoverInventory(runtime, document);
  const phase = document.extensions['generation.phase'];
  if (['operations', 'finalize'].includes(phase)) await recoverOperations(runtime, document);
  await recoverLarge(runtime, document);
  assertChainSnapshots(runtime.chains, document.rollingDigests);
  if (runtime.logicalBytes !== document.completedLogicalBytes) {
    throw integrityFailure('Checkpoint logical byte count differs from the inventory');
  }
  if (
    runtime.completedPathCount + runtime.completedOperationCount
    !== document.completedItems
  ) {
    throw integrityFailure('Checkpoint completed item count differs from the artifacts');
  }
  await removeOwnedArtifacts(runtime.stage, runtime.requestDigest, ['manifest.json', 'scenario.json', 'groups.json']);
  for (const artifact of ['manifest.json', 'scenario.json', 'groups.json']) runtime.budget.removeArtifact(artifact);
  progress(runtime.options, {
    completed: document.completedItems,
    phase,
    type: 'resumed',
  });
  return phase;
}

async function restart(runtime, reason) {
  await assertCanonicalMaterializedTree(runtime);
  await removeOwnedArtifacts(runtime.stage, runtime.requestDigest, GENERATED_ARTIFACTS);
  runtime.chains = createChains();
  runtime.completedOperationCount = 0;
  runtime.completedPathCount = 0;
  runtime.directories = new Set();
  runtime.largeDescriptor = null;
  runtime.largeRecord = null;
  runtime.logicalBytes = 0;
  runtime.sequence = 0;
  runtime.budget.retainArtifacts(['.ogvcs-fixture-owner.json']);
  await initializeStage(runtime);
  progress(runtime.options, { phase: 'paths', reason, type: 'restarted' });
  return 'paths';
}

function isProvenRecoveryCorruption(error) {
  if (error?.type !== 'integrity-failure') return false;
  // Integrity wrappers preserve host read failures in details.code. Absence is
  // deterministic damage, but permission, device, and transient I/O failures
  // must not authorize deletion of a valid resumable stage.
  return error.details?.code === undefined || error.details.code === 'ENOENT';
}

async function generatePaths(runtime) {
  const inventoryPath = path.join(runtime.stage, 'inventory.ndjson');
  const append = runtime.completedPathCount > 0;
  const writer = await BufferedFileWriter.create(inventoryPath, {
    append,
    artifact: 'inventory.ndjson',
    budget: runtime.budget,
  });
  try {
    for (let index = runtime.completedPathCount; index < runtime.request.scale.pathCount; index += 1) {
      if (index % 1024 === 0) assertRuntimeLimits(runtime);
      const record = createPathRecord(runtime.request, runtime.profile, index);
      const line = updatePathChains(runtime.chains, record);
      await writer.write(line);
      runtime.logicalBytes += record.content.logicalBytes;
      runtime.completedPathCount = index + 1;
      computeDirectorySet(record, runtime.directories);
      if (record.content.algorithm === 'sha256-recipe-v2') runtime.largeRecord = record;
      await materializeSmallRecord(runtime.stage, runtime.request, record, runtime.budget);
      const interruptAfterMaterializedPath = parseInjectedLimit(
        runtime.options.env,
        'OGVCS_FIXTURE_TEST_INTERRUPT_AFTER_MATERIALIZED_PATH',
      );
      if (interruptAfterMaterializedPath === runtime.completedPathCount) process.exit(99);

      if (
        runtime.completedPathCount % requestSettings(runtime.request).checkpointEvery === 0
        || runtime.completedPathCount === runtime.request.scale.pathCount
      ) {
        await writer.flush(true);
        await checkpoint(runtime, 'paths', runtime.completedPathCount);
      }
    }
  } finally {
    await writer.close();
  }
}

async function generateLarge(runtime) {
  if (runtime.largeRecord && !runtime.largeDescriptor) {
    runtime.largeDescriptor = await materializeLargeFile(
      runtime.stage,
      runtime.request,
      runtime.largeRecord,
      runtime.budget,
    );
  }
  await checkpoint(runtime, 'operations', runtime.completedOperationCount);
}

async function generateOperations(runtime) {
  const operationsPath = path.join(runtime.stage, 'operations.ndjson');
  const append = runtime.completedOperationCount > 0;
  const writer = await BufferedFileWriter.create(operationsPath, {
    append,
    artifact: 'operations.ndjson',
    budget: runtime.budget,
  });
  try {
    for (
      let sequence = runtime.completedOperationCount;
      sequence < runtime.request.scale.historyOperationCount;
      sequence += 1
    ) {
      if (sequence % 1024 === 0) assertRuntimeLimits(runtime);
      const operation = createOperation(runtime.request, runtime.profile, sequence);
      const line = `${canonicalStringify(operation)}\n`;
      runtime.chains.operations.update(line);
      await writer.write(line);
      runtime.completedOperationCount = sequence + 1;
      if (
        runtime.completedOperationCount % requestSettings(runtime.request).checkpointEvery === 0
        || runtime.completedOperationCount === runtime.request.scale.historyOperationCount
      ) {
        await writer.flush(true);
        await checkpoint(runtime, 'operations', runtime.completedOperationCount);
      }
    }
  } finally {
    await writer.close();
  }
  await checkpoint(runtime, 'finalize', runtime.completedOperationCount, 'verifying');
}

async function writeScenario(runtime) {
  const envelope = scenarioEnvelope(
    runtime.request,
    runtime.profile,
    [],
    runtime.chains.operations.digest,
  );
  const scenarioPath = path.join(runtime.stage, 'scenario.json');
  const writer = await BufferedFileWriter.create(scenarioPath, {
    artifact: 'scenario.json',
    budget: runtime.budget,
  });
  let closed = false;
  const orderedPrefix = {
    digest: envelope.digest,
    networkConditions: envelope.networkConditions,
  };
  const orderedSuffix = {
    extensions: envelope.extensions,
    participants: envelope.participants,
    profile: envelope.profile,
    scenarioId: envelope.scenarioId,
    schemaVersion: envelope.schemaVersion,
    seed: envelope.seed,
  };
  const prefix = canonicalStringify(orderedPrefix);
  try {
    await writer.write(`${prefix.slice(0, -1)},"operations":[`);
    for (let sequence = 0; sequence < runtime.request.scale.historyOperationCount; sequence += 1) {
      if (sequence % 1024 === 0) assertRuntimeLimits(runtime);
      if (sequence > 0) await writer.write(',');
      await writer.write(canonicalStringify(createOperation(runtime.request, runtime.profile, sequence)));
    }
    const suffix = canonicalStringify(orderedSuffix);
    await writer.write(`],${suffix.slice(1)}\n`);
    await writer.close();
    closed = true;
  } finally {
    if (!closed) await writer.abort();
  }
  return {
    digest: await hashFile(scenarioPath, runtime.budget, 'hash-final-scenario'),
    envelopeDigest: envelope.digest,
  };
}

function representationArtifactNames(runtime) {
  const names = [];
  const settings = requestSettings(runtime.request);
  const hasLarge = runtime.request.scale.largeFileBytes > 0;
  if (hasLarge) names.push('large-file.json');
  const smallPaths = runtime.request.scale.pathCount - (hasLarge ? 1 : 0);
  const sampled = settings.materialization === 'sampled'
    ? Math.min(runtime.request.scale.pathCount, settings.materializedPathLimit)
    : 0;
  const materializedSmall = settings.materialization === 'full'
    ? smallPaths
    : settings.materialization === 'sampled'
      ? sampled - (hasLarge && sampled > 0 ? 1 : 0)
      : 0;
  if (
    materializedSmall > 0
    || (hasLarge && !['stream-verified', 'virtual'].includes(settings.largeFileMode))
  ) names.push('files');
  return names;
}

function preFinalizeArtifactNames(runtime) {
  return [
    '.ogvcs-fixture-owner.json',
    'checkpoint.json',
    'fixture-request.json',
    'inventory.ndjson',
    'operations.ndjson',
    'workload-profile.json',
    ...representationArtifactNames(runtime),
  ];
}

function completedArtifactNames(runtime) {
  return [
    '.ogvcs-fixture-owner.json',
    'fixture-request.json',
    'groups.json',
    'inventory.ndjson',
    'manifest.json',
    'operations.ndjson',
    'scenario.json',
    'workload-profile.json',
    ...representationArtifactNames(runtime),
  ];
}

async function finalize(runtime) {
  runtime.phase = 'final-scenario-and-manifest';
  assertRuntimeLimits(runtime);
  const groups = createGroups(runtime.request, runtime.profile);
  assertRuntimeLimits(runtime);
  await atomicWriteCanonical(path.join(runtime.stage, 'groups.json'), groups, {
    artifact: 'groups.json',
    budget: runtime.budget,
  });
  const scenario = await writeScenario(runtime);
  const inventoryDigest = await hashFile(
    path.join(runtime.stage, 'inventory.ndjson'),
    runtime.budget,
    'hash-final-inventory',
  );
  const groupsDigest = canonicalDigest(groups, 'ogvcs.fixture/groups/v1');
  const treeDigest = canonicalDigest({
    content: runtime.chains.content.snapshot(),
    groups: groupsDigest,
    paths: runtime.chains.paths.snapshot(),
    profile: runtime.resolvedProfile.resolvedDigest,
    treeRecords: runtime.chains.tree.snapshot(),
  }, 'ogvcs.fixture/tree/v1');
  const settings = requestSettings(runtime.request);
  const manifestBody = {
    counts: {
      directories: runtime.directories.size,
      files: runtime.request.scale.pathCount,
      groups: groups.length,
      operations: runtime.request.scale.historyOperationCount,
      paths: runtime.request.scale.pathCount,
    },
    digests: {
      content: runtime.chains.content.digest,
      operations: runtime.chains.operations.digest,
      paths: runtime.chains.paths.digest,
      tree: treeDigest,
    },
    extensions: {
      'algorithms.canonical': 'ogvcs-canonical-json-v1',
      'algorithms.content': CONTENT_STREAM_ALGORITHM,
      'algorithms.paths': 'ogvcs-logical-path-v1',
      'artifacts.groups': 'groups.json',
      'artifacts.large-file': runtime.largeDescriptor ? 'large-file.json' : null,
      'groups.digest': groupsDigest,
      'large-file.descriptor-digest': runtime.largeDescriptor?.descriptorDigest ?? null,
      'representation.large-file': settings.largeFileMode,
      'representation.paths': settings.materialization,
      'scenario.envelope-digest': scenario.envelopeDigest,
    },
    groups,
    history: historyShape(runtime.request, runtime.profile, runtime.budget),
    inventory: {
      digest: inventoryDigest,
      format: 'canonical-json-lines-v1',
      path: 'inventory.ndjson',
    },
    logicalBytes: runtime.logicalBytes,
    operationScenario: {
      digest: scenario.digest,
      path: 'scenario.json',
    },
    profile: {
      id: runtime.profile.id,
      resolvedDigest: runtime.resolvedProfile.resolvedDigest,
      version: runtime.profile.version,
    },
    provenance: {
      classification: 'fully-synthetic',
      generatedArtifactsContainExternalIdentifiers: false,
      generatorAlgorithm: 'ogvcs-fixture-generator-v1',
      license: runtime.profile.license,
      requestMetadata: 'caller-supplied-unattested',
    },
    request: runtime.request,
    requestDigest: runtime.requestDigest,
    schemaVersion: MANIFEST_SCHEMA,
    schemaVersions: { ...SCHEMA_VERSIONS },
    tool: { name: TOOL_NAME, version: GENERATOR_VERSION },
  };
  const manifest = addManifestDigest(manifestBody);
  await unlink(path.join(runtime.stage, 'checkpoint.json')).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  runtime.budget.removeArtifact('checkpoint.json');
  await syncDirectory(runtime.stage, 'checkpoint-removal-sync');
  await atomicWriteCanonical(path.join(runtime.stage, 'manifest.json'), manifest, {
    artifact: 'manifest.json',
    budget: runtime.budget,
  });
  assertRuntimeLimits(runtime);
  return manifest;
}

function assertPlanWithinLimits(request) {
  const plan = planFixture(request);
  const maximumPhysicalBytes = request.resourceLimits?.maximumPhysicalBytes;
  if (maximumPhysicalBytes !== undefined && BigInt(plan.estimates.physicalBytes) > BigInt(maximumPhysicalBytes)) {
    throw resourceLimit('Planned fixture exceeds resourceLimits.maximumPhysicalBytes', {
      estimate: plan.estimates.physicalBytes,
      limit: maximumPhysicalBytes,
    });
  }
  if (
    request.resourceLimits?.maximumMemoryBytes !== undefined
    && request.resourceLimits.maximumMemoryBytes < Number(plan.estimates.peakGeneratorMemoryBytes)
  ) {
    throw resourceLimit('Planned generator memory exceeds resourceLimits.maximumMemoryBytes');
  }
  if (
    request.resourceLimits?.maximumDurationSeconds !== undefined
    && request.resourceLimits.maximumDurationSeconds < plan.estimates.durationSeconds
  ) {
    throw resourceLimit('Planned fixture exceeds resourceLimits.maximumDurationSeconds', {
      estimate: plan.estimates.durationSeconds,
      limit: request.resourceLimits.maximumDurationSeconds,
    });
  }
}

async function generateFixtureInternal(input, options = {}) {
  const startedAt = Date.now();
  const cwd = options.cwd ?? process.cwd();
  const physicalCwd = await realpath(cwd);
  const resolved = resolveRequest(input);
  assertPlanWithinLimits(resolved.request);
  const budget = new ResourceBudget({
    deadline: resolved.request.resourceLimits?.maximumDurationSeconds === undefined
      ? undefined
      : startedAt + resolved.request.resourceLimits.maximumDurationSeconds * 1000,
    failAfterBytes: parseInjectedLimit(options.env ?? {}, 'OGVCS_FIXTURE_TEST_FAIL_AFTER_BYTES'),
    maximumMemoryBytes: resolved.request.resourceLimits?.maximumMemoryBytes,
    maximumPhysicalBytes: resolved.request.resourceLimits?.maximumPhysicalBytes,
    testFailurePhase: options.env?.OGVCS_FIXTURE_TEST_FAIL_RUNTIME_PHASE,
  });
  const destinationPath = path.resolve(physicalCwd, ...resolved.request.destination.split('/'));
  const workspace = await prepareWorkspace(destinationPath, resolved.requestDigest, {
    budget,
    env: options.env,
    resume: options.resume ?? false,
  });
  const postCommitWarnings = [];

  if (workspace.completedDestination) {
    try {
      const loaded = await loadManifest(workspace.destination, { budget });
      if (loaded.manifest.requestDigest !== resolved.requestDigest) {
        throw unsafeDestination('Existing completed fixture belongs to an incompatible request', {
          path: resolved.request.destination,
        });
      }
      const verification = await budget.runPhase(
        'completed-fixture-verification',
        () => verifyFixtureDirectory(workspace.destination, { budget, deep: true }),
      );
      if (!verification.verified) {
        throw integrityFailure('Existing completed fixture failed deterministic deep verification', {
          verification,
        });
      }
      try {
        await reconcileCompletedOwnedStage(
          workspace.stage,
          workspace.destination,
          resolved.requestDigest,
          budget,
        );
      } catch (error) {
        postCommitWarnings.push(postCommitDiagnostic(error, 'stage-reconciliation'));
      }
      await releaseCommittedWorkspace(workspace.releaseLock, postCommitWarnings);
      return {
        destination: resolved.request.destination,
        manifestDigest: loaded.manifest.manifestDigest,
        ...(postCommitWarnings.length > 0 ? { postCommitWarnings } : {}),
        requestDigest: resolved.requestDigest,
        resumed: true,
        summary: loaded.manifest.counts,
      };
    } catch (error) {
      await releaseFailedWorkspace(workspace.releaseLock, error);
      throw error;
    }
  }

  const runtime = {
    budget,
    chains: createChains(),
    completedOperationCount: 0,
    completedPathCount: 0,
    directories: new Set(),
    largeDescriptor: null,
    largeRecord: null,
    logicalBytes: 0,
    options: { ...options, cwd: physicalCwd, env: options.env ?? {} },
    profile: resolved.profile,
    request: resolved.request,
    requestDigest: resolved.requestDigest,
    resolvedProfile: resolvedProfileFor(resolved.request, resolved.profile),
    sequence: 0,
    stage: workspace.stage,
    stageId: canonicalDigest(
      { destination: resolved.request.destination, requestDigest: resolved.requestDigest },
      'ogvcs.fixture/stage/v1',
    ).slice(0, 32),
  };

  let phase = 'paths';
  let published = false;
  let lockReleased = false;
  let primaryError;
  try {
    await registerExistingTopLevelArtifacts(runtime);
    if (options.resume) {
      const cleanup = await removeOwnedAtomicTemporaryArtifacts(runtime.stage, runtime.requestDigest);
      if (cleanup.removed.length > 0) {
        progress(runtime.options, {
          artifacts: cleanup.removed,
          phase: 'recovery',
          type: 'removed-owned-atomic-temporaries',
        });
      }
    }
    await assertWorkspaceArtifactAllowlist(runtime.stage, runtime.requestDigest);
    if (options.resume) {
      try {
        phase = await tryRecovery(runtime);
      } catch (error) {
        if (!isProvenRecoveryCorruption(error)) throw error;
        phase = await restart(runtime, error.message);
      }
    } else {
      await initializeStage(runtime);
    }

    if (phase === 'paths') {
      await generatePaths(runtime);
      phase = 'large-file';
    }
    if (phase === 'large-file' || phase === 'paths') {
      await generateLarge(runtime);
      phase = 'operations';
    }
    if (phase === 'operations') {
      await generateOperations(runtime);
      phase = 'finalize';
    }
    const preFinalizeArtifacts = preFinalizeArtifactNames(runtime);
    await assertWorkspaceArtifactAllowlist(runtime.stage, runtime.requestDigest, {
      allowed: preFinalizeArtifacts,
      required: preFinalizeArtifacts,
    });
    const manifest = await finalize(runtime);
    const requiredArtifacts = completedArtifactNames(runtime);
    await assertWorkspaceArtifactAllowlist(runtime.stage, runtime.requestDigest, {
      allowed: requiredArtifacts,
      required: requiredArtifacts,
    });
    runtime.phase = 'mandatory-prepublication-verification';
    const verification = await runtime.budget.runPhase(
      runtime.phase,
      () => verifyFixtureDirectory(runtime.stage, { budget: runtime.budget, deep: true }),
    );
    if (!verification.verified) {
      throw integrityFailure('Generated fixture failed deterministic deep verification before publication', {
        verification,
      });
    }
    const publicationMetadataBytes = Number(
      planFixture(runtime.request).estimates.physicalFilesystemMetadataBytes,
    );
    runtime.budget.setArtifactBytes('.stage-filesystem-metadata', publicationMetadataBytes);
    runtime.budget.setArtifactBytes('.publication-filesystem-metadata', publicationMetadataBytes);
    runtime.phase = 'publication';
    await publishWorkspace(
      runtime.stage,
      workspace.destination,
      runtime.requestDigest,
      {
        ...workspace,
        budget: runtime.budget,
        env: runtime.options.env,
        expectedArtifacts: requiredArtifacts,
        postCommitDiagnostics: postCommitWarnings,
      },
    );
    published = true;
    try {
      progress(runtime.options, {
        completed: runtime.completedPathCount + runtime.completedOperationCount,
        manifestDigest: manifest.manifestDigest,
        phase: 'published',
        type: 'complete',
      });
    } catch (error) {
      postCommitWarnings.push(postCommitDiagnostic(error, 'progress-callback'));
    }
    await releaseCommittedWorkspace(workspace.releaseLock, postCommitWarnings);
    lockReleased = true;
    return {
      destination: runtime.request.destination,
      manifestDigest: manifest.manifestDigest,
      ...(postCommitWarnings.length > 0 ? { postCommitWarnings } : {}),
      requestDigest: runtime.requestDigest,
      resumed: options.resume ?? false,
      summary: manifest.counts,
    };
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (published && !lockReleased) {
      await releaseCommittedWorkspace(workspace.releaseLock, postCommitWarnings);
    }
    else if (primaryError) await releaseFailedWorkspace(workspace.releaseLock, primaryError);
    else if (!lockReleased) await workspace.releaseLock();
  }
}

export async function generateFixture(input, options = {}) {
  try {
    return await generateFixtureInternal(input, options);
  } catch (error) {
    if (['EDQUOT', 'EFBIG', 'ENOSPC'].includes(error?.code)) {
      throw resourceLimit('Filesystem resource limit prevented fixture generation', {
        boundary: error.persistenceBoundary,
        code: error.code,
      });
    }
    if (error?.code === 'ENAMETOOLONG') {
      throw unsafeDestination('Resolved destination exceeds the host filesystem path limit', {
        code: error.code,
      });
    }
    throw error;
  }
}
