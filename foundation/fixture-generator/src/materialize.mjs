import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, open, stat } from 'node:fs/promises';
import path from 'node:path';

import { canonicalDigest } from './canonical.mjs';
import { deriveBytes } from './prng.mjs';
import { contentChunksForRecord, largeFileRecipe, largeVersionChunks } from './model.mjs';
import { requestSettings } from './request.mjs';
import { integrityFailure, resourceLimit, unsafeDestination } from './errors.mjs';
import { atomicWriteCanonical, hashFile } from './io.mjs';
import { rejectSymlinkChain } from './safety.mjs';

function shouldMaterializeSmall(request, index) {
  const settings = requestSettings(request);
  if (settings.materialization === 'index-only') return false;
  if (settings.materialization === 'sampled') return index < settings.materializedPathLimit;
  return true;
}

function accountBytes(state, bytes, artifact = 'materialized-content') {
  if (typeof state?.appendArtifactBytes === 'function') {
    state.appendArtifactBytes(artifact, bytes);
    return;
  }
  checkRuntimeBudget(state);
  state.physicalBytes += bytes;
  const injectedLimit = state.failAfterBytes;
  if (injectedLimit !== undefined && state.physicalBytes > injectedLimit) {
    throw resourceLimit('Injected physical-write limit reached', {
      limit: injectedLimit,
      written: state.physicalBytes,
    });
  }
  const requestLimit = state.maximumPhysicalBytes;
  if (requestLimit !== undefined && state.physicalBytes > requestLimit) {
    throw resourceLimit('Request maximumPhysicalBytes limit reached', {
      limit: requestLimit,
      written: state.physicalBytes,
    });
  }
}

function checkRuntimeBudget(state) {
  if (typeof state?.checkRuntime === 'function') {
    state.checkRuntime('content-materialization');
    return;
  }
  if (state.deadline !== undefined && Date.now() > state.deadline) {
    throw resourceLimit('Request maximumDurationSeconds limit reached');
  }
  if (state.maximumMemoryBytes !== undefined && process.memoryUsage().rss > state.maximumMemoryBytes) {
    throw resourceLimit('Request maximumMemoryBytes limit reached');
  }
}

function reserveSparseAllocation(state, bytes, artifact) {
  const currentPhysicalBytes = state?.physicalBytes ?? 0;
  if (typeof state?.assertPhysical === 'function') {
    state.assertPhysical(currentPhysicalBytes + bytes, artifact);
  } else if (
    state?.maximumPhysicalBytes !== undefined
    && currentPhysicalBytes + bytes > state.maximumPhysicalBytes
  ) {
    throw resourceLimit('Request maximumPhysicalBytes limit reached', {
      artifact,
      limit: state.maximumPhysicalBytes,
      required: currentPhysicalBytes + bytes,
    });
  }
  return currentPhysicalBytes;
}

function commitSparseAllocation(state, previousPhysicalBytes, bytes, artifact) {
  if (typeof state?.setArtifactBytes === 'function') {
    state.setArtifactBytes(artifact, bytes);
  } else {
    state.physicalBytes = previousPhysicalBytes + bytes;
  }
}

function runtimeBudget(state) {
  return typeof state?.checkRuntime === 'function' ? state : undefined;
}

function hasExactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

export async function writeFully(handle, bytes, position) {
  let offset = 0;
  while (offset < bytes.length) {
    const result = position === undefined
      ? await handle.write(bytes, offset, bytes.length - offset)
      : await handle.write(bytes, offset, bytes.length - offset, position + offset);
    if (!Number.isSafeInteger(result.bytesWritten) || result.bytesWritten <= 0) {
      throw new Error('Persistence write made no progress');
    }
    offset += result.bytesWritten;
  }
}

async function safeFileTarget(stage, logicalPath, budget) {
  const root = path.join(stage, 'files');
  const target = path.join(root, ...logicalPath.split('/'));
  if (path.relative(root, target).startsWith('..')) {
    throw unsafeDestination('Logical file escaped the materialization root', { logicalPath });
  }
  await rejectSymlinkChain(path.dirname(target), runtimeBudget(budget));
  await mkdir(path.dirname(target), { recursive: true });
  await rejectSymlinkChain(path.dirname(target), runtimeBudget(budget));
  return target;
}

export async function materializeSmallRecord(stage, request, record, writeState) {
  if (record.content.algorithm !== 'sha256' || !shouldMaterializeSmall(request, record.index)) return false;
  const target = await safeFileTarget(stage, record.logicalPath, writeState);
  const handle = await open(target, 'wx', record.mode === '100755' ? 0o755 : 0o644).catch((error) => {
    if (error.code === 'EEXIST') {
      throw unsafeDestination('Refusing to overwrite an existing materialized path', {
        logicalPath: record.logicalPath,
      });
    }
    throw error;
  });
  const hash = createHash('sha256');
  const artifact = `files/${record.logicalPath}`;
  let bytes = 0;
  try {
    for (const chunk of contentChunksForRecord(request, record)) {
      accountBytes(writeState, chunk.length, artifact);
      await writeFully(handle, chunk);
      hash.update(chunk);
      bytes += chunk.length;
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(target, record.mode === '100755' ? 0o755 : 0o644);
  const digest = hash.digest('hex');
  if (digest !== record.content.digest || bytes !== record.content.logicalBytes) {
    throw integrityFailure('Materialized small-file content does not match its inventory record', {
      logicalPath: record.logicalPath,
    });
  }
  return true;
}

export async function verifySmallRecord(stage, request, record, budget) {
  if (record.content.algorithm !== 'sha256' || !shouldMaterializeSmall(request, record.index)) return;
  const target = path.join(stage, 'files', ...record.logicalPath.split('/'));
  await rejectSymlinkChain(target, runtimeBudget(budget));
  const metadata = await lstat(target).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata?.isFile() || metadata.isSymbolicLink()) {
    throw integrityFailure('Materialized file is missing or unsafe', { logicalPath: record.logicalPath });
  }
  if (metadata.size !== record.content.logicalBytes) {
    throw integrityFailure('Materialized file size differs from its inventory', {
      actual: metadata.size,
      expected: record.content.logicalBytes,
      logicalPath: record.logicalPath,
    });
  }
  if (process.platform !== 'win32') {
    const actualMode = metadata.mode & 0o777;
    const expectedMode = record.mode === '100755' ? 0o755 : 0o644;
    if (actualMode !== expectedMode) {
      throw integrityFailure('Materialized file mode differs from its inventory', {
        actual: actualMode.toString(8),
        expected: expectedMode.toString(8),
        logicalPath: record.logicalPath,
      });
    }
  }
  budget?.setArtifactBytes(`files/${record.logicalPath}`, metadata.size);
  const digest = await hashFile(target, budget, 'verify-small-file');
  if (digest !== record.content.digest) {
    throw integrityFailure('Materialized file digest differs from its inventory', {
      actual: digest,
      expected: record.content.digest,
      logicalPath: record.logicalPath,
    });
  }
}

export function sparseExtents(request, size, stream) {
  if (size === 0) return [];
  // Three disjoint samples: overlapping extents make earlier stored digests
  // false as soon as a later extent overwrites the shared bytes.
  const extentBytes = Math.min(1024 * 1024, Math.max(1, Math.floor(size / 3)));
  const candidates = [0, Math.max(0, Math.floor((size - extentBytes) / 2)), Math.max(0, size - extentBytes)];
  return [...new Set(candidates)].map((offset, index) => {
    const bytes = deriveBytes(request.seed, `${stream}/sparse-extent-${index}`, extentBytes);
    return {
      bytes,
      descriptor: {
        digest: createHash('sha256').update(bytes).digest('hex'),
        length: extentBytes,
        offset,
      },
    };
  });
}

export async function materializeLargeFile(stage, request, record, writeState) {
  if (request.scale.largeFileBytes === 0) return null;
  const settings = requestSettings(request);
  const recipe = largeFileRecipe(request, record.logicalPath);
  const descriptor = { ...recipe, physical: { mode: settings.largeFileMode } };
  const artifact = `files/${record.logicalPath}`;

  if (settings.largeFileMode === 'virtual') {
    descriptor.physical = { mode: 'virtual', physicalBytes: 0 };
  } else if (settings.largeFileMode === 'stream-verified') {
    const versionDigests = digestLargeVersions(request, recipe, writeState);
    descriptor.physical = {
      mode: 'stream-verified',
      physicalBytes: 0,
      streamedLogicalBytes: versionDigests.reduce((total, entry) => total + entry.bytes, 0),
      versionDigests,
    };
  } else {
    const target = await safeFileTarget(stage, record.logicalPath, writeState);
    const sparsePreviousPhysicalBytes = settings.largeFileMode === 'sparse'
      ? reserveSparseAllocation(writeState, request.scale.largeFileBytes, artifact)
      : undefined;
    const handle = await open(target, 'wx', 0o644).catch((error) => {
      if (error.code === 'EEXIST') {
        throw unsafeDestination('Refusing to overwrite an existing large-file path', {
          logicalPath: record.logicalPath,
        });
      }
      throw error;
    });
    try {
      if (settings.largeFileMode === 'full') {
        const versionDigests = [];
        let physicalBytes = 0;
        for (const version of recipe.versions) {
          const hash = createHash('sha256');
          let bytes = 0;
          for (const chunk of largeVersionChunks(request, recipe, version.version)) {
            checkRuntimeBudget(writeState);
            if (version.version === recipe.versions.length - 1) {
              accountBytes(writeState, chunk.length, artifact);
              await writeFully(handle, chunk);
              physicalBytes += chunk.length;
            }
            hash.update(chunk);
            bytes += chunk.length;
          }
          versionDigests.push({ algorithm: 'sha256', bytes, digest: hash.digest('hex'), version: version.version });
        }
        descriptor.physical = {
          digest: versionDigests.at(-1).digest,
          logicalFileSize: request.scale.largeFileBytes,
          mode: 'full',
          physicalBytes,
          versionDigests,
        };
      } else {
        await handle.truncate(request.scale.largeFileBytes);
        const extents = sparseExtents(request, request.scale.largeFileBytes, recipe.stream);
        for (const extent of extents) {
          accountBytes(writeState, extent.bytes.length, artifact);
          await writeFully(handle, extent.bytes, extent.descriptor.offset);
        }
        commitSparseAllocation(
          writeState,
          sparsePreviousPhysicalBytes,
          request.scale.largeFileBytes,
          artifact,
        );
        descriptor.physical = {
          extentPayloadBytes: extents.reduce((total, extent) => total + extent.bytes.length, 0),
          extents: extents.map(({ descriptor: value }) => value),
          logicalFileSize: request.scale.largeFileBytes,
          maximumAllocatedBytes: request.scale.largeFileBytes,
          mode: 'sparse',
        };
      }
      await handle.sync();
    } finally {
      await handle.close();
    }
    const metadata = await stat(target);
    if (metadata.size !== request.scale.largeFileBytes) {
      throw integrityFailure('Large-file representation has the wrong logical size', {
        actual: metadata.size,
        expected: request.scale.largeFileBytes,
      });
    }
  }

  descriptor.descriptorDigest = canonicalDigest(descriptor, 'ogvcs.fixture/large-file-descriptor/v2');
  await atomicWriteCanonical(path.join(stage, 'large-file.json'), descriptor, {
    artifact: 'large-file.json',
    budget: writeState,
  });
  return descriptor;
}

export async function verifyLargeFile(directory, request, record, descriptor, options = {}) {
  if (request.scale.largeFileBytes === 0) return { bytes: 0, checked: false };
  if (descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) {
    throw integrityFailure('Large-file descriptor is not an object');
  }
  const { descriptorDigest, physical, ...actualRecipe } = descriptor;
  const descriptorBody = { ...actualRecipe, physical };
  if (canonicalDigest(descriptorBody, 'ogvcs.fixture/large-file-descriptor/v2') !== descriptorDigest) {
    throw integrityFailure('Large-file descriptor digest is invalid');
  }
  const expectedRecipe = largeFileRecipe(request, record.logicalPath);
  if (canonicalDigest(actualRecipe, 'ogvcs.fixture/large-file-recipe-shape/v2')
    !== canonicalDigest(expectedRecipe, 'ogvcs.fixture/large-file-recipe-shape/v2')) {
    throw integrityFailure('Large-file descriptor recipe differs from the canonical request');
  }
  const expectedMode = requestSettings(request).largeFileMode;
  if (physical?.mode !== expectedMode) {
    throw integrityFailure('Large-file physical mode differs from the request');
  }
  if (physical.mode === 'virtual') {
    if (
      !hasExactKeys(physical, ['mode', 'physicalBytes'])
      || physical.physicalBytes !== 0
    ) {
      throw integrityFailure('Virtual large-file representation claims physical bytes');
    }
    return { bytes: 0, checked: true };
  }
  if (physical.mode === 'stream-verified') {
    if (
      !hasExactKeys(
        physical,
        ['mode', 'physicalBytes', 'streamedLogicalBytes', 'versionDigests'],
      )
      || physical.physicalBytes !== 0
    ) {
      throw integrityFailure('Stream-verified large-file representation claims physical bytes');
    }
    assertVersionDigests(physical.versionDigests, expectedRecipe);
    const expectedStreamedBytes = expectedRecipe.logicalBytes * expectedRecipe.versions.length;
    if (physical.streamedLogicalBytes !== expectedStreamedBytes) {
      throw integrityFailure('Stream-verified logical byte count differs from the recipe');
    }
    if (!options.deep) return { bytes: 0, checked: true };
    const actual = digestLargeVersions(request, expectedRecipe, options.budget);
    if (canonicalDigest(actual, 'ogvcs.fixture/large-version-digests/v2')
      !== canonicalDigest(physical.versionDigests, 'ogvcs.fixture/large-version-digests/v2')) {
      throw integrityFailure('Stream-verified large-file version digests are invalid');
    }
    return { bytes: actual.reduce((total, entry) => total + entry.bytes, 0), checked: true };
  }

  const target = path.join(directory, 'files', ...record.logicalPath.split('/'));
  await rejectSymlinkChain(target, runtimeBudget(options.budget));
  const metadata = await lstat(target).catch((error) => {
    if (error.code === 'ENOENT') return null;
    throw error;
  });
  if (!metadata?.isFile() || metadata.isSymbolicLink() || metadata.size !== request.scale.largeFileBytes) {
    throw integrityFailure('Large-file representation is missing, unsafe, or the wrong size');
  }
  if (process.platform !== 'win32' && (metadata.mode & 0o777) !== 0o644) {
    throw integrityFailure('Large-file representation mode differs from its inventory', {
      actual: (metadata.mode & 0o777).toString(8),
      expected: '644',
      logicalPath: record.logicalPath,
    });
  }
  if (physical.mode === 'sparse') {
    if (!hasExactKeys(
      physical,
      ['extentPayloadBytes', 'extents', 'logicalFileSize', 'maximumAllocatedBytes', 'mode'],
    )) {
      throw integrityFailure('Sparse large-file representation has unexpected fields');
    }
    const expectedExtents = sparseExtents(
      request,
      request.scale.largeFileBytes,
      expectedRecipe.stream,
    );
    const expectedDescriptors = expectedExtents.map(({ descriptor: value }) => value);
    if (canonicalDigest(
      physical.extents,
      'ogvcs.fixture/sparse-extents/v2',
    ) !== canonicalDigest(expectedDescriptors, 'ogvcs.fixture/sparse-extents/v2')) {
      throw integrityFailure('Sparse extents differ from the canonical request-derived layout');
    }
    const extentPayloadBytes = expectedDescriptors
      .reduce((total, extent) => total + extent.length, 0);
    if (
      physical.extentPayloadBytes !== extentPayloadBytes
      || physical.logicalFileSize !== request.scale.largeFileBytes
      || physical.maximumAllocatedBytes !== request.scale.largeFileBytes
    ) {
      throw integrityFailure('Sparse allocation bounds differ from the declared extents and logical size');
    }
    options.budget?.setArtifactBytes(
      `files/${record.logicalPath}`,
      physical.maximumAllocatedBytes,
    );
    const handle = await open(target, 'r');
    let checkedBytes = 0;
    try {
      for (const extent of physical.extents) {
        options.budget?.checkRuntime('verify-sparse-large-file');
        const bytes = Buffer.alloc(extent.length);
        const result = await handle.read(bytes, 0, extent.length, extent.offset);
        if (result.bytesRead !== extent.length) throw integrityFailure('Sparse extent is truncated');
        const digest = createHash('sha256').update(bytes).digest('hex');
        if (digest !== extent.digest) throw integrityFailure('Sparse extent digest is invalid');
        checkedBytes += extent.length;
      }
    } finally {
      await handle.close();
    }
    return { bytes: checkedBytes, checked: true };
  }
  if (
    !hasExactKeys(
      physical,
      ['digest', 'logicalFileSize', 'mode', 'physicalBytes', 'versionDigests'],
    )
    || physical.logicalFileSize !== request.scale.largeFileBytes
    || physical.physicalBytes !== request.scale.largeFileBytes
  ) {
    throw integrityFailure('Full large-file representation metadata differs from the request');
  }
  if (options.deep) {
    options.budget?.setArtifactBytes(`files/${record.logicalPath}`, physical.physicalBytes);
    const digest = await hashFile(target, options.budget, 'verify-full-large-file');
    if (digest !== physical.digest) throw integrityFailure('Full large-file digest is invalid');
    assertVersionDigests(physical.versionDigests, expectedRecipe);
    if (physical.versionDigests.at(-1).digest !== digest) {
      throw integrityFailure('Materialized large file is not the declared final version');
    }
    const actual = digestLargeVersions(request, expectedRecipe, options.budget);
    if (canonicalDigest(actual, 'ogvcs.fixture/large-version-digests/v2')
      !== canonicalDigest(physical.versionDigests, 'ogvcs.fixture/large-version-digests/v2')) {
      throw integrityFailure('Full large-file version digests are invalid');
    }
    return { bytes: metadata.size + actual.reduce((total, entry) => total + entry.bytes, 0), checked: true };
  }
  return { bytes: 0, checked: false };
}

function digestLargeVersions(request, recipe, writeState) {
  return recipe.versions.map(({ version }) => {
    const hash = createHash('sha256');
    let bytes = 0;
    for (const chunk of largeVersionChunks(request, recipe, version)) {
      if (writeState) checkRuntimeBudget(writeState);
      hash.update(chunk);
      bytes += chunk.length;
    }
    return { algorithm: 'sha256', bytes, digest: hash.digest('hex'), version };
  });
}

function assertVersionDigests(versionDigests, recipe) {
  if (!Array.isArray(versionDigests) || versionDigests.length !== recipe.versions.length) {
    throw integrityFailure('Large-file version digest count differs from the recipe');
  }
  for (let index = 0; index < versionDigests.length; index += 1) {
    const entry = versionDigests[index];
    if (
      !hasExactKeys(entry, ['algorithm', 'bytes', 'digest', 'version'])
      || entry.algorithm !== 'sha256'
      || entry.version !== index
      || entry.bytes !== recipe.logicalBytes
      || !/^[0-9a-f]{64}$/.test(entry.digest)
    ) throw integrityFailure('Large-file version digest descriptor is invalid');
  }
}

export { shouldMaterializeSmall };
